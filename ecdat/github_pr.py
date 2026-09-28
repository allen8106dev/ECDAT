"""Prepare reviewable patches against a pinned commit; optionally publish a draft PR."""
import base64
import hashlib
import json
import os
import re
import uuid
from pathlib import PurePosixPath
from urllib.parse import quote
from urllib.request import Request, urlopen
from remediation import generate_patch


def github(path, data=None):
    token = os.environ.get('ECDAT_GITHUB_TOKEN')
    if not token:
        raise ValueError('Set ECDAT_GITHUB_TOKEN with repository contents and pull request permissions.')
    request = Request('https://api.github.com' + path, data=json.dumps(data).encode() if data is not None else None,
                      headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json', 'User-Agent': 'ECDAT', 'Content-Type': 'application/json'})
    with urlopen(request, timeout=20) as response:
        return json.load(response)


def prepare_pr(report, repository, branch=''):
    if not re.fullmatch(r'[\w.-]+/[\w.-]+', repository):
        raise ValueError('Use owner/repository.')
    base = '/repos/' + repository
    branch = branch or github(base)['default_branch']
    commit = github(base + '/commits/' + quote(branch, safe=''))
    tree = github(base + '/git/trees/' + commit['commit']['tree']['sha'] + '?recursive=1')
    if tree.get('truncated'):
        raise ValueError('Repository tree is too large for safe PR preparation through this adapter.')
    modes = {item['path']: item.get('mode') for item in tree.get('tree', []) if item.get('type') == 'blob'}
    files = []
    for patch in report.get('patches', [])[:50]:
        path = patch['file']
        if '!/' in path:
            archive, path = path.split('!/', 1)
            if archive.endswith('.zip'):
                path = path.split('/', 1)[-1]
        if PurePosixPath(path).is_absolute() or '..' in PurePosixPath(path).parts or '!/' in path or '\\' in path:
            raise ValueError('Unsupported patch path.')
        if modes.get(path) not in {'100644', '100755'}:
            raise ValueError('Patch target is not a regular source file in the selected commit.')
        item = github(base + '/contents/' + quote(path, safe='/') + '?ref=' + commit['sha'])
        if item.get('encoding') != 'base64' or item.get('size', 0) > 2 * 1024 * 1024:
            raise ValueError('Patch target is unavailable or too large.')
        original = base64.b64decode(item['content']).decode('utf-8')
        if hashlib.sha256(original.encode()).hexdigest() != patch.get('original_sha256'):
            raise ValueError('Repository content changed or scan predates patch fingerprints. Rescan before publishing.')
        regenerated = generate_patch(patch['file'], original)
        if not regenerated or regenerated['diff'] != patch['diff']:
            raise ValueError('Patch does not match the current remediation rules; rescan.')
        # Reconstruct the result from a validated unified diff, retaining untouched lines.
        lines = original.splitlines(keepends=True)
        result, cursor = [], 0
        for line in regenerated['diff'][2:]:
            if line.startswith('@@'):
                match = re.match(r'@@ -(\d+)(?:,\d+)? \+', line)
                start = int(match[1]) - 1
                result.extend(lines[cursor:start]); cursor = start
            elif line.startswith(' '):
                result.append(lines[cursor]); cursor += 1
            elif line.startswith('-'):
                cursor += 1
            elif line.startswith('+'):
                result.append(line[1:] + ('\r\n' if '\r\n' in original else '\n'))
        result.extend(lines[cursor:])
        patched = ''.join(result)
        if not original.endswith(('\n', '\r')):
            patched = patched.rstrip('\r\n')
        if hashlib.sha256(patched.encode()).hexdigest() != regenerated['patched_sha256']:
            raise ValueError('Patch reconstruction differed from the reviewed result.')
        files.append({'path': path, 'content': patched, 'diff': regenerated['diff'], 'mode': modes[path]})
    if not files:
        raise ValueError('No supported patches are available.')
    return {'repository': repository, 'base': branch, 'commit': commit['sha'], 'tree': commit['commit']['tree']['sha'], 'files': files}


def publish_pr(plan):
    base = '/repos/' + plan['repository']
    # Abort if the branch moved after review/preparation.
    if github(base + '/commits/' + quote(plan['base'], safe=''))['sha'] != plan['commit']:
        raise ValueError('Base branch moved; prepare and review the patches again.')
    tree = github(base + '/git/trees', {'base_tree': plan['tree'], 'tree': [
        {'path': f['path'], 'mode': f['mode'], 'type': 'blob', 'content': f['content']} for f in plan['files']]})
    commit = github(base + '/git/commits', {'message': 'Review legacy hash replacements suggested by ECDAT', 'tree': tree['sha'], 'parents': [plan['commit']]})
    branch = 'ecdat/remediation-' + uuid.uuid4().hex[:12]
    github(base + '/git/refs', {'ref': 'refs/heads/' + branch, 'sha': commit['sha']})
    return github(base + '/pulls', {'title': 'Review ECDAT legacy hash remediation', 'head': branch, 'base': plan['base'], 'draft': True,
        'body': 'ECDAT generated these hash replacements from scanned source. Review compatibility, persisted digests, protocol requirements and tests before merging. These changes are not a general post-quantum migration.'})
