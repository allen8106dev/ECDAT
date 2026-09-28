"""Bounded Git acquisition without checkout, hooks, submodules or build execution."""
import base64
import ipaddress
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import time
from urllib.parse import urlsplit


def public_host(host):
    addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
        raise ValueError('Private network targets require an explicitly configured ECDAT_ALLOWED_HOSTS entry.')
    return [item[4][0] for item in addresses]


def repository_url(value):
    value = value.strip()
    scp = re.fullmatch(r'([\w-]+)@([\w.-]+):([\w./~-]+)', value)
    if scp:
        value = f'ssh://{scp[1]}@{scp[2]}/{scp[3]}'
    if re.fullmatch(r'[\w.-]+/[\w.-]+', value):
        value = 'https://github.com/' + value
    parsed = urlsplit(value)
    if parsed.scheme == 'ssh':
        allowed = os.environ.get('ECDAT_ALLOWED_SSH_HOSTS', '').split(',')
        if parsed.hostname not in allowed or not parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.port not in (None, 22) or not re.fullmatch(r'/[\w./~-]+', parsed.path) or '..' in parsed.path.split('/'):
            raise ValueError('SSH requires an ECDAT_ALLOWED_SSH_HOSTS entry, a configured SSH key and a trusted known_hosts entry.')
        return value
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.port not in (None, 443):
        raise ValueError('Use an HTTPS Git clone URL without embedded credentials, or owner/repo for GitHub.')
    if not parsed.path.strip('/') or any(p in ('.', '..') for p in parsed.path.split('/')):
        raise ValueError('A repository path is required.')
    allowed = {host.strip().lower() for host in os.environ.get('ECDAT_ALLOWED_HOSTS', '').split(',')}
    if parsed.hostname.lower() not in allowed:
        public_host(parsed.hostname)
    return value


def acquire_repository(url, ref, directory):
    url = repository_url(url)
    if ref and (ref.startswith('-') or not re.fullmatch(r'[\w./-]{1,200}', ref) or '..' in ref):
        raise ValueError('Invalid branch, tag or commit.')
    if not shutil.which('git'):
        raise ValueError('Install Git on the scanner host to import repositories.')
    root = Path(directory)
    repository = root / 'checkout.git'
    env = {**os.environ, 'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_LFS_SKIP_SMUDGE': '1', 'GIT_SSH_COMMAND': 'ssh -o BatchMode=yes -o StrictHostKeyChecking=yes'}
    args = ['git', '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always', '-c', 'http.followRedirects=false', '-c', 'core.hooksPath=' + str(root / 'no-hooks'), '-c', 'credential.helper=']
    if urlsplit(url).scheme == 'ssh':
        args += ['-c', 'protocol.ssh.allow=always']
    host = urlsplit(url).hostname
    if urlsplit(url).scheme == 'https' and host not in os.environ.get('ECDAT_ALLOWED_HOSTS', '').split(','):
        address = public_host(host)[0]
        if ':' in address:
            address = '[' + address + ']'
        args += ['-c', f'http.curloptResolve={host}:443:{address}']
    if os.environ.get('ECDAT_GIT_TOKEN') and os.environ.get('ECDAT_GIT_TOKEN_HOST') == host:
        credential = base64.b64encode((os.environ.get('ECDAT_GIT_USERNAME', 'x-access-token') + ':' + os.environ['ECDAT_GIT_TOKEN']).encode()).decode()
        env.update(GIT_CONFIG_COUNT='1', GIT_CONFIG_KEY_0=f'http.https://{host}/.extraHeader', GIT_CONFIG_VALUE_0='Authorization: Basic ' + credential)

    def run(arguments, timeout=120):
        process = subprocess.Popen(args + arguments, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        start = time.monotonic()
        try:
            while process.poll() is None:
                if time.monotonic() - start > timeout:
                    raise ValueError('Git operation exceeded its time limit.')
                size = sum(p.stat().st_size for p in root.rglob('*') if p.is_file())
                if size > 512 * 1024 * 1024:
                    raise ValueError('Repository acquisition exceeded 512 MiB.')
                time.sleep(.2)
            if process.returncode:
                raise ValueError('Git import failed. Check the clone URL, ref, network access and host-scoped credentials.')
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()

    run(['init', '--bare', str(repository)])
    run(['--git-dir=' + str(repository), 'fetch', '--depth=1', '--no-tags', url, ref or 'HEAD'])
    archive = root / 'input' / 'repository.tar.gz'
    archive.parent.mkdir()
    run(['--git-dir=' + str(repository), 'archive', '--format=tar.gz', '--output=' + str(archive), 'FETCH_HEAD'])
    return archive.parent
