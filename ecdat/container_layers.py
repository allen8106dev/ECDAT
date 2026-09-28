"""Reconstruct Docker-save/OCI layer contents in memory with whiteout semantics."""
import io
import json
from pathlib import PurePosixPath
import tarfile


def safe(path):
    p = PurePosixPath(path)
    return not p.is_absolute() and '..' not in p.parts and ':' not in path and '\\' not in path and '\x00' not in path


def merged_files(data, max_bytes=512 * 1024 * 1024, max_entries=20000):
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as archive:
        members = {}
        for index, entry in enumerate(archive):
            if index >= max_entries:
                return None
            members[entry.name] = entry
        if 'manifest.json' not in members and 'oci-layout' not in members:
            return None
        consumed = 0

        def read(name):
            nonlocal consumed
            if not safe(name) or name not in members or not members[name].isfile():
                raise ValueError('Missing or unsafe container member.')
            entry = members[name]
            if consumed + entry.size > max_bytes:
                raise ValueError('Container expansion limit reached.')
            consumed += entry.size
            return archive.extractfile(entry).read(entry.size)

        warnings = []
        if 'manifest.json' in members:
            manifest = json.loads(read('manifest.json'))
            if not isinstance(manifest, list) or not manifest or 'Layers' not in manifest[0]:
                return None
            if len(manifest) > 1:
                warnings.append('Multiple images in export: only the first image was merged.')
            layers = manifest[0]['Layers']
        else:
            index = json.loads(read('index.json'))
            descriptors = index.get('manifests', [])
            if not descriptors:
                raise ValueError('OCI index has no manifests.')
            if len(descriptors) > 1:
                warnings.append('Multiple OCI manifests: only the first platform was merged.')
            digest = descriptors[0]['digest'].replace(':', '/')
            manifest = json.loads(read('blobs/' + digest))
            if 'layers' not in manifest:
                raise ValueError('Nested OCI indexes are not supported; select a platform-specific image.')
            layers = ['blobs/' + entry['digest'].replace(':', '/') for entry in manifest['layers']]
        files = {}
        visited = 0
        for name in layers:
            payload = read(name)
            additions, deletions = {}, []
            with tarfile.open(fileobj=io.BytesIO(payload), mode='r:*') as layer:
                for entry in layer:
                    visited += 1
                    if visited > max_entries:
                        raise ValueError('Container layer entry limit reached.')
                    path = entry.name.removeprefix('./')
                    if not safe(path):
                        warnings.append('Unsafe layer path skipped.'); continue
                    item = PurePosixPath(path)
                    if item.name == '.wh..wh..opq':
                        prefix = str(item.parent)
                        deletions.append('' if prefix == '.' else prefix + '/')
                    elif item.name.startswith('.wh.'):
                        deletions.append(str(item.with_name(item.name[4:])))
                    elif entry.isfile():
                        if consumed + entry.size > max_bytes:
                            raise ValueError('Container expansion limit reached.')
                        consumed += entry.size
                        additions[path] = layer.extractfile(entry).read(entry.size)
                    elif not entry.isdir():
                        warnings.append('Layer symlink, hardlink or special entry skipped: ' + path)
            for deletion in deletions:
                for path in list(files):
                    if path == deletion or path.startswith(deletion.rstrip('/') + '/') or not deletion:
                        del files[path]
            files.update(additions)
        return files, warnings
