"""Resolved npm lockfile relationships, preserving installation-path identities."""
import json
from pathlib import PurePosixPath


def dependency_graph(name, text):
    if PurePosixPath(name).name != 'package-lock.json':
        return None
    try:
        data = json.loads(text)
        packages = data.get('packages', {})
        if not isinstance(packages, dict) or len(packages) > 20000:
            return None
        nodes = [{'id': path, 'name': item.get('name') or path.rsplit('node_modules/', 1)[-1] or data.get('name', 'root'), 'version': item.get('version', '')} for path, item in packages.items()]
        edges, unresolved = [], []
        for path, item in packages.items():
            dependencies = {**item.get('dependencies', {}), **item.get('optionalDependencies', {})}
            if not path:
                dependencies.update(item.get('devDependencies', {}))
            for dependency in dependencies:
                directory = path
                while True:
                    candidate = (directory + '/' if directory else '') + 'node_modules/' + dependency
                    if candidate in packages:
                        edges.append({'from': path, 'to': candidate})
                        break
                    if not directory:
                        unresolved.append({'from': path, 'name': dependency})
                        break
                    directory = directory.rsplit('/node_modules/', 1)[0] if '/node_modules/' in directory else ''
        return {'manifest': name, 'nodes': nodes, 'edges': edges, 'unresolved': unresolved}
    except (ValueError, TypeError, AttributeError):
        return None
