"""Offline validation against the vendored official CycloneDX 1.6 schemas."""
import json
from functools import lru_cache
from pathlib import Path
import fastjsonschema


@lru_cache
def validator():
    resources = {}
    root = Path(__file__).parent / 'schemas'
    for path in root.glob('*.json'):
        schema = json.loads(path.read_text(encoding='utf-8-sig'))
        resources[schema['$id']] = schema
        for protocol in ('http', 'https'):
            resources[f'{protocol}://cyclonedx.org/schema/{path.name}'] = schema
    schema = json.loads((root / 'bom-1.6.schema.json').read_text(encoding='utf-8-sig'))
    def resolve(uri):
        if uri not in resources:
            raise ValueError('Schema reference is not vendored: ' + uri)
        return resources[uri]
    return fastjsonschema.compile(schema, handlers={'http': resolve, 'https': resolve}, use_default=False)


def validate_cbom(document):
    validator()(document)
    return document
