#!/usr/bin/env python3
"""Extract repository quotations from a caller-frozen registry, without judgments."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


def digest(data):
    return hashlib.sha256(data).hexdigest()


def object_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate JSON key: ' + key)
        value[key] = item
    return value


def parse_object(data):
    def invalid_constant(value):
        raise ValueError('non-JSON number: ' + value)
    result = json.loads(data.decode('utf-8'), object_pairs_hook=object_pairs,
                        parse_constant=invalid_constant)
    if not isinstance(result, dict):
        raise ValueError('JSON root must be an object')
    return result


def canonical_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def relative_path(value):
    if not isinstance(value, str) or not value or '\\' in value or '\x00' in value:
        raise ValueError('relative_path must be a canonical POSIX path')
    if Path(value).is_absolute() or any(part in ('', '.', '..') for part in value.split('/')):
        raise ValueError('relative_path must be a canonical POSIX path')
    return value


def line_range(start, end):
    if type(start) is not int or type(end) is not int or start < 1 or end < start:
        raise ValueError('line range must contain positive ordered integers')


def source_index(registry):
    if set(registry) != {'sources'} or not isinstance(registry['sources'], list) or not registry['sources']:
        raise ValueError('registry must contain a nonempty sources array')
    index = {}
    seen_sources = set()
    for source in registry['sources']:
        if not isinstance(source, dict) or set(source) != {'repository', 'revision', 'root', 'files'}:
            raise ValueError('invalid source registry entry')
        repository, revision = source['repository'], source['revision']
        if not isinstance(repository, str) or not repository or not isinstance(revision, str) or not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', revision):
            raise ValueError('source requires a repository and a full immutable revision')
        identity = (repository, revision)
        if identity in seen_sources:
            raise ValueError('duplicate source repository/revision')
        seen_sources.add(identity)
        if not isinstance(source['root'], str) or not Path(source['root']).is_absolute():
            raise ValueError('source root must be absolute')
        root = Path(source['root']).resolve(strict=True)
        if not root.is_dir() or not isinstance(source['files'], list) or not source['files']:
            raise ValueError('source requires a directory and nonempty files array')
        for item in source['files']:
            if not isinstance(item, dict) or set(item) != {'relative_path', 'sha256', 'allowed_ranges'}:
                raise ValueError('invalid source file entry')
            relative = relative_path(item['relative_path'])
            key = (repository, revision, relative)
            if key in index:
                raise ValueError('duplicate source file')
            if not isinstance(item['sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', item['sha256']):
                raise ValueError('source file requires a SHA-256 digest')
            ranges = item['allowed_ranges']
            if not isinstance(ranges, list) or not ranges:
                raise ValueError('source file requires nonempty allowed_ranges')
            for interval in ranges:
                if not isinstance(interval, list) or len(interval) != 2:
                    raise ValueError('invalid allowed line range')
                line_range(*interval)
            index[key] = (root, item)
    return index


def extract_citations(raw_bytes, registry_bytes, expected_registry_sha256):
    """Project only repository quote fields; caller validates role schema and receipt."""
    if not isinstance(expected_registry_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', expected_registry_sha256):
        raise ValueError('a caller-retained pre-dispatch registry digest is required')
    if digest(registry_bytes) != expected_registry_sha256:
        raise ValueError('source registry differs from its pre-dispatch SHA-256')
    artifact = parse_object(raw_bytes)
    index = source_index(parse_object(registry_bytes))
    loaded = {}
    citations = []

    def visit(value, pointer):
        if isinstance(value, list):
            for number, item in enumerate(value):
                visit(item, pointer + '/' + str(number))
        elif isinstance(value, dict):
            if value.get('source_kind') == 'repository':
                relative = relative_path(value.get('relative_path'))
                repository, revision = value.get('repository'), value.get('revision')
                if not isinstance(repository, str) or not isinstance(revision, str):
                    raise ValueError('repository citation requires string repository/revision')
                key = (repository, revision, relative)
                if key not in index:
                    raise ValueError('citation is absent from the frozen source registry')
                start, end = value.get('start_line'), value.get('end_line')
                line_range(start, end)
                root, entry = index[key]
                if not any(low <= start <= end <= high for low, high in entry['allowed_ranges']):
                    raise ValueError('citation is outside the frozen allowed ranges')
                if value.get('artifact_id') != '' or not isinstance(value.get('quote'), str):
                    raise ValueError('repository citation requires empty artifact_id and string quote')
                if key not in loaded:
                    path = (root / relative).resolve(strict=True)
                    if root not in path.parents or not path.is_file():
                        raise ValueError('source file escapes its frozen root')
                    data = path.read_bytes()
                    if digest(data) != entry['sha256']:
                        raise ValueError('source file differs from its frozen SHA-256')
                    data.decode('utf-8')
                    loaded[key] = data.splitlines(keepends=True)
                lines = loaded[key]
                if end > len(lines):
                    raise ValueError('citation exceeds the pinned source file')
                quote_bytes = b''.join(lines[start - 1:end])
                value['quote'] = quote_bytes.decode('utf-8')
                citations.append({'json_pointer': pointer, 'repository': repository, 'revision': revision,
                                  'relative_path': relative, 'start_line': start, 'end_line': end,
                                  'file_sha256': entry['sha256'], 'quote_sha256': digest(quote_bytes)})
            for key, item in value.items():
                escaped = key.replace('~', '~0').replace('/', '~1')
                visit(item, pointer + '/' + escaped)

    visit(artifact, '')
    return {'artifact': artifact, 'provenance': {
        'raw_artifact_sha256': digest(raw_bytes), 'source_registry_sha256': digest(registry_bytes),
        'derived_artifact_sha256': digest(canonical_bytes(artifact)), 'citations': citations,
    }}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifact', type=Path, required=True)
    parser.add_argument('--sources', type=Path, required=True)
    parser.add_argument('--expected-sources-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = extract_citations(args.artifact.read_bytes(), args.sources.read_bytes(), args.expected_sources_sha256)
        with args.output.open('x', encoding='utf-8') as output:
            json.dump(result, output, ensure_ascii=False, indent=2, allow_nan=False)
            output.write('\n')
    except (OSError, ValueError) as error:
        print(json.dumps({'status': 'MALFORMED', 'error': str(error)}))
        return 1
    print(json.dumps({'status': 'COMPLETE', 'output': str(args.output),
                      'provenance': result['provenance']}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
