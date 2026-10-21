#!/usr/bin/env python3
"""Freeze six bounded one-member workloads; never runs an encoder."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

SCRIPT_ROOT = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, required=True,
                    help='directory with absent corpus/generated-fixtures children')
parser.add_argument('--repository', type=Path, required=True)
parser.add_argument('--fixture-script', type=Path, required=True)
args = parser.parse_args()
ROOT = args.output.resolve()
ROOT.mkdir(parents=True, exist_ok=True)
REPO = args.repository.resolve()
FIXTURES = args.fixture_script.resolve()
CORPUS = ROOT / 'corpus'
GENERATED = ROOT / 'generated-fixtures'
SPEC = importlib.util.spec_from_file_location('fixtures', FIXTURES)
fixtures = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixtures)
fixtures.generate(GENERATED)
CORPUS.mkdir()
revision = 'e490bf558e98a4438d3e0990159c22dfd076611b'
source_names = ['crates/rars/src/codec/match_finder.rs', 'crates/rars/src/codec/rar50/encoder.rs']
source_parts = [(name, subprocess.check_output(['git', '-C', str(REPO), 'show', f'{revision}:{name}'])) for name in source_names]
source = b''.join(b'\n// Frozen source: ' + name.encode() + b'\n' + data for name, data in source_parts)
source = (source * (1 + (128 * 1024) // len(source)))[:128 * 1024]
logs = b''.join(('2026-01-01T00:00:%02dZ request=%06d status=%d path=/api/records/%04d bytes=%d\n' % (i % 60, i, 200 if i % 23 else 404, i % 997, (i * 37) % 65536)).encode() for i in range(3000))[:128 * 1024]
def generated(name):
    return (GENERATED / 'hybrid' / name).read_bytes()
pressure = bytearray(b''.join(b'ANCH' + fixtures.noise(252, 0xAC000001 + i)
                            for i in range(196608 // 256)))
first = bytes(pressure[:1024])
for offset in (66048, 140288):
    pressure[offset:offset + len(first)] = first
payloads = {
    'source-and-logs.txt': source + logs,
    'related-releases.jsonl': generated('releases/v1/export.jsonl') + generated('releases/v2/export.jsonl'),
    'shifted-repeat.bin': generated('shifted/base.bin') + generated('shifted/with-prefix.bin'),
    'dictionary-distance.bin': generated('distance/long-gap.bin'),
    'unrelated-data.bin': generated('unrelated/first.bin') + generated('unrelated/second.bin'),
    'hot-prefix-pressure.bin': bytes(pressure),
}
records = []
for name, data in payloads.items():
    target = CORPUS / name
    target.write_bytes(data)
    target.chmod(0o644)
    os.utime(target, (1700000000, 1700000000))
    records.append({'path': name, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
manifest = {
    'generator': 'temple-anchor-comparison-v2; reuse committed hybrid-fixtures-v1/xorshift64',
    'fixture_generator_sha256': hashlib.sha256((FIXTURES).read_bytes()).hexdigest(),
    'source_fixture_revision': revision,
    'source_fixture_parts': [{'path': name, 'sha256': hashlib.sha256(data).hexdigest()} for name, data in source_parts],
    'metadata': {'file_mode': '0644', 'mtime_seconds': 1700000000, 'directory_arguments': False},
    'mechanistic_stress_case': {
        'file': 'hot-prefix-pressure.bin', 'bytes': 196608, 'block_bytes': 256,
        'block_prefix_hex': b'ANCH'.hex(), 'tail_seed_base': '0xAC000001',
        'copied_source_offset': 0, 'copied_bytes': 1024, 'copy_offsets': [66048, 140288],
        'purpose': 'one declared collision-pressure case tests retention beyond the 64 KiB recent index; it is not representative workload evidence',
    },
    'files': records,
    'workloads': [{'id': Path(name).stem, 'files': [name], 'solid': False} for name in payloads],
}
(CORPUS / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
for directory in [GENERATED, *sorted((p for p in GENERATED.rglob('*') if p.is_dir()), key=lambda p: len(p.parts), reverse=True), CORPUS]:
    directory.chmod(0o755)
    os.utime(directory, (1700000000, 1700000000))
plan = {
    'fixed_dictionary_bytes': 4 * 1024**2,
    'worker_options': {'rars_add': ['--no-filter'], 'native_add': ['-mc-']},
    'execution': {'parallel_screening': False, 'screen_threads': 1, 'confirm_threads': 1},
    'budgets': {'screen': 300, 'confirm': 600},
    'task_timeout_seconds': 60,
}
(ROOT / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n')
print(json.dumps({'manifest': str(CORPUS / 'manifest.json'), 'plan': str(ROOT / 'plan.json'), 'files': len(records), 'bytes': sum(r['size'] for r in records), 'workloads': [w['id'] for w in manifest['workloads']]}))
