#!/usr/bin/env python3
"""Record workflow boundaries alongside provider step timestamps."""
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import time

root = Path(os.environ['RUNNER_TEMP']) / 'smooth-ci-evidence'
root.mkdir(parents=True, exist_ok=True)
with (root / 'workflow-clock.jsonl').open('a') as stream:
    stream.write(json.dumps({'event': sys.argv[1], 'epoch_ns': time.time_ns(),
                             'monotonic_ns': time.monotonic_ns()}) + '\n')
if sys.argv[1] == 'begin':
    info = {'run_id': os.environ['GITHUB_RUN_ID'], 'attempt': os.environ['GITHUB_RUN_ATTEMPT'],
            'head': os.environ['GITHUB_SHA'], 'engine': os.environ['ENGINE'],
            'scenario': os.environ['SCENARIO'], 'rep': os.environ['REPETITION'],
            'system': platform.platform(), 'cpu_count': os.cpu_count(),
            'disk': dict(zip(('total', 'used', 'free'), shutil.disk_usage(root))),
            'image': {k: os.environ.get(k) for k in ('ImageOS', 'ImageVersion', 'RUNNER_ARCH')},
            'cpuinfo': Path('/proc/cpuinfo').read_text(),
            'meminfo': Path('/proc/meminfo').read_text()}
    (root / 'runner.json').write_text(json.dumps(info, indent=2) + '\n')
if sys.argv[1] == 'finish':
    size = sum(p.stat().st_size for p in root.rglob('*') if p.is_file())
    if size > 64 * 1024 ** 2:
        raise SystemExit('Compact evidence exceeds 64 MiB: %d' % size)
    print('Compact evidence payload bytes:', size)
