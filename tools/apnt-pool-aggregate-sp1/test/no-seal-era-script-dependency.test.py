#!/usr/bin/env python3
"""Refuse seal-era tool paths in pool aggregate runtime scripts.

Pass --runner-file to check an earlier runner without replacing the live one.
The guest core is excluded: its historical port comment is pinned guest input.
"""
import argparse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'scripts'
RUNNER = SCRIPTS / 'aggregate-proof-runner.sh'
PROFILE = SCRIPTS / 'memory-measure.py'
FORBIDDEN = b'apnt-successor-aggregate-sp1/'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runner-file', type=Path)
    args = parser.parse_args()
    if not RUNNER.is_file() or not PROFILE.is_file():
        raise SystemExit('pool aggregate runner or memory profile missing')
    violations = []
    for path in sorted(SCRIPTS.rglob('*')):
        if path.is_symlink():
            data = str(path.readlink()).encode()
        elif path.is_file():
            data = args.runner_file.read_bytes() if path == RUNNER and args.runner_file else path.read_bytes()
        else:
            continue
        for line_number, line in enumerate(data.splitlines(), 1):
            if FORBIDDEN in line:
                violations.append(f'{path.relative_to(ROOT)}:{line_number}')
    if violations:
        print('seal-era-script-dependency: ' + ', '.join(violations))
        raise SystemExit(1)
    print('pool aggregate runtime scripts: no seal-era tool paths')


if __name__ == '__main__':
    main()
