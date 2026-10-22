#!/usr/bin/env python3
"""Reject host binaries, non-PIE ELF and dependencies unavailable to an Android app."""
from pathlib import Path
import re
import subprocess
import sys

binary = Path(sys.argv[1])
header = subprocess.check_output(['readelf', '-hW', binary], text=True)
segments = subprocess.check_output(['readelf', '-lW', binary], text=True)
dynamic = subprocess.check_output(['readelf', '-dW', binary], text=True)
assert re.search(r'Class:\s+ELF64', header), 'Expected ELF64'
assert re.search(r'Machine:\s+AArch64', header), 'Expected ARM64'
assert re.search(r'Type:\s+DYN', header), 'Expected PIE executable'
assert '/system/bin/linker64' in segments, 'Expected Android dynamic linker'
needed = set(re.findall(r'\(NEEDED\).*\[([^\]]+)\]', dynamic))
allowed = {'libc.so', 'libm.so', 'libdl.so', 'libz.so', 'liblog.so'}
assert needed <= allowed, f'Unbundled/host dependencies: {needed - allowed}'
assert 'libc.so' in needed, 'Expected dynamic Android libc'
assert not re.search(r'\((?:RPATH|RUNPATH)\)', dynamic), 'Unexpected runtime library search path'
loads = [line for line in segments.splitlines() if line.lstrip().startswith('LOAD ')]
assert loads and all(int(line.split()[-1], 16) >= 16384 for line in loads), 'Expected 16 KiB LOAD alignment'
print('PASS: ARM64 Android PIE, 16 KiB alignment, only platform shared libraries:', ', '.join(sorted(needed)))
