#!/usr/bin/env python3
"""Check Nmap's installed-file manifest in extracted assets and in the final APK."""
import argparse
import hashlib
import re
from pathlib import Path, PurePosixPath
from zipfile import ZipFile

REQUIRED = {
    'nse_main.lua', 'nmap-service-probes', 'nmap-services', 'nmap-protocols',
    'nmap-rpc', 'nmap-mac-prefixes', 'nmap-os-db', 'nmap-payloads',
    'scripts/script.db', 'nselib/stdnse.lua',
}


def verify(files, manifest, nmap_version="7.31"):
    names = manifest.splitlines()
    if len(names) != len(set(names)):
        raise ValueError('Duplicate Nmap manifest entries')
    for name in names:
        path = PurePosixPath(name)
        if not name or path.is_absolute() or '..' in path.parts or '\\' in name:
            raise ValueError('Invalid Nmap manifest entry: ' + name)
    listed = set(names)
    required = set(REQUIRED)
    if nmap_version == "7.992":
        # Modern Nmap reads UDP payloads from nmap-service-probes instead.
        required.remove('nmap-payloads')
    missing = required - listed
    if missing:
        raise ValueError('Required Nmap files absent from install manifest: ' + ', '.join(sorted(missing)))
    if listed != set(files) - {'nse-files.txt'}:
        raise ValueError('Nmap runtime files and install manifest do not match')
    for name in names:
        if files.get(name, 0) <= 0:
            raise ValueError('Missing or empty Nmap runtime file: ' + name)
    print(f'PASS: {len(listed)} Nmap runtime files, including nse_main.lua')


def main():
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--assets', type=Path)
    source.add_argument('--apk', type=Path)
    parser.add_argument('--nmap-version', choices=('7.31', '7.992'), default='7.31')
    args = parser.parse_args()
    if args.assets:
        files = {p.relative_to(args.assets).as_posix(): p.stat().st_size
                 for p in args.assets.rglob('*') if p.is_file()}
        verify(files, (args.assets / 'nse-files.txt').read_text(), args.nmap_version)
    else:
        with ZipFile(args.apk) as apk:
            prefix = 'assets/nmap-data/'
            files = {info.filename[len(prefix):]: info.file_size for info in apk.infolist()
                     if info.filename.startswith(prefix) and not info.is_dir()}
            verify(files, apk.read(prefix + 'nse-files.txt').decode('utf-8'), args.nmap_version)
            if args.nmap_version == '7.992':
                runtime_id = apk.read(prefix+'runtime-id.txt').decode('ascii').strip()
                expected = apk.read(prefix+'runtime-binary.sha256').decode('ascii').strip()
                if not re.fullmatch('[0-9a-f]{64}', runtime_id) or not re.fullmatch('[0-9a-f]{64}', expected):
                    raise ValueError('Missing or invalid packaged Nmap identity')
                actual = hashlib.sha256(apk.read('lib/arm64-v8a/libnmap.so')).hexdigest()
                if actual != expected:
                    raise ValueError('Packaged Nmap binary does not match installed runtime metadata')
            if apk.getinfo('lib/arm64-v8a/libnmap.so').file_size <= 0:
                raise ValueError('Missing packaged ARM64 Nmap executable')


if __name__ == '__main__':
    main()
