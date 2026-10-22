#!/usr/bin/env python3
"""Install a verified published Nmap archive as matching APK binary and assets."""
import argparse
import hashlib
import importlib.util
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent.parent
VERSION = '7.992'

def install(archive, expected, root=ROOT):
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    if actual != expected.lower():
        raise ValueError('Nmap archive SHA-256 mismatch')
    with tempfile.TemporaryDirectory(prefix='nmap-install-') as tmp:
        stage = Path(tmp)
        total = 0
        seen = set()
        with tarfile.open(archive, 'r:gz') as source:
            for member in source:
                path = PurePosixPath(member.name)
                if path.is_absolute() or '..' in path.parts or '\\' in member.name or not path.parts:
                    raise ValueError('Invalid Nmap archive path')
                if path.parts[0] not in {'libnmap.so', 'nmap-data', 'licenses', 'build-info.txt'}:
                    raise ValueError('Unexpected Nmap archive content')
                if member.isdir():
                    continue
                key = path.as_posix()
                if not member.isfile() or key in seen:
                    raise ValueError('Links and duplicate archive files are not allowed')
                total += member.size
                if len(seen) >= 4096 or member.size <= 0 or member.size > 32*1024*1024 or total > 128*1024*1024:
                    raise ValueError('Nmap archive bounds exceeded')
                seen.add(key)
                target = stage.joinpath(*path.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as data, target.open('wb') as out:
                    shutil.copyfileobj(data, out)
        for required in ('libnmap.so', 'build-info.txt', 'licenses/Nmap-LICENSE', 'licenses/OpenSSL-LICENSE'):
            if not (stage/required).is_file():
                raise ValueError('Missing required runtime file: '+required)
        if not (stage/'build-info.txt').read_text().startswith('Nmap '+VERSION+'\n'):
            raise ValueError('Unexpected Nmap runtime version')
        subprocess.run(['python3', str(root/'tests/verify-nmap-elf.py'), str(stage/'libnmap.so')], check=True)
        subprocess.run(['python3', str(root/'tests/verify-nmap-data.py'), '--assets', str(stage/'nmap-data'),
                        '--nmap-version', VERSION], check=True)
        # Changing the published archive creates a fresh private data directory in Android.
        (stage/'nmap-data/runtime-id.txt').write_text(actual+'\n')
        manifest = stage/'nmap-data/nse-files.txt'
        names = manifest.read_text().splitlines()
        if set(names) & {'runtime-id.txt', 'runtime-binary.sha256', '.ready'}:
            raise ValueError('Reserved runtime metadata already present')
        binary_hash = hashlib.sha256((stage/'libnmap.so').read_bytes()).hexdigest()
        (stage/'nmap-data/runtime-binary.sha256').write_text(binary_hash+'\n')
        manifest.write_text('\n'.join(sorted(names+['runtime-id.txt', 'runtime-binary.sha256']))+'\n')
        assets = root/'app/src/main/assets/nmap-data'
        binary = root/'app/src/main/jniLibs/arm64-v8a/libnmap.so'
        # Only replace existing build output after the full archive has passed validation.
        if assets.exists():
            shutil.rmtree(assets)
        assets.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(stage/'nmap-data', assets)
        binary.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(stage/'libnmap.so', binary)
        binary.chmod(0o755)
        licenses = root/'app/src/main/assets/licenses/nmap'
        if licenses.exists():
            shutil.rmtree(licenses)
        licenses.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(stage/'licenses', licenses)
        shutil.copy2(stage/'build-info.txt', licenses/'build-info.txt')
        print('Installed Nmap '+VERSION+' from verified release; runtime ID: '+actual)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('archive', type=Path)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args()
    install(args.archive, args.sha256)
