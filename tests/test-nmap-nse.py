#!/usr/bin/env python3
"""Exercise the NSE backport with a host Nmap build; no device scan is performed."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile


def run(binary, *args):
    result = subprocess.run([str(binary), *args], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    return result.stdout + result.stderr


def verify(binary, source):
    with tempfile.TemporaryDirectory(prefix='droidmap-nse-test-') as temporary:
        data = Path(temporary)
        for name in ('nse_main.lua', 'nselib', 'nmap-services', 'nmap-protocols',
                     'nmap-mac-prefixes', 'nmap-rpc', 'nmap-service-probes', 'nmap-os-db'):
            (data / name).symlink_to(source / name)
        scripts = data / 'scripts'
        scripts.mkdir()
        (scripts / 'script.db').write_text(
            'Entry { filename = "intensity-regression.nse", categories = { "droidmapregression", } }\n')
        (scripts / 'intensity-regression.nse').write_text('''local nmap = require "nmap"
description = "Check version_intensity with lazy loading, selected by category."
author = "Droidmap"
license = "Same as Nmap"
categories = {"droidmapregression"}
prerule = function()
  assert(rawget(_G, "nmap") == nil, "Test requires no global nmap table")
  return true
end
action = function() return "intensity=" .. nmap.version_intensity() end
''')
        # Explicit script names bypass the faulty registry lookup and return 9.
        # Select by category to exercise both CLI intensity and script override.
        for extra, expected in [([], 2), (['--script-args', 'script-intensity=4'], 4)]:
            output = run(binary, '--datadir', str(data), '--unprivileged', '-Pn',
                         '-n', '-sn', '--version-intensity', '2', '--script',
                         'droidmapregression', '-d', *extra, '127.0.0.1')
            if f'intensity={expected}' not in output or 'threw an error' in output:
                raise AssertionError(output)
            print(f'PASS: NSE without global nmap, intensity={expected}')

    templates = Path(__file__).resolve().parents[1] / 'app/src/main/assets/nmap-command-templates.json'
    for name, profile in json.loads(templates.read_text())['profiles'].items():
        argv = profile['argv']
        expression = argv[argv.index('--script') + 1]
        output = run(binary, '--datadir', str(source), '--script-help', expression)
        categories = re.findall(r'Categories: (.*)', output)
        if not categories or any({'broadcast', 'external'} & set(c.split()) for c in categories):
            raise AssertionError(output)
        if re.search(r'^targets-', output, re.MULTILINE):
            raise AssertionError(output)
        print(f'PASS: {name} selection excludes broadcast, external and target expansion')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--data-dir', required=True, type=Path)
    args = parser.parse_args()
    verify(args.binary.resolve(), args.data_dir.resolve())
