#!/usr/bin/env python3
"""Regression checks for legacy and source-built Nmap data requirements."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('nmap_data', Path(__file__).with_name('verify-nmap-data.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class NmapDataTests(unittest.TestCase):
    def fixture(self, modern=False):
        names = set(module.REQUIRED)
        if modern:
            names.remove('nmap-payloads')
        return {**{name: 1 for name in names}, 'nse-files.txt': 1}, '\n'.join(sorted(names))

    def test_legacy_still_requires_separate_payload_file(self):
        files, manifest = self.fixture()
        module.verify(files, manifest)
        files, manifest = self.fixture(modern=True)
        with self.assertRaisesRegex(ValueError, 'nmap-payloads'):
            module.verify(files, manifest)

    def test_modern_uses_service_probes_and_still_requires_nse(self):
        files, manifest = self.fixture(modern=True)
        module.verify(files, manifest, '7.992')
        for required in ('nmap-service-probes', 'nse_main.lua', 'scripts/script.db', 'nselib/stdnse.lua'):
            incomplete = {key: size for key, size in files.items() if key != required}
            incomplete_manifest = '\n'.join(name for name in manifest.splitlines() if name != required)
            with self.assertRaises(ValueError):
                module.verify(incomplete, incomplete_manifest, '7.992')

    def test_modern_rejects_duplicate_paths_unlisted_files_and_empty_files(self):
        files, manifest = self.fixture(modern=True)
        with self.assertRaises(ValueError):
            module.verify(files, manifest+'\n'+manifest.splitlines()[0], '7.992')
        with self.assertRaises(ValueError):
            module.verify({**files, 'unexpected.lua': 1}, manifest, '7.992')
        with self.assertRaises(ValueError):
            module.verify({**files, 'scripts/script.db': 0}, manifest, '7.992')
        with self.assertRaises(ValueError):
            module.verify(files, manifest+'\n../outside', '7.992')

if __name__ == '__main__':
    unittest.main()
