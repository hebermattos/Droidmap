#!/usr/bin/env python3
"""Reject corrupt or unsafe release archives before changing APK build outputs."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('installer',Path(__file__).resolve().parents[1]/'native-tools/install-nmap-runtime.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

class InstallTests(unittest.TestCase):
    def reject(self, entries, wrong_hash=False):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);archive=root/'runtime.tar.gz'
            marker=root/'app/src/main/assets/nmap-data/keep';marker.parent.mkdir(parents=True);marker.write_text('previous runtime')
            with tarfile.open(archive,'w:gz') as out:
                for name,kind in entries:
                    item=tarfile.TarInfo(name);item.size=1
                    if kind=='link':item.type=tarfile.SYMTYPE;item.linkname='/tmp/outside'
                    out.addfile(item,io.BytesIO(b'x') if kind!='link' else None)
            expected='0'*64 if wrong_hash else hashlib.sha256(archive.read_bytes()).hexdigest()
            with self.assertRaises(ValueError):module.install(archive,expected,root)
            self.assertEqual('previous runtime',marker.read_text())
    def test_checksum_before_install(self):self.reject([('libnmap.so','file')],True)
    def test_traversal(self):self.reject([('nmap-data/../../outside','file')])
    def test_links(self):self.reject([('libnmap.so','link')])
    def test_duplicates(self):self.reject([('libnmap.so','file'),('./libnmap.so','file')])
    def test_unexpected_content(self):self.reject([('other/file','file')])
    def test_incomplete_bundle(self):self.reject([('libnmap.so','file')])

if __name__=='__main__':unittest.main()
