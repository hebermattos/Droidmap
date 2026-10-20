#!/usr/bin/env python3
"""Exercise update rejection paths without accessing or generating signing keys."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CURRENT = 'b76460326372e4f59a999d02908b014edfe8fe25edf3aa1a4339eb95a416dfb7'
LEGACY = '82a648c2bc78d4d22d159b77864b1b60f3540a0a85b2236cafd5d3f7a8021ef2'


class UpdateIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.tools = self.directory / 'build-tools/35.0.0'
        self.tools.mkdir(parents=True)
        self.executable('aapt', '''#!/bin/bash
printf "package: name='%s' versionCode='114'\\n" "$TEST_PACKAGE"
''')
        self.executable('apksigner', '''#!/bin/bash
if [[ "${TEST_INVALID_SIGNATURE:-0}" == 1 ]]; then exit 1; fi
printf 'Signer #1 certificate SHA-256 digest: %s\\n' "$TEST_CERTIFICATE"
''')
        self.env = {**os.environ, 'ANDROID_HOME': str(self.directory),
                    'NETMAP_APK_PROFILE': 'current', 'TEST_PACKAGE': 'com.netmap.android',
                    'TEST_CERTIFICATE': CURRENT}

    def executable(self, name, contents):
        p = self.tools / name
        p.write_text(contents)
        p.chmod(0o755)

    def verify(self):
        return subprocess.run(['bash', 'tools/verify-update-apk.sh', 'fixture.apk'],
                              cwd=ROOT, env=self.env, capture_output=True, text=True)

    def test_current_identity_accepted(self):
        self.assertEqual(self.verify().returncode, 0)

    def test_legacy_requires_explicit_profile(self):
        self.env.update(TEST_PACKAGE='com.netmap.android.dns', TEST_CERTIFICATE=LEGACY)
        self.assertNotEqual(self.verify().returncode, 0)
        self.env['NETMAP_APK_PROFILE'] = 'legacy-dns'
        self.assertEqual(self.verify().returncode, 0)

    def test_wrong_certificate_rejected(self):
        self.env['TEST_CERTIFICATE'] = LEGACY
        self.assertIn('certificate mismatch', self.verify().stderr)

    def test_invalid_signature_rejected(self):
        self.env['TEST_INVALID_SIGNATURE'] = '1'
        self.assertNotEqual(self.verify().returncode, 0)

    def test_missing_certificate_rejected(self):
        self.env['TEST_CERTIFICATE'] = ''
        self.assertNotEqual(self.verify().returncode, 0)

    def test_multiple_signers_rejected(self):
        self.env['TEST_CERTIFICATE'] = CURRENT + '\nSigner #2 certificate SHA-256 digest: ' + LEGACY
        self.assertNotEqual(self.verify().returncode, 0)

    def test_unknown_profile_rejected(self):
        self.env['NETMAP_APK_PROFILE'] = 'typo'
        self.assertNotEqual(self.verify().returncode, 0)

    def test_missing_keystore_fails_before_gradle(self):
        self.env['NETMAP_DEBUG_KEYSTORE'] = str(self.directory / 'missing.jks')
        result = subprocess.run(['bash', 'build-apk.sh'], cwd=ROOT, env=self.env,
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('no replacement key', result.stderr)

    def test_wrong_keystore_rejected_before_build(self):
        # This is a dummy file and stub keytool, never a private signing key.
        dummy = self.directory / 'dummy'
        dummy.write_text('dummy')
        self.executable('keytool', '#!/bin/bash\nprintf wrong-certificate')
        self.env.update(NETMAP_DEBUG_KEYSTORE=str(dummy), PATH=str(self.tools) + ':' + os.environ['PATH'])
        result = subprocess.run(['bash', 'build-apk.sh'], cwd=ROOT, env=self.env,
                                capture_output=True, text=True)
        self.assertIn('Signing certificate mismatch', result.stderr)
        self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
