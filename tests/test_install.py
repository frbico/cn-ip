"""Exercise the real Bash installer with isolated download/install commands."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

@unittest.skipUnless(os.geteuid() == 0, 'installer requires root')
class InstallerTests(unittest.TestCase):
    def run_install(self, local):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bins = root / 'bin'
            bins.mkdir()
            install_dir = ROOT if local else root
            if not local:
                (root / 'cnip-install.sh').write_bytes((ROOT / 'install.sh').read_bytes())
                # A stray adjacent file must never be executed or installed.
                (root / 'cnip.py').write_text('raise SystemExit("UNTRUSTED")\n')
            for name, body in {
                'docker': 'exit 0\n',
                'curl': 'printf "download\\n" >> "$TEST_LOG"\nwhile [ "$1" != "-o" ]; do shift; done\ncp "$TEST_SOURCE" "$2"\n',
                'install': 'cp "$3" "$TEST_BIN/cnip"\nchmod 755 "$TEST_BIN/cnip"\n',
            }.items():
                path = bins / name
                path.write_text('#!/bin/bash\nset -eu\n' + body)
                path.chmod(0o755)
            env = dict(os.environ, PATH=str(bins) + ':' + os.environ['PATH'],
                       TEST_LOG=str(root / 'download.log'), TEST_SOURCE=str(ROOT / 'cnip.py'),
                       TEST_BIN=str(bins))
            script = install_dir / ('install.sh' if local else 'cnip-install.sh')
            result = subprocess.run(['bash', str(script)], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((bins / 'cnip').read_bytes(), (ROOT / 'cnip.py').read_bytes())
            self.assertEqual((root / 'download.log').exists(), not local)
            version = subprocess.run(['cnip', '--version'], env=env, capture_output=True, text=True)
            self.assertEqual(version.stdout.strip(), '1.0.0')
            # Redirect locking to a temporary path, leaving host state untouched.
            cli = bins / 'cnip'
            cli.write_text(cli.read_text().replace("Path('/run/lock/cnip.lock')", repr(root / 'lock').replace('PosixPath', 'Path')))
            menu = subprocess.run(['cnip'], input='0\n', env=env, capture_output=True, text=True)
            self.assertEqual(menu.returncode, 0, menu.stderr)
            self.assertIn('请输入数字', menu.stdout)

    def test_local_checkout_install(self):
        self.run_install(True)

    def test_downloaded_single_file_install_ignores_adjacent_source(self):
        self.run_install(False)
