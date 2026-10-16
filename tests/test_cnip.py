"""Unit tests do not require a real 1Panel server or Docker daemon."""
import contextlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cnip


SITE = '''# A commented server { is not a server block
server {
    listen 80;
    server_name example.com www.example.com;
    location / {
        # server_name fake.example.com;
        return 200 "server { not real";
    }
}
server {
    listen 80;
    server_name other.example.com;
    location / { return 200 "other"; }
}
'''


class ParsingTests(unittest.TestCase):
    def test_valid_domains(self):
        self.assertEqual(cnip.domain_name('WWW.Example.COM.'), 'www.example.com')
        for bad in ('https://example.com', 'bad_domain.com', '*.example.com', 'localhost',
                    'test.com/path', 'a..b.com', '-a.test', 'a-.test'):
            with self.subTest(bad=bad), self.assertRaises(cnip.CnipError):
                cnip.domain_name(bad)

    def test_cidr(self):
        self.assertEqual(cnip.cidr_value('8.8.8.8'), '8.8.8.8/32')
        self.assertEqual(cnip.cidr_value('2001:db8::1'), '2001:db8::1/128')
        self.assertEqual(cnip.cidr_value('10.0.0.1/24'), '10.0.0.0/24')
        for bad in ('0.0.0.0/0', '::/0', 'bogus'):
            with self.assertRaises(cnip.CnipError):
                cnip.cidr_value(bad)

    def test_parser_exact_names(self):
        blocks = cnip.server_blocks(SITE)
        self.assertEqual(len(blocks), 2)
        self.assertEqual(blocks[0][2], {'example.com', 'www.example.com'})
        self.assertEqual(blocks[1][2], {'other.example.com'})

    def test_parser_comments_quotes_nested(self):
        data = "server { server_name 'Quoted.Test'; location / { return 200 '{ } server {'; } }"
        blocks = cnip.server_blocks(data)
        self.assertEqual(blocks[0][2], {'quoted.test'})

    def test_generated_config_acme(self):
        state = cnip.initial_state()
        state['domains'] = ['example.com']
        conf = cnip.generate_configs(state)
        self.assertIn('"example.com:0:0" 1;', conf['map'])
        self.assertIn('~^/\\.well-known/acme-challenge/ 1;', conf['global'])
        state['acme_exempt'] = False
        self.assertNotIn('~^/', cnip.generate_configs(state)['global'])


class FileAndTransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.www = self.root / 'www'
        self.www.mkdir()
        self.conf = self.root / 'conf'
        self.conf.mkdir()
        self.site = self.conf / 'site.conf'
        self.site.write_text(SITE, encoding='utf-8')
        self.env = cnip.Environment('fake-openresty', self.www, self.conf)
        self.save = mock.patch.object(cnip, 'BACKUPS', self.root / 'backups')
        self.save.start()
        self.calls = []

        def fake_nginx(*args):
            self.calls.append(args)
            output = f'# configuration file {cnip.CONF_DEST}/{cnip.GLOBAL_FILENAME}:\n'
            return subprocess.CompletedProcess(args, 0, stdout=output)
        self.env.nginx = fake_nginx

    def tearDown(self):
        self.save.stop()
        self.tmp.cleanup()

    def test_only_selected_hostname_server_is_modified(self):
        updates = cnip.updates_for_domains(self.env, {'example.com'}, required='example.com')
        data = updates[self.site]
        self.assertEqual(data.count('CNIP-MANAGED'), 1)
        self.assertEqual(len(cnip.server_blocks(data)), 2)
        self.assertNotIn('CNIP-MANAGED', data[data.index('server_name other.example.com'):])
        with self.assertRaises(cnip.CnipError):
            cnip.updates_for_domains(self.env, {'missing.example.com'}, required='missing.example.com')

    def test_apply_remove_and_backup(self):
        st = cnip.initial_state()
        st['domains'] = ['example.com']
        backup = cnip.transact(self.env, st, 'test', cnip.GEO_HEADER + '\n1.2.3.0/24 1;\n', required='example.com')
        self.assertTrue((backup / 'manifest.json').exists())
        self.assertIn('CNIP-MANAGED', self.site.read_text())
        self.assertIn('example.com:0:0', (self.env.storage / 'domains.map').read_text())
        self.assertIn('map $uri', self.env.globalconf.read_text())
        self.assertEqual(cnip.load_state(self.env)['domains'], ['example.com'])
        st['domains'] = []
        cnip.transact(self.env, st, 'remove')
        self.assertNotIn('CNIP-MANAGED', self.site.read_text())
        self.assertFalse(self.env.globalconf.exists())

    def test_rollback_on_nginx_validation_failure(self):
        original = self.site.read_text()
        st = cnip.initial_state()
        st['domains'] = ['example.com']
        reads = [0]

        def failing_nginx(*args):
            if args == ('-t',):
                reads[0] += 1
                if reads[0] == 2:
                    raise cnip.CnipError('bad nginx syntax')
            return subprocess.CompletedProcess(args, 0,
                 stdout=f'# configuration file {cnip.CONF_DEST}/{cnip.GLOBAL_FILENAME}:\n')
        self.env.nginx = failing_nginx
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(cnip.CnipError):
                cnip.transact(self.env, st, 'fail', cnip.GEO_HEADER + '\n1.2.3.0/24 1;\n', required='example.com')
        self.assertEqual(self.site.read_text(), original)
        self.assertFalse(self.env.globalconf.exists())
        self.assertFalse(self.env.statefile.exists())

    def test_legacy_rule_refused(self):
        self.site.write_text(SITE.replace('server_name example.com www.example.com;',
                         'server_name example.com www.example.com;\ninclude /www/cn-allow.conf;'))
        with self.assertRaisesRegex(cnip.CnipError, '旧版'):
            cnip.updates_for_domains(self.env, {'example.com'}, required='example.com')

    def test_restore(self):
        st = cnip.initial_state()
        st['domains'] = ['example.com']
        b = cnip.transact(self.env, st, 'add', cnip.GEO_HEADER + '\n1.2.3.0/24 1;\n', required='example.com')
        # Snapshot before add should return config to its original, unprotected state.
        cnip.do_restore(self.env, b.name)
        self.assertEqual(self.site.read_text(), SITE)
        self.assertFalse(self.env.statefile.exists())


class CLIArgumentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root_patch = mock.patch.object(cnip.os, 'geteuid', return_value=0)
        self.lock_patch = mock.patch.object(cnip, 'LOCK', Path(self.temp.name) / 'cnip.lock')
        self.root_patch.start()
        self.lock_patch.start()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.root_patch.stop)
        self.addCleanup(self.lock_patch.stop)

    def test_auto_update_dispatch(self):
        with mock.patch.object(sys, 'argv', ['cnip', 'auto-update', 'status']), \
             mock.patch.object(cnip, 'systemd_action') as call:
            cnip.main()
        call.assert_called_once_with('status')

    def test_allow_list_dispatch(self):
        with mock.patch.object(sys, 'argv', ['cnip', 'allow', 'list']), \
             mock.patch.object(cnip, 'environment', return_value=object()), \
             mock.patch.object(cnip, 'load_state', return_value={'extra_allow': ['8.8.8.8/32']}), \
             contextlib.redirect_stdout(io.StringIO()) as result:
            cnip.main()
        self.assertIn('8.8.8.8/32', result.getvalue())

    def test_acme_dispatch(self):
        with mock.patch.object(sys, 'argv', ['cnip', 'acme', 'off']), \
             mock.patch.object(cnip, 'environment', return_value=object()), \
             mock.patch.object(cnip, 'do_acme') as call:
            cnip.main()
        call.assert_called_once_with(mock.ANY, False)


# Real Nginx regression test when nginx is available locally.
class NginxIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(__import__('shutil').which('nginx'), 'nginx not installed')
    def test_host_ip_and_acme_http_403_logic(self):
        import socket
        import urllib.request
        import urllib.error
        import time

        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            data = root / 'data'
            data.mkdir()
            state = cnip.initial_state()
            state['domains'] = ['site.test']
            state['extra_allow'] = ['8.8.4.4/32', '2001:db8:ffff::/48']
            conf = cnip.generate_configs(state)
            (data / 'china.geo').write_text('1.2.3.0/24 1;\n2001:db8:1::/48 1;\n127.0.0.1 1;\n::1 1;\n')
            (data / 'extra.geo').write_text(conf['extra'])
            (data / 'domains.map').write_text(conf['map'])
            (data / 'guard.conf').write_text(conf['guard'])
            global_text = conf['global'].replace('/www/.cnip/', str(data) + '/')
            with socket.socket() as sk:
                sk.bind(('127.0.0.1', 0))
                port = sk.getsockname()[1]
            cfg = root / 'nginx.conf'
            cfg.write_text(f'''worker_processes 1;
error_log stderr warn;
pid {root / 'nginx.pid'};
events {{ worker_connections 64; }}
http {{
access_log off;
client_body_temp_path {root / 'client_temp'};
proxy_temp_path {root / 'proxy_temp'};
fastcgi_temp_path {root / 'fastcgi_temp'};
uwsgi_temp_path {root / 'uwsgi_temp'};
scgi_temp_path {root / 'scgi_temp'};
{global_text}
server {{
    listen 127.0.0.1:{port};
    server_name site.test other.test;
    set_real_ip_from 127.0.0.1;
    real_ip_header X-Real-IP;
    include {data / 'guard.conf'};
    location / {{ return 200 "ok"; }}
}}
}}
''')
            args = ['nginx', '-p', str(root) + '/', '-c', str(cfg)]
            test = subprocess.run(args + ['-t'], capture_output=True, text=True)
            self.assertEqual(test.returncode, 0, test.stderr)
            with open('/dev/null', 'wb') as devnull:
                start = subprocess.run(args, stdout=devnull, stderr=devnull, timeout=5)
                self.assertEqual(start.returncode, 0)
                try:
                    def status(host, source_ip, uri='/'):
                        req = urllib.request.Request(
                            f'http://127.0.0.1:{port}{uri}',
                            headers={'Host': host, 'X-Real-IP': source_ip},
                        )
                        for _ in range(10):
                            try:
                                with urllib.request.urlopen(req, timeout=3) as rsp:
                                    return rsp.status
                            except urllib.error.HTTPError as e:
                                return e.code
                            except OSError:
                                time.sleep(0.05)
                        raise AssertionError('nginx did not become reachable')
                    self.assertEqual(status('site.test', '8.8.8.8'), 403)
                    self.assertEqual(status('other.test', '8.8.8.8'), 200)
                    self.assertEqual(status('site.test', '1.2.3.4'), 200)
                    self.assertEqual(status('site.test', '8.8.4.4'), 200)
                    self.assertEqual(status('site.test', '2001:4860:4860::8888'), 403)
                    self.assertEqual(status('site.test', '2001:db8:1::1'), 200)
                    self.assertEqual(status('site.test', '2001:db8:ffff::1'), 200)
                    self.assertEqual(status('other.test', '2001:4860:4860::8888'), 200)
                    self.assertEqual(status('site.test', '8.8.8.8', '/.well-known/acme-challenge/token'), 200)
                finally:
                    subprocess.run(args + ['-s', 'stop'], stdout=devnull, stderr=devnull, timeout=5)

class ReleaseRegressionTests(unittest.TestCase):
    setUp = FileAndTransactionTests.setUp
    tearDown = FileAndTransactionTests.tearDown

    def test_reject_symlink_storage(self):
        other = self.root / 'other'
        other.mkdir()
        self.env.storage.symlink_to(other, target_is_directory=True)
        with self.assertRaisesRegex(cnip.CnipError, '符号链接'):
            cnip.transact(self.env, cnip.initial_state(), 'test', delete_all=True)

    def test_reject_writable_storage(self):
        self.env.storage.mkdir(mode=0o777)
        self.env.storage.chmod(0o777)
        with self.assertRaisesRegex(cnip.CnipError, 'root'):
            cnip.transact(self.env, cnip.initial_state(), 'test', delete_all=True)

    def test_reload_failure_rolls_back(self):
        state = cnip.initial_state()
        state['domains'] = ['example.com']
        original = self.env.nginx
        failed = []
        def nginx(*args):
            if args == ('-s', 'reload') and not failed:
                failed.append(True)
                raise cnip.CnipError('reload failed')
            return original(*args)
        self.env.nginx = nginx
        with self.assertRaises(cnip.CnipError), contextlib.redirect_stderr(io.StringIO()):
            cnip.transact(self.env, state, 'test', cnip.GEO_HEADER + '\n1.2.3.0/24 1;\n')
        self.assertEqual(self.site.read_text(), SITE)
        self.assertFalse(self.env.statefile.exists())

    def test_database_rejects_failure_and_keeps_existing(self):
        state = cnip.initial_state()
        state['domains'] = ['example.com']
        cnip.transact(self.env, state, 'test', cnip.GEO_HEADER + '\n1.2.3.0/24 1;\n')
        before = {p: p.read_bytes() for p in self.env.storage.iterdir()}
        with mock.patch.object(cnip, 'execute', side_effect=cnip.CnipError('network failed')):
            with self.assertRaises(cnip.CnipError):
                cnip.do_update(self.env)
        self.assertEqual(before, {p: p.read_bytes() for p in self.env.storage.iterdir()})

    def test_database_ipv4_ipv6_validation(self):
        def download(args, **kwargs):
            path = Path(args[-1])
            v6 = 'ipv6' in path.name
            path.write_text('\n'.join(f'2001:db8:{i:x}::/48' if v6 else f'1.2.{i}.0/24' for i in range(150)))
            return subprocess.CompletedProcess(args, 0, stdout='')
        with mock.patch.object(cnip, 'execute', side_effect=download):
            text, v4, v6 = cnip.download_database(True)
        self.assertEqual((v4, v6), (150, 150))
        self.assertIn('2001:db8:', text)

    def test_uninstall_removes_rules_and_preserves_backups(self):
        state = cnip.initial_state()
        state['domains'] = ['example.com']
        cnip.transact(self.env, state, 'add', cnip.GEO_HEADER + '\n1.2.3.0/24 1;\n')
        # Never touch the host's executable in a unit test.
        real_path = cnip.Path
        def path(value):
            return self.root / 'nonexistent-binary' if value == '/usr/local/bin/cnip' else real_path(value)
        with mock.patch.object(cnip, 'systemd_action') as timer, mock.patch.object(cnip, 'Path', side_effect=path):
            cnip.do_uninstall(self.env)
        timer.assert_called_once_with('disable')
        self.assertNotIn('CNIP-MANAGED', self.site.read_text())
        self.assertFalse(self.env.globalconf.exists())
        self.assertTrue(cnip.backup_dirs())


class MenuTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        patch = mock.patch.object(cnip, 'LOCK', Path(temp.name) / 'lock')
        tty = mock.patch.object(sys.stdin, 'isatty', return_value=False)
        patch.start()
        tty.start()
        self.addCleanup(temp.cleanup)
        self.addCleanup(patch.stop)
        self.addCleanup(tty.stop)

    def test_all_numeric_actions(self):
        cases = [
            (['1', 'example.com', '0'], 'do_add'),
            (['2', 'example.com', '0'], 'do_remove'),
            (['3', '0'], 'do_list'), (['4', '0'], 'do_update'),
            (['5', '8.8.8.8', '0'], 'do_allow'),
            (['6', '8.8.8.8', '0'], 'do_allow'),
            (['7', 'y', '0'], 'do_acme'),
            (['8', '1', '0'], 'systemd_action'),
            (['8', '2', '0'], 'systemd_action'),
            (['8', '3', '0'], 'systemd_action'),
            (['9', '0'], 'do_doctor'), (['10', '0'], 'do_repair'),
            (['11', '0'], 'do_backups'),
            (['12', '20261016-120000-000000-add', 'y', '0'], 'do_restore'),
            (['13', 'y', 'y'], 'do_uninstall'),
        ]
        for inputs, action in cases:
            answers = iter(inputs)
            def read(prompt):
                return '' if '按回车' in prompt else next(answers)
            with self.subTest(action=action, inputs=inputs), \
                 mock.patch('builtins.input', side_effect=read), \
                 mock.patch.object(cnip, 'environment', return_value=cnip.Environment('fake-resty', Path('/tmp'), Path('/tmp'))), \
                 mock.patch.object(cnip, 'load_state', return_value=cnip.initial_state()), \
                 mock.patch.object(cnip, 'do_backups'), \
                 mock.patch.object(cnip, action) as call, \
                 contextlib.redirect_stdout(io.StringIO()):
                cnip.menu()
                call.assert_called_once()

    def test_eof_exits(self):
        with mock.patch('builtins.input', side_effect=EOFError), contextlib.redirect_stdout(io.StringIO()):
            cnip.menu()


class EnvironmentAndTimerTests(unittest.TestCase):
    def test_discovers_nonstandard_1panel_directory(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            www, conf = root / 'custom-www', root / 'custom-conf'
            www.mkdir()
            conf.mkdir()
            import json
            obj = [{'Name': '/1panel-openresty-abcd', 'Config': {'Image': '1panel/openresty:latest'},
                    'Mounts': [{'Type': 'bind', 'Destination': '/www', 'Source': str(www)},
                               {'Type': 'bind', 'Destination': cnip.CONF_DEST, 'Source': str(conf)}]}]
            responses = [subprocess.CompletedProcess([], 0, stdout='abc\t1panel/openresty:latest\t1panel-openresty-abcd\n'),
                         subprocess.CompletedProcess([], 0, stdout=json.dumps(obj))]
            with mock.patch.object(cnip, 'execute', side_effect=responses), mock.patch.dict(cnip.os.environ, {'CNIP_CONTAINER': ''}):
                env = cnip.environment()
            self.assertEqual((env.container, env.webroot, env.confdir), ('1panel-openresty-abcd', www, conf))

    def test_multiple_containers_require_selection(self):
        envs = [cnip.Environment(n, Path('/tmp'), Path('/tmp')) for n in ('first', 'second')]
        with mock.patch.object(cnip, 'find_environments', return_value=envs):
            with mock.patch.dict(cnip.os.environ, {'CNIP_CONTAINER': ''}), self.assertRaises(cnip.CnipError):
                cnip.environment()
            with mock.patch.dict(cnip.os.environ, {'CNIP_CONTAINER': 'second'}):
                self.assertEqual(cnip.environment().container, 'second')

    def test_timer_records_container_and_disables_cleanly(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            service, timer = root / 'cnip-update.service', root / 'cnip-update.timer'
            real_exists = Path.exists
            real_is_dir = Path.is_dir
            def exists(path):
                return True if str(path) == '/usr/local/bin/cnip' else real_exists(path)
            def is_dir(path):
                return True if str(path) == '/run/systemd/system' else real_is_dir(path)
            with mock.patch.object(cnip, 'SYSTEMD_SERVICE', service), \
                 mock.patch.object(cnip, 'SYSTEMD_TIMER', timer), \
                 mock.patch.object(cnip.Path, 'is_dir', is_dir), \
                 mock.patch.object(cnip.Path, 'exists', exists), \
                 mock.patch.object(cnip, 'environment', return_value=cnip.Environment('selected-resty', root, root)), \
                 mock.patch.object(cnip, 'execute') as execute:
                cnip.systemd_action('enable')
                self.assertIn('Environment=CNIP_CONTAINER=selected-resty', service.read_text())
                self.assertIn('OnCalendar=daily', timer.read_text())
                execute.assert_any_call(['systemctl', 'enable', '--now', 'cnip-update.timer'])
                cnip.systemd_action('disable')
                self.assertFalse(service.exists())
                self.assertFalse(timer.exists())


if __name__ == '__main__':
    unittest.main()
