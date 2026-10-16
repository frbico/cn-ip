"""Exercise complete menu actions with real subprocesses and isolated Docker/curl stand-ins."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import cnip


class InteractionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.www = self.root / 'www'
        self.conf = self.root / 'conf'
        self.bins = self.root / 'bin'
        for path in (self.www, self.conf, self.bins):
            path.mkdir()
        self.site = self.conf / 'site.conf'
        self.original = 'server { listen 80; server_name example.com other.test; location / { return 200 "ok"; } }\n'
        self.site.write_text(self.original)
        self.log = self.root / 'docker.log'
        docker = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
with open(os.environ['CNIP_TEST_LOG'], 'a') as f:
    f.write(json.dumps(args) + '\\n')
if args[0] == 'ps':
    print('abc\\t1panel/openresty:latest\\tpanel-resty')
elif args[0] == 'inspect':
    print(json.dumps([{'Name':'/panel-resty','Mounts':[
      {'Type':'bind','Destination':'/www','Source':os.environ['CNIP_TEST_WWW']},
      {'Type':'bind','Destination':'/usr/local/openresty/nginx/conf/conf.d','Source':os.environ['CNIP_TEST_CONF']}]}]))
elif args[0] == 'exec':
    if args[-1] == '-T':
        print('# configuration file /usr/local/openresty/nginx/conf/conf.d/00-cnip-managed.conf:')
else:
    sys.exit(1)
'''
        curl = '''#!/usr/bin/env python3
import sys
from pathlib import Path
args = sys.argv[1:]
path = Path(args[args.index('-o')+1])
v6 = 'ipv6' in path.name
path.write_text('\\n'.join(f'2001:db8:{i:x}::/48' if v6 else f'1.2.{i}.0/24' for i in range(150)))
'''
        for name, text in [('docker', docker), ('curl', curl)]:
            path = self.bins / name
            path.write_text(text)
            path.chmod(0o755)
        for target, value in [('LOCK', self.root / 'lock'), ('BACKUPS', self.root / 'backups')]:
            patch = mock.patch.object(cnip, target, value)
            patch.start()
            self.addCleanup(patch.stop)
        patch = mock.patch.dict(os.environ, {'PATH': str(self.bins) + ':' + os.environ['PATH'],
            'CNIP_CONTAINER': '', 'CNIP_TEST_LOG': str(self.log),
            'CNIP_TEST_WWW': str(self.www), 'CNIP_TEST_CONF': str(self.conf)})
        patch.start()
        self.addCleanup(patch.stop)
        self.env = cnip.Environment('panel-resty', self.www, self.conf)

    def menu(self, inputs, tty=False):
        if callable(inputs):
            read = inputs
        else:
            answers = iter(inputs)
            def read(prompt):
                return '' if '按回车' in prompt else next(answers)
        with mock.patch('builtins.input', side_effect=read), \
             mock.patch.object(sys.stdin, 'isatty', return_value=tty), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            cnip.menu()
        return out.getvalue()

    def test_status_option_three_without_existing_database(self):
        out = self.menu(['3', '0'])
        self.assertIn('正在识别', out)
        self.assertIn('panel-resty', out)
        self.assertIn('IPv4 0 段 / IPv6 0 段', out)
        self.assertIn('尚未更新', out)
        self.assertFalse(self.env.statefile.exists())
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual([x[0] for x in calls], ['ps', 'inspect'])

    def test_option_four_initializes_database_without_enabling_domains(self):
        out = self.menu(['4', '3', '0'])
        state = cnip.load_state(self.env)
        self.assertEqual(state['domains'], [])
        self.assertEqual((state['ipv4_count'], state['ipv6_count']), (150, 150))
        self.assertIn('正在下载 IPv4', out)
        self.assertIn('正在下载 IPv6', out)
        self.assertIn('IPv4 150 段 / IPv6 150 段', out)
        self.assertFalse(self.env.globalconf.exists())
        self.assertEqual(self.site.read_text(), self.original)

    def test_menu_full_lifecycle_without_mocking_domain_handlers(self):
        out = self.menu(['1', 'example.com', '5', '8.8.8.8', '6', '8.8.8.8',
                         '7', '是', '9', '10', '4', '11', '2', 'example.com', '3', '0'])
        self.assertNotIn('操作失败', out)
        self.assertEqual(cnip.load_state(self.env)['domains'], [])
        self.assertEqual(cnip.load_state(self.env)['extra_allow'], [])
        self.assertNotIn('CNIP-MANAGED', self.site.read_text())
        self.assertFalse(self.env.globalconf.exists())
        self.assertGreaterEqual(len(cnip.backup_dirs()), 7)

    def test_restore_and_cancellations_in_menu(self):
        self.menu(['1', 'example.com', '0'])
        backup = cnip.backup_dirs()[0].name
        out = self.menu(['12', backup, '是', '13', '否', '12', '', '8', '9', '0'])
        self.assertNotIn('操作失败', out)
        self.assertIn('已取消卸载', out)
        self.assertIn('已取消恢复', out)
        self.assertIn('无效选择', out)
        self.assertEqual(cnip.load_state(self.env)['domains'], [])

    def test_auto_update_submenu_enable_status_disable(self):
        systemctl = self.bins / 'systemctl'
        systemctl.write_text('#!/bin/sh\nexit 0\n')
        systemctl.chmod(0o755)
        service, timer = self.root / 'update.service', self.root / 'update.timer'
        real_exists, real_is_dir = Path.exists, Path.is_dir
        def exists(path):
            return True if str(path) == '/usr/local/bin/cnip' else real_exists(path)
        def is_dir(path):
            return True if str(path) == '/run/systemd/system' else real_is_dir(path)
        with mock.patch.object(cnip, 'SYSTEMD_SERVICE', service), \
             mock.patch.object(cnip, 'SYSTEMD_TIMER', timer), \
             mock.patch.object(cnip.Path, 'exists', exists), \
             mock.patch.object(cnip.Path, 'is_dir', is_dir):
            out = self.menu(['8', '1', '8', '3', '8', '2', '0'])
        self.assertNotIn('操作失败', out)
        self.assertIn('已设置每日自动更新', out)
        self.assertIn('定时器状态', out)
        self.assertIn('运行中', out)
        self.assertIn('已关闭自动更新', out)
        self.assertFalse(service.exists())
        self.assertFalse(timer.exists())

    def test_menu_uninstall_uses_real_rule_removal_and_keeps_backups(self):
        self.menu(['1', 'example.com', '0'])
        real_path = cnip.Path
        def path(value):
            return self.root / 'absent-binary' if value == '/usr/local/bin/cnip' else real_path(value)
        with mock.patch.object(cnip, 'Path', side_effect=path), mock.patch.object(cnip, 'systemd_action') as timer:
            out = self.menu(['13', '是', '是'])
        timer.assert_called_once_with('disable')
        self.assertIn('已取消 cnip 管理的所有限制', out)
        self.assertFalse(self.env.statefile.exists())
        self.assertFalse(self.env.globalconf.exists())
        self.assertNotIn('CNIP-MANAGED', self.site.read_text())
        self.assertTrue(cnip.backup_dirs())

    def test_busy_operation_reports_error_and_menu_still_exits(self):
        with cnip.operation_lock():
            out = self.menu(['3', '0'])
        self.assertIn('另一个 cnip 操作', out)
        self.assertFalse(self.log.exists())

    def test_restore_by_number_uses_displayed_backup(self):
        self.menu(['1', 'example.com', '0'])
        out = self.menu(['12', '1', '是', '0'])
        self.assertIn('已恢复', out)
        self.assertNotIn('操作失败', out)
        self.assertEqual(cnip.load_state(self.env)['domains'], [])
        self.assertNotIn('CNIP-MANAGED', self.site.read_text())

    def test_invalid_backup_number_keeps_current_configuration(self):
        self.menu(['1', 'example.com', '0'])
        before = self.site.read_bytes()
        out = self.menu(['12', '999', '0'])
        self.assertIn('备份序号无效', out)
        self.assertEqual(self.site.read_bytes(), before)
        self.assertEqual(cnip.load_state(self.env)['domains'], ['example.com'])

    def test_confirmation_reprompts_after_invalid_answer(self):
        with mock.patch('builtins.input', side_effect=['wrong', '是']), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertTrue(cnip.yn('继续？'))
        self.assertIn('请输入 y / n', out.getvalue())

    def test_results_wait_for_enter_in_terminal_and_release_lock_first(self):
        inputs = iter(['3', '', '0'])
        def read(prompt):
            if '按回车' in prompt:
                with cnip.operation_lock():
                    pass
            return next(inputs)
        self.menu(read, tty=True)

    def test_timeout_is_visible_and_returns_to_menu(self):
        with mock.patch.object(cnip, 'environment', side_effect=cnip.CnipError('Docker 超时')):
            out = self.menu(['3', '4', '0'])
        self.assertEqual(out.count('操作失败'), 2)
        self.assertIn('Docker 超时', out)

    def test_real_terminal_status_update_and_return_to_menu(self):
        import pty
        import select
        master, slave = pty.openpty()
        source = (f'import sys; sys.path.insert(0, {str(Path(cnip.__file__).parent)!r}); '
                  'import cnip, os; from pathlib import Path; '
                  "root=Path(os.environ['CNIP_TEST_LOG']).parent; "
                  "cnip.LOCK=root/'lock'; cnip.BACKUPS=root/'backups'; cnip.menu()")
        process = subprocess.Popen([sys.executable, '-u', '-c', source],
                                   stdin=slave, stdout=slave, stderr=slave)
        os.close(slave)
        received = bytearray()
        def expect(text, count=1):
            expected = text.encode()
            deadline = time.monotonic() + 5
            while received.count(expected) < count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.fail('Terminal did not show: ' + text + '\n' + received.decode(errors='replace'))
                if select.select([master], [], [], remaining)[0]:
                    received.extend(os.read(master, 65536))
        try:
            expect('请输入数字')
            os.write(master, b'3\n')
            expect('IPv4 0 段 / IPv6 0 段')
            expect('按回车返回主菜单')
            os.write(master, b'\n')
            expect('请输入数字', 2)
            os.write(master, b'4\n')
            expect('正在下载 IPv4')
            expect('正在下载 IPv6')
            expect('IP 库已更新')
            expect('按回车返回主菜单', 2)
            os.write(master, b'\n0\n')
            self.assertEqual(process.wait(timeout=5), 0)
            self.assertEqual(cnip.load_state(self.env)['ipv4_count'], 150)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            os.close(master)

    def test_ctrl_c_at_every_input_exits_without_redrawing_menu(self):
        cases = [[], ['1'], ['2'], ['5'], ['6'], ['7'], ['8'], ['12'],
                 ['12', '20261016-120000-000000-add'], ['13'], ['13', 'y'],
                 ['3'], ['invalid'], ['7', 'invalid']]
        for prefix in cases:
            with self.subTest(prefix=prefix), \
                 mock.patch('builtins.input', side_effect=prefix + [KeyboardInterrupt]), \
                 contextlib.redirect_stdout(io.StringIO()) as out:
                with self.assertRaises(KeyboardInterrupt):
                    cnip.menu()
                self.assertEqual(out.getvalue().count('cnip · 1Panel'), 1)
            with cnip.operation_lock():
                pass

    def test_return_prompt_requires_empty_enter(self):
        answers = iter(['3', 'wrong', '', '0'])
        prompts = []
        def read(prompt):
            prompts.append(prompt)
            return next(answers)
        out = self.menu(read)
        self.assertEqual(sum('按回车' in prompt for prompt in prompts), 2)
        self.assertIn('请直接按 Enter', out)
        self.assertEqual(out.count('cnip · 1Panel'), 2)

    def test_ctrl_c_from_result_page_exits_process_with_130(self):
        import pty
        import select
        import signal
        master, slave = pty.openpty()
        script = self.root / 'cnip-test.py'
        script.write_text(Path(cnip.__file__).read_text().replace(
            "Path('/run/lock/cnip.lock')", repr(self.root / 'lock').replace('PosixPath', 'Path')))
        wrapper = "import os,runpy,sys; os.geteuid=lambda:0; script=sys.argv[1]; sys.argv=[script]; runpy.run_path(script,run_name='__main__')"
        process = subprocess.Popen([sys.executable, '-u', '-c', wrapper, str(script)],
                                   stdin=slave, stdout=slave, stderr=slave)
        os.close(slave)
        data = bytearray()
        def expect(text):
            deadline = time.monotonic() + 5
            while text.encode() not in data:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.fail('Missing terminal output: ' + text)
                if select.select([master], [], [], remaining)[0]:
                    try:
                        data.extend(os.read(master, 65536))
                    except OSError:
                        self.fail('Terminal exited early: ' + data.decode(errors='replace'))
        try:
            expect('请输入数字')
            os.write(master, b'3\n')
            expect('按回车返回主菜单')
            process.send_signal(signal.SIGINT)
            self.assertEqual(process.wait(timeout=5), 130)
            while select.select([master], [], [], 0)[0]:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                data.extend(chunk)
            self.assertIn('已中断操作', data.decode())
            self.assertNotIn('Traceback', data.decode())
            self.assertEqual(data.decode().count('cnip · 1Panel'), 1)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            os.close(master)

    def test_real_docker_timeout_returns_error_in_menu(self):
        (self.bins / 'docker').write_text('#!/bin/sh\nexec sleep 5\n')
        original = cnip.execute
        def execute(args, **kwargs):
            self.assertEqual(kwargs.get('timeout'), 15)
            return original(args, timeout=0.05)
        with mock.patch.object(cnip, 'execute', side_effect=execute):
            out = self.menu(['3', '0'])
        self.assertIn('命令在 0.05 秒内未完成', out)
        self.assertIn('操作失败', out)

    def test_command_timeout_really_stops_waiting(self):
        before = time.monotonic()
        with self.assertRaisesRegex(cnip.CnipError, '未完成'):
            cnip.execute([sys.executable, '-c', 'import time; time.sleep(5)'], timeout=0.05)
        self.assertLess(time.monotonic() - before, 2)

    def test_competing_operation_fails_immediately(self):
        with cnip.operation_lock():
            before = time.monotonic()
            with self.assertRaisesRegex(cnip.CnipError, '另一个 cnip'):
                with cnip.operation_lock():
                    self.fail('second lock must not succeed')
            self.assertLess(time.monotonic() - before, 1)

    def test_main_idle_menu_holds_no_lock(self):
        def read(prompt):
            with cnip.operation_lock():
                pass
            return '0'
        with mock.patch.object(cnip.os, 'geteuid', return_value=0), \
             mock.patch.object(sys, 'argv', ['cnip']), \
             mock.patch('builtins.input', side_effect=read), \
             contextlib.redirect_stdout(io.StringIO()):
            cnip.main()

    def test_ctrl_c_rolls_back_changed_config(self):
        state = cnip.initial_state()
        state['domains'] = ['example.com']
        original_nginx = self.env.nginx
        first = [True]
        def nginx(*args):
            if args == ('-s', 'reload') and first[0]:
                first[0] = False
                raise KeyboardInterrupt
            return original_nginx(*args)
        with mock.patch.object(self.env, 'nginx', side_effect=nginx), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                cnip.transact(self.env, state, 'interrupt', cnip.GEO_HEADER + '\n1.2.3.0/24 1;\n')
        self.assertEqual(self.site.read_text(), self.original)
        self.assertFalse(self.env.globalconf.exists())
        self.assertFalse(self.env.statefile.exists())


if __name__ == '__main__':
    unittest.main()
