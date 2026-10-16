"""Legacy migration must be explicit, scoped, backed up, and reversible."""
import contextlib
import io
from pathlib import Path
import unittest
from unittest import mock

import cnip
import test_interaction as interaction


class LegacyMigrationTests(unittest.TestCase):
    menu = interaction.InteractionTests.menu

    def setUp(self):
        interaction.InteractionTests.setUp(self)
        self.current = self.original.replace('example.com other.test', 'example.com')
        self.legacy_site = self.current.replace('server_name example.com;',
                            'server_name example.com; include /www/cn-allow.conf;')
        self.site.write_text(self.legacy_site)
        self.shared = self.www / 'cn-allow.conf'
        self.shared.write_text('allow 1.2.3.0/24;\ndeny all;\n')
        self.other = self.conf / 'other.conf'
        self.other_text = 'server { listen 80; server_name other.test; include /www/cn-allow.conf; }\n'
        self.other.write_text(self.other_text)

    def assert_others_unchanged(self):
        self.assertEqual(self.other.read_text(), self.other_text)
        self.assertEqual(self.shared.read_text(), 'allow 1.2.3.0/24;\ndeny all;\n')

    def test_default_add_refuses_without_modifying_site(self):
        with self.assertRaises(cnip.LegacyRuleError):
            cnip.do_add(self.env, 'example.com')
        self.assertEqual(self.site.read_text(), self.legacy_site)
        self.assertFalse(self.env.statefile.exists())
        self.assert_others_unchanged()

    def test_confirmed_migration_removes_only_target_include(self):
        out = self.menu(['1', 'example.com', '是', '0'])
        self.assertNotIn('操作失败', out)
        self.assertIn('迁移确认', out)
        self.assertNotIn('include /www/cn-allow.conf;', self.site.read_text())
        self.assertIn('CNIP-MANAGED', self.site.read_text())
        self.assertEqual(cnip.load_state(self.env)['domains'], ['example.com'])
        backup = cnip.backup_dirs()[0]
        original = backup / 'originals' / self.site.relative_to('/')
        self.assertEqual(original.read_text(), self.legacy_site)
        cnip.do_restore(self.env, backup.name)
        self.assertEqual(self.site.read_text(), self.legacy_site)
        self.assert_others_unchanged()

    def test_cancel_keeps_every_file_unchanged(self):
        out = self.menu(['1', 'example.com', '否', '0'])
        self.assertIn('已取消迁移', out)
        self.assertEqual(self.site.read_text(), self.legacy_site)
        self.assertFalse(self.env.storage.exists())
        self.assertFalse(cnip.backup_dirs())
        self.assert_others_unchanged()

    def test_shared_server_alias_stops_before_confirmation(self):
        shared_server = self.legacy_site.replace('server_name example.com;', 'server_name example.com other.test;')
        self.site.write_text(shared_server)
        out = self.menu(['1', 'example.com', '0'])
        self.assertIn('同一 server 还包含其他域名', out)
        self.assertNotIn('迁移确认', out)
        self.assertEqual(self.site.read_text(), shared_server)
        self.assertFalse(self.env.storage.exists())
        self.assert_others_unchanged()

    def test_nested_legacy_include_requires_manual_check(self):
        nested = self.current.replace('location / {', 'location / { include /www/cn-allow.conf;')
        self.site.write_text(nested)
        out = self.menu(['1', 'example.com', '0'])
        self.assertIn('嵌套配置块', out)
        self.assertEqual(self.site.read_text(), nested)
        self.assertFalse(self.env.storage.exists())

    def test_comments_and_quoted_messages_are_not_legacy_directives(self):
        data = self.current.replace('location / {', '# include /www/cn-allow.conf;\nlocation / {')
        data = data.replace('return 200 "ok";', 'return 200 "include /www/cn-allow.conf;";')
        self.site.write_text(data)
        out = self.menu(['1', 'example.com', '0'])
        self.assertNotIn('迁移确认', out)
        self.assertNotIn('操作失败', out)
        self.assertIn('# include /www/cn-allow.conf;', self.site.read_text())
        self.assertIn('CNIP-MANAGED', self.site.read_text())
        self.assert_others_unchanged()

    def test_quoted_old_path_and_v2_include_are_supported(self):
        data = self.current.replace('server_name example.com;', 'server_name example.com; include "/www/cn-allow.conf"; include /www/.cn-only-v2/guard.conf;')
        self.site.write_text(data)
        out = self.menu(['1', 'example.com', 'y', '0'])
        self.assertNotIn('操作失败', out)
        self.assertEqual(cnip.legacy_includes(self.site.read_text()), [])
        self.assertIn('CNIP-MANAGED', self.site.read_text())
        self.assert_others_unchanged()

    def test_validation_failure_rolls_back_original_legacy_config(self):
        original = cnip.Environment.nginx
        checks = [0]
        def nginx(env, *args):
            if args == ('-t',):
                checks[0] += 1
                if checks[0] == 2:
                    raise cnip.CnipError('test invalid migrated config')
            return original(env, *args)
        with mock.patch.object(cnip.Environment, 'nginx', nginx), contextlib.redirect_stderr(io.StringIO()):
            out = self.menu(['1', 'example.com', 'y', '0'])
        self.assertIn('操作失败', out)
        self.assertEqual(self.site.read_text(), self.legacy_site)
        self.assertFalse(self.env.statefile.exists())
        self.assert_others_unchanged()

    def test_ctrl_c_in_migration_confirmation_exits_without_writes(self):
        answers = iter(['1', 'example.com'])
        def read(prompt):
            if '确认迁移' in prompt:
                raise KeyboardInterrupt
            return next(answers)
        with self.assertRaises(KeyboardInterrupt):
            self.menu(read)
        self.assertEqual(self.site.read_text(), self.legacy_site)
        self.assertFalse(self.env.storage.exists())

    def test_interrupt_during_migration_reload_rolls_back(self):
        original = cnip.Environment.nginx
        first = [True]
        def nginx(env, *args):
            if args == ('-s', 'reload') and first[0]:
                first[0] = False
                raise KeyboardInterrupt
            return original(env, *args)
        with mock.patch.object(cnip.Environment, 'nginx', nginx), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                self.menu(['1', 'example.com', 'y'])
        self.assertEqual(self.site.read_text(), self.legacy_site)
        self.assertFalse(self.env.statefile.exists())
        self.assert_others_unchanged()


if __name__ == '__main__':
    unittest.main()
