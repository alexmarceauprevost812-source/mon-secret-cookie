import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from mon_secret_cookie import environments, fusion


class EnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.bin = self.home/'.local/bin'
        self.bin.mkdir(parents=True)
        (self.bin/'kali').write_text('exec env LANG=C.UTF-8 distrobox enter kali-lexos\n')
        self.calls = []
        self.data = {'release': {'ID': 'kali', 'VERSION_ID': '2026.3'},
                     'tools': {'wifite': {'path': '/usr/sbin/wifite', 'version': '2.8.2-2'}}}

    def metadata_run(self, argv):
        self.calls.append(argv)
        if argv[1] == 'ps':
            return {'status': 'ok', 'output': 'kali-lexos\n'}
        if argv[-2] == '-c':
            return {'status': 'ok', 'output': json.dumps(self.data)}
        return {'status': 'ok', 'output': 'help/version'}

    def discover(self, diagnostic=False):
        return environments.discover(lambda name: '/usr/bin/podman', self.metadata_run, self.home, diagnostic)

    def test_launcher_recognized_without_execution(self):
        self.assertEqual(environments.launcher(self.home)['container'], 'kali-lexos')
        (self.bin/'kali').write_text('exec distrobox enter --name kali-lexos\n')
        self.assertEqual(environments.launcher(self.home)['container'], 'kali-lexos')

    def test_menu_is_not_a_container_launcher(self):
        (self.bin/'kali').unlink()
        (self.bin/'lexos-kali').write_text('exec "$HOME/.local/bin/kali-menu" "$@"\n')
        self.assertIsNone(environments.launcher(self.home))

    def test_detects_sbin_wifite_package_version_without_running_wifite(self):
        result = self.discover()
        self.assertEqual(result['status'], 'available')
        self.assertEqual(result['tools']['wifite']['path'], '/usr/sbin/wifite')
        self.assertEqual(result['tools']['wifite']['version'], '2.8.2-2')
        self.assertEqual(len(self.calls), 2)
        self.assertIn('PYTHONDONTWRITEBYTECODE=1', self.calls[1])
        self.assertTrue(all('start' not in call for call in self.calls))

    def test_optional_diagnostic_uses_exact_path_and_help_only(self):
        self.discover(True)
        self.assertEqual(self.calls[-1][-2:], ['/usr/sbin/wifite', '--help'])
        self.assertEqual(len(self.calls), 3)

    def test_stopped_container_never_started(self):
        def run(argv):
            self.calls.append(argv)
            return {'status': 'ok', 'output': 'another-container\n'}
        result = environments.discover(lambda n: '/bin/podman', run, self.home)
        self.assertEqual(result['status'], 'stopped')
        self.assertEqual(len(self.calls), 1)

    def test_permissions_error_no_repair_or_exec(self):
        def run(argv):
            self.calls.append(argv)
            return {'status': 'unavailable', 'output': 'read-only file system'}
        result = environments.discover(lambda n: '/bin/podman', run, self.home)
        self.assertIn('read-only', result['reason'])
        self.assertEqual(len(self.calls), 1)

    def test_non_kali_and_invalid_json_refused(self):
        self.data['release']['ID'] = 'debian'
        self.assertEqual(self.discover()['status'], 'unavailable')
        self.data = {'bad': 'metadata'}
        self.assertEqual(self.discover()['status'], 'unavailable')

    def test_unexpected_tool_path_never_executed(self):
        self.data['tools']['wifite']['path'] = '/tmp/wifite'
        self.assertEqual(self.discover(True)['status'], 'unavailable')
        self.assertEqual(len(self.calls), 2)

    def test_lynis_ownership_failure_never_runs_diagnostic(self):
        self.data['tools']['lynis'] = {'path': '/usr/sbin/lynis', 'version': '3.1.4-1', 'ownership_safe': False}
        result = self.discover(True)
        self.assertEqual(result['tools']['lynis']['diagnostic']['status'], 'unavailable')
        self.assertFalse(any(call[-2:] == ['/usr/sbin/lynis', '--version'] for call in self.calls))

    def test_bad_metadata_schema_is_reported(self):
        self.data = {'release': {'ID': 'kali'}, 'tools': {'wifite': []}}
        self.assertEqual(self.discover()['status'], 'unavailable')

    def test_untrusted_launcher_options_not_executed(self):
        (self.bin/'kali').write_text('exec distrobox enter --root kali-lexos\n')
        self.assertIsNone(environments.launcher(self.home))

    def test_reported_confirmation_is_distinct_from_live_discovery(self):
        config = self.home/'integration'
        config.mkdir()
        (config/'environments.json').write_text(json.dumps({'reported': {'kali-lexos': {
            'tools': {'wifite': {'path': '/usr/sbin/wifite', 'version': '2.8.2-2'}}}}}))
        self.assertEqual(environments.reported(self.home, 'kali-lexos')['tools']['wifite']['version'], '2.8.2-2')

    def test_dashboard_reads_existing_history_and_authorizations(self):
        def read(table):
            return [{'id': 'AUTH-test'}] if table == 'targets' else [{'id': 'RUN-test', 'status': 'completed'}]
        with patch.object(fusion, 'registry', return_value={'tools': {'mon-secret-cookie': {'version': '0.3.0'}}}), patch.object(fusion, 'read_table', side_effect=read):
            result = fusion.dashboard()
        self.assertEqual(result['dashboard']['authorizations'], 1)
        self.assertEqual(result['dashboard']['last_mission']['id'], 'RUN-test')
        self.assertFalse(result['dashboard']['deployed'])


if __name__ == '__main__':
    unittest.main()
