import contextlib
import io
import json
import os
import tempfile
import unittest
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from mon_secret_cookie import core, fusion, security

Disk = namedtuple('Disk', 'total used free')


class FusionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        env = patch.dict(os.environ, MSC_STATE_DIR=str(self.root/'state'))
        env.start(); self.addCleanup(env.stop)
        # Tout diagnostic réel est interdit dans cette suite.
        runner = patch.object(fusion, 'version_probe', side_effect=AssertionError('Diagnostic réel interdit'))
        runner.start(); self.addCleanup(runner.stop)

    def target(self, tests=None):
        return security.add_target('lab', 'responsable', '192.168.1.0/24',
                                   tests or ['inventory'],
                                   (datetime.now(timezone.utc)+timedelta(days=1)).isoformat(), 'preuve test')

    def ready(self):
        disk = patch.object(fusion.shutil, 'disk_usage', return_value=Disk(10*1024**3, 5*1024**3, 5*1024**3))
        exe = patch.object(fusion, 'executable', return_value='/usr/bin/nmap')
        disk.start(); exe.start()
        self.addCleanup(disk.stop); self.addCleanup(exe.stop)

    def test_registry_does_not_execute_or_initialize_state(self):
        with patch.object(fusion, 'executable', return_value=None):
            result = fusion.registry()
        self.assertEqual(result['tools']['wifite']['status'], 'missing')
        self.assertEqual(result['tools']['mon-secret-cookie']['version'], '0.3.0')
        self.assertEqual(result['tools']['wifite-kali']['status'], 'unverified')
        self.assertFalse((self.root/'state').exists())

    def test_no_state_created_for_empty_report(self):
        self.assertEqual(fusion.report(), {'missions': []})
        self.assertFalse((self.root/'state').exists())

    def test_no_registry_never_scans(self):
        with patch.object(security, 'scan_complete') as scan:
            with self.assertRaises(core.AuditError):
                fusion.scan(['AUTH-unknown'], True)
            scan.assert_not_called()
        self.assertFalse((self.root/'state').exists())

    def test_preparation_does_not_write_registry_or_scan(self):
        self.ready()
        target = self.target()
        path = self.root/'state/security.sqlite3'
        before = path.read_bytes()
        with patch.object(security, 'scan_complete') as scan:
            plan = fusion.scan([target['id']])
            scan.assert_not_called()
        self.assertEqual(path.read_bytes(), before)
        self.assertTrue(plan['ready'])
        self.assertFalse(plan['network_executed'])
        self.assertEqual(plan['operations'][0]['tests'], ['inventory'])

    def test_execute_delegates_only_selected_ids(self):
        self.ready()
        first = self.target(); self.target()
        with patch.object(security, 'scan_complete', return_value={'status': 'completed'}) as scan:
            fusion.scan([first['id'], first['id']], True)
            scan.assert_called_once_with([first['id']])

    def test_expired_revoked_or_unknown_never_execute(self):
        self.ready()
        target = self.target()
        security.revoke(target['id'])
        with patch.object(security, 'scan_complete') as scan:
            for ids in ([target['id']], ['AUTH-absent'], []):
                with self.assertRaises(core.AuditError):
                    fusion.scan(ids, True)
            scan.assert_not_called()
        target = self.target()
        target['expires'] = '2000-01-01T00:00:00Z'
        with security.database() as conn:
            conn.execute('UPDATE targets SET data=? WHERE id=?', (json.dumps(target), target['id']))
        with self.assertRaises(core.AuditError):
            fusion.prepare([target['id']])

    def test_low_storage_prevents_scan_and_keeps_files(self):
        self.ready()
        target = self.target()
        before = (self.root/'state/security.sqlite3').read_bytes()
        with patch.object(fusion.shutil, 'disk_usage', return_value=Disk(10*1024**3, 10*1024**3-10, 10)), patch.object(security, 'scan_complete') as scan:
            self.assertFalse(fusion.prepare([target['id']])['ready'])
            with self.assertRaises(core.AuditError):
                fusion.scan([target['id']], True)
            scan.assert_not_called()
        self.assertEqual((self.root/'state/security.sqlite3').read_bytes(), before)

    def test_missing_nmap_prevents_scan(self):
        self.ready(); target = self.target()
        with patch.object(fusion, 'executable', return_value=None), patch.object(security, 'scan_complete') as scan:
            with self.assertRaises(core.AuditError):
                fusion.scan([target['id']], True)
            scan.assert_not_called()

    def test_storage_percent_accounts_for_reserved_blocks(self):
        with patch.object(fusion.shutil, 'disk_usage', return_value=Disk(100, 87, 6)):
            result = fusion.storage()
        self.assertEqual(result['used_percent'], 94)
        self.assertEqual(result['reserved_or_unavailable_bytes'], 7)

    def test_diagnostic_allowlist_and_kali_exec_only(self):
        kali_tools = {'wifite': {'environment': 'kali-lexos', 'path': '/usr/sbin/wifite',
                      'version': '2.8.2-2', 'diagnostic': {'status': 'ok'}}}
        with patch.object(fusion, 'executable', side_effect=lambda name: '/bin/'+name), patch.object(fusion, 'version_probe', return_value={'status': 'ok'}) as probe, patch.object(fusion.environments, 'discover', return_value={'status': 'available', 'tools': kali_tools}) as discover:
            result = fusion.registry(True, True)
        calls = [call.args[0] for call in probe.call_args_list]
        self.assertTrue(discover.call_args.kwargs['diagnostic'])
        self.assertIn(['/bin/tshark', '--version'], calls)
        self.assertNotIn(['/bin/wifite'], calls)
        self.assertTrue(all('start' not in cmd and 'capture' not in cmd for cmd in calls))
        self.assertEqual(result['tools']['wifite-kali']['diagnostic']['status'], 'ok')

    def test_kali_failure_is_reported_without_repair(self):
        with patch.object(fusion, 'executable', return_value='/bin/tool'), patch.object(fusion, 'version_probe', return_value={'status': 'unavailable', 'error': 'read-only file system'}):
            result = fusion.registry(True, True)
        self.assertEqual(result['tools']['wifite-kali']['status'], 'unverified')
        self.assertIn('read-only', result['kali']['reason'])
        with self.assertRaises(core.AuditError):
            fusion.registry(False, True)

    def test_report_export_no_overwrite_and_disk_full(self):
        output = self.root/'report.json'
        fusion.report(output)
        self.assertEqual(json.loads(output.read_text()), {'missions': []})
        with self.assertRaises(FileExistsError):
            fusion.report(output)
        with patch.object(core, 'private_write', side_effect=OSError(28, 'No space left on device')):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(fusion.main(['rapport', '--output', str(self.root/'other.json')]), 1)

    def test_symlink_registry_refused(self):
        self.target()
        path = self.root/'state/security.sqlite3'
        real = self.root/'original.sqlite3'
        path.rename(real); path.symlink_to(real)
        with self.assertRaises(core.AuditError):
            fusion.report()

    def test_connection_is_plan_only_with_strict_options(self):
        result = fusion.ssh_plan('alex@lexos.local')
        self.assertFalse(result['executed'])
        self.assertIn('StrictHostKeyChecking=yes', result['ssh'])
        self.assertIn('PasswordAuthentication=no', result['ssh'])
        self.assertIn('127.0.0.1:8765:127.0.0.1:8765', result['ssh'])
        for host in ('-oProxyCommand=bad', 'alex@host;touch /tmp/x', 'host name'):
            with self.assertRaises(core.AuditError):
                fusion.ssh_plan(host)
        with self.assertRaises(core.AuditError):
            fusion.ssh_plan('host', 22)

    def test_cli_missing_id_and_arbitrary_arguments_rejected(self):
        for args in (['scan'], ['scan', '--cible', 'AUTH-x', '--script', 'anything']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                fusion.main(args)

    def test_mission_plan_cli(self):
        self.ready(); target = self.target()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(fusion.main(['mission', '--cible', target['id']]), 0)
        self.assertEqual(json.loads(output.getvalue())['mode'], 'preparation')


class ProbeTests(unittest.TestCase):
    def test_nonzero_diagnostic_is_not_available(self):
        import subprocess
        with patch('subprocess.run', return_value=subprocess.CompletedProcess([], 1, '', 'blocked')):
            self.assertEqual(fusion.version_probe(['/bin/fake', '--version'])['status'], 'unavailable')

    def test_timeout_is_reported(self):
        import subprocess
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired('fake', 15)):
            self.assertEqual(fusion.version_probe(['/bin/fake', '--version'])['status'], 'unavailable')


if __name__ == '__main__':
    unittest.main()
