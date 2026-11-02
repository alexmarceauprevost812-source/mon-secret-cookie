import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from mon_secret_cookie import cli, core, diagnostics, security, server


def host(ip='192.168.1.10', port='22', mac='02:00:00:00:00:01'):
    addresses = [{'addrtype': 'ipv4', 'addr': ip}]
    if mac:
        addresses.append({'addrtype': 'mac', 'addr': mac})
    return {'addresses': addresses, 'status': 'up', 'ports': [
        {'port': port, 'protocol': 'tcp', 'state': 'open', 'service': 'ssh'}]}


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = patch.dict(os.environ, MSC_STATE_DIR=self.tmp.name)
        self.env.start()
        self.addCleanup(self.env.stop)
        tools = patch.object(diagnostics, 'tools', return_value={'nmap': {'status': 'ok'}})
        tools.start()
        self.addCleanup(tools.stop)

    def target(self, scope='192.168.1.0/24', tests=None):
        return security.add_target('laboratoire', 'propriétaire', scope, tests or ['inventory'],
                                   (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
                                   'Autorisation laboratoire personnel', ['lab.example'])

    def scan(self, hosts):
        with patch.object(security, 'discover', return_value=hosts):
            return security.scan_complete()

    def test_registration_persistence_and_validation(self):
        target = self.target()
        self.assertEqual(security.targets()[0]['id'], target['id'])
        self.assertTrue(security.authorizations()['authorizations'][0]['valid'])
        self.assertEqual(target['references'], ['lab.example'])
        with self.assertRaises(core.AuditError):
            self.target('example.com')
        with self.assertRaises(core.AuditError):
            self.target('192.168.0.0/16')
        with self.assertRaises(core.AuditError):
            self.target(tests=['inventory', 'intrusive'])

    def test_no_targets_no_scan(self):
        with patch.object(security, 'discover') as discover:
            with self.assertRaises(core.AuditError):
                security.scan_complete()
            discover.assert_not_called()

    def test_revoked_no_scan_preserves_proof(self):
        target = self.target()
        security.revoke(target['id'])
        with patch.object(security, 'discover') as discover:
            with self.assertRaises(core.AuditError):
                security.scan_complete()
            discover.assert_not_called()
        entry = security.authorizations()['authorizations'][0]
        self.assertFalse(entry['valid'])
        self.assertEqual(entry['proof'], target['proof'])

    def test_expired_and_timezone_required(self):
        for value in ('2020-01-01T00:00:00Z', '2030-01-01', 'invalid'):
            with self.assertRaises(core.AuditError):
                security.add_target('lab', 'owner', '127.0.0.1', ['inventory'], value, 'preuve')
        target = self.target()
        target['expires'] = '2020-01-01T00:00:00Z'
        with security.database() as conn:
            conn.execute('UPDATE targets SET data=? WHERE id=?', (json.dumps(target), target['id']))
        with patch.object(security, 'discover') as discover:
            with self.assertRaises(core.AuditError):
                security.scan_complete()
            discover.assert_not_called()

    def test_new_inherits_only_scope_tests_and_expiry(self):
        target = self.target()
        with patch.object(security.network, 'scan_address') as tcp:
            mission = self.scan([host()])
            tcp.assert_not_called()
        asset = mission['inventories'][0]['assets'][0]
        self.assertEqual(asset['authorization'], target['id'])
        self.assertEqual(asset['tests'], ['inventory'])
        self.assertEqual(asset['expires'], target['expires'])
        self.assertEqual(len(security.new_assets()['new']), 1)
        self.assertIsNotNone(security.targets()[0]['last_scan'])

    def test_unknown_outside_scope_never_scanned(self):
        self.target(tests=['inventory', 'tcp'])
        with patch.object(security.network, 'scan_address') as tcp:
            mission = self.scan([host('192.168.2.10')])
            tcp.assert_not_called()
        self.assertEqual(len(mission['pending']), 1)
        self.assertEqual(mission['inventories'][0]['assets'], [])

    def test_mixed_addresses_not_authorized(self):
        self.target(tests=['inventory', 'tcp'])
        observed = host()
        observed['addresses'].append({'addrtype': 'ipv4', 'addr': '192.168.2.10'})
        with patch.object(security.network, 'scan_address') as tcp:
            self.assertEqual(len(self.scan([observed])['pending']), 1)
            tcp.assert_not_called()

    def test_compare_ip_and_service_changes_and_absence(self):
        self.target(tests=['inventory','tcp'])
        with patch.object(security.network, 'scan_address', return_value=[host()]):
            self.scan([host()])
        with patch.object(security.network, 'scan_address', return_value=[host('192.168.1.11', '80')]):
            diff = self.scan([host('192.168.1.11', '80')])['inventories'][0]['changes']
        self.assertEqual(len(diff['changed']), 1)
        self.assertEqual(diff['new'], [])
        diff = self.scan([])['inventories'][0]['changes']
        self.assertEqual(len(diff['not_observed']), 1)
        self.assertEqual(len(security.reports()['missions']), 3)

    def test_failed_scan_does_not_replace_baseline(self):
        self.target(tests=['inventory', 'tcp'])
        with patch.object(security.network, 'scan_address', return_value=[host()]):
            self.scan([host()])
        with patch.object(security.network, 'scan_address', side_effect=core.AuditError('Nmap absent')):
            with self.assertRaises(core.AuditError):
                self.scan([host()])
        self.assertEqual(security.reports()['missions'][-1]['status'], 'failed')
        with patch.object(security.network, 'scan_address', return_value=[host()]):
            mission = self.scan([host()])
        self.assertEqual(mission['inventories'][0]['changes']['new'], [])

    def test_revocation_during_discovery_blocks_tcp(self):
        target = self.target(tests=['inventory', 'tcp'])
        def discover(_):
            security.revoke(target['id'])
            return [host()]
        with patch.object(security, 'discover', side_effect=discover), patch.object(security.network, 'scan_address') as tcp:
            with self.assertRaises(core.AuditError):
                security.scan_complete()
            tcp.assert_not_called()
        self.assertIn('revoked', security.targets()[0])

    def test_cidr_delegates_to_local_network_guard(self):
        target = self.target()
        with patch.object(security.network, 'devices', side_effect=core.AuditError('Pas le LAN')) as devices:
            with self.assertRaises(core.AuditError):
                security.discover(target)
            devices.assert_called_once_with('192.168.1.0/24', True)

    def test_nmap_partial_results_rejected(self):
        for xml in ('<wrong/>', '<nmaprun><host timedout="true"/></nmaprun>',
                    '<nmaprun><runstats><finished exit="error"/></runstats></nmaprun>',
                    '<nmaprun><host><ports><port portid="22"/></ports></host></nmaprun>'):
            with self.assertRaises(core.AuditError):
                security.network.parse_nmap(xml)

    def test_interruption_logged_without_reference(self):
        self.target()
        with patch.object(security, 'discover', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                security.scan_complete()
        self.assertEqual(security.reports()['missions'][-1]['status'], 'failed')
        with security.database() as conn:
            self.assertEqual(conn.execute('SELECT count(*) FROM snapshots').fetchone()[0], 0)

    def test_no_scan_when_journal_write_fails(self):
        self.target()
        original = security.database
        count = 0
        @contextlib.contextmanager
        def failing_database():
            nonlocal count
            count += 1
            if count >= 2:
                raise OSError('disque plein')
            with original() as conn:
                yield conn
        with patch.object(security, 'database', failing_database), patch.object(security, 'discover') as discover:
            with self.assertRaises(OSError):
                security.scan_complete()
            discover.assert_not_called()

    def test_report_never_overwrites(self):
        self.target()
        self.scan([host()])
        path = os.path.join(self.tmp.name, 'rapport.json')
        security.export_report(path)
        with open(path) as stream:
            self.assertEqual(len(json.load(stream)['missions']), 1)
        with self.assertRaises(FileExistsError):
            security.export_report(path)

    def test_cli_registry_and_scan_failure(self):
        self.target()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(cli.main(['cibles']), 0)
        self.assertEqual(len(json.loads(output.getvalue())['cibles']), 1)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(['scan', 'complet', '--cible', 'AUTH-absent']), 1)

    def test_api_authentication_and_read_only(self):
        self.target()
        token = 'a' * 40
        app = server.create_app(token)
        client = app.test_client()
        for path in ('health', 'cibles', 'autorisations', 'nouvelles', 'rapports', 'outils'):
            self.assertEqual(client.get('/api/' + path).status_code, 401)
            response = client.get('/api/' + path, headers={'Authorization': 'Bearer ' + token})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(client.get('/api/health', headers={'Authorization': 'Bearer ' + 'b'*40}).status_code, 401)
        self.assertEqual(client.post('/api/cibles', headers={'Authorization': 'Bearer ' + token}).status_code, 405)
        for token in ('', 'short', 'a' * 40 + '\n', 'é'*40):
            with self.assertRaises(core.AuditError):
                server.create_app(token)


class DiagnosticsTests(unittest.TestCase):
    def test_tools_only_fixed_diagnostics(self):
        with patch.object(diagnostics.shutil, 'which', return_value='/tool'), patch.object(diagnostics.core, 'run', return_value='version 1') as run:
            result = diagnostics.tools()
        calls = [c.args[0] for c in run.call_args_list]
        self.assertIn(['wifite', '--help'], calls)
        self.assertIn(['hashcat', '-I'], calls)
        self.assertIn(['nmap', '--version'], calls)
        self.assertNotIn(['wifite'], calls)
        self.assertEqual(result['nvidia']['status'], 'ok')

    def test_missing_and_failed_backend_are_reported(self):
        with patch.object(diagnostics.shutil, 'which', return_value=None):
            self.assertEqual(diagnostics.probe('hashcat', ['-I'])['status'], 'missing')
        with patch.object(diagnostics.shutil, 'which', return_value='/tool'), patch.object(diagnostics.core, 'run', side_effect=core.AuditError('backend absent')):
            self.assertEqual(diagnostics.probe('hashcat', ['-I'])['status'], 'unavailable')
