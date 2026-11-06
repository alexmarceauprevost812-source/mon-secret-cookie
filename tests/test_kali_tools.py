"""Tests entièrement locaux ; tout processus est simulé sauf tests CLI sans outil."""
import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from mon_secret_cookie import core, fusion, kali_tools as tools, security


class KaliToolsTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        env = patch.dict(os.environ, MSC_STATE_DIR=str(self.root/'state'))
        env.start(); self.addCleanup(env.stop)
        # Interdit tout processus réel dans cette suite, donc tout trafic réseau.
        runner = patch('subprocess.run', side_effect=AssertionError('Processus réel interdit'))
        self.runner = runner.start(); self.addCleanup(runner.stop)

    def target(self):
        return security.add_target('lab', 'responsable', '192.168.50.0/24', ['inventory','tcp'],
            (datetime.now(timezone.utc)+timedelta(days=1)).isoformat(), 'preuve locale')

    def test_inventory_observed_no_versions_no_state(self):
        with patch.object(fusion, 'executable', side_effect=lambda n: '/usr/bin/nmap' if n=='nmap' else None), patch.object(fusion.environments, 'discover', return_value={'status':'stopped','tools':{}}):
            x=tools.inventory()
        self.assertTrue(x['host']['nmap']['installed'])
        self.assertFalse(x['host']['wifite']['installed'])
        self.assertFalse(x['host']['nmap']['rights_verified'])
        self.assertFalse((self.root/'state').exists())
        self.runner.assert_not_called()

    def test_help_fixed_argv_and_no_sudo(self):
        with patch.object(fusion, 'executable', return_value='/usr/bin/nmap'), patch.object(fusion, 'version_probe', return_value={'status':'ok','returncode':0,'output':'-sT TCP connect'}) as probe:
            result=tools.help_tool('nmap')
        probe.assert_called_once_with(['/usr/bin/nmap','-h'])
        self.assertFalse(result['network_executed'])

    def test_arbitrary_tool_or_arguments_rejected(self):
        for name in ('sh','python3','nmap;id','nmap -sS','airmon-ng'):
            with self.assertRaises(core.AuditError): tools.help_tool(name)
        self.runner.assert_not_called()

    def test_missing_tool_not_claimed_available(self):
        with patch.object(fusion,'executable',return_value=None):
            with self.assertRaises(core.AuditError):tools.help_tool('wifite')
        self.runner.assert_not_called()

    def test_help_failure_not_fabricated_success(self):
        with patch.object(fusion,'executable',return_value='/usr/bin/lynis'), patch.object(fusion,'version_probe',return_value={'status':'unavailable','returncode':1,'output':'permission denied'}):
            self.assertEqual(tools.help_tool('lynis')['status'],'unavailable')

    def test_unknown_scope_refused_before_any_tool(self):
        for target in (None,'AUTH-unknown','192.168.50.1','example.org'):
            with self.assertRaises(core.AuditError):tools.proposal('audit réseau',target)
        self.runner.assert_not_called()

    def test_proposal_does_not_scan_or_modify_registry(self):
        t=self.target();db=self.root/'state/security.sqlite3';before=db.read_bytes()
        with patch.object(fusion,'executable',return_value='/usr/bin/nmap'), patch.object(fusion,'storage',return_value={'scan_allowed':True}), patch.object(security,'scan_complete') as scan:
            result=tools.proposal('inventaire réseau',t['id'])
            scan.assert_not_called()
        self.assertFalse(result['executed']); self.assertNotIn('--executer', result['command'])
        self.assertEqual(before,db.read_bytes());self.runner.assert_not_called()

    def test_revoked_target_refused_before_network(self):
        t=self.target();security.revoke(t['id'])
        with self.assertRaises(core.AuditError):tools.proposal('audit',t['id'])
        self.runner.assert_not_called()

    def test_expired_target_refused(self):
        t=self.target();t['expires']='2000-01-01T00:00:00Z'
        with security.database() as db:db.execute('UPDATE targets SET data=? WHERE id=?',(json.dumps(t),t['id']))
        with self.assertRaises(core.AuditError):tools.proposal('audit',t['id'])
        self.runner.assert_not_called()

    def test_sudo_is_proposal_by_default(self):
        with patch.object(fusion,'executable',return_value='/usr/bin/dumpcap'):
            result=tools.interfaces(privileged=True)
        self.assertEqual(result['command'],['sudo','--','/usr/bin/dumpcap','-D'])
        self.assertFalse(result['executed']);self.runner.assert_not_called()

    def test_interfaces_unprivileged_first_no_escalation(self):
        with patch.object(fusion,'executable',return_value='/usr/bin/dumpcap'), patch.object(fusion,'version_probe',return_value={'status':'unavailable','returncode':1,'output':'permission denied'}) as probe:
            result=tools.interfaces(True)
        probe.assert_called_once_with(['/usr/bin/dumpcap','-D'])
        self.assertTrue(result['executed']);self.assertNotIn('sudo',result['command'])
        self.assertEqual(result['returncode'],1);self.runner.assert_not_called()

    def test_sudo_noninteractive_refused(self):
        with patch.object(fusion,'executable',return_value='/usr/bin/dumpcap'), patch('sys.stdin.isatty',return_value=False):
            with self.assertRaises(core.AuditError):tools.interfaces(True, True)
        self.runner.assert_not_called()

    def test_sudo_unsafe_binary_refused(self):
        f=self.root/'tool';f.write_text('test');f.chmod(0o755)
        with self.assertRaises(core.AuditError):tools.privileged_path(f)
        self.runner.assert_not_called()

    def test_sudo_cancelled_refused(self):
        with patch.object(fusion,'executable',return_value='/usr/bin/dumpcap'), patch('sys.stdin.isatty',return_value=True), patch('sys.stdout.isatty',return_value=True), patch.object(tools,'privileged_path',side_effect=lambda p:Path(p)), patch('builtins.input',return_value='non'):
            with self.assertRaises(core.AuditError):tools.interfaces(True, True)
        self.runner.assert_not_called()

    def test_sudo_success_only_fixed_function(self):
        with patch.object(fusion,'executable',return_value='/usr/bin/dumpcap'), patch('sys.stdin.isatty',return_value=True), patch('sys.stdout.isatty',return_value=True), patch.object(tools,'privileged_path',side_effect=lambda p:Path(p)), patch('builtins.input',return_value='OUI'), patch('subprocess.run',return_value=subprocess.CompletedProcess([],1)) as run:
            result=tools.interfaces(True, True)
        run.assert_called_once_with(['/usr/bin/sudo','--','/usr/bin/dumpcap','-D'],check=False,timeout=60)
        self.assertEqual(result['returncode'],1)

    def test_secrets_and_terminal_controls_masked(self):
        text=tools.clean('Authorization: Bearer supersecret\nCookie: session=secret\npassword=hidden\n\x1b[31m')
        for value in ('supersecret','session=secret','hidden','\x1b'):self.assertNotIn(value,text)

    def test_reports_private_metadata_no_raw_secrets(self):
        core.record('test',{'output':'token=SECRET','password':'SECRET','available':True})
        f=next((self.root/'state').glob('*.json'))
        self.assertNotIn('SECRET',f.read_text());self.assertEqual(f.stat().st_mode & 0o777,0o600)

    def test_global_root_refused(self):
        with patch('os.geteuid',return_value=0), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(fusion.main(['interfaces','--executer']),1)
        self.runner.assert_not_called()

    def test_mission_inventories_before_tcp_and_outside_refused(self):
        t=self.target();events=[]
        inside={'addresses':[{'addrtype':'ipv4','addr':'192.168.50.10'}],'status':'up','ports':[]}
        outside={'addresses':[{'addrtype':'ipv4','addr':'192.168.51.10'}],'status':'up','ports':[]}
        def discover(target):events.append('inventory');return [outside,inside]
        def tcp(addr):events.append(addr);return [inside]
        with patch.object(security.diagnostics,'tools',return_value={}), patch.object(security,'discover',side_effect=discover), patch.object(security.network,'scan_address',side_effect=tcp):
            result=security.scan_complete([t['id']])
        self.assertEqual(events,['inventory','192.168.50.10'])
        self.assertEqual(len(result['pending']),1);self.runner.assert_not_called()

    def test_cli_no_free_arguments(self):
        with contextlib.redirect_stderr(io.StringIO()),self.assertRaises(SystemExit):
            fusion.main(['interfaces','--executer','--command','sh'])
        self.runner.assert_not_called()
