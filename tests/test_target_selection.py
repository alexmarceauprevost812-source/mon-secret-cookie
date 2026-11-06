import json
from unittest.mock import patch
import test_kali_tools
import unittest
from mon_secret_cookie import security, target_selection as selection, core, fusion


class TargetSelectionTests(unittest.TestCase):
    setUp = test_kali_tools.KaliToolsTests.setUp
    target = test_kali_tools.KaliToolsTests.target
    # Classe indépendante de la suite de base : données simulées uniquement.
    def observed(self):
        t=self.target()
        h=lambda ip:{'addresses':[{'addrtype':'ipv4','addr':ip}],'status':'up','ports':[]}
        with patch.object(security.diagnostics,'tools',return_value={}),patch.object(security,'discover',return_value=[h('192.168.50.10'),h('192.168.51.20')]),patch.object(security.network,'scan_address',return_value=[h('192.168.50.10')]):
            security.scan_complete([t['id']])
        return t

    def test_inherits_exact_limits_dates_and_scope(self):
        t=self.observed();inside,outside=selection.candidates()['candidates']
        self.assertEqual(inside['authorization'],t['id'])
        for key in ('created','scope','tests','expires'):self.assertEqual(inside[key],t[key])
        self.assertEqual(outside['status'],'pending');self.assertFalse(outside['tests'])
        self.runner.assert_not_called()

    def test_explicit_confirmation_required_and_no_scan(self):
        t=self.observed()
        for phrase in ('oui','OUI','AUTORISER 192.168.51.21',''):
            with self.assertRaises(core.AuditError):selection.authorize_selected('192.168.51.20','owner','proof',t['expires'],['inventory'],phrase)
        new=selection.authorize_selected('192.168.51.20','owner','proof',t['expires'],['inventory'],'AUTORISER 192.168.51.20')
        self.assertEqual(new['scope'],'192.168.51.20/32');self.assertEqual(new['tests'],['inventory'])
        self.assertTrue(new['created']);self.assertEqual(selection.candidates()['candidates'][1]['authorization'],new['id'])
        self.runner.assert_not_called()

    def test_revocation_removes_inheritance_without_erasing_observation(self):
        t=self.observed();security.revoke(t['id'])
        self.assertEqual(selection.candidates()['candidates'][0]['status'],'pending')
        self.assertEqual(len(selection.candidates()['candidates']),2)
        self.runner.assert_not_called()

    def test_unknown_ip_cannot_be_selected(self):
        t=self.observed()
        with self.assertRaises(core.AuditError):selection.authorize_selected('192.168.51.99','owner','proof',t['expires'],['inventory'],'AUTORISER 192.168.51.99')
        self.runner.assert_not_called()

    def test_menu_authorizes_selection_without_analysis(self):
        t=self.observed()
        import io,contextlib
        replies=['2','owner','preuve',t['expires'],'inventory','AUTORISER 192.168.51.20']
        with patch('sys.stdin.isatty',return_value=True),patch('builtins.input',side_effect=replies),contextlib.redirect_stdout(io.StringIO()):
            result=selection.menu()
        self.assertFalse(result['network_executed']);self.assertEqual(len(result['authorized']),1)
        self.runner.assert_not_called()

    def test_noninteractive_selection_refused(self):
        with patch('sys.stdin.isatty',return_value=False),self.assertRaises(core.AuditError):selection.menu()
        self.runner.assert_not_called()
