"""Conversation et exécution simulées : chaque processus réel est interdit."""
import contextlib
import io
import json
import os
import runpy
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from mon_secret_cookie import core, fusion, scan_dialogue as scan, security


def xml(ip='192.168.50.10', port=None):
    ports = '' if port is None else '<ports><port protocol="tcp" portid="'+str(port)+'"><state state="open"/><service name="ssh"/></port></ports>'
    return '<nmaprun><host><status state="up"/><address addr="'+ip+'" addrtype="ipv4"/>'+ports+'</host><runstats><finished exit="success"/></runstats></nmaprun>'


class ScanDialogueTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)
        env=patch.dict(os.environ,MSC_STATE_DIR=str(self.root/'state'));env.start();self.addCleanup(env.stop)
        for obj,name,value in ((fusion,'executable','/usr/bin/nmap'),(fusion,'storage',{'scan_allowed':True})):
            p=patch.object(obj,name,return_value=value);p.start();self.addCleanup(p.stop)
        p=patch('subprocess.run',side_effect=AssertionError('Processus réel interdit : aucun scan réseau'))
        self.runner=p.start();self.addCleanup(p.stop)
        self.expires=(datetime.now(timezone.utc)+timedelta(days=1)).isoformat()

    def target(self, tests=None, limits=None, scope='192.168.50.0/24'):
        return security.add_target('lab','owner',scope,tests or ['inventory','tcp'],self.expires,'preuve',limits=limits)

    def processes(self, command, **kwargs):
        return subprocess.CompletedProcess(command,0,xml(port=22 if '-sT' in command else None),'')

    def talk(self, target=None, answers=('', 'oui'), request='fais un nmap complet'):
        output=io.StringIO()
        with patch('builtins.input',side_effect=answers) as prompts,contextlib.redirect_stdout(output):
            result=scan.dialogue(request,target)
        return result,output.getvalue(),prompts

    def test_missing_target_exact_short_question_and_reuses_authorization(self):
        self.target()
        with patch('subprocess.run',side_effect=self.processes) as run:
            result,output,prompts=self.talk(answers=['192.168.50.10','','oui'])
        self.assertEqual(prompts.call_args_list[0].args[0],scan.QUESTION+' ')
        self.assertEqual(len(prompts.call_args_list),3)
        self.assertEqual(result['status'],'completed');self.assertEqual(run.call_count,2)
        self.assertNotIn('Ajouter',str(prompts.call_args_list))
        self.assertIn('1–65535',output)

    def test_authorized_operation_not_reauthorized(self):
        t=self.target();before=len(security.targets())
        with patch('subprocess.run',side_effect=self.processes) as run:
            result,output,prompts=self.talk('192.168.50.10')
        self.assertEqual(len(prompts.call_args_list),2)
        self.assertEqual(len(security.targets()),before)
        self.assertIn(t['id'],output);self.assertIn('sans sudo',output)
        calls=[c.args[0] for c in run.call_args_list]
        self.assertIn('-sn',calls[0]);self.assertIn('-sT',calls[1]);self.assertIn('1-65535',calls[1])
        self.assertNotIn('192.168.50.0/24',calls[0]);self.assertEqual(calls[0][-1],'192.168.50.10/32')
        self.assertTrue(all('sudo' not in cmd for cmd in calls))
        self.assertTrue(all('--unprivileged' in cmd for cmd in calls))

    def test_unknown_target_proposes_authorization_without_process(self):
        result,_,prompts=self.talk('192.168.50.10',answers=['',''])
        self.assertEqual(result['status'],'needs_authorization')
        self.assertIn('Ajouter 192.168.50.10/32 au périmètre autorisé',prompts.call_args_list[1].args[0])
        self.runner.assert_not_called();self.assertFalse((self.root/'state').exists())

    def test_new_authorization_records_limits_and_does_not_execute_on_cancel(self):
        answers=['2','AUTORISER 192.168.50.10/32','owner','preuve',self.expires,'non']
        result,_,_=self.talk('192.168.50.10',answers)
        t=security.targets()[0]
        self.assertEqual(t['limits'],{'tcp_ports':'top100','privileged':False})
        self.assertEqual(t['scope'],'192.168.50.10/32');self.assertTrue(t['created'])
        self.assertEqual(result['status'],'cancelled');self.runner.assert_not_called()

    def test_inventory_only_or_rapid_permission_does_not_authorize_complete(self):
        t=self.target(tests=['inventory'])
        self.assertIsNone(scan.authorization('192.168.50.10/32','complet'))
        t=self.target(limits={'tcp_ports':'top100','privileged':False})
        self.assertIsNone(scan.authorization('192.168.50.10/32','complet'))
        self.assertEqual(scan.authorization('192.168.50.10/32','rapide')['id'],t['id'])
        self.runner.assert_not_called()

    def test_expired_revoked_and_outside_authorizations_not_reused(self):
        t=self.target();security.revoke(t['id'])
        self.assertIsNone(scan.authorization('192.168.50.10/32','complet'))
        t=self.target();t['expires']='2000-01-01T00:00:00Z'
        with security.database() as conn:conn.execute('UPDATE targets SET data=? WHERE id=?',(json.dumps(t),t['id']))
        self.assertIsNone(scan.authorization('192.168.50.10/32','complet'))
        self.assertIsNone(scan.authorization('192.168.51.10/32','complet'))
        self.runner.assert_not_called()

    def test_real_results_and_private_report_from_simulated_output(self):
        self.target()
        with patch('subprocess.run',side_effect=self.processes):result,_,_=self.talk('192.168.50.10')
        report=Path(result['report']);data=json.loads(report.read_text())
        self.assertEqual(report.stat().st_mode&0o777,0o600)
        self.assertEqual(report.parent.stat().st_mode&0o777,0o700)
        self.assertEqual(data['observations'][0]['stage'],'inventory')
        self.assertEqual(data['observations'][1]['stage'],'tcp')
        self.assertEqual(result['results'][0]['assets'][0]['services'][0]['port'],'22')
        self.assertEqual(fusion.read_table('missions')[0]['status'],'completed')

    def test_inventory_failure_has_no_invented_results_and_saved_error(self):
        self.target()
        with patch('subprocess.run',return_value=subprocess.CompletedProcess([],2,'','permission denied; token=SECRET')):
            result,output,_=self.talk('192.168.50.10')
        self.assertEqual(result['status'],'failed');self.assertEqual(result['results'],[])
        self.assertIn('permission denied',output);self.assertNotIn('SECRET',Path(result['report']).read_text())
        self.assertEqual(json.loads(Path(result['report']).read_text())['observations'][0]['returncode'],2)

    def test_timeout_and_invalid_xml_record_failure(self):
        self.target()
        for response in (subprocess.TimeoutExpired('nmap',900,output='partial'), subprocess.CompletedProcess([],0,'not xml','')):
            effect=([response] if isinstance(response,BaseException) else lambda *a,**k:response)
            with patch('subprocess.run',side_effect=effect):result,_,_=self.talk('192.168.50.10')
            self.assertEqual(result['status'],'failed');self.assertTrue(Path(result['report']).is_file())
            self.assertFalse(result['results'])

    def test_outside_inventory_never_analyzed_and_kept_pending(self):
        self.target()
        with patch('subprocess.run',return_value=subprocess.CompletedProcess([],0,xml('192.168.51.10'),'')) as run:
            result,_,_=self.talk('192.168.50.10')
        self.assertEqual(run.call_count,1);self.assertEqual(len(result['pending']),1)
        self.assertEqual(result['results'][0]['assets'],[])

    def test_revocation_during_inventory_stops_tcp(self):
        t=self.target()
        def revoke(*args,**kwargs):
            security.revoke(t['id']);return subprocess.CompletedProcess([],0,xml(),'')
        with patch('subprocess.run',side_effect=revoke) as run:result,_,_=self.talk('192.168.50.10')
        self.assertEqual(result['status'],'failed');self.assertEqual(run.call_count,1)

    def test_cancelled_execution_no_report_or_process(self):
        self.target();result,_,_=self.talk('192.168.50.10',answers=['','non'])
        self.assertEqual(result['status'],'cancelled');self.runner.assert_not_called()
        self.assertFalse((self.root/'state/scan-reports').exists())

    def test_invalid_target_does_not_resolve_dns(self):
        result,output,_=self.talk('host.example',answers=[])
        self.assertEqual(result['status'],'needs_target');self.assertIn('CIDR valide',output)
        self.runner.assert_not_called()

    def test_rapid_profile_and_ipv6_argv(self):
        self.target()
        with patch('subprocess.run',side_effect=self.processes) as run:result,_,_=self.talk('192.168.50.10',answers=['2','oui'])
        self.assertIn('--top-ports',run.call_args_list[1].args[0]);self.assertNotIn('1-65535',run.call_args_list[1].args[0])
        self.assertIn('-6',scan.argv('/usr/bin/nmap','::1/128','complet'))

    def test_unknown_profile_never_starts_inventory(self):
        t=self.target()
        with self.assertRaises(core.AuditError):scan.execute('192.168.50.10','arbitrary',t)
        self.runner.assert_not_called()

    def test_scan_intent_and_literal_target_detection(self):
        for request in ('fais un nmap complet','lance nmap 192.168.50.10','nmap complet'):
            self.assertTrue(scan.is_scan_request(request))
        for request in ('comment utiliser nmap?','ne fais pas de nmap complet','explique nmap complet'):
            self.assertFalse(scan.is_scan_request(request))
        self.assertEqual(scan.extract_target('fais un nmap complet sur 192.168.50.10'),'192.168.50.10')
        self.assertIsNone(scan.extract_target('nmap --script evil.example'))

    def atelier(self):
        source=Path(__file__).resolve().parent.parent/'integration/prevost-ia.py'
        return runpy.run_path(str(source))['main']

    def test_plain_language_routes_through_existing_kali_without_llm(self):
        main=self.atelier();calls=[]
        with patch.dict(main.__globals__,choose_model=lambda:None,tools_status=lambda:None,kali_context=lambda:'test',kali_bridge=lambda args:calls.append(args) or 0,ask=lambda *args:(_ for _ in ()).throw(AssertionError('IA non requise'))),patch('builtins.input',side_effect=['fais un nmap complet','192.168.50.10','/quitter']) as prompts,contextlib.redirect_stdout(io.StringIO()):
            main()
        self.assertIn(['nmap','--cible','192.168.50.10/32','--demande','fais un nmap complet'],calls)
        self.assertTrue(any(call.args[0]==scan.QUESTION+' ' for call in prompts.call_args_list))
        self.runner.assert_not_called()

    def test_selected_target_avoids_repeating_target_question(self):
        main=self.atelier();calls=[]
        with patch.dict(main.__globals__,choose_model=lambda:None,tools_status=lambda:None,kali_context=lambda:'test',kali_bridge=lambda args:calls.append(args) or 0),patch('builtins.input',side_effect=['/cible 192.168.50.10','fais un nmap complet','fais un nmap rapide','/quitter']) as prompts,contextlib.redirect_stdout(io.StringIO()):main()
        self.assertEqual(len([args for args in calls if args[0]=='nmap']),2)
        self.assertFalse(any(call.args[0]==scan.QUESTION+' ' for call in prompts.call_args_list))
        self.runner.assert_not_called()

    def test_invalid_explicit_target_never_falls_back_to_selected_target(self):
        main=self.atelier();calls=[]
        g=main.__globals__
        with patch.dict(g,kali_bridge=lambda args:calls.append(args)),contextlib.redirect_stdout(io.StringIO()):
            selected=g['scan_conversation']('fais un nmap complet sur 10.0.0.0/16','192.168.50.10/32')
            self.assertEqual(selected,'192.168.50.10/32')
            g['scan_conversation']('fais un nmap complet sur host.example','192.168.50.10/32')
            g['scan_conversation']('fais un nmap complet 999.168.50.10','192.168.50.10/32')
        self.assertFalse(calls);self.runner.assert_not_called()

    def test_cli_nmap_routes_to_dialogue_and_reports_failure_exit_code(self):
        with patch.object(scan,'dialogue',return_value={'status':'failed','executed':True,'error':'simulation'}) as dialogue,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(fusion.main(['nmap','--cible','192.168.50.10','--demande','fais un nmap complet']),1)
        dialogue.assert_called_once_with('fais un nmap complet','192.168.50.10')
        self.runner.assert_not_called()

    def test_proposer_nmap_missing_target_asks_exact_question_without_tool(self):
        from mon_secret_cookie import kali_tools
        result=kali_tools.proposal('fais un nmap complet')
        self.assertEqual(result['question'],scan.QUESTION)
        self.assertFalse(result['executed']);self.runner.assert_not_called()

    def test_new_full_authorization_is_reused_on_next_request(self):
        answers=['1','AUTORISER 192.168.50.10/32','owner','preuve',self.expires,'non']
        self.talk('192.168.50.10',answers)
        _,output,prompts=self.talk('192.168.50.10',answers=['1','non'])
        self.assertEqual(len(prompts.call_args_list),2)
        self.assertEqual(len(security.targets()),1)
        self.assertIn('Autorisation existante',output);self.runner.assert_not_called()
