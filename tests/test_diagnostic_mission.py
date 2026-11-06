import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from mon_secret_cookie import core, diagnostic_mission as mission, fusion, menu_tools, tool_install, watch, security, network


class DiagnosticMissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)
        env=patch.dict(os.environ,MSC_STATE_DIR=str(self.path/'state'));env.start();self.addCleanup(env.stop)
        self.fake={'outils_LexOS':{
            'nmap':{'etat':'disponible','code':0,'message':'Nmap version 7.95\ntoken=TEST-SECRET-NEVER-SAVE\npassword=999.123'},
            'john':{'etat':'erreur','code':1,'message':'error password=private-value'},
            'wifite':{'etat':'manquant'}}}

    def test_orchestration_reports_notification_once_and_no_secrets(self):
        with patch.object(mission,'local_report',return_value=self.fake), \
             patch.object(mission,'notify_finished',return_value='service_accepte') as notify:
            result=mission.run(output=self.path/'export.json')
            notify.assert_called_once_with(result['mission'],2)
        self.assertEqual(result['etat'],'partiel')
        self.assertEqual(result['resultats'][0]['version'],'7.95')
        for p in (Path(result['export_json']),self.path/'export.json'):
            self.assertEqual(json.loads(p.read_text()),result)
            self.assertEqual(p.stat().st_mode & 0o777,0o600)
        log=Path(result['rapport_texte'])
        self.assertIn('nmap',log.read_text());self.assertEqual(log.stat().st_mode & 0o777,0o600)
        self.assertEqual(log.parent.stat().st_mode & 0o777,0o700)
        for p in log.parent.glob('*'):
            if p.is_file():
                self.assertNotIn('TEST-SECRET-NEVER-SAVE',p.read_text())
                self.assertNotIn('private-value',p.read_text())
                self.assertNotIn('999.123',p.read_text())

    def test_notifications_disabled_and_append_history(self):
        with patch.object(mission,'local_report',return_value=self.fake),patch.object(mission,'notify_finished') as notify:
            one=mission.run(notifications=False);two=mission.run(notifications=False)
            notify.assert_not_called()
        text=Path(one['rapport_texte']).read_text()
        self.assertIn(one['mission'],text);self.assertIn(two['mission'],text)
        self.assertNotEqual(one['export_json'],two['export_json'])

    def test_storage_failure_stops_before_commands(self):
        directory=mission.directory();(directory/'cookie.txt').symlink_to(self.path/'victim')
        with patch.object(mission,'local_report') as run,patch.object(mission,'notify_finished') as notify:
            with self.assertRaises(OSError):mission.run()
            run.assert_not_called();notify.assert_not_called()

    def test_kali_failure_is_a_typed_finding(self):
        with patch.object(menu_tools,'report',return_value={**self.fake,'kali':{'status':'unavailable'}}), \
             patch.object(mission,'notify_finished',return_value='terminal'):
            result=mission.run(kali=True)
        self.assertEqual(result['resultats'][-1]['outil'],'conteneur-kali')
        self.assertEqual(result['resultats'][-1]['erreur'],'conteneur_indisponible')

    def test_local_report_never_discovers_network_or_container(self):
        with patch.object(menu_tools,'check',return_value={'etat':'disponible'}) as check, \
             patch.object(menu_tools.environments,'discover') as discover:
            mission.local_report()
            self.assertEqual(check.call_count,len(menu_tools.CHECKS));discover.assert_not_called()

    def test_adapter_deadline_nonzero_and_oserror(self):
        for error in (subprocess.TimeoutExpired(['nmap','-h'],15),OSError('blocked')):
            with patch('subprocess.run',side_effect=error):
                result=fusion.version_probe(['/fake/nmap','-h'])
                self.assertEqual(result['status'],'unavailable')
        with patch('subprocess.run') as run:
            run.return_value.returncode=2;run.return_value.stdout='';run.return_value.stderr='failure'
            self.assertEqual(fusion.version_probe(['/fake/nmap','-h'])['returncode'],2)
            self.assertEqual(run.call_args.kwargs['timeout'],15)
            self.assertFalse(run.call_args.kwargs.get('shell',False))


    def test_prevost_unknown_alert_once_without_active_analysis(self):
        with patch.object(watch.network,'devices',return_value={'neighbors':[{'dst':'192.0.2.125','lladdr':'02:00:00:00:00:ad'}]}), \
             patch.object(watch,'notify') as notify, \
             patch.object(security,'scan_complete') as scan, \
             patch.object(network,'authorized_scan') as active, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(fusion.main(['surveillance','--once']),0)
            self.assertEqual(fusion.main(['surveillance','--once']),0)
            notify.assert_called_once()
            scan.assert_not_called();active.assert_not_called()
        known=json.loads((self.path/'state/surveillance/inventaire.json').read_text())
        self.assertEqual(len(known),1)

    def test_mission_notification_service_status_and_structured_args(self):
        with patch.object(core,'executable',return_value='/usr/bin/notify-send'), \
             patch.object(mission.subprocess,'run') as run, contextlib.redirect_stderr(io.StringIO()):
            run.return_value.returncode=0
            self.assertEqual(mission.notify_finished('DIAG-test',0),'service_accepte')
            self.assertEqual(run.call_args.args[0][:3],['/usr/bin/notify-send','--','PRÉVOST — diagnostic terminé'])
            self.assertEqual(run.call_args.kwargs['timeout'],5)
            self.assertFalse(run.call_args.kwargs.get('shell',False))
            run.return_value.returncode=1
            self.assertEqual(mission.notify_finished('DIAG-test',0),'terminal_service_indisponible')


class InstallToolsTests(unittest.TestCase):
    def test_plan_is_closed_no_installation(self):
        with patch.object(fusion,'executable',return_value='/usr/bin/apt-get'), \
             patch.object(tool_install.subprocess,'run') as run:
            plan=tool_install.install()
            run.assert_not_called()
        self.assertFalse(plan['execute']);self.assertIn('wifite',plan['paquets'])
        self.assertEqual(plan['commande'][:4],['sudo','--','/usr/bin/apt-get','install'])
        self.assertIn('codex',plan['hors_catalogue_apt'])

    def test_requires_terminal_and_running_kali(self):
        with patch.object(fusion,'executable',return_value='/usr/bin/apt-get'), \
             patch.object(tool_install.sys.stdin,'isatty',return_value=False), \
             patch.object(tool_install.subprocess,'run') as run:
            with self.assertRaises(core.AuditError):tool_install.install(execute=True)
            run.assert_not_called()
        with patch.object(tool_install.environments,'discover',return_value={'status':'stopped','reason':'arrêté'}):
            with self.assertRaises(core.AuditError):tool_install.install(kali=True)

    def test_simulated_install_skips_no_candidate(self):
        def runner(argv,**kwargs):
            if 'policy' in argv:
                return subprocess.CompletedProcess(argv,0,'  Candidate: '+('(none)' if argv[-1]=='radare2' else '1.0')+'\n','')
            return subprocess.CompletedProcess(argv,0)
        with patch.object(fusion,'executable',return_value='/usr/bin/apt-get'), \
             patch.object(tool_install.sys.stdin,'isatty',return_value=True), \
             patch.object(tool_install.subprocess,'run',side_effect=runner) as run:
            result=tool_install.install(execute=True)
        self.assertEqual(result['paquets_sans_candidat'],['radare2'])
        self.assertEqual(result['etat'],'partiel');self.assertNotIn('radare2',run.call_args.args[0])
        self.assertFalse(run.call_args.kwargs.get('shell',False))

    def test_kali_install_plan_uses_only_running_container(self):
        detected={'status':'available','launcher':{'container':'kali-lexos'}}
        with patch.object(tool_install.environments,'discover',return_value=detected), \
             patch.object(fusion,'executable',return_value='/bin/distrobox'), \
             patch.object(tool_install.subprocess,'run') as run:
            plan=tool_install.install(kali=True)
            run.assert_not_called()
        self.assertEqual(plan['commande'][:5],['/bin/distrobox','enter','--name','kali-lexos','--'])
        self.assertNotIn('create',plan['commande'])
