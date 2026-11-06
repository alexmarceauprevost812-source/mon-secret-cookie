import contextlib
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from mon_secret_cookie import core,environments,fusion,host_access,menu_tools,watch


class HostAccessTests(unittest.TestCase):
    def test_classification_is_observation_not_host_failure(self):
        self.assertEqual(host_access.classify_error('read-only file system'),'systeme_fichiers_lecture_seule')
        self.assertEqual(host_access.classify_error('Operation not permitted'),'acces_refuse')
        with patch.object(environments,'launcher',return_value={'container':'kali-lexos'}):
            result=environments.discover(lambda _: '/bin/podman',lambda _: {'status':'unavailable','output':'read-only file system'})
        self.assertTrue(result['host_validation_required'])
        self.assertEqual(result['tools'],{})
        self.assertEqual(result['failure_kind'],'systeme_fichiers_lecture_seule')

    def test_lynis_reports_exact_file_uid_requirement(self):
        with patch.object(host_access,'path_info',return_value={'present':True,'uid':65534,'mode':'0o644'}), \
             patch.object(host_access.os,'getuid',return_value=1002):
            result=host_access.lynis_ownership()
        self.assertFalse(result['valide']);self.assertIn('UID observé 65534',result['message'])
        self.assertIn('/usr/share/lynis/include/functions',result['message'])

    def test_readonly_probe_handles_zero_exit_with_denial(self):
        with patch.object(core,'executable',return_value='/usr/bin/ss'), \
             patch.object(host_access.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'','Cannot open netlink socket: Operation not permitted')) as run:
            result=host_access.probe('ss',['-H','-lntu'])
        self.assertEqual(result['etat'],'erreur');self.assertEqual(result['code'],0)
        self.assertEqual(result['categorie'],'acces_refuse')
        self.assertFalse(run.call_args.kwargs.get('shell',False))

    def test_missing_on_host_routes_only_to_verified_active_kali(self):
        detected={'status':'available','launcher':{'container':'kali-lexos'},'tools':{'wifite':{'installed':True,'path':'/usr/sbin/wifite'}}}
        with patch.object(menu_tools,'resolve',return_value=None), \
             patch.object(environments,'discover',return_value=detected), \
             patch.object(fusion,'executable',return_value='/bin/podman'), \
             patch.object(fusion,'version_probe',return_value={'status':'ok','returncode':0,'output':'help'}) as run:
            result=menu_tools.routed_check('wifite')
        self.assertEqual(result['environnement'],'kali-lexos')
        run.assert_called_once_with(['/bin/podman','exec','kali-lexos','/usr/sbin/wifite','--help'])

    def test_inaccessible_kali_is_unknown_not_missing(self):
        with patch.object(menu_tools,'resolve',return_value=None), \
             patch.object(environments,'discover',return_value={'status':'unavailable','reason':'read-only file system'}), \
             patch.object(fusion,'version_probe') as run:
            result=menu_tools.routed_check('nikto')
        self.assertEqual(result['etat'],'manquant');self.assertEqual(result['kali_etat'],'non_verifie')
        run.assert_not_called()

    def test_lynis_kali_allowed_only_with_validated_ownership(self):
        detected={'status':'available','launcher':{'container':'kali-lexos'},'tools':{'lynis':{'installed':True,'path':'/usr/sbin/lynis','ownership_safe':True}}}
        with patch.object(fusion,'executable',return_value='/bin/podman'):
            argv=menu_tools.help_command('lynis',True,detected)
            self.assertEqual(argv[-2:],['/usr/sbin/lynis','--help'])
            detected['tools']['lynis']['ownership_safe']=False
            with self.assertRaises(core.AuditError):menu_tools.help_command('lynis',True,detected)

    def test_normal_notification_uses_unmodified_program_path(self):
        script=runpy.run_path(str(Path(__file__).resolve().parent.parent/'integration/test_normal_notification.py'))
        with patch.object(watch.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'',b'')) as run, \
             patch.object(watch.shutil,'which',return_value='/usr/bin/notify-send'), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(script['main']([]),0)
        run.assert_called_once_with(['/usr/bin/notify-send','--','TI-LEXOS KALI',
                                    'Nouvel appareil : IP 192.0.2.124 — MAC 02:00:00:00:00:ac'],
                                   capture_output=True,timeout=5,check=False)
        self.assertNotIn('critical',str(run.call_args))
        self.assertIn('NON CONFIRMÉ',output.getvalue())

    def test_no_notification_option_keeps_program_silent(self):
        script=runpy.run_path(str(Path(__file__).resolve().parent.parent/'integration/test_normal_notification.py'))
        with patch.object(watch.subprocess,'run') as run,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(script['main'](['--no-notifications']),0)
            run.assert_not_called()

    def test_host_access_command_never_saves_to_existing_cookie(self):
        with patch.object(host_access,'report',return_value={'aucun_scan':True}) as report, \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), tempfile.TemporaryDirectory() as temporary:
            target=Path(temporary)/'host.json'
            self.assertEqual(fusion.main(['acces-hote','--output',str(target)]),0)
            self.assertEqual(target.stat().st_mode & 0o777,0o600)
            self.assertEqual(json.loads(target.read_text()),{'aucun_scan':True})
            self.assertEqual(fusion.main(['acces-hote','--output',str(target)]),1)
