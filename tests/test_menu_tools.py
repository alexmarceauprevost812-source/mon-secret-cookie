import contextlib
import importlib.util
import io
import json
import runpy
import unittest
from unittest.mock import patch
from pathlib import Path
from mon_secret_cookie import cli, core, menu_tools


class MenuToolsTests(unittest.TestCase):
    def test_entries_preserve_all_choices_and_missing(self):
        with patch.object(menu_tools,'resolve',return_value=None):
            entries=menu_tools.entries()
        self.assertEqual(set(entries),{str(n) for n in range(1,28)})
        self.assertEqual(entries['9']['etat'],'manquant')
        self.assertEqual(entries['22']['commande'],'terminal-codex')

    def test_host_help_and_john_classic(self):
        with patch.object(menu_tools,'resolve',return_value=['/usr/sbin/john']), \
             patch.object(menu_tools.fusion,'version_probe',return_value={'status':'ok','returncode':0,'output':'help'}) as run:
            self.assertEqual(menu_tools.check('john')['etat'],'disponible')
            run.assert_called_once_with(['/usr/sbin/john'])

    def test_failure_and_missing_are_distinct(self):
        with patch.object(menu_tools,'resolve',return_value=None):
            self.assertEqual(menu_tools.check('nmap')['etat'],'manquant')
        with patch.object(menu_tools,'resolve',return_value=['/bin/nmap']), \
             patch.object(menu_tools.fusion,'version_probe',return_value={'status':'unavailable','returncode':1,'output':'dependency error'}):
            self.assertEqual(menu_tools.check('nmap')['etat'],'erreur')

    def test_container_stopped_no_exec(self):
        with patch.object(menu_tools.environments,'discover',return_value={'status':'stopped','reason':'arrêté'}), \
             patch.object(menu_tools.fusion,'version_probe') as run:
            self.assertEqual(menu_tools.check('nmap',True)['etat'],'erreur')
            run.assert_not_called()

    def test_kali_only_fixed_help(self):
        detected={'status':'available','launcher':{'container':'kali-lexos'},
                  'tools':{'nmap':{'installed':True,'path':'/usr/bin/nmap'}}}
        with patch.object(menu_tools.fusion,'executable',return_value='/bin/podman'):
            self.assertEqual(menu_tools.help_command('nmap',True,detected),
                             ['/bin/podman','exec','kali-lexos','/usr/bin/nmap','-h'])
        with self.assertRaises(core.AuditError):menu_tools.help_command('nmap; bad')

    def test_core_resolves_sbin_and_preserves_arguments(self):
        with patch.object(core,'executable',return_value='/usr/sbin/john'), \
             patch.object(core.subprocess,'run') as run:
            run.return_value.returncode=0
            run.return_value.stdout='help'
            self.assertEqual(core.run(['john']), 'help')
            self.assertEqual(run.call_args.args[0],['/usr/sbin/john'])

    def test_report_does_not_write_private_reports(self):
        with patch.object(menu_tools,'report',return_value={'menu':{}}), \
             patch.object(cli.private_reports,'save') as save, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['menu-outils']),0)
            save.assert_not_called()

    def test_terminal_codex_resolves_installed_codex(self):
        module=runpy.run_path(str(Path(__file__).resolve().parent.parent/'integration/terminal-codex.py'))
        with patch.object(module['shutil'],'which',return_value=None), \
             patch.object(Path,'glob',return_value=[Path('/fake/bin/codex')]), \
             patch.object(Path,'is_file',return_value=True), \
             patch.object(module['os'],'access',return_value=True), \
             patch.object(module['subprocess'],'run') as run:
            run.return_value.returncode=0
            self.assertEqual(module['run'](['codex','--version']),0)
            run.assert_called_once_with(['/fake/bin/codex','--version'],check=False)
