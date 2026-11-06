import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from mon_secret_cookie import core, fusion, security

PROJECT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('install_launcher', PROJECT/'integration/install_launcher.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class UnifiedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        env = patch.dict(os.environ, MSC_STATE_DIR=str(self.root/'state'))
        env.start(); self.addCleanup(env.stop)

    def call(self, argv):
        out, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(error):
            status = fusion.main(argv)
        return status, out.getvalue(), error.getvalue()

    def target(self):
        return security.add_target('lab', 'owner', '192.168.1.0/24', ['inventory'],
               (datetime.now(timezone.utc)+timedelta(days=1)).isoformat(), 'preuve test')

    def test_help_default_and_french_alias(self):
        for argv in ([], ['aide']):
            code, output, _ = self.call(argv)
            self.assertEqual(code, 0)
            for command in ('outils', 'mission', 'cibles', 'scan', 'nouvelles', 'rapport', 'diagnostic', 'kali', 'ia'):
                self.assertIn(command, output)
        self.assertFalse((self.root/'state').exists())

    def test_mission_lists_and_unknown_id_refused(self):
        code, output, _ = self.call(['mission'])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output), {'missions': []})
        self.assertEqual(self.call(['mission', '--id', 'RUN-inconnue'])[0], 1)
        self.assertEqual(self.call(['mission', '--executer'])[0], 1)
        self.assertFalse((self.root/'state').exists())

    def test_read_targets_and_new_assets_without_creating_state(self):
        for argv in (['cibles'], ['nouvelles']):
            self.assertEqual(self.call(argv)[0], 0)
        self.assertFalse((self.root/'state').exists())

    def test_targets_preserved_with_explicit_validity(self):
        target = self.target()
        path = self.root/'state/security.sqlite3'
        before = path.read_bytes()
        code, output, _ = self.call(['cibles'])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)['cibles'][0]['id'], target['id'])
        self.assertTrue(json.loads(output)['cibles'][0]['valid'])
        self.assertEqual(path.read_bytes(), before)
        security.revoke(target['id'])
        self.assertFalse(json.loads(self.call(['cibles'])[1])['cibles'][0]['valid'])

    def test_unknown_target_never_scanned(self):
        with patch.object(security, 'scan_complete') as scan:
            self.assertEqual(self.call(['scan', '--cible', 'AUTH-inconnue', '--executer'])[0], 1)
            self.assertEqual(self.call(['mission', '--cible', 'AUTH-inconnue', '--executer'])[0], 1)
            scan.assert_not_called()

    def test_mission_execute_uses_existing_scan_guard(self):
        with patch.object(fusion, 'scan', return_value={'status': 'completed'}) as scan:
            self.assertEqual(self.call(['mission', '--cible', 'AUTH-test', '--executer'])[0], 0)
            scan.assert_called_once_with(['AUTH-test'], True)

    def test_diagnostic_uses_local_orchestrator(self):
        with patch('mon_secret_cookie.diagnostic_mission.run', return_value={'resultats': []}) as run:
            self.assertEqual(self.call(['diagnostic', '--kali'])[0], 0)
            run.assert_called_once_with(True, True, None)

    def test_existing_bridges_accept_no_arbitrary_arguments(self):
        for command in ('kali', 'ia'):
            with patch.object(fusion, 'existing_launcher') as launch:
                self.assertEqual(self.call([command])[0], 0)
                launch.assert_called_once_with(command)
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                fusion.main([command, '--command', 'anything'])

    def test_bridge_executes_only_installed_launcher(self):
        binary = self.root/'.local/bin/kali'
        binary.parent.mkdir(parents=True)
        binary.write_text('#!/bin/sh\nexit 0\n'); binary.chmod(0o700)
        with patch.object(fusion.Path, 'home', return_value=self.root), patch.object(fusion.os, 'execv') as execute:
            fusion.existing_launcher('kali')
            execute.assert_called_once_with(str(binary), [str(binary)])
        with patch.object(fusion.Path, 'home', return_value=self.root):
            with self.assertRaises(core.AuditError):
                fusion.existing_launcher('ia')

    def test_report_export_reads_history_without_modifying_it(self):
        self.target()
        history = {'id': 'RUN-test', 'status': 'completed', 'inventories': [], 'pending': []}
        with security.database() as conn:
            conn.execute('INSERT INTO missions VALUES (?,?,?,?)', ('RUN-test', '2026-01-01', 'completed', json.dumps(history)))
        db = self.root/'state/security.sqlite3'
        before = db.read_bytes()
        output = self.root/'report.json'
        self.assertEqual(self.call(['rapport', '--output', str(output)])[0], 0)
        self.assertEqual(json.loads(output.read_text())['missions'][0]['id'], 'RUN-test')
        self.assertEqual(db.read_bytes(), before)
        self.assertEqual(self.call(['rapport', '--output', str(output)])[0], 1)

    def test_new_assets_reuses_existing_engine_in_read_only_mode(self):
        history = [{'status': 'completed', 'pending': [], 'inventories': [
                   {'target': 'AUTH-test', 'changes': {'new': [{'asset_id': 'DEV-test', 'authorization_status': 'authorized'}]}}]}]
        with patch.object(fusion, 'read_table', return_value=history), patch.object(security, 'reports', side_effect=AssertionError('Écriture non permise')):
            code, output, _ = self.call(['nouvelles'])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)['new'][0]['asset_id'], 'DEV-test')

    def test_python_launcher_works_with_minimal_ssh_environment_and_untrusted_cwd(self):
        # Une session SSH exécute le lanceur sur LexOS ; aucun Python Android requis.
        (self.root/'mon_secret_cookie.py').write_text('raise RuntimeError("Module du dossier courant interdit")')
        env = {'HOME': str(Path.home()), 'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
               'SSH_CONNECTION': 'test', 'PYTHONPATH': str(self.root), 'MSC_STATE_DIR': str(self.root/'state')}
        result = subprocess.run(['/usr/bin/python3', '-I', '-B', str(PROJECT/'integration/prevost.py'), 'aide'],
                                env=env, cwd=self.root, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('diagnostic', result.stdout)
        self.assertFalse((self.root/'state').exists())


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.destination = self.root/'bin/prevost'

    def test_installs_new_executable_exactly(self):
        result = installer.install(self.destination)
        self.assertTrue(result['installed'])
        self.assertEqual(self.destination.read_bytes(), (PROJECT/'integration/prevost.py').read_bytes())
        self.assertEqual(self.destination.stat().st_mode & 0o777, 0o700)

    def test_preview_does_not_install(self):
        self.assertFalse(installer.install(self.destination, preview=True)['installed'])
        self.assertFalse(self.destination.exists())

    def test_existing_file_never_overwritten_and_diff_available(self):
        self.destination.parent.mkdir()
        self.destination.write_text('ancien lanceur\n')
        result = installer.install(self.destination, preview=True)
        self.assertIn('-ancien lanceur', result['diff'])
        with self.assertRaises(FileExistsError):
            installer.install(self.destination)
        self.assertEqual(self.destination.read_text(), 'ancien lanceur\n')

    def test_dangling_symlink_never_overwritten(self):
        self.destination.parent.mkdir()
        self.destination.symlink_to(self.root/'absent')
        with self.assertRaises(FileExistsError):
            installer.install(self.destination)
        self.assertTrue(self.destination.is_symlink())

    def test_concurrent_destination_creation_is_refused(self):
        with patch.object(installer.os, 'open', side_effect=FileExistsError('Création concurrente')):
            with self.assertRaises(FileExistsError):
                installer.install(self.destination)


if __name__ == '__main__':
    unittest.main()
