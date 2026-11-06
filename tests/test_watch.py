import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from mon_secret_cookie import watch, cli, core


class WatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env = patch.dict(os.environ, MSC_STATE_DIR=self.tmp.name)
        self.env.start()
        self.addCleanup(self.env.stop)

    def cycle(self, rows):
        with patch.object(watch.network, 'devices', return_value={'neighbors': rows}) as passive, \
             patch.object(watch, 'notify') as notify, contextlib.redirect_stdout(io.StringIO()):
            watch.run(once=True, notifications=True)
            passive.assert_called_once_with()
            return notify.call_count

    def test_persistence_alerts_and_ip_change(self):
        row = {'dst': '192.168.1.5', 'lladdr': 'aa:bb:cc:dd:ee:ff'}
        self.assertEqual(self.cycle([row]), 1)
        path = watch.directory()
        before = json.loads((path/'inventaire.json').read_text())
        self.assertEqual(self.cycle([dict(row, dst='192.168.1.8')]), 0)
        after = json.loads((path/'inventaire.json').read_text())
        key = next(iter(before))
        self.assertEqual(before[key]['premiere_detection'], after[key]['premiere_detection'])
        self.assertEqual(after[key]['ip'], '192.168.1.8')
        self.assertGreaterEqual(after[key]['derniere_detection'], before[key]['derniere_detection'])
        events = [json.loads(line) for line in (path/'cookie.txt').read_text().splitlines()]
        self.assertEqual([e['evenement'] for e in events], ['nouvel_appareil', 'observation'])
        for name in ('cookie.txt', 'inventaire.json'):
            self.assertEqual((path/name).stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.stat().st_mode & 0o777, 0o700)

    def test_missing_mac_and_failed_entries(self):
        self.assertEqual(self.cycle([{'dst': '192.168.1.9'},
                                    {'dst': '192.168.1.10', 'state': ['FAILED']}]), 1)
        values = json.loads((watch.directory()/'inventaire.json').read_text()).values()
        self.assertIsNone(next(iter(values))['mac'])

    def test_symlink_refused_without_modifying_target(self):
        victim = Path(self.tmp.name)/'victim'
        victim.write_text('original')
        (watch.directory()/'cookie.txt').symlink_to(victim)
        with self.assertRaises(OSError):
            self.cycle([{'dst': '192.168.1.9'}])
        self.assertEqual(victim.read_text(), 'original')

    def test_log_failure_does_not_record_known_or_notify(self):
        path = watch.directory()
        (path/'cookie.txt').mkdir()
        with self.assertRaises((OSError, core.AuditError)):
            self.cycle([{'dst': '192.168.1.9'}])
        self.assertEqual((path/'inventaire.json').read_text(), '')

    def test_interval_and_inventory_no_network(self):
        for value in (0, float('nan'), float('inf')):
            with self.assertRaises(core.AuditError):
                watch.run(value, once=True)
        with patch.object(watch.network, 'devices') as devices, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['surveillance', '--inventaire']), 0)
            devices.assert_not_called()

    def test_menu_preserves_choices_and_launches_22(self):
        with patch('builtins.input', side_effect=['22', '0']), \
             patch.object(cli, 'main') as main, contextlib.redirect_stdout(io.StringIO()) as output:
            cli.menu()
        main.assert_called_once_with(['terminal-codex'])
        for n in range(1, 25):
            self.assertRegex(output.getvalue(), rf'\b{n}\b')
        self.assertTrue(output.getvalue().startswith('TI-LEXOS KALI'))

    def test_launcher(self):
        with patch.object(cli.shutil, 'which', return_value='/example/terminal-codex'), \
             patch.object(cli.subprocess, 'run') as run:
            run.return_value.returncode = 0
            self.assertEqual(cli.main(['terminal-codex']), 0)
            run.assert_called_once_with(['/example/terminal-codex'], check=False)

    def test_opt_in_alert_once_and_cli_disable(self):
        row = {'dst': '192.168.1.9', 'lladdr': 'aa:bb:cc:dd:ee:01'}
        other = {'dst': '192.168.1.10', 'lladdr': 'aa:bb:cc:dd:ee:02'}
        with patch.object(watch.network, 'devices', return_value={'neighbors': [row, row]}) as devices, \
             patch.object(watch, 'notify') as notify, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['surveillance', '--once', '--notifications']), 0)
            notify.assert_called_once()
            self.assertEqual(notify.call_args.args[0]['ip'], row['dst'])
            # Nouvelle invocation : reconnaissance depuis l’inventaire sur disque.
            notify.reset_mock()
            self.assertEqual(cli.main(['surveillance', '--once', '--notifications']), 0)
            notify.assert_not_called()
            # Un autre appareil est inventorié sans notification avec l’option CLI.
            devices.return_value = {'neighbors': [row, other]}
            self.assertEqual(cli.main(['surveillance', '--once', '--no-notifications']), 0)
            notify.assert_not_called()
            # Réactiver ne doit pas signaler rétroactivement un appareil connu.
            self.assertEqual(cli.main(['surveillance', '--once', '--notifications']), 0)
            notify.assert_not_called()
        path = watch.directory()
        self.assertEqual(len(json.loads((path/'inventaire.json').read_text())), 2)
        events = [json.loads(line) for line in (path/'cookie.txt').read_text().splitlines()]
        self.assertEqual(sum(e['evenement'] == 'nouvel_appareil' for e in events), 2)
        self.assertEqual(len(events), 6)

    def test_default_disables_alerts_but_keeps_discovery_and_log(self):
        with patch.object(watch.network, 'devices', return_value={'neighbors': [{'dst': '192.168.1.9'}]}), \
             patch.object(watch, 'notify') as notify, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(['surveillance', '--once']), 0)
            notify.assert_not_called()
        path = watch.directory()
        self.assertEqual(len(json.loads((path/'inventaire.json').read_text())), 1)
        self.assertEqual(json.loads((path/'cookie.txt').read_text())['evenement'], 'nouvel_appareil')
