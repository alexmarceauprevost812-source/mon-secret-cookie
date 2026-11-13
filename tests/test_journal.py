import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from mon_secret_cookie import core, journal
from mon_secret_cookie.cli import main


class FakeServer:
    started = 0
    def __init__(self, model): FakeServer.started += 1; self.stopped = False; FakeServer.last = self
    def wait(self): pass
    def chat(self, messages): self.messages = messages; return ' réponse IA '
    def stop(self): self.stopped = True


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        (self.home/'modeles').mkdir(); (self.home/'modeles/coder3b.gguf').write_bytes(b'0')
        env = patch.dict(os.environ, {'HOME': str(self.home), 'MSC_STATE_DIR': str(self.home/'state')})
        env.start(); self.addCleanup(env.stop)
        os.environ.pop('LEX_MODELES', None)
        FakeServer.started = 0

    def answers(self, *values):
        values = list(values)
        return lambda prompt='': values.pop(0)

    def test_add_is_private_and_searchable(self):
        journal.add('  Pneu à changer\n demain ')
        journal.add('LexOS : le launcher marche')
        self.assertEqual(journal.path().stat().st_mode & 0o777, 0o600)
        self.assertEqual([n['texte'] for n in journal.notes()], ['Pneu à changer demain', 'LexOS : le launcher marche'])
        self.assertEqual(len(journal.search('LEXOS')), 1)
        self.assertEqual(journal.search(' '), [])
        with self.assertRaises(core.AuditError):
            journal.add('   ')

    def test_damaged_line_is_skipped(self):
        journal.add('bonne note')
        with open(journal.path(), 'a', encoding='utf-8') as f:
            f.write('{"date": "2026-\n[1]\n')
        journal.add('autre note')
        self.assertEqual(len(journal.notes()), 2)

    def test_symlink_refused(self):
        target = self.home/'ailleurs'; target.write_text('')
        journal.path().symlink_to(target)
        with self.assertRaises(OSError):
            journal.add('note')
        self.assertEqual(target.read_text(), '')

    def test_select_prefers_matching_notes_and_respects_limit(self):
        found = [{'date': '2026-11-01 08:00', 'texte': 'voyage Girardville'},
                 {'date': '2026-11-02 08:00', 'texte': 'launcher LexOS terminé'},
                 {'date': '2026-11-03 08:00', 'texte': 'x'*journal.LIMIT}]
        self.assertEqual(journal.select(found, 'quoi sur lexos ?'), [found[1]])
        self.assertEqual(journal.select(found[:2]), found[:2])
        self.assertEqual(journal.select(found), [])

    def test_menu_loads_model_once_and_stops_it(self):
        journal.add('launcher LexOS terminé')
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            result = journal.run(ask=self.answers('4', 'quoi sur lexos ?', '5', '2', '0'), server_class=FakeServer)
        self.assertEqual(result, {'notes': 1})
        self.assertEqual(FakeServer.started, 1)
        self.assertTrue(FakeServer.last.stopped)
        self.assertIn('launcher LexOS terminé', FakeServer.last.messages[1]['content'])
        self.assertIn('réponse IA', out.getvalue())

    def test_menu_without_notes_never_starts_model(self):
        with contextlib.redirect_stdout(io.StringIO()):
            journal.run(ask=self.answers('4', 'question', '5', '1', '', '0'), server_class=FakeServer)
        self.assertEqual(FakeServer.started, 0)

    def test_cli_quick_note_stays_out_of_audit_reports(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['journal', 'note', 'secrète']), 0)
        self.assertEqual(journal.notes()[0]['texte'], 'note secrète')
        self.assertEqual(list((self.home/'state').glob('*.json')), [])
        core.report(self.home/'rapport.json', 'json')
        self.assertNotIn('secrète', (self.home/'rapport.json').read_text())


if __name__ == '__main__':
    unittest.main()
