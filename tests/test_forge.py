import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from mon_secret_cookie import core, forge


class FakeServer:
    replies = []
    def __init__(self, model): self.model = model; self.stopped = False
    def wait(self): pass
    def chat(self, messages): return self.replies.pop(0)
    def stop(self): self.stopped = True


class ForgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        (self.home/'modeles').mkdir()
        for name in ('soldal-q4.gguf', 'coder3b.gguf'):
            (self.home/'modeles'/name).write_bytes(b'0')
        env = patch.dict(os.environ, {'HOME': str(self.home), 'MSC_STATE_DIR': str(self.home/'state')})
        env.start(); self.addCleanup(env.stop)
        os.environ.pop('PREFIX', None); os.environ.pop('LEX_MODELES', None)

    def answers(self, *values):
        values = list(values)
        return lambda prompt='': values.pop(0)

    def test_extract_and_check(self):
        self.assertEqual(forge.extract('Voici :\n```python\nprint(1)\n```\nfin'), 'print(1)\n')
        self.assertIsNone(forge.check('print(1)\n', 'python'))
        self.assertIn('ligne', forge.check('def f(:\n', 'python'))
        self.assertIsNotNone(forge.check('if then\n', 'bash'))

    def test_coder_model_is_default_and_name_filter(self):
        self.assertTrue(forge.pick_model(ask=self.answers('')).endswith('coder3b.gguf'))
        self.assertTrue(forge.pick_model('soldal').endswith('soldal-q4.gguf'))
        with self.assertRaises(core.AuditError):
            forge.pick_model('absent')

    def test_modify_then_install_never_runs_code(self):
        FakeServer.replies = ['```python\ndef f(:\n```', '```python\n#!/bin/bash\nprint("salut")\n```']
        with patch('subprocess.run') as run:
            result = forge.run('outil qui dit salut', ask=self.answers('', 'm', 'corrige', 'i', 'Salut!'),
                               server_class=FakeServer)
            run.assert_not_called()
        self.assertEqual(result['outil'], 'salut'); self.assertTrue(result['installe'])
        installed = self.home/'.local/bin/salut'
        self.assertTrue(os.access(installed, os.X_OK))
        self.assertNotIn('/bin/bash', installed.read_text())

    def test_quit_installs_nothing(self):
        FakeServer.replies = ['```python\nprint(1)\n```']
        result = forge.run('test', ask=self.answers('', 'q'), server_class=FakeServer)
        self.assertFalse(result['installe'])
        self.assertFalse((self.home/'.local/bin').exists())


if __name__ == '__main__':
    unittest.main()
