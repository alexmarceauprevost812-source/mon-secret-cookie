import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mon_secret_cookie import ai_planner, cookie_organizer, core

ACTIFS = ("# Netscape HTTP Cookie File\n"
          "example.com\tFALSE\t/\tTRUE\t9999999999\tsid\tVALEUR\n")
EXPIRES = ("# Netscape HTTP Cookie File\n"
           "vieux.com\tFALSE\t/\tFALSE\t100\told\tVALEUR\n")
SESSION = ("# Netscape HTTP Cookie File\n"
           "site.org\tFALSE\t/\tFALSE\t0\ttmp\tVALEUR\n")


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')


class OrganizerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        write(self.base / 'a' / 'cookies.txt', ACTIFS)
        write(self.base / 'b' / 'cookies.txt', EXPIRES)
        write(self.base / 'c' / 'cookies.txt', SESSION)

    def test_apercu_ne_deplace_rien(self):
        result = cookie_organizer.organize(str(self.base), execute=False)
        self.assertEqual(result['mode'], 'aperçu')
        self.assertEqual(result['fichiers_trouves'], 3)
        self.assertEqual(result['deplaces'], [])
        # Les fichiers d'origine existent encore.
        self.assertTrue((self.base / 'a' / 'cookies.txt').is_file())

    def test_regle_locale_classe_correctement(self):
        cats = {Path(p['source']).parent.name: p['categorie']
                for p in cookie_organizer.organize(str(self.base))['plan']}
        self.assertEqual(cats['a'], 'actifs')
        self.assertEqual(cats['b'], 'expires')
        self.assertEqual(cats['c'], 'session')

    def test_execute_deplace_sous_le_dossier(self):
        result = cookie_organizer.organize(str(self.base), execute=True)
        self.assertEqual(len(result['deplaces']), 3)
        self.assertEqual(result['ignores'], [])
        root = self.base / cookie_organizer.BASE_SUBDIR
        self.assertTrue(any((root / 'actifs').glob('*-cookies.txt')))
        self.assertTrue(any((root / 'expires').glob('*-cookies.txt')))
        self.assertTrue(any((root / 'session').glob('*-cookies.txt')))
        # Tout reste dans le dossier choisi.
        for moved in result['deplaces']:
            self.assertTrue(Path(moved['destination']).resolve().is_relative_to(self.base.resolve()))

    def test_relance_ne_retouche_pas_le_rangement(self):
        cookie_organizer.organize(str(self.base), execute=True)
        again = cookie_organizer.organize(str(self.base), execute=True)
        self.assertEqual(again['deplaces'], [])

    def test_dossier_autre_utilisateur_refuse(self):
        with patch.object(core, 'is_owned', return_value=False):
            with self.assertRaises(core.AuditError):
                cookie_organizer.organize(str(self.base))

    def test_sous_dossier_rangement_pirate_refuse(self):
        # Un « ranger-cookies » qui est un lien symbolique est refusé à l'exécution.
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        ailleurs = Path(outside.name)
        os.symlink(ailleurs, self.base / cookie_organizer.BASE_SUBDIR)
        result = cookie_organizer.organize(str(self.base), execute=True)
        self.assertEqual(result['deplaces'], [])
        self.assertTrue(result['ignores'])
        # Rien n'a fui en dehors du dossier choisi.
        self.assertEqual(list(ailleurs.iterdir()), [])

    def test_ia_indisponible_repli_sur_regle(self):
        servers = [{'endpoint': ai_planner.ENDPOINTS[0], 'status': 'unavailable', 'models': []}]
        with patch.object(ai_planner, 'local_models', return_value=servers):
            result = cookie_organizer.organize(str(self.base), use_ai=True, model='absent:1b')
        self.assertFalse(result['ia_utilisee'])
        self.assertIsNotNone(result['ia_note'])
        self.assertEqual(result['plan'][0]['par'], 'règle')

    def test_ia_disponible_utilise_le_modele(self):
        servers = [{'endpoint': ai_planner.ENDPOINTS[0], 'status': 'ok', 'models': ['bon:8b']}]
        with patch.object(ai_planner, 'local_models', return_value=servers), \
             patch.object(cookie_organizer, '_ai_category', return_value='vides'):
            result = cookie_organizer.organize(str(self.base), use_ai=True, model='bon:8b')
        self.assertTrue(result['ia_utilisee'])
        self.assertTrue(all(p['par'] == 'ia' for p in result['plan']))

    def test_ia_hors_liste_rejetee(self):
        bad = {'message': {'content': '{"categorie": "rm -rf"}'}}
        with patch.object(ai_planner, 'local_request', return_value=bad):
            with self.assertRaises(core.AuditError):
                cookie_organizer._ai_category({'total': 1}, 'bon:8b', ai_planner.ENDPOINTS[0])


if __name__ == '__main__':
    unittest.main()
