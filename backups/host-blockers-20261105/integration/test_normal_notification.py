#!/usr/bin/env python3
"""Événement fictif via le CLI normal, sans changer la configuration ni le LAN."""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mon_secret_cookie import cli, watch


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--notifications', action='store_true', help='Tester aussi le chemin normal activé explicitement')
    args=parser.parse_args()
    row={'dst':'192.0.2.124','lladdr':'02:00:00:00:00:ac','state':['REACHABLE']}
    results=[]
    real_notify=watch.notify
    def notification(device):
        result=real_notify(device)
        results.append(result)
        return result
    with tempfile.TemporaryDirectory(prefix='lexos-normal-alert-') as temporary:
        command=['surveillance','--once', *(['--notifications'] if args.notifications else [])]
        with patch.dict(os.environ, MSC_STATE_DIR=temporary), \
             patch.object(watch.network,'devices',return_value={'neighbors':[row]}), \
             patch.object(watch,'notify',side_effect=notification) as notified, \
             contextlib.redirect_stdout(io.StringIO()):
            assert cli.main(command)==0
            assert notified.call_count == int(args.notifications)
            assert cli.main(command)==0
            assert notified.call_count == int(args.notifications)
        directory=Path(temporary)/'surveillance'
        assert len(json.loads((directory/'inventaire.json').read_text()))==1
        events=[json.loads(line) for line in (directory/'cookie.txt').read_text().splitlines()]
        assert [event['evenement'] for event in events]==['nouvel_appareil','observation']
    print('Chaîne normale CLI → détection simulée → inventaire → journal : RÉUSSIE ; aucun doublon.')
    print('Données fictives : 192.0.2.124 / 02:00:00:00:00:ac ; aucun scan, stockage temporaire supprimé.')
    print('Réglages de production inchangés ; notifications :', 'activées explicitement' if args.notifications else 'désactivées par défaut')
    print('Service :', 'envoi accepté' if 'bureau' in results else 'non validé' if results else 'aucun envoi attendu')
    print('Affichage alerte normale : NON CONFIRMÉ ; confirmation visuelle utilisateur nécessaire.')
    return int(args.notifications and 'bureau' not in results)


if __name__=='__main__':
    raise SystemExit(main())
