#!/usr/bin/env python3
"""Chemin normal du programme, voisin fictif et stockage temporaire uniquement."""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from mon_secret_cookie import cli, fusion, watch


def require(condition,message):
    if not condition:
        raise RuntimeError(message)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--programme',choices=['prevost','mon-secret-cookie'],default='prevost')
    flags=parser.add_mutually_exclusive_group()
    flags.add_argument('--notifications',action='store_true',help='Option normale d’activation du CLI historique ; Prévost les active déjà')
    flags.add_argument('--no-notifications',action='store_true')
    args=parser.parse_args(argv)
    enabled=not args.no_notifications if args.programme=='prevost' else args.notifications
    command=['surveillance','--once']
    if args.no_notifications:
        command.append('--no-notifications')
    elif args.notifications and args.programme=='mon-secret-cookie':
        command.append('--notifications')
    entrypoint=fusion.main if args.programme=='prevost' else cli.main
    row={'dst':'192.0.2.124','lladdr':'02:00:00:00:00:ac','state':['REACHABLE']}
    print('Test normal :',args.programme,' '.join(command),flush=True)
    print('Événement fictif : 192.0.2.124 / 02:00:00:00:00:ac. Titre normal « TI-LEXOS KALI », aucune urgence critique ajoutée.',flush=True)
    deliveries=[]
    real_run=watch.subprocess.run

    def observe_send(argv,**kwargs):
        # Observateur seulement : arguments, délai et environnement INCHANGÉS.
        result=real_run(argv,**kwargs)
        if Path(argv[0]).name=='notify-send':
            error=result.stderr or ''
            if isinstance(error,bytes):
                error=error.decode(errors='replace')
            deliveries.append({'code':result.returncode,'erreur':error.strip()[:500]})
        return result

    with tempfile.TemporaryDirectory(prefix='lexos-normal-alert-') as temporary:
        with patch.dict(os.environ,MSC_STATE_DIR=temporary), \
             patch.object(watch.network,'devices',return_value={'neighbors':[row]}), \
             patch.object(watch.subprocess,'run',side_effect=observe_send), \
             patch.object(watch,'notify',wraps=watch.notify) as notified, \
             contextlib.redirect_stdout(io.StringIO()):
            require(entrypoint(command)==0,'Échec de la première détection simulée')
            require(notified.call_count==int(enabled),'Notification incompatible avec le réglage normal')
            require(entrypoint(command)==0,'Échec de la seconde détection simulée')
            require(notified.call_count==int(enabled),'Alerte répétée pour un appareil déjà connu')
        directory=Path(temporary)/'surveillance'
        require(len(json.loads((directory/'inventaire.json').read_text()))==1,'Inventaire incohérent')
        events=[json.loads(line) for line in (directory/'cookie.txt').read_text().splitlines()]
        require([event['evenement'] for event in events]==['nouvel_appareil','observation'],'Journal incohérent')
    accepted=len(deliveries)==1 and deliveries[0]['code']==0
    print('Chaîne normale CLI → détection simulée → inventaire → journal → notification : RÉUSSIE ; aucun doublon.')
    print('Aucun scan ; stockage temporaire supprimé ; inventaire et configuration de production non utilisés.')
    print('Notifications normales :','activées' if enabled else 'désactivées')
    print('Service :','envoi accepté' if accepted else 'non validé' if enabled else 'aucun envoi attendu',json.dumps(deliveries,ensure_ascii=False))
    print('Affichage alerte normale : NON CONFIRMÉ — confirmation visuelle utilisateur nécessaire.')
    return int(enabled and not accepted)


if __name__=='__main__':
    raise SystemExit(main())
