#!/usr/bin/env python3
"""Test bureau explicite, appareil fictif et stockage temporaire, sans réseau."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from mon_secret_cookie import watch


def main():
    real_run = subprocess.run
    print('Session :', json.dumps({key: os.environ.get(key) for key in
          ('DISPLAY', 'WAYLAND_DISPLAY', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS')}, ensure_ascii=False))
    if shutil.which('gdbus'):
        for destination, path, method, extra in (
            ('org.freedesktop.DBus', '/org/freedesktop/DBus',
             'org.freedesktop.DBus.NameHasOwner', ['org.freedesktop.Notifications']),
            ('org.freedesktop.Notifications', '/org/freedesktop/Notifications',
             'org.freedesktop.Notifications.GetServerInformation', []),
        ):
            try:
                result = real_run(['gdbus', 'call', '--session', '--dest', destination,
                                   '--object-path', path, '--method', method, *extra],
                                  capture_output=True, text=True, timeout=5)
                print(method+':', result.returncode, result.stdout.strip(), result.stderr.strip())
            except (OSError, subprocess.TimeoutExpired) as error:
                print(method+':', str(error))
    row = {'dst': '192.0.2.123', 'lladdr': '02:00:00:00:00:ab', 'state': ['REACHABLE']}
    deliveries = []

    def marked_send(argv, **kwargs):
        # Conserve l’envoi réel de watch.notify, mais marque clairement le test.
        assert Path(argv[0]).name == 'notify-send', argv
        args = [argv[0], '--print-id', '--', 'TEST — nouvel appareil',
                'SIMULATION LexOS — IP 192.0.2.123 — MAC 02:00:00:00:00:ab (données fictives)']
        try:
            result = real_run(args, **kwargs)
            deliveries.append({'code': result.returncode,
                               'id': result.stdout.decode(errors='replace').strip(),
                               'erreur': result.stderr.decode(errors='replace').strip()})
            return result
        except (OSError, subprocess.TimeoutExpired) as error:
            deliveries.append({'erreur': str(error)})
            raise

    with tempfile.TemporaryDirectory(prefix='lexos-test-notification-') as temporary:
        with patch.dict(os.environ, MSC_STATE_DIR=temporary), \
             patch.object(watch.network, 'devices', return_value={'neighbors': [row]}) as detection, \
             patch.object(watch.subprocess, 'run', side_effect=marked_send), \
             patch.object(watch, 'notify', wraps=watch.notify) as notification, \
             contextlib.redirect_stdout(io.StringIO()):
            watch.run(once=True, notifications=True)
            notification.assert_called_once()
            path = Path(temporary)/'surveillance'
            inventory = json.loads((path/'inventaire.json').read_text())
            assert len(inventory) == 1
            device = next(iter(inventory.values()))
            assert device['ip'] == row['dst'] and device['mac'] == row['lladdr']
            assert device['premiere_detection'] and device['derniere_detection']
            events = [json.loads(line) for line in (path/'cookie.txt').read_text().splitlines()]
            assert len(events) == 1 and events[0]['evenement'] == 'nouvel_appareil'
            assert (path/'cookie.txt').stat().st_mode & 0o777 == 0o600
            # Une seconde détection ne doit pas produire une seconde notification.
            watch.run(once=True, notifications=True)
            notification.assert_called_once()
            assert detection.call_count == 2
            events = [json.loads(line) for line in (path/'cookie.txt').read_text().splitlines()]
            assert [event['evenement'] for event in events] == ['nouvel_appareil', 'observation']
    print('Chaîne simulée détection → inventaire → journal → appel notification : RÉUSSIE ; aucun doublon.')
    print('Aucun scan ; stockage temporaire supprimé ; inventaire et configuration réels inchangés.')
    sent = bool(deliveries) and deliveries[0].get('code') == 0
    print('Envoi au service :', 'ACCEPTÉ' if sent else 'NON VALIDÉ', json.dumps(deliveries, ensure_ascii=False))
    print('Affichage visuel : NON CONFIRMÉ — confirmation de l’utilisateur nécessaire.')
    return 0 if sent else 1


if __name__ == '__main__':
    raise SystemExit(main())
