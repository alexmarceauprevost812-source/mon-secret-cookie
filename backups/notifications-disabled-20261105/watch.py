"""Surveillance passive : métadonnées du cache voisin, aucune sonde réseau."""
import ipaddress
import json
import math
import os
import re
import shutil
import stat
import subprocess
import time
import uuid
from datetime import datetime, timezone
from . import core, network


def directory():
    path = core.state_dir() / 'surveillance'
    path.mkdir(mode=0o700, exist_ok=True)
    if path.is_symlink() or not core.is_owned(path):
        raise core.AuditError('Dossier de surveillance non sûr.')
    path.chmod(0o700)
    return path


def private_open(path):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
                 | getattr(os, 'O_NONBLOCK', 0), 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not core.is_owned(path):
        os.close(fd)
        raise core.AuditError('Fichier de surveillance non sûr.')
    os.fchmod(fd, 0o600)
    return os.fdopen(fd, 'r+', encoding='utf-8')


def notify(device):
    message = f"Nouvel appareil : IP {device['ip']} — MAC {device['mac'] or 'indisponible'}"
    print('\aALERTE LOCALE — ' + message, flush=True)
    tool = shutil.which('notify-send')
    if tool:
        try:
            result = subprocess.run([tool, '--', 'TI-LEXOS KALI', message],
                                    capture_output=True, timeout=5, check=False)
            return 'bureau' if result.returncode == 0 else 'terminal (notification bureau indisponible)'
        except (OSError, subprocess.TimeoutExpired):
            pass
    return 'terminal'


def observe():
    rows = network.devices()['neighbors']
    observations = {}
    for row in rows:
        try:
            ip = ipaddress.ip_address(row.get('dst') or row.get('IPAddress') or '')
        except ValueError:
            continue
        if ip.is_multicast or ip.is_unspecified or ip.is_loopback:
            continue
        mac = (row.get('lladdr') or row.get('LinkLayerAddress') or '').lower().replace('-', ':')
        if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac) or mac == '00:00:00:00:00:00':
            mac = None
        # Une entrée incomplète sans MAC n'est pas une preuve de présence.
        state = row.get('state', row.get('State', []))
        if isinstance(state, str):
            state = [state]
        if any(str(s).upper() in ('FAILED', 'INCOMPLETE', 'UNREACHABLE') for s in state):
            continue
        observations[network.asset_id(mac, str(ip))] = {'ip': str(ip), 'mac': mac}
    return observations


def run(interval=30, once=False, inventory=False, notifications=True):
    if not math.isfinite(interval) or interval < 5:
        raise core.AuditError('Intervalle minimum : 5 secondes, valeur finie.')
    path = directory()
    # Verrou exclusif conservé pendant la surveillance : pas de doublons concurrents.
    import fcntl
    with private_open(path/'.lock') as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise core.AuditError('Une surveillance est déjà en cours.') from error
        with private_open(path/'inventaire.json') as store:
            text = store.read()
        known = json.loads(text) if text else {}
        if inventory:
            print(json.dumps({'appareils_connus': known, 'journal': str(path/'cookie.txt')}, ensure_ascii=False, indent=2))
            return
        while True:
            observations = observe()
            now = datetime.now(timezone.utc).isoformat()
            events = []
            for identifier, data in observations.items():
                previous = known.get(identifier)
                data = dict(data, premiere_detection=previous['premiere_detection'] if previous else now,
                            derniere_detection=now)
                events.append(dict(evenement='observation' if previous else 'nouvel_appareil',
                                   date=now, id=identifier, **data))
            # Le journal précède la mise à jour de l'inventaire ; une panne est bloquante.
            with private_open(path/'cookie.txt') as log:
                log.seek(0, 2)
                for event in events:
                    log.write(json.dumps(event, ensure_ascii=False)+'\n')
                log.flush()
                os.fsync(log.fileno())
            for event in events:
                identifier = event['id']
                if notifications and identifier not in known:
                    notify(event)
                known[identifier] = {key: event[key] for key in
                                     ('ip', 'mac', 'premiere_detection', 'derniere_detection')}
            temporary = path/('.inventory-'+uuid.uuid4().hex)
            try:
                core.private_write(temporary, json.dumps(known, ensure_ascii=False, indent=2)+'\n')
                with temporary.open('r') as saved:
                    os.fsync(saved.fileno())
                os.replace(temporary, path/'inventaire.json')
            finally:
                temporary.unlink(missing_ok=True)
            print(json.dumps({'appareils_connus': known, 'observes': len(observations),
                              'journal': str(path/'cookie.txt')}, ensure_ascii=False, indent=2), flush=True)
            if once:
                return
            time.sleep(interval)
