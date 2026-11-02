"""Adaptateur de projet : registre, préparation et missions explicitement exécutées."""
import argparse
import json
import math
import os
import re
import shutil
import sqlite3
import sys
from pathlib import Path
from . import __version__, core, platforms, security, environments

MIN_FREE_BYTES = 1024 ** 3
PROJECT = Path(__file__).resolve().parent.parent
DIAGNOSTICS = {
    'nmap': ['--version'], 'tshark': ['--version'], 'hashcat': ['--version'],
    'lynis': ['--version'], 'wifite': ['--help'], 'ollama': ['--version'],
    'codex': ['--version'], 'ssh': ['-V'],
}


def executable(name):
    found = shutil.which(name)
    if found:
        return found
    for directory in ('/usr/sbin', '/usr/local/sbin'):
        candidate = Path(directory)/name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    if name == 'codex':
        root = Path.home()/'.codex/packages/app-server-daemon/releases'
        for candidate in sorted(root.glob('*/bin/codex'), reverse=True):
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
    return None


def version_probe(argv):
    # SSH écrit sa version sur stderr ; les deux flux sont capturés et bornés.
    import subprocess
    try:
        process = subprocess.run(argv, capture_output=True, text=True,
                                 encoding='utf-8', errors='replace', timeout=15,
                                 stdin=subprocess.DEVNULL)
        output = (process.stdout + process.stderr)[:16000]
        return {'status': 'ok' if process.returncode == 0 else 'unavailable',
                'returncode': process.returncode, 'output': output}
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'status': 'unavailable', 'error': str(error)}


def registry(diagnostic=False, kali=False):
    if kali and not diagnostic:
        raise core.AuditError('--kali nécessite --diagnostic ; aucun conteneur lancé automatiquement.')
    entries = {}
    for name, args in DIAGNOSTICS.items():
        path = executable(name)
        entry = {'environment': 'host', 'path': path, 'installed': bool(path),
                 'status': 'found' if path else 'missing'}
        if diagnostic and path:
            if name == 'lynis' and path == '/usr/sbin/lynis' and any(
                    p.exists() and p.stat().st_uid not in (0, os.getuid()) for p in
                    (Path('/usr/share/lynis/include/consts'), Path('/usr/share/lynis/include/functions'))):
                entry['diagnostic'] = {'status': 'unavailable',
                    'error': 'Propriétaires visibles incompatibles avec le contrôle Lynis ; vérifier sur le terminal hôte. Aucun contrôle contourné.'}
            else:
                entry['diagnostic'] = version_probe([path, *args])
        entries[name] = entry
    entries['mon-secret-cookie'] = {
        'environment': 'current-python', 'installed': True, 'version': __version__,
        'python': sys.executable, 'project': str(PROJECT),
        'command': [sys.executable, '-B', '-m', 'mon_secret_cookie'],
    }
    detected = environments.discover(executable, version_probe, diagnostic=kali)
    for name, entry in detected['tools'].items():
        entries[name+'-kali'] = entry
    container = (detected.get('launcher') or {}).get('container', 'kali-lexos')
    reported = environments.reported(PROJECT, container).get('tools', {})
    for name in environments.TOOLS:
        if name+'-kali' not in entries:
            entries[name+'-kali'] = {'environment': container, 'status': 'unverified',
                                    'installed': None, 'path': None, 'version': None,
                                    'reported': reported.get(name), 'reason': detected.get('reason')}
    return {'tools': entries, 'kali': detected, 'storage': storage(),
            'ssh_server_detected': bool(executable('sshd') or Path('/usr/sbin/sshd').is_file())}


def dashboard(diagnostic=False):
    result = registry(diagnostic)
    targets = read_table('targets')
    missions = read_table('missions')
    result['dashboard'] = {'adapter_version': '3.2', 'package_version': __version__,
                           'authorizations': len(targets), 'missions': len(missions),
                           'last_mission': {k: missions[-1].get(k) for k in ('id', 'status', 'started')} if missions else None,
                           'integration': 'Mon Secret Cookie via le Python existant',
                           'deployed': False}
    return result


def storage(path='/'):
    usage = shutil.disk_usage(path)
    # Comme df : exclure les blocs réservés du dénominateur disponible à l'utilisateur.
    available_capacity = usage.used + usage.free
    percent = math.ceil(100 * usage.used / available_capacity) if available_capacity else 100
    return {'path': str(path), 'total_bytes': usage.total, 'used_bytes': usage.used,
            'free_bytes': usage.free, 'used_percent': percent,
            'reserved_or_unavailable_bytes': max(0, usage.total - usage.used - usage.free),
            'minimum_free_bytes': MIN_FREE_BYTES, 'scan_allowed': usage.free >= MIN_FREE_BYTES,
            'action': 'observation uniquement ; aucune suppression ni déplacement'}


def state_location():
    default = (Path(os.environ.get('LOCALAPPDATA', Path.home()/'AppData/Local'))/'mon-secret-cookie'
               if platforms.is_windows() else Path.home()/'.local/state/mon-secret-cookie')
    return Path(os.environ.get('MSC_STATE_DIR', default)).absolute()


def read_table(table):
    # Liste fermée : aucun identifiant SQL fourni par l'utilisateur.
    queries = {'targets': 'SELECT data FROM targets ORDER BY id',
               'missions': 'SELECT data FROM missions ORDER BY started'}
    query = queries[table]
    directory = state_location()
    path = directory/'security.sqlite3'
    if directory.is_symlink() or path.is_symlink():
        raise core.AuditError('Registre symbolique refusé.')
    if not path.exists():
        return []
    if not directory.is_dir() or not core.is_owned(directory) or not path.is_file() or not core.is_owned(path):
        raise core.AuditError('Registre privé de cet utilisateur requis.')
    conn = sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=10)
    try:
        return [json.loads(row[0]) for row in conn.execute(query)]
    finally:
        conn.close()


def prepare(ids):
    if not ids:
        raise core.AuditError('Sélection explicite --cible AUTH-… requise.')
    known = {target['id']: target for target in read_table('targets')}
    if set(ids) - known.keys():
        raise core.AuditError('ID absent du registre : ' + ', '.join(sorted(set(ids) - known.keys())))
    selected = [known[key] for key in sorted(set(ids))]
    for target in selected:
        security.validate(target)
    disk = storage()
    nmap = executable('nmap')
    blockers = []
    if not disk['scan_allowed']:
        blockers.append('Moins de 1 Gio disponible : opération active bloquée ; aucun nettoyage automatique.')
    if not nmap:
        blockers.append('Nmap absent : aucune réinstallation automatique.')
    return {'mode': 'preparation', 'ready': not blockers, 'blockers': blockers,
            'authorizations': selected, 'selected_tools': {'nmap': nmap}, 'storage': disk,
            'operations': [{'authorization': t['id'], 'scope': t['scope'], 'tests': t['tests'],
                            'expires': t['expires']} for t in selected],
            'coverage': 'Découverte approuvée ; TCP : 100 ports courants seulement si permis.',
            'intrusive_operations': False, 'network_executed': False}


def scan(ids, execute=False):
    plan = prepare(ids)
    if not execute:
        return plan
    if not plan['ready']:
        raise core.AuditError('Précontrôle refusé : ' + '; '.join(plan['blockers']))
    # Le moteur existant recharge et vérifie les autorisations pendant la mission.
    return security.scan_complete([t['id'] for t in plan['authorizations']])


def report(output=None, fmt='json', mission=None):
    missions = read_table('missions')
    if mission:
        missions = [item for item in missions if item['id'] == mission]
        if not missions:
            raise core.AuditError('Mission inconnue : ' + mission)
    result = {'missions': missions}
    if output:
        text = json.dumps(result, ensure_ascii=False, indent=2)
        if fmt == 'txt':
            text = 'FUSION — Rapport de missions\n\n' + text
        core.private_write(output, text + '\n')
        return {'rapport': str(output), 'missions': len(missions)}
    return result


def ssh_plan(destination, port=8765):
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.@-]{0,252}', destination):
        raise core.AuditError('Destination SSH : utilisateur@nom-ou-IP, sans options ni espaces.')
    if not 1024 <= port <= 65535:
        raise core.AuditError('Port entre 1024 et 65535 requis.')
    return {'executed': False, 'ssh': ['ssh', '-N', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'ExitOnForwardFailure=yes', '-o', 'PasswordAuthentication=no',
            '-o', 'IdentitiesOnly=yes', '-i', '~/.ssh/id_ed25519',
            '-L', f'127.0.0.1:{port}:127.0.0.1:{port}', destination],
            'requirements': ['Clé client et serveur SSH déjà configurés.',
                             'Empreinte serveur vérifiée et inscrite dans known_hosts.',
                             'API locale authentifiée ; token transféré par un canal sûr.']}


def parser():
    root = argparse.ArgumentParser(prog='prevost', description='Adaptateur local : préparation par défaut')
    sub = root.add_subparsers(dest='command', required=True)
    tools = sub.add_parser('outils')
    tools.add_argument('--diagnostic', action='store_true')
    tools.add_argument('--kali', action='store_true')
    panel = sub.add_parser('tableau')
    panel.add_argument('--diagnostic', action='store_true')
    for name in ('mission', 'scan'):
        item = sub.add_parser(name)
        item.add_argument('--cible', action='append', required=True)
        if name == 'scan':
            item.add_argument('--executer', action='store_true')
    item = sub.add_parser('rapport')
    item.add_argument('--output'); item.add_argument('--format', choices=['json', 'txt'], default='json')
    item.add_argument('--mission')
    sub.add_parser('stockage')
    item = sub.add_parser('connexion')
    item.add_argument('--host', required=True); item.add_argument('--port', type=int, default=8765)
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == 'outils':
            result = registry(args.diagnostic, args.kali)
        elif args.command == 'tableau':
            result = dashboard(args.diagnostic)
        elif args.command == 'mission':
            result = prepare(args.cible)
        elif args.command == 'scan':
            result = scan(args.cible, args.executer)
        elif args.command == 'rapport':
            result = report(args.output, args.format, args.mission)
        elif args.command == 'stockage':
            result = storage()
        else:
            result = ssh_plan(args.host, args.port)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (core.AuditError, OSError, ValueError, sqlite3.Error) as error:
        print('Erreur : ' + (core.disk_full_hint(error) or str(error)), file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print('Opération interrompue.', file=sys.stderr)
        return 130


if __name__ == '__main__':
    sys.exit(main())
