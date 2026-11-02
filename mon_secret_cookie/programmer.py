"""Réutiliser les tests isolés AUTO V5, avec quota persistant par processus lancé."""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from contextlib import contextmanager
from . import core, security, notifications

LIMIT = 250


def status():
    from .fusion import read_table
    records = read_table('budget')
    data = records[0] if records else {'used': 0, 'generation': 1, 'notified': False}
    return {**data, 'limit': LIMIT, 'remaining': max(0, LIMIT-data['used']),
            'validation_required': data['used'] >= LIMIT,
            'scope': 'Commandes directement lancées par l’orchestrateur et AUTO V5 ; droits utilisateur.'}


def write_budget(conn, data, event):
    evidence = {'time': security.now(), 'event': event, 'ordinal': data['used'], 'generation': data['generation']}
    conn.execute('INSERT INTO programmer_budget VALUES (?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data',
                 ('programmer', json.dumps(data)))
    conn.execute('INSERT INTO programmer_events(time,event,ordinal) VALUES (?,?,?)',
                 (evidence['time'], json.dumps(evidence), data['used']))


def report():
    from .fusion import read_table
    return {'budget': status(), 'events': read_table('programmer_events')[-250:]}


def tables(conn):
    conn.executescript('''CREATE TABLE IF NOT EXISTS programmer_budget(id TEXT PRIMARY KEY,data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS programmer_events(id INTEGER PRIMARY KEY,time TEXT,event TEXT,ordinal INTEGER);''')


def reserve(program):
    blocked, notify = False, False
    with security.database() as conn:
        tables(conn)
        conn.execute('BEGIN IMMEDIATE')
        row = conn.execute('SELECT data FROM programmer_budget WHERE id=?', ('programmer',)).fetchone()
        data = json.loads(row['data']) if row else {'used': 0, 'generation': 1, 'notified': False}
        if data['used'] >= LIMIT:
            blocked = True
            notify = not data.get('notified')
            data['notified'] = True
            write_budget(conn, data, 'validation_required')
        else:
            data['used'] += 1
            write_budget(conn, data, 'process_reserved:'+Path(str(program)).name)
    if notify:
        notifications.required('renewal')
    if blocked:
        raise core.AuditError('Lot de 250 épuisé. Consulter programmeur rapport, puis programmeur renouveler dans le terminal.')
    return data['used']


class BudgetedSubprocess:
    """Proxy du module AUTO V5 seulement ; aucun monkeypatch global de subprocess."""
    def run(self, argv, *args, **kwargs):
        reserve(argv[0])
        return subprocess.run(argv, *args, **kwargs)

    def Popen(self, argv, *args, **kwargs):
        reserve(argv[0])
        return subprocess.Popen(argv, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(subprocess, name)


@contextmanager
def execution_budget():
    from . import fusion, network
    saved = (core.run, network.run, fusion.version_probe)
    def wrap(function):
        def checked(argv, *args, **kwargs):
            reserve(argv[0])
            return function(argv, *args, **kwargs)
        return checked
    core.run, network.run, fusion.version_probe = [wrap(f) for f in saved]
    try:
        yield
    finally:
        core.run, network.run, fusion.version_probe = saved


def project_tests(project, execute=False):
    if not execute:
        notifications.required('approval')
        return {'mode': 'preview', 'project': project, 'executor': 'AUTO V5 auto_tests', 'budget': status()}
    if os.geteuid() == 0:
        raise core.AuditError('Les contrôles de projet doivent être exécutés comme utilisateur normal.')
    from .brain import lock
    with lock():
        return project_tests_locked(project)


def project_tests_locked(project):
    source = Path.home()/'LexOS-Projets/prevost-auto-v5/prevost-ia'
    if not source.is_file():
        raise core.AuditError('AUTO V5 existant introuvable ; aucun remplaçant installé.')
    loader = importlib.machinery.SourceFileLoader('fusion_existing_v5', str(source))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    module.subprocess = BudgetedSubprocess()
    # auto_project et auto_tests conservent les restrictions et la sonde bwrap existantes.
    selected = module.auto_project(project)
    module.auto_tests(selected)
    report = {'validated': True, 'project': str(selected), 'executor': 'AUTO V5', 'budget': status()}
    if report['budget']['validation_required']:
        notifications.required('renewal')
    return report


def renew():
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise core.AuditError('Renouvellement réservé au terminal interactif ; aucun mot de passe accepté par l’IA.')
    from .brain import lock
    with lock():
        before = status()
        print(json.dumps({'report_before_validation': report()}, ensure_ascii=False, indent=2))
        sudo = Path('/usr/bin/sudo')
        if not sudo.is_file():
            raise core.AuditError('sudo absent ; aucune modification de sudoers.')
        # Le vrai terminal est hérité : ni -S, ni capture, ni lecture du mot de passe en Python.
        result = subprocess.run([str(sudo), '-k', '-v'])
        if result.returncode:
            raise core.AuditError('Validation sudo refusée ; compteur conservé.')
        data = {'used': 0, 'generation': before['generation']+1, 'notified': False}
        with security.database() as conn:
            tables(conn)
            write_budget(conn, data, 'operator_sudo_validation')
        return status()
