"""Planification et reprise au-dessus du moteur d'audit existant, sans shell IA."""
from contextlib import contextmanager
import json
import os
import time
import uuid
from . import core, security, ai_planner, notifications


@contextmanager
def lock():
    import fcntl
    path = core.state_dir()/'brain.lock'
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise core.AuditError('Une mission du cerveau est déjà en cours.') from error
        yield
    finally:
        os.close(fd)


def save(plan, event):
    evidence = {'plan_id': plan['id'], 'type': event, 'time': security.now(),
                'status': plan['status'], 'cycle': plan['cycle'],
                'tasks': [{'id': t['id'], 'status': t['status'], 'attempts': t['attempts'],
                           'error': t.get('error'), 'validated': t.get('result', {}).get('validated'),
                           'audit_id': t.get('result', {}).get('audit_id'),
                           'warnings': t.get('result', {}).get('warnings', [])} for t in plan['tasks']]}
    with security.database() as conn:
        conn.executescript('''CREATE TABLE IF NOT EXISTS brain_plans (id TEXT PRIMARY KEY, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS brain_events (id INTEGER PRIMARY KEY, plan TEXT, time TEXT, event TEXT);''')
        conn.execute('INSERT INTO brain_plans VALUES (?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data',
                     (plan['id'], json.dumps(plan)))
        conn.execute('INSERT INTO brain_events(plan,time,event) VALUES (?,?,?)',
                     (plan['id'], evidence['time'], json.dumps(evidence)))


def history(identifier):
    from .fusion import read_table
    plans(identifier)
    return {'plan_id': identifier, 'events': [e for e in read_table('plan_events') if e['plan_id'] == identifier]}


def plans(identifier=None):
    from .fusion import read_table
    values = read_table('plans')
    if identifier:
        found = next((p for p in values if p['id'] == identifier), None)
        if found is None:
            raise core.AuditError('Plan inconnu : '+identifier)
        return found
    return {'plans': values}


def validate_draft(draft, ids, project=None):
    if not isinstance(draft, dict) or set(draft) != {'tasks'} or not isinstance(draft['tasks'], list) or not 1 <= len(draft['tasks']) <= 16:
        raise core.AuditError('Plan JSON invalide.')
    tasks, seen = [], set()
    for item in draft['tasks']:
        if not isinstance(item, dict) or set(item) != {'id', 'tool', 'target_ids'}:
            raise core.AuditError('Champs de tâche non permis.')
        name, tool, targets = item['id'], item['tool'], item['target_ids']
        if not isinstance(name, str) or not name or len(name) > 64 or name in seen or tool not in ai_planner.TOOLS:
            raise core.AuditError('Identifiant ou outil de tâche invalide.')
        if not isinstance(targets, list) or any(not isinstance(t, str) for t in targets) or set(targets)-set(ids):
            raise core.AuditError('Cible de tâche non autorisée.')
        if (tool == 'inventory' and not targets) or (tool != 'inventory' and targets):
            raise core.AuditError('Périmètre de tâche invalide.')
        if tool == 'project_tests' and not project:
            raise core.AuditError('Les tests de projet exigent un projet explicitement sélectionné.')
        seen.add(name)
        tasks.append({**item, 'target_ids': sorted(set(targets)), 'status': 'pending', 'attempts': 0})
    # L'inventaire est systématique pour tous les IDs approuvés, même si l'IA l'omet.
    if ids and not any(t['tool'] == 'inventory' and set(t['target_ids']) == set(ids) for t in tasks):
        name = 'inventory-required'
        while name in seen:
            name += '-1'
        tasks.insert(0, {'id': name, 'tool': 'inventory', 'target_ids': sorted(set(ids)), 'status': 'pending', 'attempts': 0})
    return tasks


def create(objective, ids=None, backend='local', model=None, endpoint=ai_planner.ENDPOINTS[0], authorize_cloud=False, project=None, cookie_directory=None):
    from .fusion import prepare
    if not isinstance(objective, str) or not objective.strip() or len(objective) > 4000:
        raise core.AuditError('Objectif requis, 4000 caractères maximum.')
    ids = sorted(set(ids or []))
    if cookie_directory:
        from .cookie_inventory import selected_path
        cookie_directory = str(selected_path(cookie_directory))
    if ids:
        prepare(ids)
    if backend == 'codex':
        draft = ai_planner.codex_plan(objective, ids, authorize_cloud)
    elif backend == 'local':
        draft = ai_planner.local_plan(objective, ids, model, endpoint)
    else:
        raise core.AuditError('Backend inconnu.')
    tasks = validate_draft(draft, ids, project)
    # L'autorisation peut avoir changé pendant la génération du modèle.
    if ids:
        prepare(ids)
    plan = {'id': 'PLN-'+uuid.uuid4().hex, 'objective': objective.strip(), 'created': security.now(),
            'backend': backend, 'model': model, 'target_ids': ids, 'tasks': tasks, 'project': project,
            'local_cookie_directory': cookie_directory,
            'status': 'planned', 'cycle': 0, 'schedule': {'enabled': False, 'delay_seconds': 60, 'next_due': None}}
    save(plan, 'plan_created')
    return plan


def run_task(task, plan=None):
    from . import fusion, environments
    if task['tool'] == 'inventory':
        result = fusion.scan(task['target_ids'], True)
        if result.get('status') != 'completed' or not str(result.get('id', '')).startswith('RUN-'):
            raise core.AuditError('Audit non validé par le moteur existant.')
        return {'validated': True, 'audit_id': result['id'],
                'new_assets': sum(len(i['changes']['new']) for i in result['inventories']),
                'pending': len(result['pending'])}
    if task['tool'] == 'diagnostic_host':
        result = fusion.registry(True)
        warnings = [name for name, tool in result['tools'].items()
                    if tool.get('diagnostic', {}).get('status') == 'unavailable' or tool.get('status') in ('missing', 'unverified')]
        return {'validated': True, 'warnings': warnings, 'result': result}
    if task['tool'] == 'diagnostic_kali':
        result = environments.discover(fusion.executable, fusion.version_probe, diagnostic=True)
        if result['status'] != 'available':
            raise core.AuditError('Kali indisponible : '+result.get('reason', ''))
        failed = [n for n, entry in result['tools'].items()
                  if not entry.get('installed') or entry.get('diagnostic', {}).get('status') != 'ok']
        return {'validated': True, 'warnings': failed, 'result': result}
    if task['tool'] == 'report':
        return {'validated': True, 'report': fusion.report()}
    if task['tool'] == 'project_tests' and plan and plan.get('project'):
        from .programmer import project_tests_locked
        return project_tests_locked(plan['project'])
    raise core.AuditError('Outil non permis.')


def run_locked(identifier):
    from .fusion import prepare
    plan = plans(identifier)
    # Revalider le contenu persistant, pas seulement la réponse initiale du modèle.
    draft = {'tasks': [{k: t[k] for k in ('id', 'tool', 'target_ids')} for t in plan['tasks']]}
    validated = validate_draft(draft, plan['target_ids'], plan.get('project'))
    if len(validated) != len(plan['tasks']):
        raise core.AuditError('Inventaire obligatoire absent du plan persistant.')
    def check_authorization():
        if plan['target_ids']:
            try:
                prepare(plan['target_ids'])
            except core.AuditError:
                plan['status'] = 'blocked'
                save(plan, 'authorization_blocked')
                notifications.required('blocked')
                raise
    check_authorization()
    for task in plan['tasks']:
        if task['status'] == 'completed':
            continue
        check_authorization()
        if task['status'] == 'running':
            save(plan, 'interrupted_task_recovered:'+task['id'])
        task.update(status='running', attempts=task['attempts']+1)
        plan['status'] = 'running'
        save(plan, 'task_started:'+task['id'])
        try:
            from .programmer import execution_budget
            with execution_budget():
                result = run_task(task, plan)
            if not isinstance(result, dict) or result.get('validated') is not True:
                raise core.AuditError('Résultat sans preuve de validation.')
            task.update(status='completed', result=result)
            task.pop('error', None)
            save(plan, 'task_validated:'+task['id'])
        except BaseException as error:
            task.update(status='interrupted' if isinstance(error, KeyboardInterrupt) else 'failed', error=str(error))
            plan['status'] = task['status']
            save(plan, 'task_failed:'+task['id'])
            if not isinstance(error, KeyboardInterrupt):
                notifications.required('blocked')
            raise
    if plan.get('local_cookie_directory'):
        from .cookie_inventory import collect
        plan['local_cookie_metadata'] = collect(plan['local_cookie_directory'])
        save(plan, 'local_cookie_metadata_collected')
    plan.update(status='completed', finished=security.now())
    save(plan, 'plan_completed')
    return plan


def resume(identifier, execute=False):
    plan = plans(identifier)
    if not execute:
        notifications.required('approval')
        return {'mode': 'preview', 'plan': plan, 'network_executed': False}
    with lock():
        return run_locked(identifier)


def watch(identifier, execute=False, cycles=None, clock=time.time, sleep=time.sleep):
    plan = plans(identifier)
    if not plan['target_ids']:
        raise core.AuditError('Une boucle d’inventaire exige des cibles explicitement autorisées.')
    if not execute:
        notifications.required('approval')
        return {'mode': 'preview', 'plan_id': identifier, 'delay_after_completion_seconds': 60,
                'next_due': plan['schedule']['next_due'], 'enabled': False, 'network_executed': False}
    if cycles is not None and (not isinstance(cycles, int) or cycles < 1):
        raise core.AuditError('Nombre de cycles positif requis.')
    from .fusion import prepare
    with lock():
        if plan['status'] == 'completed' and plan['schedule']['next_due'] is None:
            from datetime import datetime
            plan['schedule']['next_due'] = datetime.fromisoformat(plan['finished']).timestamp()+60
        plan['schedule']['enabled'] = True
        save(plan, 'watch_started')
        count = 0
        def check_authorization():
            try:
                prepare(plan['target_ids'])
            except core.AuditError:
                plan['status'] = 'blocked'
                save(plan, 'watch_authorization_blocked')
                notifications.required('blocked')
                raise
        try:
            while cycles is None or count < cycles:
                check_authorization()
                due = plan['schedule']['next_due']
                while due is not None and clock() < due:
                    sleep(max(0, min(1, due-clock())))
                check_authorization()
                if plan['status'] == 'completed':
                    for task in plan['tasks']:
                        task.update(status='pending')
                    plan['status'] = 'planned'
                    save(plan, 'new_cycle_prepared')
                plan = run_locked(identifier)
                plan['cycle'] += 1
                plan['schedule'].update(enabled=True, next_due=clock()+60)
                save(plan, 'next_inventory_scheduled')
                count += 1
                if cycles is not None and count >= cycles:
                    break
                for task in plan['tasks']:
                    task.update(status='pending')
                plan['status'] = 'planned'
                save(plan, 'new_cycle_prepared')
        finally:
            plan = plans(identifier)
            plan['schedule']['enabled'] = False
            save(plan, 'watch_stopped')
    return plan
