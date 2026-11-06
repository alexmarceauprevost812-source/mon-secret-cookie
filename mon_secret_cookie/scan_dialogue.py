"""Dialogue Nmap déterministe derrière /kali ; aucune commande libre de l'IA."""
import ipaddress
import json
import re
import subprocess
import unicodedata
import uuid
from pathlib import Path
from . import core, fusion, kali_tools, network, security

QUESTION = 'Quelle IP ou quel réseau veux-tu scanner?'
PROFILES = {'complet': ['-p', '1-65535'], 'rapide': ['--top-ports', '100']}


def normalized(text):
    return ''.join(c for c in unicodedata.normalize('NFD', text.casefold()) if not unicodedata.combining(c))


def is_scan_request(text):
    value = normalized(text)
    if re.search(r'\b(comment|explique|aide|annule|annuler)\b|\bne\b.*\bpas\b', value):
        return False
    return bool(re.search(r'\bnmap\b', value) and re.search(r'\b(fais|fait|faire|lance|lancer|execute|executer|scan|scanner|complet|rapide)\b', value))


def extract_target(text):
    # Seulement des IP/CIDR littéraux, jamais résolution DNS ou argument shell.
    for token in text.split():
        token = token.strip(' ,;()[]!?"\'')
        try:
            ipaddress.ip_network(token, strict=True)
        except ValueError:
            if re.fullmatch(r'[0-9]+(?:\.[0-9]+){3}(?:/[0-9]+)?', token):
                return token  # Ne jamais remplacer une cible invalide par l’ancienne.
            continue
        return token
    explicit = re.search(r'\b(?:sur|cible)\s+(\S+)', text, re.IGNORECASE)
    return explicit.group(1).strip(' ,;!?') if explicit else None


def permits(target, scope, profile):
    try:
        security.validate(target)
        net = security.scope_network(scope)
        approved = security.scope_network(target['scope'])
        if net.version != approved.version or not net.subnet_of(approved):
            return False
        if not {'inventory', 'tcp'} <= set(target['tests']):
            return False
        limits = target.get('limits', {})
        # Ne pas ignorer une restriction inconnue, ni fusionner plusieurs droits.
        if not isinstance(limits, dict) or set(limits) - {'tcp_ports', 'privileged'}:
            return False
        if limits.get('privileged', False):
            return False
        ports = limits.get('tcp_ports', '1-65535')
        return ports == '1-65535' or (ports == 'top100' and profile == 'rapide')
    except (core.AuditError, KeyError, ValueError, TypeError):
        return False


def authorization(scope, profile):
    matches = [t for t in fusion.read_table('targets') if permits(t, scope, profile)]
    matches.sort(key=lambda t: (-security.scope_network(t['scope']).prefixlen, t['id']))
    return matches[0] if matches else None


def authorize(scope, profile):
    # Nouvelle autorisation explicite, sans altérer une ancienne entrée/limite.
    phrase = 'AUTORISER '+scope
    answer = input(f'Ajouter {scope} au périmètre autorisé pour TCP {profile}? Taper {phrase} (Entrée : annuler) : ')
    if answer != phrase:
        return None
    owner = input('Responsable : ').strip()
    proof = input('Preuve ou motif de l’autorisation : ').strip()
    expires = input('Expiration ISO 8601 avec fuseau : ').strip()
    target = security.add_target('Nmap '+scope, owner, scope, ['inventory', 'tcp'], expires, proof,
                                 limits={'tcp_ports': '1-65535' if profile == 'complet' else 'top100', 'privileged': False})
    return target


def current_authorization(target, scope, profile):
    current = next((t for t in fusion.read_table('targets') if t['id'] == target['id']), None)
    if not current or not permits(current, scope, profile):
        raise core.AuditError('L’autorisation a changé. Veux-tu vérifier le périmètre?')
    return current


def argv(path, scope, profile=None):
    args = [path, '-n', '--unprivileged']
    args += ['-sT', '-Pn', *PROFILES[profile]] if profile else ['-sn', '-PS80,443']
    args += ['-T3', '--max-retries', '1', '--host-timeout', '120s' if profile else '15s', '-oX', '-']
    if ipaddress.ip_network(scope).version == 6:
        args.append('-6')
    return args+[scope]


def observed_run(command, mission):
    item = {'argv': command, 'stage': 'tcp' if '-sT' in command else 'inventory'}
    mission['observations'].append(item)
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, encoding='utf-8', errors='replace', timeout=900, check=False)
        item.update(returncode=result.returncode, stdout=kali_tools.clean(result.stdout),
                    stderr=kali_tools.clean(result.stderr))
    except subprocess.TimeoutExpired as error:
        def text(value):
            return value.decode('utf-8', errors='replace') if isinstance(value, bytes) else (value or '')
        item.update(returncode=None, stdout=kali_tools.clean(text(error.stdout)),
                    stderr=kali_tools.clean(text(error.stderr)), error='Délai maximal dépassé.')
        raise core.AuditError('Nmap a dépassé le délai maximal. Réduire le périmètre ou choisir le scan rapide?') from error
    if result.returncode:
        raise core.AuditError('Nmap a échoué (code '+str(result.returncode)+') : '+
                              (kali_tools.clean(result.stderr or result.stdout).strip()[:500] or 'aucun détail fourni'))
    hosts = network.parse_nmap(result.stdout)
    # Toute réponse hors périmètre devient pending et ne provoque aucun scan.
    scope = security.scope_network(command[-1])
    accepted = []
    for host in hosts:
        if not security.in_scope(host, scope):
            mission['pending'].append({'target': mission['authorizations'][0]['id'], 'host': host,
                                       'reason': 'hors périmètre ; autorisation requise avant analyse'})
        else:
            accepted.append(host)
    return accepted


def scrub(value):
    if isinstance(value, str): return kali_tools.clean(value)
    if isinstance(value, list): return [scrub(v) for v in value]
    if isinstance(value, dict): return {k: scrub(v) for k, v in value.items()}
    return value


def execute(scope, profile, target):
    # Tout précontrôle précède le premier processus ; revalidation à chaque étape.
    if profile not in PROFILES:
        raise core.AuditError('Choisir le scan complet ou rapide?')
    scope = str(security.scope_network(scope))
    current_authorization(target, scope, profile)
    path = fusion.executable('nmap')
    if not path:
        raise core.AuditError('Nmap est absent. Veux-tu consulter /kali catalogue?')
    if not fusion.storage()['scan_allowed']:
        raise core.AuditError('Espace insuffisant pour le rapport. Veux-tu vérifier le stockage?')
    directory = core.state_dir()/'scan-reports'
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink() or not core.is_owned(directory):
        raise core.AuditError('Dossier de rapports non sûr.')
    directory.chmod(0o700)
    mission = {'id': 'RUN-'+uuid.uuid4().hex, 'started': security.now(), 'status': 'running',
               'scope': scope, 'profile': profile, 'authorizations': [target],
               'inventories': [], 'pending': [], 'observations': [],
               'coverage': 'Inventaire puis TCP '+('1–65535' if profile=='complet' else '100 ports courants')+
                           ' ; sans UDP, scripts NSE, détection OS ni sudo.'}
    report = directory/(mission['id']+'.json')
    # Réserver le rapport avant de faire quoi que ce soit sur le réseau.
    core.private_write(report, json.dumps(mission, ensure_ascii=False)+'\n')
    with security.database() as conn:
        conn.execute('INSERT INTO missions VALUES (?,?,?,?)', (mission['id'], mission['started'], 'running', json.dumps(mission)))
    try:
        current_authorization(target, scope, profile)
        hosts = observed_run(argv(path, scope), mission)
        # L'inventaire autorisé complet précède toute analyse de ports.
        assets = []
        inventory = {'target': target['id'], 'assets': assets, 'changes': {'new': []}}
        mission['inventories'].append(inventory)
        for host in hosts:
            if host.get('status') != 'up': continue
            asset = security.normalize(host)
            asset.update(authorization=target['id'], authorization_status='authorized',
                         tests=list(target['tests']), expires=target['expires'])
            assets.append(asset)
        for asset in assets:
            current_authorization(target, scope, profile)
            # Une IP par invocation ; aucune cible ou option libre issue de la sortie.
            address = asset['addresses'][0]
            scanned = observed_run(argv(path, address, profile), mission)
            if not scanned:
                raise core.AuditError('Nmap n’a renvoyé aucun résultat TCP valide. Réessayer en mode rapide?')
            asset['services'] = security.normalize({**scanned[0], 'ports': [p for h in scanned for p in h.get('ports', [])]})['services']
        current_authorization(target, scope, profile)
        mission.update(status='completed', finished=security.now())
        with security.database() as conn:
            latest = conn.execute('SELECT data FROM targets WHERE id=?', (target['id'],)).fetchone()
            if not latest or not permits(json.loads(latest['data']), scope, profile):
                raise core.AuditError('Autorisation modifiée ; mission interrompue.')
            previous = conn.execute('SELECT data FROM snapshots WHERE target=? ORDER BY created DESC LIMIT 1', (target['id'],)).fetchone()
            # Filtrer l'ancien inventaire au sous-périmètre demandé, éviter de déclarer
            # disparues les machines d'autres sous-réseaux de la même autorisation.
            previous = json.loads(previous['data']) if previous else []
            previous = [a for a in previous if all(ipaddress.ip_address(ip) in security.scope_network(scope) for ip in a['addresses'])]
            inventory['changes'] = security.changes(previous, assets)
            # Ne pas remplacer la référence d'une autorisation plus large avec un scan partiel.
            if security.scope_network(scope) == security.scope_network(target['scope']):
                conn.execute('INSERT INTO snapshots VALUES (?,?,?,?)', (mission['id'], target['id'], mission['finished'], json.dumps(scrub(assets))))
    except (core.AuditError, OSError, ValueError, KeyboardInterrupt) as error:
        mission.update(status='failed', finished=security.now(), error=kali_tools.clean(str(error)) or 'Opération interrompue.')
    finally:
        safe = scrub(mission)
        # Rapport privé existant, écriture via remplacement atomique O_EXCL.
        temporary = directory/('.'+uuid.uuid4().hex)
        core.private_write(temporary, json.dumps(safe, ensure_ascii=False, indent=2)+'\n')
        temporary.replace(report)
        with security.database() as conn:
            conn.execute('UPDATE missions SET status=?,data=? WHERE id=?', (safe['status'], json.dumps(safe), safe['id']))
    return {'status': mission['status'], 'executed': True, 'report': str(report),
            'mission': mission['id'], 'coverage': mission['coverage'], 'error': mission.get('error'),
            'results': scrub(mission['inventories']), 'pending': scrub(mission['pending'])}


def proposal(request, target=None):
    """Proposition en lecture seule pour /kali proposer, jamais un scan."""
    target = target or extract_target(request)
    if target and target.startswith('AUTH-'):
        record = next((t for t in fusion.read_table('targets') if t['id']==target), None)
        target = record['scope'] if record else None
    if not target:
        return {'mode': 'QUESTION', 'executed': False, 'question': QUESTION}
    try:
        scope = str(security.scope_network(target))
    except core.AuditError:
        return {'mode': 'QUESTION', 'executed': False, 'question': 'Quelle IP ou quel réseau CIDR valide veux-tu scanner?'}
    profile = 'rapide' if 'rapide' in normalized(request) else 'complet'
    approved = authorization(scope, profile)
    return {'mode': 'PROPOSITION', 'executed': False, 'scope': scope, 'profile': profile,
            'authorization': approved['id'] if approved else None,
            'question': 'Exécuter ce scan via /kali nmap?' if approved else 'Ajouter '+scope+' au périmètre autorisé pour TCP '+profile+'?',
            'options': {'complet': 'TCP 1–65535', 'rapide': '100 ports TCP courants'},
            'permissions': 'Inventaire puis TCP connect sans sudo ; aucun UDP, SYN brut, OS ou script NSE.',
            'command': ['/kali', 'nmap', '--cible', scope, '--demande', request]}


def dialogue(request='fais un nmap complet', target=None):
    target = target or extract_target(request)
    if not target:
        target = input(QUESTION+' ').strip()
    if not target:
        return {'status': 'cancelled', 'executed': False}
    try:
        scope = str(security.scope_network(target))
    except core.AuditError:
        print('Une IP ou un réseau CIDR valide, par exemple 192.168.1.10 ou 192.168.1.0/24?')
        return {'status': 'needs_target', 'executed': False}
    print('Cible : '+scope)
    print('[1] Complet TCP : ports 1–65535. [2] Rapide : 100 ports courants.')
    print('Inventaire avant les ports ; connexion TCP sans sudo. UDP, SYN brut et OS nécessitent des droits supplémentaires et ne font pas partie de ces options.')
    default = '2' if 'rapide' in normalized(request) else '1'
    choice = input('Option (Entrée : '+default+', 0 : annuler) : ').strip() or default
    if choice == '0': return {'status': 'cancelled', 'executed': False}
    if choice not in ('1', '2'):
        print('Choisir 1 ou 2?'); return {'status': 'needs_option', 'executed': False}
    profile = 'complet' if choice=='1' else 'rapide'
    approved = authorization(scope, profile)
    if approved:
        print('Autorisation existante '+approved['id']+' — périmètre '+approved['scope']+' — expiration '+approved['expires']+'.')
    else:
        approved = authorize(scope, profile)
    if not approved:
        return {'status': 'needs_authorization', 'executed': False}
    path = fusion.executable('nmap')
    if not path:
        print('Nmap est absent. Veux-tu consulter /kali catalogue?')
        return {'status': 'missing_tool', 'executed': False}
    import shlex
    print('PROPOSITION via /kali nmap :')
    print('Inventaire : '+shlex.join(argv(path, scope)))
    print('Puis pour chaque IP active autorisée : '+shlex.join(argv(path, str(security.scope_network(scope).network_address), profile)[:-1]+['<IP inventoriée>']))
    if input('Exécuter ce scan maintenant? (oui/non) : ').strip().casefold() != 'oui':
        return {'status': 'cancelled', 'executed': False}
    # Confirmation d'exécution distincte de l'autorisation, qui n'est pas redemandée.
    result = execute(scope, profile, approved)
    print(('RÉSULTATS OBSERVÉS' if result['status']=='completed' else 'ÉCHEC : '+result['error'])+' — rapport : '+result['report'])
    return result
