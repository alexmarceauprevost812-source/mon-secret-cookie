"""Autorisations explicites, missions bornées et historique persistant."""
import ipaddress
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from . import core, network, diagnostics


def now():
    return datetime.now(timezone.utc).isoformat()


def expiry(value):
    try:
        date = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if date.tzinfo is None:
            raise ValueError('fuseau horaire requis')
        return date.astimezone(timezone.utc)
    except (ValueError, AttributeError) as error:
        raise core.AuditError('Expiration ISO 8601 avec fuseau requise, ex. 2027-01-01T00:00:00Z.') from error


def scope_network(value):
    try:
        net = ipaddress.ip_network(value, strict=True)
    except ValueError as error:
        raise core.AuditError('Périmètre : IP littérale ou CIDR canonique requis ; aucun DNS automatique.') from error
    if net.num_addresses > 256 or net.is_multicast or net.is_unspecified:
        raise core.AuditError('Périmètre limité à 256 adresses unicast explicites.')
    if net.num_addresses > 1 and (net.version != 4 or not net.is_private or net.is_loopback or net.is_link_local):
        raise core.AuditError('Découverte réseau limitée à un CIDR IPv4 privé du LAN.')
    return net


@contextmanager
def database():
    path = core.state_dir() / 'security.sqlite3'
    try:
        core.private_write(path, '')
    except FileExistsError:
        pass
    if path.is_symlink() or not path.is_file() or not core.is_owned(path):
        raise core.AuditError('Base de sécurité non sûre.')
    if os.name != 'nt':
        path.chmod(0o600)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS targets (id TEXT PRIMARY KEY, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS missions (id TEXT PRIMARY KEY, started TEXT NOT NULL,
                status TEXT NOT NULL, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS snapshots (mission TEXT, target TEXT, created TEXT,
                data TEXT NOT NULL, PRIMARY KEY(mission, target));
        ''')
        conn.commit()
        with conn:
            yield conn
    finally:
        conn.close()


def add_target(name, owner, scope, tests, expires, proof, references=None):
    if not all(isinstance(v, str) and v.strip() and len(v) <= 4000 for v in (name, owner, proof)):
        raise core.AuditError('Nom, responsable et preuve textuelle requis (4000 caractères maximum).')
    net = scope_network(scope)
    tests = sorted(set(tests))
    if not tests or not set(tests) <= {'inventory', 'tcp'} or 'inventory' not in tests:
        raise core.AuditError('Tests permis : inventory obligatoire, tcp optionnel ; aucun test intrusif.')
    expiration = expiry(expires)
    if expiration <= datetime.now(timezone.utc):
        raise core.AuditError('Autorisation déjà expirée.')
    target = {'id': 'AUTH-' + uuid.uuid4().hex, 'name': name.strip(), 'owner': owner.strip(),
              'scope': str(net), 'tests': tests, 'expires': expiration.isoformat(),
              'proof': proof.strip(), 'references': references or [], 'created': now(), 'last_scan': None}
    with database() as conn:
        conn.execute('INSERT INTO targets VALUES (?,?)', (target['id'], json.dumps(target)))
    return target


def targets():
    with database() as conn:
        return [json.loads(row['data']) for row in conn.execute('SELECT data FROM targets ORDER BY id')]


def validate(target):
    scope_network(target['scope'])
    if target.get('revoked'):
        raise core.AuditError('Autorisation révoquée : ' + target['id'])
    if not target.get('proof') or not target.get('owner'):
        raise core.AuditError('Preuve et responsable requis pour ' + target['id'])
    if expiry(target['expires']) <= datetime.now(timezone.utc):
        raise core.AuditError('Autorisation expirée : ' + target['id'])
    if 'inventory' not in target['tests'] or not set(target['tests']) <= {'inventory', 'tcp'}:
        raise core.AuditError('Tests non approuvés : ' + target['id'])


def revoke(identifier):
    with database() as conn:
        row = conn.execute('SELECT data FROM targets WHERE id=?', (identifier,)).fetchone()
        if row is None:
            raise core.AuditError('Autorisation inconnue : ' + identifier)
        target = json.loads(row['data'])
        target['revoked'] = now()
        conn.execute('UPDATE targets SET data=? WHERE id=?', (json.dumps(target), identifier))
    return target


def validate_current(target):
    with database() as conn:
        row = conn.execute('SELECT data FROM targets WHERE id=?', (target['id'],)).fetchone()
    if row is None:
        raise core.AuditError('Autorisation supprimée.')
    validate(json.loads(row['data']))


def authorizations():
    result = []
    for target in targets():
        entry = {**target, 'valid': True}
        try:
            validate(target)
        except (core.AuditError, ValueError) as error:
            entry.update(valid=False, reason=str(error))
        result.append(entry)
    return {'authorizations': result}


def host_addresses(host):
    result = []
    for address in host.get('addresses', []):
        if address.get('addrtype') in ('ipv4', 'ipv6'):
            try:
                result.append(str(ipaddress.ip_address(address['addr'])))
            except (ValueError, KeyError) as error:
                raise core.AuditError('Adresse invalide dans la réponse Nmap.') from error
    return sorted(set(result))


def in_scope(host, net):
    addresses = host_addresses(host)
    return bool(addresses) and all(ipaddress.ip_address(a) in net for a in addresses)


def normalize(host):
    addresses = host_addresses(host)
    mac = next((a.get('addr') for a in host.get('addresses', []) if a.get('addrtype') == 'mac'), None)
    identifier = network.asset_id(mac, addresses[0] if addresses else None)
    if not identifier:
        raise core.AuditError('Hôte sans identifiant exploitable.')
    services = sorted([{'port': p['port'], 'protocol': p['protocol'], 'service': p.get('service')}
                       for p in host.get('ports', []) if p.get('state') == 'open'],
                      key=lambda p: (p['protocol'], int(p['port'])))
    return {'asset_id': identifier, 'addresses': addresses, 'mac': mac,
            'status': host.get('status'), 'services': services}


def changes(previous, current):
    before = {h['asset_id']: h for h in previous}
    after = {h['asset_id']: h for h in current}
    return {'new': [after[k] for k in sorted(after.keys() - before.keys())],
            'not_observed': [before[k] for k in sorted(before.keys() - after.keys())],
            'changed': [{'asset_id': k, 'before': before[k], 'after': after[k]}
                        for k in sorted(before.keys() & after.keys()) if before[k] != after[k]]}


def discover(target):
    net = scope_network(target['scope'])
    if net.num_addresses > 1:
        return network.devices(str(net), True)['hosts']
    address = str(net.network_address)
    args = ['nmap', '-n', '-sn', '-T3', '--max-retries', '1', '--host-timeout', '10s', '-oX', '-']
    if net.version == 6:
        args.append('-6')
    return network.parse_nmap(core.run([*args, address], timeout=30))


def scan_complete(ids=None):
    selected = targets()
    if ids:
        missing = set(ids) - {t['id'] for t in selected}
        if missing:
            raise core.AuditError('Autorisation inconnue : ' + ', '.join(sorted(missing)))
        selected = [t for t in selected if t['id'] in ids]
    if not selected:
        raise core.AuditError('Aucune cible autorisée enregistrée. Utilisez cibles ajouter.')
    for target in selected:
        validate(target)
    mission = {'id': 'RUN-' + uuid.uuid4().hex, 'started': now(), 'status': 'running',
               'authorizations': selected, 'inventories': [], 'pending': [],
               'coverage': 'Découverte des hôtes ; TCP : 100 ports courants si permis. UDP non testé.'}
    with database() as conn:
        conn.execute('INSERT INTO missions VALUES (?,?,?,?)',
                     (mission['id'], mission['started'], 'running', json.dumps(mission)))
    try:
        mission['tools'] = diagnostics.tools()
        mission['selected_tools'] = ['nmap']
        for target in selected:
            validate_current(target)
            net = scope_network(target['scope'])
            hosts = discover(target)
            if len(hosts) > 256:
                raise core.AuditError('Réponse inventaire trop volumineuse.')
            assets = []
            for host in hosts:
                if not in_scope(host, net):
                    mission['pending'].append({'target': target['id'], 'host': host,
                                               'reason': 'hors périmètre ; aucune analyse active supplémentaire'})
                    continue
                if host.get('status') != 'up':
                    continue
                if 'tcp' in target['tests']:
                    validate_current(target)
                    address = host_addresses(host)[0]
                    scanned = network.scan_address(address)
                    if not scanned:
                        raise core.AuditError('Scan TCP sans résultat : inventaire incomplet.')
                    for observed in scanned:
                        if not in_scope(observed, ipaddress.ip_network(address)):
                            raise core.AuditError('Réponse TCP hors de la cible demandée.')
                    host = {**host, 'ports': [p for h in scanned for p in h.get('ports', [])]}
                asset = normalize(host)
                asset.update(authorization=target['id'], authorization_status='authorized',
                             tests=target['tests'], expires=target['expires'])
                assets.append(asset)
            assets = sorted({a['asset_id']: a for a in assets}.values(), key=lambda a: a['asset_id'])
            with database() as conn:
                row = conn.execute('SELECT data FROM snapshots WHERE target=? ORDER BY created DESC LIMIT 1',
                                   (target['id'],)).fetchone()
            previous = json.loads(row['data']) if row else []
            mission['inventories'].append({'target': target['id'], 'assets': assets,
                                           'changes': changes(previous, assets)})
        for target in selected:
            validate_current(target)
        mission.update(status='completed', finished=now())
        # Publication atomique : les missions échouées ne deviennent pas une référence.
        with database() as conn:
            conn.execute('BEGIN IMMEDIATE')
            # Relire dans la transaction pour ne jamais effacer une révocation concurrente.
            current_targets = []
            for target in selected:
                current = json.loads(conn.execute('SELECT data FROM targets WHERE id=?',
                                                 (target['id'],)).fetchone()['data'])
                validate(current)
                current_targets.append(current)
            for inventory in mission['inventories']:
                conn.execute('INSERT INTO snapshots VALUES (?,?,?,?)',
                             (mission['id'], inventory['target'], mission['finished'], json.dumps(inventory['assets'])))
            for target in current_targets:
                target = {**target, 'last_scan': mission['finished']}
                conn.execute('UPDATE targets SET data=? WHERE id=?', (json.dumps(target), target['id']))
            conn.execute('UPDATE missions SET status=?,data=? WHERE id=?',
                         (mission['status'], json.dumps(mission), mission['id']))
    except BaseException as error:
        mission.update(status='failed', finished=now(), error=str(error))
        with database() as conn:
            conn.execute('UPDATE missions SET status=?,data=? WHERE id=?',
                         ('failed', json.dumps(mission), mission['id']))
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        raise core.AuditError('Mission échouée et journalisée : ' + str(error)) from error
    return mission


def reports():
    with database() as conn:
        return {'missions': [json.loads(r['data']) for r in conn.execute('SELECT data FROM missions ORDER BY started')]}


def new_assets(missions=None):
    latest = {}
    pending = []
    for mission in reports()['missions'] if missions is None else missions:
        pending.extend(mission['pending'])
        if mission['status'] == 'completed':
            for inventory in mission['inventories']:
                latest[inventory['target']] = inventory['changes']['new']
    return {'new': [a for group in latest.values() for a in group], 'pending': pending}


def export_report(output, fmt='json'):
    data = reports()
    text = json.dumps(data, ensure_ascii=False, indent=2)
    if fmt == 'txt':
        text = 'SECURITY PRO 2.1 — Rapport IA locale\n\n' + text
    core.private_write(output, text + '\n')
    return {'rapport': str(output), 'missions': len(data['missions'])}
