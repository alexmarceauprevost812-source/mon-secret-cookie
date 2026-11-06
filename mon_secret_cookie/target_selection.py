"""Sélection d'IP observées : registre existant, aucune découverte ni analyse."""
import ipaddress
import sys
from . import core, fusion, security


def candidates():
    # Les observations sont déjà persistées dans les missions, y compris pending.
    observed = {}
    for mission in fusion.read_table('missions'):
        groups = [(asset.get('addresses', []), inventory['target'])
                  for inventory in mission.get('inventories', []) for asset in inventory.get('assets', [])]
        groups += [(security.host_addresses(item['host']), item['target']) for item in mission.get('pending', [])]
        for addresses, source in groups:
            for address in addresses:
                ip = ipaddress.ip_address(address)
                if ip.is_multicast or ip.is_unspecified: continue
                observed[str(ip)] = {'ip': str(ip), 'observed': mission['started'],
                                     'mission': mission['id'], 'source_authorization': source}
    valid = []
    for target in fusion.read_table('targets'):
        try: security.validate(target)
        except (core.AuditError, KeyError, ValueError): continue
        valid.append(target)
    for ip, entry in observed.items():
        matching = [t for t in valid if ipaddress.ip_address(ip) in security.scope_network(t['scope'])]
        matching.sort(key=lambda t: (-security.scope_network(t['scope']).prefixlen, t['id']))
        # Ne jamais fusionner les tests de plusieurs autorisations en droits plus larges.
        target = matching[0] if matching else None
        entry.update(status='authorized' if target else 'pending', authorization=target['id'] if target else None,
                     scope=target['scope'] if target else None, tests=list(target['tests']) if target else [],
                     created=target['created'] if target else None, expires=target['expires'] if target else None,
                     limits=dict(target.get('limits', {})) if target else {})
    return {**security.new_assets(fusion.read_table('missions')), 'candidates': sorted(observed.values(), key=lambda x:(ipaddress.ip_address(x['ip']).version,int(ipaddress.ip_address(x['ip'])))),
            'network_executed': False}


def authorize_selected(address, owner, proof, expires, tests, confirmation):
    address = str(ipaddress.ip_address(address))
    entry = next((e for e in candidates()['candidates'] if e['ip']==address), None)
    if entry is None: raise core.AuditError('IP absente des observations : aucune autorisation implicite.')
    if entry['authorization']:
        return {'inherited': True, **entry}
    scope = str(ipaddress.ip_network(address))
    if confirmation != 'AUTORISER '+address:
        raise core.AuditError('Confirmation explicite requise : AUTORISER '+address)
    # Relit et revalide les limites via add_target ; autorise uniquement cette IP.
    return security.add_target('Cible découverte '+address, owner, scope, tests, expires, proof,
                               ['mission:'+entry['mission']])


def menu():
    if not sys.stdin.isatty(): raise core.AuditError('Sélection interactive requise dans un terminal.')
    entries = candidates()['candidates']
    print('Nouvelles cibles → Autoriser la sélection')
    for i, entry in enumerate(entries,1):
        print(f"[{i}] {entry['ip']} — {entry['status']} — périmètre {entry['scope']} — limites {entry['tests']} {entry['limits']} — expiration {entry['expires']}")
    if not entries: return {'authorized': [], 'network_executed': False}
    selection = input('Numéros séparés par des espaces (Entrée : retour) : ').split()
    try:
        indexes = sorted(set(int(i)-1 for i in selection))
        if any(i<0 or i>=len(entries) for i in indexes): raise ValueError()
    except ValueError as error: raise core.AuditError('Sélection invalide.') from error
    result=[]
    for i in indexes:
        entry=entries[i];address=entry['ip']
        if entry['authorization']:
            # Revalidation immédiate de l'héritage, pas de nouvelle autorisation.
            fresh=next(e for e in candidates()['candidates'] if e['ip']==address)
            if not fresh['authorization']: raise core.AuditError('Autorisation modifiée ; recommencer la sélection.')
            result.append(fresh);continue
        print('Cible hors périmètre : '+address+' ; périmètre proposé : '+str(ipaddress.ip_network(address)))
        owner=input('Responsable : ').strip();proof=input('Preuve / motif de l’autorisation : ').strip()
        expires=input('Expiration ISO 8601 avec fuseau : ').strip()
        choice=input('Limites : inventory (défaut) ou inventory tcp : ').strip()
        tests=choice.split() or ['inventory']
        print(f'Cible : {address} ; limites : {tests} ; expiration : {expires}. Aucun scan ne sera lancé.')
        confirmation=input('Confirmer en tapant AUTORISER '+address+' : ')
        result.append(authorize_selected(address,owner,proof,expires,tests,confirmation))
    return {'authorized':result,'network_executed':False}
