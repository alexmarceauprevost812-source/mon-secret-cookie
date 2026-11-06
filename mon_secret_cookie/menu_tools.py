"""États du menu et aides fermées ; aucune analyse réseau ni installation."""
import importlib.util
import os
from pathlib import Path
import sys
from . import core, environments, fusion, kali_tools

# Aides/versions uniquement. John classique affiche son aide sans argument.
CHECKS = {name: ([arg] if arg else []) for name, (arg, _) in kali_tools.TOOLS.items()
          if arg is not None}
CHECKS.update({'john': [], 'ip': ['-Version'], 'codex': ['--version'],
               'ollama': ['--version'], 'git': ['--version'], 'nano': ['--version'],
               'python3': ['--version'], 'notify-send': ['--version']})
DEPENDENCIES = {
    '1': ('device-id', ['ip']), '2': ('scan-local', ['ip', 'nmap']),
    '3': ('ports', ['ss']), '4': ('wifi-info', ['iw']), '5': ('devices', ['ip']),
    '6': ('cookie-lab', []), '7': ('password-lab', ['john']), '8': ('flask-lab', ['python:flask']),
    '9': ('nmap', ['nmap']), '10': ('cookies', []), '11': ('report', []),
    '12': ('devices --cidr', ['ip', 'nmap']), '13': ('cookie-guide', []),
    '14': ('bilan', []), '15': ('multi-report', []), '16': ('menu-outils', []),
    '17': ('cibles', []), '18': ('nouvelles', []), '19': ('autorisations', []),
    '20': ('scan complet', ['ip', 'nmap']), '21': ('rapport', []),
    '22': ('terminal-codex', ['terminal-codex']), '23': ('surveillance', ['ip', 'python:fcntl']),
    '24': ('surveillance --inventaire', ['python:fcntl']), '25': ('aide-outil', []),
    '26': ('diagnostic-prevost', []), '27': ('installer-outils', ['apt-get']),
}


def resolve(name):
    if name == 'terminal-codex':
        path = fusion.executable(name)
        fallback = Path(__file__).resolve().parent.parent/'integration/terminal-codex.py'
        return [path] if path else ([sys.executable, str(fallback)] if fallback.is_file() else None)
    path = core.executable(name)
    return [path] if path else None


def entries():
    result = {}
    for number, (command, dependencies) in DEPENDENCIES.items():
        missing = [name for name in dependencies if
                   (importlib.util.find_spec(name[7:]) is None if name.startswith('python:') else not resolve(name))]
        result[number] = {'commande': command, 'environnement': 'LexOS',
                          'etat': 'manquant' if missing else 'disponible', 'dependances_manquantes': missing,
                          'message': 'Installer/configurer : '+', '.join(missing) if missing else
                          'Commande accessible ; droits et données requis selon opération.'}
    result['14']['message'] = 'Bilan partiel si ip, ss ou iw sont indisponibles ; aucun contrôle réseau actif ici.'
    result['23']['message'] += ' Alertes désactivées par défaut ; option --notifications pour les activer.'
    return result


def help_command(name, kali=False, detected=None):
    if name not in CHECKS:
        raise core.AuditError('Aide non prise en charge ; utiliser un outil du catalogue fermé.')
    if not kali:
        prefix = resolve(name)
        if not prefix:
            raise core.AuditError(name+' manquant sur LexOS ; vérifier kali-lexos avec menu-outils --verify.')
        return prefix+CHECKS[name]
    detected = detected or environments.discover(fusion.executable, fusion.version_probe)
    if detected.get('status') != 'available':
        raise core.AuditError('kali-lexos inaccessible : '+detected.get('reason', detected.get('status', 'erreur')))
    entry = detected.get('tools', {}).get(name, {})
    if not entry.get('installed') or not entry.get('path'):
        raise core.AuditError(name+' absent ou non vérifié dans kali-lexos.')
    if name == 'lynis' and entry.get('ownership_safe') is not True:
        raise core.AuditError('Propriété des fichiers Lynis Kali non validée ; vérifier leurs UID depuis le terminal du conteneur.')
    return [fusion.executable('podman'), 'exec', detected['launcher']['container'], entry['path'], *CHECKS[name]]


def check(name, kali=False, detected=None):
    if kali and detected is None:
        detected=environments.discover(fusion.executable,fusion.version_probe)
    try:
        argv = help_command(name, kali, detected)
        if name=='lynis' and not kali:
            from .host_access import lynis_ownership
            ownership=lynis_ownership()
            if not ownership['valide']:
                raise core.AuditError('Propriété Lynis incompatible : '+ownership['message']+' ; vérifier sur le terminal hôte, sans chown automatique.')
        observed = fusion.version_probe(argv)
        return {'etat': 'disponible' if observed['status'] == 'ok' else 'erreur',
                'commande': argv, 'environnement': 'kali-lexos' if kali else 'LexOS',
                'message': kali_tools.clean(observed.get('error') or observed.get('output', '')),
                'code': observed.get('returncode')}
    except core.AuditError as error:
        absent=(not kali and not resolve(name)) or (kali and detected.get('status')=='available' and not detected.get('tools',{}).get(name,{}).get('installed'))
        return {'etat':'manquant' if absent else 'erreur', 'message':str(error),
                'environnement':'kali-lexos' if kali else 'LexOS'}


def report(verify=False):
    detected = environments.discover(fusion.executable, fusion.version_probe)
    tools = {}
    for name in CHECKS:
        prefix = resolve(name)
        tools[name] = check(name) if verify else {'etat': 'disponible' if prefix else 'manquant',
                       'commande': prefix, 'environnement': 'LexOS', 'message': 'Présence vérifiée ; aide non exécutée.'}
    container = {name: check(name, True, detected) if verify else entry
                 for name, entry in detected.get('tools', {}).items()}
    menu=entries()
    if verify:
        for number, (_, dependencies) in DEPENDENCIES.items():
            errors=[name for name in dependencies if tools.get(name, {}).get('etat') == 'erreur']
            if errors:
                menu[number].update(etat='erreur', message=' ; '.join(name+': '+tools[name]['message'] for name in errors))
    return {'menu': menu, 'outils_LexOS': tools, 'outils_kali': container,
            'kali': detected, 'verification': 'aides et versions uniquement' if verify else 'présence uniquement',
            'analyse_reseau': False}


def routed_check(name, kali=False):
    """Une aide absente de LexOS utilise Kali seulement après vérification réelle."""
    if name not in CHECKS:
        raise core.AuditError('Outil absent du catalogue fermé.')
    if kali or resolve(name):
        return check(name,kali)
    detected=environments.discover(fusion.executable,fusion.version_probe)
    entry=detected.get('tools',{}).get(name,{})
    if detected.get('status')=='available' and entry.get('installed'):
        return check(name,True,detected)
    result=check(name)
    result['kali_etat']='manquant' if detected.get('status')=='available' else 'non_verifie'
    result['kali_raison']=detected.get('reason','Commande absente du conteneur vérifié.')
    result['message']+=' Kali : '+result['kali_etat']+'. '+result['kali_raison']
    result['commande_hote']='prevost aide-outil '+name+' --kali'
    return result
