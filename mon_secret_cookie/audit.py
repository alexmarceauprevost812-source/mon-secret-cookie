"""Bilan défensif local en texte : regroupe les vérifications de votre propre machine."""
import json
import platform
import socket
from pathlib import Path
from . import network
from .core import AuditError, device_id


def system_identity():
    """Identité réelle de votre propre machine (sans dépendance externe)."""
    identity = {
        'hostname': socket.gethostname(),
        'systeme': platform.system(),
        'version_noyau': platform.release(),
        'architecture': platform.machine(),
        'python': platform.python_version(),
    }
    # machine-id : identifiant d'installation local, lisible sur votre propre machine.
    for candidate in ('/etc/machine-id', '/var/lib/dbus/machine-id'):
        try:
            value = Path(candidate).read_text(encoding='utf-8').strip()
        except OSError:
            continue
        if value:
            identity['machine_id'] = value
            break
    return identity


def _section(title, fn):
    """Exécute une vérification locale sans jamais interrompre tout le bilan."""
    try:
        return {'titre': title, 'ok': True, 'data': fn()}
    except (AuditError, OSError, ValueError, ImportError) as error:
        return {'titre': title, 'ok': False, 'erreur': str(error)}


def collect(include_neighbors=True, label=None):
    """Rassemble les informations de votre propre appareil et, en lecture passive, de votre LAN.

    label : étiquette libre choisie par vous pour distinguer vos appareils (ex. telephone-1, pc-bureau).
    """
    sections = [
        _section('Identité', lambda: {**device_id(), 'hostname': socket.gethostname()}),
        _section('Système (cette machine)', system_identity),
        _section('Interfaces et adresses', lambda: {'adresses': network.local_addresses()}),
        _section('Ports en écoute (cette machine)', network.ports),
        _section('Wi-Fi', network.wifi_info),
        _section('Scan local (localhost et IP propres, 20 ports courants)', network.scan_local),
    ]
    if include_neighbors:
        # Lecture passive du cache de voisinage : aucun paquet de scan émis.
        sections.append(_section('Voisins LAN (cache passif, sans scan)', lambda: network.devices()))
    result = {'bilan': 'appareil local', 'sections': sections}
    if label:
        result['etiquette'] = label
    return result


def _render_value(value, indent='    '):
    lines = []
    if isinstance(value, dict):
        for key, sub in value.items():
            if isinstance(sub, (dict, list)):
                lines.append(f'{indent}{key} :')
                lines.extend(_render_value(sub, indent + '  '))
            else:
                lines.append(f'{indent}{key} : {sub}')
    elif isinstance(value, list):
        if not value:
            lines.append(f'{indent}(aucun)')
        for item in value:
            if isinstance(item, (dict, list)):
                lines.extend(_render_value(item, indent + '  '))
                lines.append('')
            else:
                lines.append(f'{indent}- {item}')
    else:
        lines.append(f'{indent}{value}')
    return lines


def _report_device(data):
    """Déduit l'ID de l'appareil d'un rapport : un fichier provient d'une seule machine.

    Cherche un device_id au niveau d'une entrée (cookies, scan-local) ou niché dans
    une section du bilan (Identité). Retourne 'inconnu' si vraiment aucun.
    """
    for entry in data.get('audits', []):
        result = entry.get('result')
        if not isinstance(result, dict):
            continue
        if result.get('device_id'):
            return result['device_id']
        for section in result.get('sections', []) or []:
            sdata = section.get('data') if isinstance(section, dict) else None
            if isinstance(sdata, dict) and sdata.get('device_id'):
                return sdata['device_id']
    return 'inconnu'


def merge_reports(paths):
    """Regroupe par appareil des rapports JSON exportés sur plusieurs machines.

    Chaque fichier est un export `report --format json` ({"audits":[...]}),
    appartenant à votre utilisateur, et provient d'un seul appareil : toutes ses
    entrées sont donc attribuées à l'ID déduit de ce fichier. Entièrement local.
    """
    from .core import AuditError, owned_text
    devices = {}
    read = 0
    for path in paths:
        try:
            data = json.loads(owned_text(path))
        except (AuditError, ValueError, OSError):
            continue  # fichier illisible, non possédé ou non JSON : ignoré
        read += 1
        device = _report_device(data)
        d = devices.setdefault(device, {'device_id': device, 'audits': 0,
                                        'cookie_files': [], 'cookie_entries': 0})
        for entry in data.get('audits', []):
            result = entry.get('result')
            if not isinstance(result, dict):
                continue
            d['audits'] += 1
            if entry.get('command') == 'cookies':
                files = result.get('files') or ([result['file']] if result.get('file') else [])
                for f in files:
                    if f not in d['cookie_files']:
                        d['cookie_files'].append(f)
                d['cookie_entries'] += len(result.get('cookies') or [])
    appareils = sorted(devices.values(), key=lambda d: d['device_id'])
    return {'rapport': 'multi-appareils', 'fichiers_lus': read, 'appareils': appareils}


def format_multi_text(result):
    out = ['MON-SECRET-COOKIE — Rapport multi-appareils', '=' * 44,
           f"Fichiers lus : {result['fichiers_lus']}", '']
    if not result['appareils']:
        out.append('(aucune donnée exploitable)')
        return '\n'.join(out) + '\n'
    for d in result['appareils']:
        titre = f"Appareil {d['device_id']}"
        out.append(titre)
        out.append('-' * len(titre))
        out.append(f"  audits enregistrés : {d['audits']}")
        out.append(f"  cookies — fichiers trouvés : {len(d['cookie_files'])}")
        for f in d['cookie_files']:
            out.append(f"    - {f}")
        out.append(f"  cookies — entrées analysées : {d['cookie_entries']}")
        out.append('')
    return '\n'.join(out).rstrip() + '\n'


def format_text(result):
    out = ['MON-SECRET-COOKIE — Bilan défensif de votre appareil', '=' * 52]
    if result.get('etiquette'):
        out.append(f'Appareil : {result["etiquette"]}')
    out.append('')
    for section in result['sections']:
        out.append(section['titre'])
        out.append('-' * len(section['titre']))
        if section['ok']:
            out.extend(_render_value(section['data']))
        else:
            out.append(f'    Indisponible : {section["erreur"]}')
        out.append('')
    return '\n'.join(out).rstrip() + '\n'
