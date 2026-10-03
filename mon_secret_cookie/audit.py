"""Bilan défensif local en texte : regroupe les vérifications de votre propre machine."""
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
