"""Découverte en lecture seule des lanceurs et conteneurs déjà actifs."""
import json
import re
import shlex
from pathlib import Path

TOOLS = ('wifite', 'nmap', 'tshark', 'lynis', 'hashcat', 'john', 'dumpcap', 'wireshark', 'tcpdump', 'aircrack-ng', 'airodump-ng', 'iw', 'ip', 'ss', 'nikto', 'sqlmap', 'gobuster', 'ffuf', 'whatweb', 'curl', 'openssl', 'dig', 'whois', 'exiftool', 'strings', 'file', 'binwalk', 'radare2')
# Programme fixe : aucune commande ni option issue d'un modèle ou de la configuration.
KALI_METADATA = r'''
import json, os, shutil, subprocess
from pathlib import Path
release = {}
for line in Path('/etc/os-release').read_text().splitlines():
    if '=' in line:
        k, v = line.split('=', 1); release[k] = v.strip('"')
tools = {}
for name in ('wifite', 'nmap', 'tshark', 'lynis', 'hashcat', 'john', 'dumpcap', 'wireshark', 'tcpdump', 'aircrack-ng', 'airodump-ng', 'iw', 'ip', 'ss', 'nikto', 'sqlmap', 'gobuster', 'ffuf', 'whatweb', 'curl', 'openssl', 'dig', 'whois', 'exiftool', 'strings', 'file', 'binwalk', 'radare2'):
    path = shutil.which(name)
    if not path and os.access('/usr/sbin/'+name, os.X_OK): path = '/usr/sbin/'+name
    item = {'path': path, 'installed': bool(path), 'version': None}
    if name == 'lynis' and path:
        includes = (Path('/usr/share/lynis/include/consts'), Path('/usr/share/lynis/include/functions'))
        item['ownership_safe'] = all(p.is_file() and p.stat().st_uid in (0, os.getuid()) for p in includes)
    if path:
        p = subprocess.run(['dpkg-query', '-W', '-f=${Version}', name],
                           capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
        if p.returncode == 0: item['version'] = p.stdout.strip()
    tools[name] = item
print(json.dumps({'release': release, 'tools': tools}))
'''


def launcher(home=None):
    home = Path.home() if home is None else Path(home)
    for path in (home/'.local/bin/kali', home/'.local/bin/lexos-kali'):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding='utf-8')
            if len(text) > 32000:
                continue
            for line in text.splitlines():
                tokens = shlex.split(line, comments=True)
                for index, token in enumerate(tokens):
                    if Path(token).name == 'distrobox' and tokens[index+1:index+2] == ['enter']:
                        rest = tokens[index+2:]
                        if rest[:1] == ['--name']:
                            rest = rest[1:]
                        if rest and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', rest[0]):
                            return {'path': str(path), 'container': rest[0], 'type': 'distrobox'}
        except (OSError, ValueError):
            continue
    return None


def discover(resolve, run, home=None, diagnostic=False):
    found = launcher(home)
    result = {'launcher': found, 'status': 'unavailable', 'tools': {}}
    if not found:
        return {**result, 'reason': 'Aucun lanceur Distrobox reconnu ; aucun script exécuté.'}
    podman = resolve('podman')
    if not podman:
        return {**result, 'reason': 'Podman absent.'}
    active = run([podman, 'ps', '--format', '{{.Names}}'])
    if active.get('status') != 'ok':
        return {**result, 'reason': active.get('error') or active.get('output', 'Podman inaccessible.')}
    if found['container'] not in active.get('output', '').splitlines():
        return {**result, 'status': 'stopped', 'reason': 'Conteneur non actif ; aucun démarrage automatique.'}
    prefix = [podman, 'exec', '--env', 'PYTHONDONTWRITEBYTECODE=1', found['container']]
    metadata = run([*prefix, 'python3', '-B', '-c', KALI_METADATA])
    if metadata.get('status') != 'ok':
        return {**result, 'reason': metadata.get('error') or metadata.get('output', 'Métadonnées inaccessibles.')}
    try:
        data = json.loads(metadata['output'])
        if not isinstance(data, dict) or not isinstance(data.get('release'), dict) or not isinstance(data.get('tools'), dict):
            raise ValueError('Structure de métadonnées inattendue')
        if data['release']['ID'] != 'kali':
            return {**result, 'reason': 'Le conteneur détecté ne déclare pas Kali.'}
        tools = {}
        for name in TOOLS:
            item = data['tools'].get(name, {})
            if not isinstance(item, dict):
                raise ValueError('Entrée outil invalide')
            path = item.get('path')
            # Le chemin retourné ne peut pas servir à lancer un autre programme.
            allowed = [f'{directory}/{name}' for directory in ('/usr/bin', '/usr/sbin', '/usr/local/bin', '/usr/local/sbin')]
            if path is not None and path not in allowed:
                raise ValueError('Chemin inattendu pour '+name)
            entry = {'environment': found['container'], 'path': path,
                     'installed': bool(path), 'version': item.get('version'),
                     'version_source': 'dpkg-query', 'status': 'found' if path else 'missing'}
            if diagnostic and path:
                if name == 'lynis' and item.get('ownership_safe') is not True:
                    entry['diagnostic'] = {'status': 'unavailable', 'error': 'Propriété Lynis non validée ; aucun contrôle contourné.'}
                else:
                    from .menu_tools import CHECKS
                    args = ['--version'] if name in ('nmap','tshark','hashcat','lynis') else CHECKS.get(name, ['--help'])
                    entry['diagnostic'] = run([*prefix, path, *args])
            tools[name] = entry
        return {**result, 'status': 'available', 'release': data['release'], 'tools': tools}
    except (ValueError, KeyError, TypeError) as error:
        return {**result, 'reason': 'Métadonnées Kali invalides : '+str(error)}


def reported(project, container):
    path = Path(project)/'integration/environments.json'
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding='utf-8'))
    return data.get('reported', {}).get(container, {})
