"""Rapports locaux : seuls compteurs et constats typés sont persistés."""
import json
import os
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Aucun champ libre, nom de cookie, chemin, sortie brute ou valeur secrète.
FIELDS = {'secure', 'http_only', 'session', 'expired', 'invalid_lines',
          'matched', 'hashes', 'audits', 'fichiers_lus', 'available', 'authorized'}

def metadata(value):
    if isinstance(value, dict):
        out = {}
        for key in sorted(FIELDS):
            item = value.get(key)
            if type(item) in (bool, int):
                out[key] = item
        # Les clés des données d'entrée ne sont jamais recopiées.
        children = [metadata(v) for v in value.values() if isinstance(v, (dict, list))]
        if children:
            out['groupes'] = children
        return out
    if isinstance(value, list):
        return {'nombre': len(value), 'constats': [metadata(v) for v in value if isinstance(v, (dict, list))]}
    return {}

def directory():
    path = Path.home()/'.local/share/ti-lexos-kali/rapports/cookie'
    for part in (path.parent.parent, path.parent, path):
        part.mkdir(mode=0o700, exist_ok=True)
        info = part.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise OSError('Dossier de rapports non sûr')
        part.chmod(0o700)
    return path

def save(command, result):
    os.umask(0o077)
    path = directory()
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')+'-'+uuid.uuid4().hex
    # command provient exclusivement du parseur interne.
    data = {'date': datetime.now(timezone.utc).isoformat(), 'commande': command,
            'resultat': metadata(result)}
    body = json.dumps(data, ensure_ascii=False, indent=2)+'\n'
    for suffix in ('txt', 'json'):
        latest = path/('cookie.'+suffix)
        if latest.exists() or latest.is_symlink():
            info = latest.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise OSError('Rapport non sûr')
            latest.chmod(0o600)
            # Lien dur exclusif : conserve exactement la version précédente.
            os.link(latest, path/('cookie-'+stamp+'.'+suffix), follow_symlinks=False)
        temporary = path/('.'+uuid.uuid4().hex)
        try:
            fd = os.open(temporary, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                stream.write(('MON-SECRET-COOKIE — constats privés\n' if suffix=='txt' else '')+body)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, latest)
        finally:
            temporary.unlink(missing_ok=True)
    return data
