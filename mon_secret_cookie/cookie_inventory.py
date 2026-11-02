"""Nouveaux cookies.txt locaux sélectionnés : uniquement métadonnées, sans valeurs."""
import hashlib
import json
from pathlib import Path
from . import core, cookies, security


def selected_path(directory):
    source = Path(directory)
    if source.is_symlink():
        raise core.AuditError('Dossier symbolique refusé.')
    base = source.resolve()
    if not base.is_dir() or base in (Path('/'), Path.home()):
        raise core.AuditError('Choisir un dossier de travail local précis.')
    return base


def collect(directory):
    base = selected_path(directory)
    device = core.device_id()['device_id']
    identifier = hashlib.sha256((device+'\0'+str(base)).encode()).hexdigest()
    found = cookies.search(base)['files']
    metadata, errors = [], []
    for path in found:
        try:
            metadata.append(cookies.analyze(path))
        except core.AuditError as error:
            errors.append({'file': path, 'error': str(error)})
    current = {m['file']: hashlib.sha256(json.dumps(m, sort_keys=True).encode()).hexdigest() for m in metadata}
    with security.database() as conn:
        conn.execute('CREATE TABLE IF NOT EXISTS cookie_inventory(id TEXT PRIMARY KEY,data TEXT NOT NULL)')
        row = conn.execute('SELECT data FROM cookie_inventory WHERE id=?', (identifier,)).fetchone()
        previous = json.loads(row['data']) if row else {}
        conn.execute('INSERT INTO cookie_inventory VALUES (?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data',
                     (identifier, json.dumps(current)))
    return {'source': 'dossier local explicitement sélectionné', 'device_id': device, 'directory': str(base),
            'new_files': [m for m in metadata if m['file'] not in previous],
            'changed_files': [m for m in metadata if m['file'] in previous and previous[m['file']] != current[m['file']]],
            'errors': errors, 'values': 'jamais affichées ou enregistrées',
            'limit': '100 fichiers, profondeur 4 ; aucun accès aux appareils distants'}
