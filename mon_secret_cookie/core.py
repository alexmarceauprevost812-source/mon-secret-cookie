"""Stockage privé, exécution bornée et fichiers appartenant à l'utilisateur."""
import errno
import json
import os
import shutil
import stat
import subprocess
import sys
import uuid
from pathlib import Path
from datetime import datetime, timezone
from . import platforms

class AuditError(Exception):
    pass


def disk_full_hint(error):
    """Message clair en français si l'erreur est un disque plein, sinon None."""
    if isinstance(error, OSError) and error.errno == errno.ENOSPC:
        return ("Disque plein : libérez de l'espace puis réessayez "
                "(Termux : pkg clean ; Linux : sudo apt clean ; "
                "ou supprimez des fichiers inutiles).")
    return None

def run(argv, timeout=30):
    if not shutil.which(argv[0]):
        raise AuditError(f"Dépendance absente : {argv[0]}. Consultez l’installateur de votre plateforme dans le README.")
    try:
        p = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise AuditError("Délai dépassé ; opération arrêtée.") from e
    if p.returncode:
        raise AuditError(f"{argv[0]} : {p.stderr.strip()[:500] or 'échec'}")
    return p.stdout

def is_owned(path):
    if platforms.is_windows():
        return platforms.windows_owner(Path(path).absolute())
    return Path(path).stat().st_uid == os.getuid()


def state_dir():
    default = Path(os.environ.get("LOCALAPPDATA", Path.home()/"AppData/Local"))/"mon-secret-cookie" if platforms.is_windows() else Path.home()/".local/state/mon-secret-cookie"
    p = Path(os.environ.get("MSC_STATE_DIR", default))
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    if p.is_symlink() or not is_owned(p):
        raise AuditError("Répertoire d'état non sûr.")
    if not platforms.is_windows():
        p.chmod(0o700)
    return p

def owned_text(path, limit=2_000_000):
    # O_NOFOLLOW + fstat évitent une substitution du dernier composant.
    try:
        before = os.lstat(path)
        if stat.S_ISLNK(before.st_mode) or getattr(before,'st_file_attributes',0) & 0x400:
            raise AuditError("Liens et points de réanalyse refusés.")
        owner = is_owned(path) if platforms.is_windows() else before.st_uid == os.getuid()
        fd = os.open(path, os.O_RDONLY | getattr(os,'O_NOFOLLOW',0) | getattr(os,'O_NONBLOCK',0))
        with os.fdopen(fd, 'r', encoding='utf-8') as f:
            s = os.fstat(f.fileno())
            if not owner or (before.st_dev,before.st_ino) != (s.st_dev,s.st_ino) or not stat.S_ISREG(s.st_mode) or s.st_size > limit:
                raise AuditError("Fichier régulier de votre utilisateur requis (maximum 2 Mo).")
            return f.read(limit+1)
    except (OSError, UnicodeError) as e:
        raise AuditError(f"Lecture refusée : {path}: {e}") from e

def private_write(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os,'O_NOFOLLOW',0), 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(text)

def device_id():
    p = state_dir()/"device-id"
    try:
        private_write(p, "MSC-"+uuid.uuid4().hex.upper()+"\n")
    except FileExistsError:
        pass
    value = owned_text(p).strip()
    if not value.startswith("MSC-") or len(value) != 36:
        raise AuditError("Device ID invalide ; vérifiez le fichier d'état.")
    return {"device_id": value}

def record(command, result):
    data = {"command":command,"time":datetime.now(timezone.utc).isoformat(),"result":result}
    path = None
    try:
        path = state_dir()/(uuid.uuid4().hex+'.json')
        private_write(path, json.dumps(data, ensure_ascii=False, indent=2))
    except OSError as error:
        # Une écriture interrompue (par exemple disque plein pendant f.write) peut laisser
        # un fichier d'audit partiel qui ferait échouer report() ensuite : on le supprime.
        if path is not None:
            try:
                path.unlink()
            except OSError:
                pass
        # Le journal d'audit est accessoire : ne pas faire échouer une commande de lecture
        # seulement parce que l'écriture du journal a échoué.
        hint = disk_full_hint(error) or f"journal d'audit non enregistré ({error})"
        print(f"Avertissement : {hint}", file=sys.stderr)
    return result

def report(output, fmt):
    entries = []
    for p in sorted(state_dir().glob('*.json')):
        try:
            entries.append(json.loads(owned_text(p)))
        except (AuditError, ValueError):
            # Ignorer un fichier d'audit illisible ou partiel plutôt que de tout bloquer.
            continue
    text = json.dumps({"audits":entries},ensure_ascii=False,indent=2)
    if fmt == 'txt':
        text = "MON-SECRET-COOKIE — Rapport défensif\n\n" + "\n\n".join(
            f"{e['time']} — {e['command']}\n"+json.dumps(e['result'],ensure_ascii=False,indent=2) for e in entries)
    private_write(output, text+'\n')
    return {"rapport":str(output),"audits":len(entries)}
