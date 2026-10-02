"""Analyse de fichiers Netscape locaux sans exposition des valeurs."""
from pathlib import Path
import time
from .core import AuditError, owned_text, private_write

DEMO = "# Netscape HTTP Cookie File\n#HttpOnly_localhost\tFALSE\t/\tFALSE\t0\tlab_session\tFICTIF_SANS_SESSION_REELLE\nlocalhost\tFALSE\t/\tTRUE\t0\tlab_secure\tFICTIF\n"

def analyze(path):
    rows=[]
    invalid=0
    for line in owned_text(path).splitlines():
        http_only=line.startswith('#HttpOnly_')
        if http_only:
            line=line[len('#HttpOnly_'):]
        elif line.startswith('#') or not line.strip():
            continue
        fields=line.split('\t')
        if len(fields)!=7 or fields[1] not in ('TRUE','FALSE') or fields[3] not in ('TRUE','FALSE'):
            invalid+=1
            continue
        domain,sub,path_value,secure,expires,name,_value=fields
        try:
            expiry=int(expires)
        except ValueError:
            invalid+=1
            continue
        rows.append({'domain':domain,'name':name,'path':path_value,'secure':secure=='TRUE',
                     'http_only':http_only,'session':expiry==0,'expired':expiry!=0 and expiry<time.time(),
                     'same_site':'non représenté dans cookies.txt'})
    return {'file':str(path),'cookies':rows,'invalid_lines':invalid,'values':'masquées'}

def search(directory):
    base=Path(directory).resolve()
    if not base.is_dir():
        raise AuditError("Répertoire inexistant.")
    found=[]
    # Profondeur bornée ; aucun lien symbolique suivi, aucun profil navigateur lu.
    import os
    for current, dirs, names in os.walk(base,followlinks=False):
        depth=len(Path(current).relative_to(base).parts)
        dirs[:] = [d for d in dirs if not (Path(current)/d).is_symlink()] if depth<4 else []
        if 'cookies.txt' in names:
            p=Path(current)/'cookies.txt'
            if not p.is_symlink() and p.stat().st_uid==os.getuid():
                found.append(str(p))
        if len(found)>=100:
            break
    return {'files':found}

def demo(output):
    private_write(output,DEMO)
    return analyze(output)
