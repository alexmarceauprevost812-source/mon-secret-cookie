"""Dictionnaire borné sur MD5 de laboratoire ou fichiers autorisés."""
import os
import hashlib
import re
import tempfile
from pathlib import Path
from .core import AuditError, owned_text, private_write, run, state_dir

def password_lab(engine, hashes=None, wordlist=None, authorized=False):
    if hashes and not authorized:
        raise AuditError("Hashes fournis : --authorized requis.")
    if bool(hashes)!=bool(wordlist):
        raise AuditError("Fournissez ensemble --hashes et --wordlist.")
    if hashes:
        lines=owned_text(hashes).splitlines()
        words=owned_text(wordlist)
        if not 1<=len(lines)<=100 or any(not re.fullmatch('[0-9a-fA-F]{32}',h) for h in lines):
            raise AuditError("1 à 100 hashes MD5 bruts (32 caractères hexadécimaux) requis.")
        if len(words.splitlines())>10000:
            raise AuditError("Dictionnaire limité à 10 000 lignes.")
    else:
        lines=[hashlib.md5(b'cookie-demo').hexdigest()]
        words='bonjour\ncookie-demo\nexemple\n'
    with tempfile.TemporaryDirectory(prefix='password-lab-',dir=state_dir()) as directory:
        base=Path(directory)
        h=base/'hashes.txt'; w=base/'words.txt'
        private_write(h,'\n'.join(lines)+'\n'); private_write(w,words)
        if engine=='john':
            # Le paquet john Ubuntu/Kali non-jumbo accepte le format dynamique MD5.
            private_write(base/'john.txt','\n'.join('lab'+str(i)+':$dynamic_0$'+v for i,v in enumerate(lines))+'\n')
            run(['john','--format=dynamic_0',f'--session={base / "session"}',f'--wordlist={w}',f'--pot={base / "john.pot"}',str(base/'john.txt')],timeout=60)
            result=run(['john','--show','--format=dynamic_0',f'--pot={base / "john.pot"}',str(base/'john.txt')])
            matched=sum(1 for line in result.splitlines() if re.match(r'^lab[0-9]+:',line))
        else:
            # Hashcat retourne 1 si le dictionnaire est épuisé : résultat normal.
            import subprocess, shutil
            if not shutil.which('hashcat'):
                raise AuditError("Dépendance absente : hashcat")
            try:
                (base/'data').mkdir(); (base/'cache').mkdir()
                env=dict(os.environ, XDG_DATA_HOME=str(base/'data'), XDG_CACHE_HOME=str(base/'cache'))
                p=subprocess.run(['hashcat','--session','msc-lab','-m','0','-a','0','--runtime','30','--potfile-disable',
                    '--restore-disable','--quiet','--outfile',str(base/'matches'), '--outfile-format','1',str(h),str(w)],
                    capture_output=True,text=True,timeout=60,cwd=base,env=env)
            except subprocess.TimeoutExpired as e:
                raise AuditError("Hashcat : délai dépassé.") from e
            if p.returncode not in (0,1):
                raise AuditError('Hashcat : backend indisponible ou erreur : '+p.stderr[:500])
            matched=len((base/'matches').read_text().splitlines()) if (base/'matches').exists() else 0
        return {'engine':engine,'mode':'MD5 pédagogique, dictionnaire borné','hashes':len(lines),
                'matched':matched,'plaintext':'non affiché et non enregistré dans les rapports'}
