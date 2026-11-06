#!/usr/bin/python3
"""Lanceur LexOS/SSH : utilise le venv existant sans dépendre du dossier courant."""
import os
from pathlib import Path
import sys


def main():
    source = Path(__file__).resolve()
    project = source.parent.parent if source.parent.name == 'integration' else Path.home()/'LexOS-Projets/mon-secret-cookie'
    # Conserver les anciennes fonctions du lanceur de test sans déplacer leur code.
    if len(sys.argv) > 1 and sys.argv[1] in ('cerveau', 'programmeur'):
        project = Path.home()/'LexOS-Projets/mon-secret-cookie-brain-test'
    python = project/'.venv/bin/python'
    if not python.is_file() or not os.access(python, os.X_OK) or not (project/'mon_secret_cookie/fusion.py').is_file():
        print('Erreur : projet ou venv existant introuvable : '+str(project), file=sys.stderr)
        return 1
    # -I ignore PYTHONPATH/PYTHONHOME et le dossier courant ; seul le projet choisi est ajouté.
    bootstrap = 'import sys; sys.path.insert(0, '+repr(str(project))+'); from mon_secret_cookie.fusion import main; sys.exit(main())'
    environment = os.environ.copy()
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    os.execve(str(python), [str(python), '-I', '-B', '-c', bootstrap, *sys.argv[1:]], environment)


if __name__ == '__main__':
    sys.exit(main())
