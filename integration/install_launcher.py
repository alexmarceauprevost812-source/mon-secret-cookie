#!/usr/bin/python3
"""Installer exclusivement le nouveau lanceur, sans écrasement ni profil modifié."""
import argparse
import difflib
import os
from pathlib import Path
import sys


def install(destination=None, source=None, preview=False):
    destination = Path(destination) if destination is not None else Path.home()/'.local/bin/prevost'
    source = Path(source) if source is not None else Path(__file__).with_name('prevost.py')
    payload = source.read_bytes()
    if os.path.lexists(destination):
        if destination.is_symlink() or not destination.is_file():
            raise FileExistsError('Destination existante (lien ou fichier non régulier), laissée intacte : '+str(destination))
        difference = ''.join(difflib.unified_diff(destination.read_text().splitlines(True),
                             payload.decode().splitlines(True), fromfile=str(destination), tofile=str(source)))
        if preview:
            return {'installed': False, 'exists': True, 'diff': difference or 'Contenu identique.'}
        raise FileExistsError('Lanceur existant laissé intact ; examiner --preview et obtenir une approbation avant remplacement.')
    if preview:
        return {'installed': False, 'exists': False, 'destination': str(destination)}
    if destination.parent.is_symlink():
        raise OSError('Répertoire de destination symbolique refusé.')
    destination.parent.mkdir(parents=True, exist_ok=True)
    # O_EXCL refuse aussi une création concurrente ou un lien apparu après le précontrôle.
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o700)
    created = os.fstat(fd)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fchmod(stream.fileno(), 0o700)
            os.fsync(stream.fileno())
    except BaseException:
        try:
            current = destination.lstat()
            if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                destination.unlink()
        except OSError:
            pass
        raise
    return {'installed': True, 'destination': str(destination)}


def main():
    import json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--preview', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(install(preview=args.preview), ensure_ascii=False, indent=2))
        return 0
    except (OSError, UnicodeError) as error:
        print('Erreur : '+str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
