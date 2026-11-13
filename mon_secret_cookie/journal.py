"""Journal de bord : notes privées sur l'appareil, questions et résumés par l'IA locale (GGUF)."""
from datetime import datetime, timedelta
import json
import os
import re
from . import core, forge

LIMIT = 6000  # caractères de notes envoyés au modèle (contexte de 4096 jetons)
SYSTEM = ("Tu es l'assistant d'un journal de bord personnel. Réponds en français, court et clair, "
          "seulement à partir des notes fournies. Si la réponse n'est pas dans les notes, dis-le.")


def path():
    return core.state_dir()/'journal.jsonl'


def notes():
    if not path().exists():
        return []
    found = []
    for line in core.owned_text(path()).splitlines():
        try:
            note = json.loads(line)
        except ValueError:
            continue  # ligne abîmée (écriture interrompue) : ignorée sans bloquer le journal
        if isinstance(note, dict) and isinstance(note.get('date'), str) and isinstance(note.get('texte'), str):
            found.append(note)
    return found


def add(text):
    text = ' '.join(text.split())
    if not text:
        raise core.AuditError('Note vide.')
    note = {'date': datetime.now().strftime('%Y-%m-%d %H:%M'), 'texte': text}
    fd = os.open(path(), os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'a', encoding='utf-8') as f:
        f.write(json.dumps(note, ensure_ascii=False)+'\n')
    return note


def search(word):
    word = word.strip().lower()
    return [n for n in notes() if word and word in n['texte'].lower()]


def recent(days=7):
    since = (datetime.now()-timedelta(days=days)).strftime('%Y-%m-%d %H:%M')
    return [n for n in notes() if n['date'] >= since]


def words(text):
    return {w for w in re.findall(r'\w+', text.lower()) if len(w) > 3}


def select(found, question=''):
    """Les notes qui partagent des mots avec la question, sinon les plus récentes, dans la limite du contexte."""
    keys = words(question)
    scored = [(len(keys & words(n['texte'])), i, n) for i, n in enumerate(found)]
    hits = [s for s in scored if s[0]]
    ordered = sorted(hits, key=lambda s: (-s[0], -s[1])) if hits else scored[::-1]
    kept, total = [], 0
    for _, i, n in ordered:
        total += len(n['texte'])+20
        if total > LIMIT:
            break
        kept.append((i, n))
    return [n for _, n in sorted(kept, key=lambda k: k[0])]


def ask_ai(server, request, found):
    block = '\n'.join(f"[{n['date']}] {n['texte']}" for n in found)
    return server.chat([{'role': 'system', 'content': SYSTEM},
                        {'role': 'user', 'content': f'Notes :\n{block}\n\nDemande : {request}'}]).strip()


def show(found):
    if not found:
        print('  (aucune note)')
    for n in found:
        print(f"{n['date']}  {n['texte']}")


def run(model=None, ask=input, server_class=forge.Server):
    """Menu du journal. Le modèle n'est chargé qu'à la première demande IA, puis arrêté à la sortie."""
    server = None

    def ai(request, found):
        nonlocal server
        if not found:
            print('  (aucune note à analyser)')
            return
        if server is None:
            server = server_class(forge.pick_model(model, ask))
            server.wait()
        print("L'IA réfléchit...", flush=True)
        print(ask_ai(server, request, found))

    try:
        while True:
            print('\n— JOURNAL DE BORD —\n1 Écrire une note  2 Dernières notes  3 Chercher un mot\n'
                  "4 Question à l'IA  5 Résumé de la semaine (IA)  0 Retour")
            choice = ask('Journal > ').strip()
            if choice == '0':
                return {'notes': len(notes())}
            try:
                if choice == '1':
                    add(ask('Note : '))
                    print('  enregistré.')
                elif choice == '2':
                    show(notes()[-10:])
                elif choice == '3':
                    show(search(ask('Mot : ')))
                elif choice == '4':
                    question = ask('Question : ').strip()
                    if question:
                        ai(question, select(notes(), question))
                elif choice == '5':
                    ai('Fais un résumé en quelques points de ces notes.', select(recent()))
            except core.AuditError as error:
                print(f'Erreur : {error}')
    finally:
        if server is not None:
            server.stop()
