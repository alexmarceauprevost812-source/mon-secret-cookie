"""Forge : l'IA locale (modèle GGUF via llama-server) écrit un outil ; rien ne s'exécute sans accord."""
import atexit
import glob
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from . import core

PORT = int(os.environ.get('MSC_FORGE_PORT', '8089'))
SYSTEM = ("Tu es un programmeur expert pour Termux et Linux (sans root). Tu écris UN SEUL script complet, "
          "court et fonctionnel, en {langue}, dans un seul bloc de code. Pas d'explication. "
          "Messages en français, bibliothèque standard seulement, aucune action destructrice sans confirmation. "
          "N'ajoute pas d'option --help ou -h : argparse le fait déjà.")


def model_dirs():
    home = Path.home()
    return [Path(os.environ.get('LEX_MODELES', home/'modeles')), home/'storage/downloads']


def models():
    found = []
    for directory in model_dirs():
        found += sorted(glob.glob(str(directory/'*.gguf')))
    return found


def default_model(found):
    """Le premier modèle « coder », sinon le premier de la liste."""
    return next((m for m in found if 'coder' in Path(m).name.lower()), found[0])


def pick_model(name=None, ask=input):
    found = models()
    if not found:
        raise core.AuditError(f'Aucun modèle .gguf dans {model_dirs()[0]}.')
    if name:
        match = next((m for m in found if name.lower() in Path(m).name.lower()), None)
        if not match:
            raise core.AuditError(f'Aucun modèle ne correspond à « {name} ».')
        return match
    default = default_model(found)
    if len(found) == 1:
        return default
    for i, m in enumerate(found, 1):
        print(f'{i:2d}) {Path(m).name}  ({os.path.getsize(m)/1e9:.1f} Go)' + ('  <- défaut' if m == default else ''))
    answer = ask(f'Modèle [{found.index(default)+1}] : ').strip()
    try:
        return found[int(answer)-1] if answer else default
    except (ValueError, IndexError):
        return default


def extract(text):
    """Le plus long bloc de code de la réponse, sinon la réponse entière."""
    blocks = re.findall(r'```[\w+-]*\n(.*?)```', text, re.S)
    return (max(blocks, key=len) if blocks else text).strip('\n') + '\n'


def check(code, langue):
    """None si la syntaxe est valide, sinon le message d'erreur."""
    if langue == 'python':
        try:
            compile(code, 'outil', 'exec')
            return None
        except SyntaxError as error:
            return f'ligne {error.lineno} : {error.msg}'
    done = subprocess.run(['bash', '-n'], input=code, capture_output=True, text=True)
    return None if done.returncode == 0 else done.stderr.strip()


def bin_dir():
    prefix = os.environ.get('PREFIX')
    return Path(prefix)/'bin' if prefix and 'com.termux' in prefix else Path.home()/'.local/bin'


def with_shebang(code, langue):
    exe = sys.executable if langue == 'python' else (shutil.which('bash') or '/bin/bash')
    lines = code.split('\n')
    if lines and lines[0].startswith('#!'):
        lines = lines[1:]
    return f'#!{exe}\n' + '\n'.join(lines)


def safe_name(text, fallback='monoutil'):
    return re.sub(r'[^a-z0-9_-]', '', text.strip().lower()) or fallback


def save(code, langue, name, install=False, ask=input):
    out = Path.home()/'outils-ia'
    out.mkdir(parents=True, exist_ok=True)
    path = out/f"{name}.{'py' if langue == 'python' else 'sh'}"
    path.write_text(with_shebang(code, langue), encoding='utf-8')
    path.chmod(0o755)
    print(f'Sauvegardé : {path}')
    installed = False
    if install:
        target = bin_dir()/name
        if target.exists() and ask(f'La commande « {name} » existe déjà. Remplacer ? (o/N) ').strip().lower() != 'o':
            return path, False
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(path, target)
        target.chmod(0o755)
        installed = True
        print(f'✓ Commande installée : {name}')
    return path, installed


class Server:
    """llama-server local (127.0.0.1 seulement), arrêté à la sortie."""
    def __init__(self, model):
        exe = shutil.which('llama-server')
        if not exe:
            raise core.AuditError('llama-server absent. Lancez : pkg install llama-cpp')
        self.log = core.state_dir()/'forge-serveur.log'
        self.process = subprocess.Popen(
            [exe, '-m', model, '-c', '4096', '-t', str(os.cpu_count() or 4), '--host', '127.0.0.1', '--port', str(PORT)],
            stdout=subprocess.DEVNULL, stderr=open(self.log, 'w'))
        atexit.register(self.stop)

    def wait(self, limit=900):
        print('Chargement du modèle (quelques minutes possibles)...', flush=True)
        start = time.time()
        while time.time()-start < limit:
            if self.process.poll() is not None:
                raise core.AuditError(f'Le serveur IA s\'est arrêté. Voir {self.log}')
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{PORT}/health', timeout=3) as response:
                    if response.status == 200:
                        print(f'Modèle prêt ({int(time.time()-start)} s).')
                        return
            except (urllib.error.URLError, OSError):
                pass
            time.sleep(2)
        raise core.AuditError('Le modèle met trop de temps à charger.')

    def chat(self, messages):
        body = json.dumps({'messages': messages, 'temperature': 0.2, 'max_tokens': 1800}).encode()
        request = urllib.request.Request(f'http://127.0.0.1:{PORT}/v1/chat/completions', data=body,
                                         headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=3600) as response:
            return json.load(response)['choices'][0]['message']['content']

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(5)
            except subprocess.TimeoutExpired:
                self.process.kill()


def run(description, langue='python', model=None, ask=input, server_class=Server):
    """Boucle interactive : générer, montrer, vérifier, puis installer / modifier / exécuter sur accord."""
    description = description.strip()
    if not description:
        raise core.AuditError('Description vide.')
    server = server_class(pick_model(model, ask))
    try:
        server.wait()
        messages = [{'role': 'system', 'content': SYSTEM.format(langue=langue)},
                    {'role': 'user', 'content': 'Écris cet outil : '+description}]
        default = '-'.join(re.findall(r'[a-z0-9]+', description.lower())[:2]) or 'monoutil'
        while True:
            print("\nL'IA écrit le code (patience)...", flush=True)
            start = time.time()
            reply = server.chat(messages)
            messages.append({'role': 'assistant', 'content': reply})
            code = extract(reply)
            error = check(code, langue)
            print('\n'+'='*50+'\n'+code+'='*50)
            print(f'(généré en {int(time.time()-start)} s) '+('✓ syntaxe OK' if error is None else '⚠️ erreur de syntaxe : '+error))
            while True:
                choice = ask('[i]nstaller  [m]odifier  [e]xécuter  [s]auvegarder  [q]uitter > ').strip().lower()
                if choice == 'q':
                    return {'outil': None, 'installe': False}
                if choice in ('i', 's'):
                    name = safe_name(ask(f'Nom de la commande [{default}] : '), default)
                    path, installed = save(code, langue, name, install=choice == 'i', ask=ask)
                    return {'outil': name, 'fichier': str(path), 'langue': langue, 'installe': installed,
                            'syntaxe_ok': error is None}
                if choice == 'e' and ask('Exécuter ce code maintenant ? Tapez OUI : ') == 'OUI':
                    path, _ = save(code, langue, 'essai', ask=ask)
                    subprocess.run([str(path)])
                if choice == 'm':
                    change = ask("Qu'est-ce qu'on change ? ").strip()
                    if error:
                        change += f'\n(Erreur de syntaxe à corriger : {error})'
                    if change:
                        messages.append({'role': 'user', 'content': 'Modifie le script : '+change+'\nRéponds avec le script complet.'})
                        break
    finally:
        server.stop()
