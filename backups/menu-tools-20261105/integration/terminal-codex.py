#!/usr/bin/env python3
import os
import shutil
import subprocess

MENU = """
⚜ TERMINAL-CODEX — IA PRO

[1] CODEX CLI
[2] OLLAMA — IA LOCALE
[3] QWEN CODER
[4] TI-PRÉVOST IA
[5] REA — AGENT IA
[6] GITHUB — PROJETS
[7] ÉDITEUR PYTHON
[8] MODÈLES GGUF
[9] DIAGNOSTICS IA
[L] AGENT LOCAL — CHOISIR LE MODÈLE

[0] Quitter
[R] Rafraîchir
[A] Aide
"""

def run(cmd):
    if not shutil.which(cmd[0]):
        print(f"❌ {cmd[0]} introuvable")
        return
    try:
        subprocess.run(cmd, check=False)
    except OSError as error:
        print(error)


def menu_prevost():
    while True:
        print("""
⚜ TI-PRÉVOST — CENTRE IA

[1] État du cerveau
[2] Plans enregistrés
[3] Programmeur
[4] Missions
[5] Diagnostics
[6] Modèles Ollama
[7] Nouvelles cibles → Autoriser la sélection
[8] Consulter les autorisations
[9] Révoquer une autorisation

[0] Retour
""")
        choix = input("⚜ Prévost > ").strip()

        if choix == "1":
            run(["prevost", "cerveau", "etat"])
        elif choix == "2":
            run(["prevost", "cerveau", "plans"])
        elif choix == "3":
            run(["prevost", "programmeur", "rapport"])
        elif choix == "4":
            menu_prevost()
        elif choix == "5":
            run(["prevost", "diagnostic"])
        elif choix == "6":
            run(["ollama", "list"])
        elif choix == "7":
            run(["prevost", "nouvelles", "--autoriser"])
        elif choix == "8":
            run(["prevost", "autorisations"])
        elif choix == "9":
            identifiant = input("Identifiant AUTH-… à révoquer : ").strip()
            if identifiant:
                run(["prevost", "revoquer", identifiant])
        elif choix == "0":
            return
        else:
            print("Choix invalide")


def menu_prevost():
    while True:
        print("""
⚜ TI-PRÉVOST — CENTRE IA

[1] État du cerveau
[2] Plans enregistrés
[3] Programmeur
[4] Missions
[5] Diagnostics
[6] Modèles Ollama
[7] Nouvelles cibles → Autoriser la sélection
[8] Consulter les autorisations
[9] Révoquer une autorisation

[0] Retour
""")
        choix = input("⚜ Prévost > ").strip()

        if choix == "1":
            run(["prevost", "cerveau", "etat"])
        elif choix == "2":
            run(["prevost", "cerveau", "plans"])
        elif choix == "3":
            run(["prevost", "programmeur", "rapport"])
        elif choix == "4":
            run(["prevost", "mission"])
        elif choix == "5":
            run(["prevost", "diagnostic"])
        elif choix == "6":
            run(["ollama", "list"])
        elif choix == "7":
            run(["prevost", "nouvelles", "--autoriser"])
        elif choix == "8":
            run(["prevost", "autorisations"])
        elif choix == "9":
            identifiant = input("Identifiant AUTH-… à révoquer : ").strip()
            if identifiant:
                run(["prevost", "revoquer", identifiant])
        elif choix == "0":
            return
        else:
            print("Choix invalide")


# LEXOS_AGENT_LOCAL_V1
def agent_local():
    import json
    import urllib.request
    from pathlib import Path

    try:
        with urllib.request.urlopen(
            "http://127.0.0.1:11435/api/tags", timeout=5
        ) as response:
            models = [
                m["name"] for m in json.load(response).get("models", [])
            ]
        if not models:
            print("Aucun modèle local disponible.")
            return

        for i, name in enumerate(models, 1):
            print(f"[{i}] {name}")
        selection = input("Modèle [0 = retour] > ").strip()
        if selection == "0":
            return
        if not selection.isdigit() or not 1 <= int(selection) <= len(models):
            print("Choix invalide.")
            return
        model = models[int(selection) - 1]

        folder = input("Dossier du projet [vide = dossier actuel] > ").strip()
        project = Path(folder).expanduser().resolve() if folder else Path.cwd()
        if not project.is_dir():
            print("Dossier introuvable.")
            return

        print(f"Agent local : {model}")
        print(f"Projet : {project}")
        run([
            "codex",
            "-c", 'model_provider="lexos_local"',
            "-c", 'model_providers.lexos_local.name="LexOS Ollama"',
            "-c", 'model_providers.lexos_local.base_url="http://127.0.0.1:11435/v1"',
            "-c", 'model_providers.lexos_local.wire_api="responses"',
            "-c", 'model_providers.lexos_local.requires_openai_auth=false',
            "-m", model,
            "-C", str(project),
            "--sandbox", "workspace-write",
            "--ask-for-approval", "on-request",
        ])
    except Exception as error:
        print(f"Agent local : {error}")

def action(choice):
    if choice.lower() == "l":
        agent_local()
        return
    if choice == "1":
        run(["codex"])
    elif choice == "2":
        run(["ollama", "list"])
    elif choice == "3":
        run(["ollama", "run", "qwen2.5-coder:7b"])
    elif choice == "4":
        menu_prevost()
    elif choice == "5":
        print("REA : intégration à configurer")
    elif choice == "6":
        run(["git", "status"])
    elif choice == "7":
        run(["nano"])
    elif choice == "8":
        run(["ollama", "list"])
    elif choice == "9":
        run(["python3", "--version"])
        run(["ollama", "--version"])
        run(["codex", "--version"])
    elif choice.lower() == "a":
        print("Terminal dédié aux outils IA.")
    elif choice.lower() != "r":
        print("Commande inconnue")

def main():
    while True:
        print(MENU)
        choice = input("⚜ Choix > ").strip()
        if choice == "0":
            break
        action(choice)

if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nTerminal fermé.")
