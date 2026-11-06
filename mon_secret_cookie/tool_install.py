"""Installateur explicite du catalogue APT ; aucune installation à l’import."""
import os
import sys
import subprocess
from . import core, environments, fusion

PACKAGES = {
    'nmap':'nmap','tshark':'tshark','dumpcap':'wireshark-common','wireshark':'wireshark',
    'tcpdump':'tcpdump','lynis':'lynis','hashcat':'hashcat','john':'john','wifite':'wifite',
    'aircrack-ng':'aircrack-ng','airodump-ng':'aircrack-ng','iw':'iw','ip':'iproute2','ss':'iproute2',
    'nikto':'nikto','sqlmap':'sqlmap','gobuster':'gobuster','ffuf':'ffuf','whatweb':'whatweb',
    'curl':'curl','openssl':'openssl','dig':'dnsutils','whois':'whois',
    'exiftool':'libimage-exiftool-perl','strings':'binutils','file':'file',
    'binwalk':'binwalk','radare2':'radare2','git':'git','nano':'nano',
    'notify-send':'libnotify-bin','flask':'python3-flask',
}


def plan(kali=False):
    environment='kali-lexos' if kali else 'LexOS'
    prefix=[]
    if kali:
        detected=environments.discover(fusion.executable,fusion.version_probe)
        if detected.get('status') != 'available':
            raise core.AuditError('Kali doit être accessible et déjà actif : '+detected.get('reason','indisponible'))
        distrobox=fusion.executable('distrobox')
        if not distrobox:
            raise core.AuditError('Distrobox manquant.')
        prefix=[distrobox,'enter','--name',detected['launcher']['container'],'--']
        apt='apt-get'
    else:
        apt=fusion.executable('apt-get')
        if not apt:
            raise core.AuditError('Installateur limité à APT (Debian/Ubuntu/Kali). Gestionnaire APT absent.')
    packages=sorted(set(PACKAGES.values()))
    command=[*prefix,'sudo','--',apt,'install','--yes','--no-install-recommends',*packages]
    return {'environnement':environment,'execute':False,'commande':command,'paquets':packages,
            'outils':PACKAGES,'hors_catalogue_apt':['codex','ollama'],
            'message':'Installe les paquets du catalogue, sans purge ni mise à niveau générale. '
                      'Les paquets sans candidat dans les dépôts seront signalés et exclus. '
                      'Aucun dépôt tiers ni configuration radio ajouté. Codex et Ollama existants sont conservés.',
            'activation':'prevost installer-outils '+('--kali ' if kali else '')+'--executer'}


def install(kali=False, execute=False):
    result=plan(kali)
    if not execute:
        return result
    if not sys.stdin.isatty():
        raise core.AuditError('Installation : terminal interactif requis pour sudo ; afficher le plan sans --executer.')
    command=result['commande']
    apt_index=command.index('install')-1
    prefix=command[:apt_index-2]  # Retirer sudo -- et apt-get ; conserver Distrobox.
    available=[]
    unavailable=[]
    for package in result['paquets']:
        try:
            query=subprocess.run([*prefix,'apt-cache','policy',package],capture_output=True,
                                 text=True,timeout=15,check=False,env=dict(os.environ,LC_ALL='C'))
        except (OSError,subprocess.TimeoutExpired):
            unavailable.append(package)
            continue
        if query.returncode==0 and any(line.strip().startswith('Candidate:') and '(none)' not in line
                                      for line in query.stdout.splitlines()):
            available.append(package)
        else:
            unavailable.append(package)
    if not available:
        raise core.AuditError('Aucun candidat APT disponible. Vérifier les dépôts depuis le terminal hôte.')
    argv=command[:command.index('--no-install-recommends')+1]+available
    try:
        process=subprocess.run(argv,check=False,timeout=1800)
    except subprocess.TimeoutExpired as error:
        raise core.AuditError('Délai installation dépassé ; vérifier l’état APT avant une nouvelle tentative.') from error
    return {**result,'execute':True,'commande':argv,'code_retour':process.returncode,
            'etat':'disponible' if process.returncode==0 and not unavailable else 'partiel' if process.returncode==0 else 'erreur',
            'paquets_sans_candidat':unavailable,
            'message':'Installation terminée ; relancer prevost outils --diagnostic pour vérifier. '
                      'Les droits GPU/radio et les services restent à valider.'}
