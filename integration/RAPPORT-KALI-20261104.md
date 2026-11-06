# Prévost : outils Kali et autorisations

Branche : `codex/prevost-kali-20261104-200037`.
Sauvegarde privée : `~/.local/state/prevost-backups/20261104-200037` (dossiers 700, fichiers 600).
Le projet avait déjà des changements dans cli.py/core.py et des rapports non suivis : ils sont conservés.

Démarrage de l'atelier existant enrichi :

```sh
/home/ti-lex-al/.local/bin/prevost-ia
```

Depuis `/lexos`, le choix 8 conserve ce lanceur. `prevost` utilise désormais le projet demandé ; les commandes existantes `cerveau` et `programmeur` restent dirigées vers leur projet brain-test d'origine. Modèles, GGUF, menus, lexos-ia et autres lanceurs conservés.

Commandes :

```sh
prevost catalogue
prevost aide-outil nmap
prevost proposer 'inventaire réseau' --cible AUTH-IDENTIFIANT
prevost mission --cible AUTH-IDENTIFIANT
prevost nouvelles
prevost nouvelles --autoriser
prevost autorisations
prevost revoquer AUTH-IDENTIFIANT
prevost interfaces
```

Dans l'atelier : `/kali catalogue`, `/kali aide-outil nmap`, `/kali proposer "inventaire réseau" --cible AUTH-…`, `/nouvelles` (choix 11 : « Nouvelles cibles → Autoriser la sélection »), `/autorisations`, `/revoquer AUTH-…`.

`mission` prépare seulement. Seul `--executer` déclenche la mission : vérification du registre, inventaire, puis TCP connect si autorisé. Aucun argument libre généré par l'IA ne devient une commande. Les autres outils sont découverts et leur aide peut être consultée ; leurs opérations actives hors gabarits ne sont pas automatisées. Une proposition d'aide indique séparément que seule l'aide locale a été exécutée. Aucun texte de l'IA ne lance automatiquement un outil.

Les nouvelles IP proviennent des inventaires et observations hors périmètre déjà persistés dans les missions SQLite. Une IP couverte hérite de la date, de l'expiration, du périmètre et des tests exacts de l'autorisation valide la plus spécifique ; les droits de plusieurs autorisations ne sont jamais fusionnés. Une IP hors périmètre reste en attente. La sélection demande responsable, preuve, expiration et limites, puis `AUTORISER IP`. Elle crée uniquement un /32 ou /128 et ne déclenche aucun scan. Une révocation retire immédiatement l'héritage sans effacer l'observation.

Catalogue observé sur l'hôte : 26/29 outils. Présents : nmap, tshark, dumpcap, wireshark, tcpdump, lynis, hashcat, john, aircrack-ng, airmon-ng, airodump-ng, iw, ip, ss, sqlmap, gobuster, ffuf, whatweb, curl, openssl, dig, whois, exiftool, strings, file, binwalk. Non détectés : wifite, nikto, radare2. Le catalogue est borné, non exhaustif de tous les paquets Kali. Présence ne signifie pas droits effectifs. Le conteneur Kali est non vérifié : Podman est bloqué par un système de fichiers en lecture seule ; aucun démarrage ni réparation automatique.

Les lectures de fichiers, aides et scans TCP connect fonctionnent sans sudo sous réserve des droits des fichiers. Capture réseau, radio et paquets bruts nécessitent des permissions spécifiques et ne sont pas automatisés ici. Seule opération sudo ajoutée : `interfaces --sudo --executer`, qui affiche les risques, exige un TTY et `OUI`, vérifie les propriétaires/modes des chemins, puis appelle exclusivement `/usr/bin/sudo -- /usr/bin/dumpcap -D`. Elle liste les interfaces sans capture. Par défaut `interfaces --executer` tente cette lecture sans sudo et signale les refus sans escalade automatique. Aucun sudoers, groupe, capacité, Python ou shell privilégié n'est modifié. L'environnement de validation expose les binaires avec un propriétaire non-root : l'élévation est alors refusée. Prévost entier refuse de tourner en root.

Consignes IA en français, catalogue rafraîchi à chaque demande, permissions et proposition/exécution distinctes, résultats jamais inventés, sorties et aides traitées comme données non fiables. Rapports privés et journaux à métadonnées typées ; sorties d'aide filtrées des caractères de contrôle et motifs usuels de secrets. Aucun filtre textuel ne peut reconnaître tous les secrets : les sorties brutes ne sont pas journalisées par cette intégration.

Vérification : `python3 integration/test_local.py` — **128 tests réussis**, sans scan réseau. Données simulées : cible inconnue/révoquée/expirée, héritage, sélection explicite, refus hors périmètre, révocation, absence de sudo implicite, TTY et confirmation, chemins dangereux, échec de sudo, permissions 600 et secrets exclus des journaux. Aides réelles Nmap/Tshark/Hashcat : code 0. Historique réel : 0 nouvelle IP, aucune découverte active effectuée.

Un test historique a réécrit les rapports cookie dans le dossier réel lors du premier passage. Le contenu original de cookie.txt et cookie.json a été restauré depuis leur archive automatique ; cookie.txt correspond à son SHA-256 d'avant modification. Le lanceur de tests ajouté isole désormais ces rapports dans un dossier temporaire.

Le centre Prévost de `terminal-codex` conserve ses fonctions et propose aussi les nouvelles cibles (7), les autorisations (8) et leur révocation (9). Son original est sauvegardé.
