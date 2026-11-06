# PRÉVOST — diagnostics, menu et installateur — 2026-11-05

Inspection : ARCHITECTURE.md, README.md, validations existantes, CLI, fusion,
registre, adaptateurs de plateforme, rapports privés, intégrations et tests.
Aucun AGENTS.md trouvé dans le projet ou ses dossiers parents inspectés.
Modifications préexistantes conservées ; aucun commit ni déploiement effectué.

Sauvegardes : backups/menu-tools-20261105/ et
backups/prevost-diagnostics-20261105/ (incluant les lanceurs avant réparation).
Le lanceur mon-secret-cookie installé était un lien vers un script dont l’import
échouait (ModuleNotFoundError) : remplacement du lien par un lanceur du venv du
projet, sans modifier le venv initial ciblé. Son chemin initial est conservé dans
launcher-original.json. terminal-codex source et installé retrouvent Codex dans
son installation existante hors PATH ; erreurs de sous-commandes signalées.
Les outils de /usr/sbin sont maintenant résolus même si ce dossier manque au PATH.

## Vérifications exécutées

- `python3 integration/test_local.py` : **179 tests réussis**, 0,579 s.
- Couverture ajoutée : états distincts disponible/manquant/erreur ; John classique ;
  aides à arguments fermés ; conteneur arrêté non lancé ; résolution sbin/Codex ;
  orchestration fictive, erreurs et délais ; exclusion des secrets des rapports ;
  permissions 600/700 ; journal ajouté sans écrasement ; échec de stockage bloquant ;
  export JSON final cohérent ; notification unique de fin ; installation simulée et
  exclusion des paquets sans candidat ; aucun shell=True ni scan dans ces tests. Vérifications supplémentaires :
  un nouvel appareil dans prevost surveillance déclenche une seule alerte sans
  appel au moteur actif ; statut du service de notification simulé séparément.
- `prevost outils` : succès depuis /tmp, 64 entrées LexOS/Kali, erreurs Kali explicites.
- `prevost installer-outils` : succès, plan de 30 paquets APT, execute=false.
- `prevost aide-outil john` : succès réel, aide de John 1.9.0 sans chargement de données.
- `prevost diagnostic --help` et `prevost surveillance --help` : succès.
- `prevost diagnostic --kali`, état redirigé dans un dossier temporaire : succès
  d’orchestration, état partiel ; aides/versions uniquement, aucun scan.
  Échantillon de rapports privés dans integration/verification-diagnostics-20261105/.
- Menu installé ouvert en pseudo-terminal depuis /tmp, choix 1–27 affichés,
  sortie par 0, code 0. Choix 1–21 et 22 terminal-codex conservés.
- terminal-codex source et installé ouverts/quittés : code 0 ; Codex résolu.
- Compilation Python et git diff --check : succès.
- Comparaison finale des SHA-256 et modes des 48 fichiers d’état protégés :
  aucune différence. Inventaire, anciens cookie.txt/JSON et registre conservés.

## Résultats locaux réellement observés

Aides/versions fonctionnelles : nmap, tshark, dumpcap, wireshark, tcpdump,
hashcat, john, aircrack-ng, airodump-ng, iw, ip (-Version), ss, sqlmap,
gobuster, ffuf, whatweb, curl, openssl, whois, exiftool, strings, file,
binwalk, codex, git, nano, python3 et notify-send.
Cela ne valide ni scan, ni capture, ni GPU/radio, ni l’ouverture d’une interface
Wireshark. John classique est disponible ; sa variante ne garantit pas les
formats MD5 du laboratoire existant. Ces calculs n’ont pas été lancés.

Manquants sur LexOS : wifite, nikto, radare2. Leur éventuelle présence dans Kali
reste non vérifiable ici. Lynis : propriété incompatible dans cet environnement,
aucun contrôle contourné. dig : sockets refusées même pour son aide. Ollama :
version du client accessible, avertissement de connexion au service local ;
le service n’est pas validé. Kali : Podman échoue sur /run/user/1002/libpod
(système de fichiers en lecture seule), aucun conteneur démarré ni modifié.

## Notifications et réseau

Le test graphique critique a été vu par l’utilisateur (confirmation reçue).
L’alerte normale est une validation distincte :
`python3 integration/test_normal_notification.py` : chaîne simulée réussie,
aucun envoi attendu avec le défaut historique sans notifications.
Avec `--notifications` : chaîne réussie, pas de doublon, notification bureau
non validée ; D-Bus refuse l’accès (Operation not permitted).
Notification de fin de mission : repli terminal, service bureau non validé.
Aucun affichage normal ni affichage de fin de mission déclaré confirmé.

La nouvelle commande `prevost surveillance` active les alertes par invocation,
sauf --no-notifications ; elle réutilise l’inventaire persistant sans conférer
de droit aux appareils inconnus et ne lance aucun diagnostic actif. Le CLI
historique conserve son réglage sans notifications. L’orchestrateur diagnostic
ne propose aucune opération active ni argument de cible réseau. Les commandes
actives historiques restent séparées avec leur registre et confirmations.

## Installation : implémentée, non exécutée sur le système

Plan : `prevost installer-outils` ; installation explicite dans un terminal :
`prevost installer-outils --executer`. Ajouter --kali pour le conteneur déjà actif.
APT ne reçoit que les paquets du catalogue fermé. Les paquets sans candidat sont
exclus et signalés par un résultat partiel/code non nul. Codex et Ollama ne sont
pas installés par APT ; leurs installations existantes sont conservées.
Aucun paquet installé, aucune mise à jour de dépôt ni règle sudo modifiée pendant
le développement. Le résultat réel d’une installation reste à valider sur l’hôte.
