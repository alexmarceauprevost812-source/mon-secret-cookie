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

## Réexamen des blocages — résultats de la dernière intervention

Cette section précise et actualise les conclusions précédentes. Les erreurs
observées dans l’environnement de l’agent ne sont pas des preuves d’une panne
sur le véritable hôte LexOS. La confirmation visuelle reçue concerne uniquement
le test notify-send critique, pas l’alerte normale ni la notification de fin.

Sauvegarde avant correction : `backups/host-blockers-20261105/`.
Preuves privées : `integration/verification-host-access-20261105/host-access.json`.
Nouvelle commande : `prevost acces-hote`, sondes locales à arguments fixes,
sans sudo, scan, installation, démarrage ni recréation de conteneur.
L’option `--output NOUVEAU-FICHIER.json` écrit un export privé 600 sans écrasement.
Elle n’écrit pas dans les cookie.txt, l’inventaire ou le registre existants.

| Élément | Résultat réel dans l’environnement de l’agent | Conclusion sur l’hôte LexOS |
| --- | --- | --- |
| Confinement | UID 1002, CapEff=0, NoNewPrivs=1, Seccomp=2, espace de noms UID/GID limité | Le filtre exact responsable des refus n’a pas été identifié ; aucune panne de l’hôte démontrée |
| Runtime Podman | `/run/user/1002` et `libpod` en lecture seule ; modes 700 et 1700 | Ne pas tenter un chmod : le sticky bit est déjà présent ici. Vérifier le montage et Podman depuis l’hôte |
| Podman | `ps --all`, `inspect kali-lexos` et même `--version` échouent avant accès aux métadonnées | Existence, état et contenu actuels du conteneur non déterminés ; il n’a pas été recréé ni démarré |
| Dépendances Podman | podman 5.4.2, uidmap, conmon, crun, slirp4netns, passt installés selon dpkg-query | Aucun de ces paquets n’est démontré manquant ; ne pas réinstaller pour contourner la validation |
| Socket Podman API | `/run/user/1002/podman/podman.sock` absent | Ce socket est facultatif pour le CLI Podman local ; son absence n’explique pas à elle seule l’échec |
| Outils absents | wifite, nikto, radare2 absents des chemins exposés et des paquets LexOS interrogés | Dans Kali : **non vérifiés**, pas déclarés absents. Wifite a seulement une ancienne confirmation opérateur dans environments.json |
| Lynis | Deux fichiers requis présents, modes 644 ; UID observé 65534, attendu 0 ou UID courant 1002 | Contrôle de propriétaire bloquant, pas dépendance absente. D’autres fichiers système ont aussi l’UID 65534 : remappage de l’espace de noms plausible, à confirmer sur l’hôte |
| Réseau | Création de sockets IPv4/IPv6 UDP et Netlink ROUTE refusée avec EPERM, sans envoi de paquet | Refus local de création de sockets, pas preuve de panne réseau ni carte Wi-Fi absente |
| ip/ss/iw | ip et ss : refus Netlink ; iw : échec generic Netlink | iproute2 et iw installés. Les lectures locales ne justifient pas d’ajouter automatiquement des capacités ou sudo |
| dig | Même `dig -v` échoue à créer des sockets IPv4/IPv6 | bind9-dnsutils installé ; ce n’est pas un paquet manquant ni un échec d’une requête DNS effectuée |
| Notifications | Bus présent dans les variables, mais connexion et GetServerInformation refusés avec EPERM | État actuel du service de bureau non vérifié ici. Le test critique vu par l’utilisateur ne valide pas le chemin normal |

Précision : `ss -H -lntu` renvoie ici **0** malgré les refus Netlink sur stderr.
`prevost acces-hote` reconnaît désormais ce refus comme une erreur au lieu de
considérer le seul code de retour comme une réussite. Aucune sonde n’a été envoyée.

### Corrections effectuées

- Les erreurs de découverte Kali portent une catégorie et une indication explicite
  de validation nécessaire sur l’hôte ; l’état du conteneur n’est pas inventé.
- `prevost aide-outil OUTIL` utilise LexOS si présent ; sinon, il utilise le chemin
  exact dans Kali seulement si le conteneur est déjà actif et l’outil réellement
  découvert. Cela passe par `podman exec`, sans start/create et sans shell libre.
  Le menu d’aide réutilise ce routage ; `--kali` force la vérification dans Kali.
- Si Kali est inaccessible, l’outil reste « manquant sur LexOS / non vérifié dans
  Kali ». Aucune installation n’est proposée comme résultat d’une validation.
- Lynis fournit les chemins et UID précis attendus. Son aide dans Kali n’est plus
  refusée systématiquement lorsque la propriété a réellement été vérifiée par les
  métadonnées du conteneur. Aucun contrôle n’est contourné, aucun chown effectué.
- Le test de notification passe désormais par `fusion.main` et donc le chemin
  normal `prevost surveillance --once`, avec ses réglages normaux. Seuls la source
  de voisins (événement fictif) et le stockage temporaire sont substitués. Le
  véritable `watch.notify` et le véritable `notify-send` sont appelés avec leurs
  arguments inchangés : titre TI-LEXOS KALI, sans urgence critique ni réglage ajouté.
  L’observateur de processus ne modifie pas la commande.

### Vérifications exécutées après correction

`python3 integration/test_local.py` : **188 tests réussis**, 0,609 s.
Les nouveaux tests couvrent la classification des restrictions, l’UID Lynis,
le refus Netlink avec code 0, le routage vers Kali actif, l’état non vérifié si
Kali est inaccessible, le garde Lynis Kali, l’export privé et l’absence de doublon.
Un test vérifie exactement les arguments normaux de notify-send, sans --urgency.
Compilation Python et `git diff --check` réussis.

Le test réel `.venv/bin/python integration/test_normal_notification.py --programme prevost`
a exercé la chaîne simulée détection → inventaire → journal → appel normal de
notification : réussite, un seul appel malgré deux détections. `notify-send`
renvoie **1** avec « Could not connect: Operation not permitted ».
**Envoi accepté par le service : non validé. Affichage normal : non confirmé.**
Le script retourne 1 pour ce blocage du service, sans confondre cette limitation
avec les 188 tests automatisés réussis. Les vrais appareils ne sont pas utilisés.

Les commandes installées `prevost aide-outil wifite` et `prevost aide-outil lynis`
renvoient des erreurs utiles et véridiques ; `prevost acces-hote --help` fonctionne.
Comparaison finale des SHA-256 et modes des 48 fichiers protégés : aucune différence.
Aucune installation, aucun scan, aucun lancement Wifite/Nikto contre une cible,
aucune élévation automatique, aucune modification du stockage du conteneur.

### Commandes exactes à lancer dans le terminal de bureau LexOS

Exécuter comme utilisateur habituel, sans sudo :

```bash
cd /home/ti-lex-al/LexOS-Projets/mon-secret-cookie
~/.local/bin/prevost acces-hote
podman ps --all --format '{{.Names}} {{.Status}}'
podman inspect --format '{{.State.Status}}' kali-lexos
stat -Lc '%n uid=%u gid=%g mode=%a' "$XDG_RUNTIME_DIR" "$XDG_RUNTIME_DIR/libpod"
findmnt -T "$XDG_RUNTIME_DIR" -o TARGET,FSTYPE,OPTIONS
```

Si Podman fonctionne et kali-lexos est **déjà actif**, consulter les métadonnées
et les aides uniquement :

```bash
~/.local/bin/prevost outils
~/.local/bin/prevost aide-outil wifite --kali
~/.local/bin/prevost aide-outil nikto --kali
~/.local/bin/prevost aide-outil radare2 --kali
~/.local/bin/prevost aide-outil lynis --kali
```

Ces aides ne reçoivent aucune cible. S’il est arrêté, les vérifications le signalent
sans le démarrer. Aucun changement de storage.conf, root/runroot ou répertoire de
stockage n’est requis par ces commandes.

Pour distinguer les refus de confinement d’un problème reproduit sur l’hôte :

```bash
stat -Lc '%n uid=%u gid=%g mode=%a' /usr/share/lynis/include/consts /usr/share/lynis/include/functions
~/.local/bin/prevost aide-outil lynis
ip -j address show
ss -H -lntu
/usr/sbin/iw list
dig -v
gdbus call --session --dest org.freedesktop.Notifications --object-path /org/freedesktop/Notifications --method org.freedesktop.Notifications.GetServerInformation
```

Test **normal**, événement fictif et inventaire temporaire, dans cette même session :

```bash
.venv/bin/python integration/test_normal_notification.py --programme prevost
```

Le test ne modifie ni titre, ni urgence, ni environnement graphique du programme.
L’utilisateur doit confirmer avoir vu la notification normale. Pour vérifier aussi
le comportement désactivé : ajouter `--no-notifications`. Pour tester l’ancien CLI
avec son option normale d’activation :

```bash
.venv/bin/python integration/test_normal_notification.py --programme mon-secret-cookie --notifications
```

Un code 0 de notify-send signifie un envoi accepté ; il ne prouve pas un affichage.
Ne pas modifier les réglages « Ne pas déranger », l’urgence ou le serveur pour
réussir artificiellement ce test. Si les commandes échouent aussi dans le terminal
hôte, leurs sorties constituent alors la preuve d’un blocage réel sur cet hôte.
