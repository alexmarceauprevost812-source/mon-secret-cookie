# Fusion V3.1 — rapport de mise en service

## Résultat

L'adaptateur local est fonctionnel pour l'aide, le registre des outils, la lecture
du stockage, la préparation des missions et la consultation des rapports. Les
scans autorisés sont validés par simulation. Aucun scan réel n'a été exécuté.
La connexion Android et Wifite dans Kali restent non validés sur matériel.

Les 82 tests automatisés et les 10 vérifications de commandes ont réussi. Les
empreintes SHA-256 de 35 fichiers sont identiques avant et après validation.
Les preuves détaillées sont dans [PREUVES-V3.1.json](PREUVES-V3.1.json).

## 1. Kali et Wifite

Deux lanceurs distincts existent :

- `~/.local/bin/kali` exécute `distrobox enter kali-lexos`, avec les locales
  `LANG=C.UTF-8` et `LC_ALL=C.UTF-8`.
- `~/.local/bin/lexos-kali` exécute `~/.local/bin/kali-menu`. Ce menu lance ses
  commandes dans l'environnement courant ; il n'entre pas lui-même dans Kali.
  L'absence de Wifite dans ce menu sur l'hôte ne prouve donc pas son absence dans Kali.

`podman ps -a` échoue sur `/run/user/1002/libpod`, visible en lecture seule dans
l'environnement agent. L'erreur demande une modification du sticky bit. Aucune
modification, contournement, relance ou reconfiguration de conteneur n'a été tenté.
La présence et la version de Wifite dans Kali restent inconnues.

Vérification à effectuer depuis le terminal LexOS normal, lorsque le conteneur
est déjà actif : `podman exec kali-lexos wifite --help`. L'aide n'est pas une
attaque. L'adaptateur propose le même diagnostic avec
`bash integration/prevost outils --diagnostic --kali`. Il ne démarre pas le conteneur.

## 2. Lynis : diagnostic et correction minimale proposée

Lynis 3.1.4-1 est installé. Son code initial (`/usr/sbin/lynis`, lignes 151–179)
vérifie exactement deux fichiers avant de les charger :

| Fichier | UID/GID visibles | Mode |
| --- | --- | --- |
| `/usr/share/lynis/include/consts` | 65534 / 65534 | 0644 |
| `/usr/share/lynis/include/functions` | 65534 / 65534 | 0644 |

Les deux propriétaires visibles sont différents de root et de l'utilisateur
courant, UID 1002. Le message final cite `functions`, car c'est le dernier fichier
de cette boucle. Les modes 0644 satisfont le contrôle initial.

Le même UID 65534 est visible sur Python, Nmap, Bash et `/etc/passwd`. La table
`/proc/self/uid_map` indique `1002 0 1` : un seul UID est mappé dans cet espace de
noms. Ces observations expliquent le contrôle refusé dans le bac à sable ; elles
ne démontrent pas une propriété incorrecte sur l'hôte LexOS. `dpkg --verify lynis`
retourne 0 sans sortie, ce qui ne signale pas d'écart de contenu selon les sommes
enregistrées par dpkg. Cette vérification ne certifie pas les propriétaires.

**Correction minimale proposée maintenant : aucune modification de propriétaire.**
Depuis le terminal LexOS normal, relever d'abord les propriétaires numériques :

```bash
stat -c '%u:%g %a %n' /usr/sbin/lynis \
  /usr/share/lynis/include/consts /usr/share/lynis/include/functions
```

Si les deux fichiers appartiennent déjà à root sur l'hôte, aucun `chown` n'est
nécessaire. Si une mauvaise propriété réelle est confirmée, proposer après
approbation une correction limitée aux fichiers effectivement incorrects. Pour
les deux fichiers initiaux, la correction candidate serait
`chown root:root /usr/share/lynis/include/consts /usr/share/lynis/include/functions`.
Cette commande n'a pas été exécutée. Les autres anomalies éventuelles exigeraient
un examen séparé ; aucun `chown -R`, réinstallation ou abandon du contrôle Lynis.

## 3. Adaptateur et autorisations

Commandes exécutées avec leur résultat attendu :

| Commande | Résultat |
| --- | --- |
| `bash integration/prevost --help` | Aide, code 0 |
| `bash integration/prevost outils` | Inventaire des chemins existants, code 0 |
| `bash integration/prevost stockage` | Lecture de l'espace disponible, code 0 |
| `bash integration/prevost rapport` | Liste vide de missions, code 0 |
| `bash integration/prevost mission --cible AUTH-inconnue` | Refus, code 1 |
| `bash integration/prevost scan --cible AUTH-inconnue --executer` | Refus avant toute sonde, code 1 |
| `bash integration/prevost rapport --mission RUN-inconnue` | Refus, code 1 |
| `bash integration/prevost connexion --host utilisateur@lexos.local` | Plan SSH uniquement, code 0 |
| `.venv/bin/python -B -m mon_secret_cookie --help` | Aide historique, code 0 |
| `.venv/bin/python -B -m mon_secret_cookie --version` | Version 0.3.0, code 0 |

Le registre d'état réel `~/.local/state/mon-secret-cookie` était absent au début
et reste absent après ces vérifications. Aucune cible ou autorisation n'a été
créée, modifiée ou supprimée. Il n'existe donc aucune autorisation réelle dans
ce registre pour lancer une mission active à ce stade.

La préparation nécessite des IDs présents et valides. Les scans de l'adaptateur
exigent `--executer`, Nmap et au moins 1 Gio libre. Le moteur vérifie expiration,
révocation et périmètre avant les opérations. Les tests vérifient le refus des
actifs hors périmètre, l'héritage borné des autorisations, les échecs et l'absence
de remplacement de l'inventaire de référence en cas d'erreur.

Les commandes autonomes historiques `nmap` et `devices --authorized` conservent
leurs validations propres et ne passent pas par le registre Fusion. La garantie
de sélection d'IDs du registre s'applique à l'adaptateur, sans empêcher un opérateur
d'exécuter directement un outil système.

L'adaptateur est local au projet. Les lanceurs installés V4/V5 et les profils shell
restent inchangés. Voir [UTILISATION.md](UTILISATION.md) pour l'usage du nom court
dans la session courante.

## 4. Termus Android et OpenSSH

Le paquet client OpenSSH est installé. `openssh-server` n'est pas installé ;
`sshd`, `/etc/ssh/sshd_config` et les clés publiques d'hôte ED25519/RSA attendues
ne sont pas présents. Aucune empreinte serveur ne peut donc être calculée ou
comparée dans cet état. Aucune clé existante n'a été remplacée ou générée.

Le plan de connexion par clé est préparé avec `StrictHostKeyChecking=yes`,
`PasswordAuthentication=no`, `IdentitiesOnly=yes` et une redirection entre
`127.0.0.1:8765` et `127.0.0.1:8765`. Il n'a pas été exécuté.
Voir [TERMUS.md](TERMUS.md) pour les prérequis et les commandes.

Étapes restantes, sous approbation avant installation ou activation : mettre en
place OpenSSH serveur, définir l'accès limité au réseau approuvé, enregistrer la
clé publique Android, puis relever l'empreinte sur la console LexOS normale :

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

Comparer ensuite cette empreinte à celle reçue sur Android via un canal
indépendant avant d'approuver la clé d'hôte. L'absence actuelle de clé rend cette
commande inapplicable aujourd'hui ; aucune empreinte fictive n'est fournie.
Aucun service, règle réseau ou accès Internet n'a été activé.

## 5. Validation et préservation

- Suite outil/adaptateur : **72 tests réussis**.
- Suite AUTO V5 : **10 tests réussis**, sur des projets temporaires.
- Commandes réelles sans scan : **10 vérifications réussies**.
- SHA-256 : **35 fichiers inchangés**, incluant sources, tests, documents
  préexistants, lanceurs Kali et V4/V5. Les quatre empreintes conservées lors de
  la phase précédente correspondent aussi aux fichiers actuels.
- Registre réel : aucun état créé ou modifié.
- Aucun scan réel, capture réseau, attaque Wi-Fi ou calcul de récupération de
  mots de passe. Aucun changement de propriétaire, paquet système ou service.
- Aucun accès en écriture à Ollama, aux modèles GGUF ou aux partitions Windows.
  Les fichiers GGUF volumineux n'ont pas été intégralement rehachés ; la
  comparaison SHA-256 porte sur les 35 fichiers listés dans les preuves.

La validation API emploie le client de test Flask ; la validation des scans,
Windows, Android et diagnostics matériels utilise des réponses simulées.
Les points encore à valider réellement sont Wifite dans Kali, Lynis depuis le
terminal hôte normal, les scans sur un périmètre enregistré et approuvé, ainsi
que la connexion SSH/API depuis un appareil Android.

V3.1 désigne cette mission de validation ; le paquet Mon Secret Cookie reste en
version 0.3.0. Seuls ce rapport et son fichier de preuves sont ajoutés pendant
cette phase. Aucun changement n'a été publié sur GitHub.
