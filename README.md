# mon-secret-cookie

Outil CLI Python pour **Linux (Kali Linux et Ubuntu), Termux (Android) et Windows**, audit défensif et laboratoire autorisé. Interface interactive TI-LEX noir/vert, avec logo en relief « LE SECRET » vert lime et « COOKIE » orange. Le logo se simplifie dans les petits terminaux ; `NO_COLOR=1` désactive ses couleurs. Python 3.10 minimum.

## Installation

```bash
git clone https://github.com/alexmarceauprevost812-source/mon-secret-cookie.git
cd mon-secret-cookie
bash install.sh
export PATH="$HOME/.local/bin:$PATH"
mon-secret-cookie --help
```

Exécuter l'installateur comme utilisateur normal. Il vérifie les paquets Debian, utilise sudo seulement pour les paquets manquants (python3, python3-venv, python3-pip, nmap, john, hashcat, iproute2 et iw), puis installe le CLI et Flask dans `~/.local/share/mon-secret-cookie/venv`. Une connexion Internet et les dépôts apt de la distribution sont nécessaires. Réexécuter pour mettre à jour depuis votre copie du dépôt. Le Python système n'est pas modifié par pip.

Option : `bash install.sh --with-wifite` installe Wifite. Le CLI ne lance jamais Wifite et n'automatise aucune attaque ou capture Wi-Fi. Son usage manuel est réservé à votre laboratoire autorisé.

Alternative sans installer les paquets système :

```bash
python3 -m venv .venv
.venv/bin/python -m pip install .
.venv/bin/mon-secret-cookie --help
```

## Commandes

| Commande | Fonction |
| --- | --- |
| `device-id` | Identifiant aléatoire applicatif, persistant et indépendant du matériel (l'identité système réelle apparaît dans `bilan`) |
| `scan-local` | Scan TCP des 20 ports courants de localhost et des IP propres à la machine |
| `ports` | Sockets TCP/UDP en écoute via ss ; ports, protocole et nom /etc/services |
| `bilan` | Rapport texte tout-en-un de votre propre appareil : identité applicative, système réel (nom d'hôte, noyau, architecture, machine-id), interfaces, ports en écoute, Wi-Fi, scan local et voisins LAN (cache passif) |
| `bilan --format json` | Même bilan en JSON |
| `bilan --no-neighbors` | Bilan sans lecture du cache de voisinage LAN |
| `bilan --label NOM` | Étiquette libre pour distinguer vos appareils (ex. `telephone-1`, `pc-bureau`) |
| `wifite` | Vérifie la présence de Wifite et affiche les instructions manuelles |
| `wifi-info` | Interface, SSID/BSSID, fréquence, signal et débit disponibles via iw |
| `devices` | Cache voisin du LAN, consultation passive ; chaque appareil reçoit un `asset_id` d'inventaire stable |
| `devices --cidr CIDR --authorized` | Découverte active Nmap sans scan de ports sur une portion du LAN directement connecté ; chaque appareil reçoit un `asset_id` stable |
| `nmap IP [IP ...] --authorized` | Scan TCP des 100 ports courants, maximum 16 IP explicites |
| `cookies --file FICHIER` | Métadonnées d'un fichier Netscape cookies.txt appartenant à votre utilisateur |
| `cookies --search DOSSIER` | Recherche de cookies.txt, profondeur 4, maximum 100 résultats |
| `cookie-guide` | Guide français pas à pas : Flask, Set-Cookie, curl, analyse et suppression |
| `cookie-lab --output cookies.txt` | Création d'un fichier pédagogique avec cookies fictifs |
| `password-lab --engine john` | Démonstration MD5 avec John the Ripper |
| `password-lab --engine hashcat` | Même démonstration avec Hashcat |
| `flask-lab --port 5000` | Laboratoire web sur 127.0.0.1 uniquement |
| `report --format json --output rapport.json` | Export des résultats déjà enregistrés |
| `report --format txt --output rapport.txt` | Export texte |
| `menu` | Menu interactif TI-LEX |

Sans argument, le menu s'ouvre dans un terminal interactif ; sinon l'aide s'affiche. Toutes les sorties d'audit sont JSON ; `cookie-guide` affiche un guide en texte. Les erreurs vont vers stderr et produisent un code non nul. Ctrl+C interrompt l'opération.

## Exemples

```bash
mon-secret-cookie device-id
mon-secret-cookie bilan            # rapport texte tout-en-un de votre appareil
# Lancer le même bilan sur chacun de vos appareils en les étiquetant :
mon-secret-cookie bilan --label telephone-1
mon-secret-cookie bilan --label pc-bureau
mon-secret-cookie ports
mon-secret-cookie scan-local
# Pour vérifier explicitement que vous testez la machine portant cet ID :
mon-secret-cookie scan-local --device-id MSC-REMPLACER_PAR_VOTRE_ID
mon-secret-cookie wifi-info
mon-secret-cookie wifite
mon-secret-cookie devices
# Adapter ces adresses à votre réseau et à votre autorisation réelle :
mon-secret-cookie devices --cidr 192.168.1.0/24 --authorized
mon-secret-cookie nmap 192.168.1.10 --authorized
mon-secret-cookie cookie-lab --output cookies.txt
mon-secret-cookie cookies --file cookies.txt
mon-secret-cookie cookies --search ./mon-laboratoire
mon-secret-cookie password-lab --engine john
mon-secret-cookie flask-lab
# Ouvrir http://127.0.0.1:5000 puis arrêter avec Ctrl+C.
mon-secret-cookie report --format txt --output rapport.txt
```

Pour un audit de mots de passe autorisé :

```bash
mon-secret-cookie password-lab --engine john \
  --hashes ./hashes-md5.txt --wordlist ./mots.txt --authorized
```

Le fichier contient uniquement 1 à 100 hashes MD5 bruts, un hash hexadécimal de 32 caractères par ligne. Le dictionnaire contient au maximum 10 000 lignes. Les deux fichiers doivent appartenir à votre utilisateur et peser au maximum 2 Mo. Pas de modes supplémentaires ni d'arguments arbitraires transmis aux outils. MD5 sert ici à l'apprentissage et ne convient pas au stockage de mots de passe réels. John doit proposer le format `dynamic_0` ; certaines versions peuvent nécessiter un paquet John adapté. Hashcat nécessite un backend OpenCL/CUDA/CPU compatible : installer le paquet seul ne garantit pas un backend utilisable. Un backend absent est signalé proprement, sans utiliser `--force`.

## Périmètre et limites de sécurité

Utilisez uniquement vos appareils ou un périmètre explicitement autorisé. `--authorized` est une déclaration de votre autorisation, pas une preuve technique de propriété. Un scan envoie des paquets et peut être journalisé ; aucun scan ne garantit un impact nul.

La découverte active accepte seulement un réseau IPv4 privé de 256 adresses maximum, inclus dans une interface locale active. `nmap` accepte uniquement des adresses IP littérales, sans nom DNS, CIDR, scripts NSE, exploitation, détection intrusive de versions ni arguments libres. Le scan est TCP connect, avec temporisations et délais bornés. L'inventaire passif peut être incomplet ; les appareils filtrant les sondes peuvent rester invisibles. Les adresses locales IPv6 link-local sont exclues du scan local.

Chaque appareil découvert reçoit un `asset_id` d'inventaire (`DEV-…`), dérivé par hachage de sa MAC, sinon de son IP, à partir des seules données déjà renvoyées : aucune collecte supplémentaire. Il sert à reconnaître le même appareil d'un relevé à l'autre et n'est produit que dans le cache passif et la découverte autorisée. Il ne contourne pas l'autorisation : la découverte active exige toujours `--authorized` et un périmètre appartenant à une interface locale. Cet outil est destiné à vos propres réseaux ou à un périmètre explicitement autorisé ; chaque personne qui s'en sert déclare sa propre autorisation.

Les cookies sont lus uniquement depuis des fichiers locaux explicitement indiqués. Aucun profil navigateur, trafic réseau, appareil tiers, session, mot de passe ou clé Wi-Fi n'est extrait. Les valeurs des cookies ne sont jamais affichées ni enregistrées dans les rapports ; Secure, HttpOnly, expiration et métadonnées sont analysés. SameSite n'est pas représenté par le format Netscape. La recherche ne suit pas les liens symboliques ; un fichier final symbolique est refusé.

Le laboratoire Flask utilise des cookies fictifs, ne possède aucun mécanisme d'authentification et écoute seulement sur `127.0.0.1`, sans mode debug. Ne pas exposer ce serveur de développement sur Internet. Le cookie est HttpOnly et SameSite=Strict ; Secure reste désactivé pour l'exemple HTTP local et doit être activé dans une application HTTPS réelle.

Le Password Lab utilise des fichiers temporaires privés et un dictionnaire borné ; aucun mot de passe trouvé n'apparaît dans les rapports. Les fichiers temporaires sont supprimés en sortie normale ou en erreur ; une interruption forcée du processus peut laisser des fichiers dans le dossier d'état. John est limité à 60 secondes et Hashcat à 30 secondes de calcul avec un délai global de 60 secondes.

## Stockage et rapports

Identifiant et résultats dans `~/.local/state/mon-secret-cookie` (répertoire 0700, fichiers 0600). `MSC_STATE_DIR` permet un emplacement différent, utile pour les tests. Les rapports ne contiennent pas de valeurs de cookies ou de mots de passe, mais peuvent contenir IP, SSID/BSSID et noms de cookies : choisissez leur destinataire en conséquence. Aucun envoi externe automatique. Les exports et fichiers de démonstration refusent d'écraser un fichier existant.

Le journal d'audit est accessoire : si son écriture échoue (par exemple disque plein), la commande affiche quand même son résultat et signale l'avertissement sur la sortie d'erreur, au lieu d'échouer. Un disque plein (`ENOSPC`) est indiqué par un message clair rappelant comment libérer de l'espace (`pkg clean` sous Termux, `sudo apt clean` sous Linux).

## Développement et tests

Modules : `platforms` (Windows et Termux), `branding` (logo), `core` (état, exécution, rapports), `network`, `cookies`, `passwords`, `lab` (Flask), `cli` (arguments et menu).

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v
bash -n install.sh
```

Tests : persistance et permissions, refus des liens/fichiers non réguliers, masquage des cookies, autorisation des scans, restriction au LAN local, IPv6, rapports et cookie Flask. L'installation apt doit être vérifiée sur une machine Kali/Ubuntu ; les tests Python ne modifient pas vos paquets système.

`device-id` affiche aussi le hostname et les interfaces locales. `scan-local --device-id ID` refuse un ID différent et inclut le Device ID dans le résultat. Cet ID identifie cette installation, ne prouve pas la propriété et ne permet pas de contrôler ou de scanner un appareil distant. Copiez l’ID exact affiché par `device-id`.


## Termux sur Android

Utiliser Termux depuis une source officielle compatible avec les extensions ([projet Termux](https://termux.dev/en/)). Ne pas placer le dépôt ou le venv sur le stockage partagé Android : conserver le projet dans le dossier privé de Termux.

```bash
pkg install git
git clone https://github.com/alexmarceauprevost812-source/mon-secret-cookie.git
cd mon-secret-cookie
bash install-termux.sh
export PATH="$HOME/.local/bin:$PATH"
mon-secret-cookie device-id
mon-secret-cookie scan-local
mon-secret-cookie menu
```

Option Wi-Fi : `bash install-termux.sh --with-wifi-info`, plus l'application Android Termux:API de la même source que Termux et les permissions demandées. `wifi-info` utilise uniquement `termux-wifi-connectioninfo` et filtre les champs non secrets. Ne pas rooter le téléphone pour cet outil. Android peut interdire `ip`/`ss`, les sondes Nmap ou la lecture du cache voisin : ces commandes signalent l'erreur ; `device-id` reste utilisable et `scan-local` se limite explicitement à localhost si les interfaces sont inaccessibles. La découverte active est refusée si l'appartenance au LAN ne peut pas être vérifiée. Aucune tentative de contourner les restrictions Android.

John, Hashcat et Wifite ne sont pas installés automatiquement par l'installateur Termux ; leur disponibilité dépend de la plateforme et des paquets. Les cookies locaux, Cookie Lab, Flask Lab et rapports ne nécessitent pas ces outils.

## Windows 10/11 (PowerShell / Windows Terminal)

Installer [Python 3.10+](https://www.python.org/downloads/windows/) et Git pour cloner le dépôt, ou télécharger le ZIP du dépôt. Installer [Nmap pour Windows](https://nmap.org/book/inst-windows.html) pour les scans et ajouter le dossier contenant `nmap.exe` au PATH.

```powershell
git clone https://github.com/alexmarceauprevost812-source/mon-secret-cookie.git
cd mon-secret-cookie
& .\install-windows.ps1
mon-secret-cookie device-id
mon-secret-cookie scan-local
mon-secret-cookie ports
mon-secret-cookie wifi-info
mon-secret-cookie menu
```

Si votre politique PowerShell interdit le script, ne pas modifier la politique globale : utiliser l'installation manuelle ci-dessous (dans le dossier du dépôt).

```powershell
py -3 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install .
& .\.venv\Scripts\mon-secret-cookie.exe menu
```

L'installateur crée un environnement sous `%LOCALAPPDATA%\mon-secret-cookie`, ajoute le lanceur au PATH de la session actuelle et affiche le dossier à ajouter au PATH utilisateur pour les sessions suivantes. Il ne télécharge pas automatiquement de programmes externes. Les interfaces, sockets et voisins utilisent les commandes fixes PowerShell `Get-NetIPAddress`, `Get-NetIPInterface`, `Get-NetTCPConnection`, `Get-NetUDPEndpoint` et `Get-NetNeighbor`. Le Wi-Fi utilise `netsh wlan show interfaces`, jamais les clés des profils ; Windows peut demander une autorisation de localisation.

John/Hashcat sont optionnels et doivent être installés depuis leurs distributions officielles avec leurs exécutables dans PATH. Le Password Lab reste limité au même mode MD5 et au même dictionnaire. Wifite n'est pas pris en charge nativement sous Windows ; utiliser Kali/Ubuntu pour cette fonction. WSL est une autre possibilité pour le CLI Linux, mais son réseau et son ID correspondent à l'environnement WSL, et l'accès Wi-Fi matériel n'est pas garanti.

Sous Windows, l'état est dans `%LOCALAPPDATA%\mon-secret-cookie`. La propriété des fichiers est vérifiée par leur SID Windows, les liens/points de réanalyse sont refusés, et les ACL héritées du profil utilisateur remplacent les permissions POSIX 0600/0700. Les exports dans un dossier partagé héritent des ACL de ce dossier : conserver les données d'audit dans votre profil privé.

### Niveau de validation

Les adaptateurs Windows et les restrictions Termux sont couverts par des tests simulés sur Linux. Le CLI et ses fonctions Linux ont été exécutés réellement. Les installateurs Windows/Android et leurs permissions réseau doivent encore être validés sur des appareils physiques ; cette version ne prétend pas à une validation native complète.

## Guide des cookies

Consultez le [guide pas à pas](mon_secret_cookie/GUIDE_COOKIES.md), ou lancez `mon-secret-cookie cookie-guide` (option 13 du menu). Il explique comment créer un cookie fictif sur `127.0.0.1:8000`, voir `Set-Cookie`, l’enregistrer avec curl, le renvoyer, l’analyser et l’effacer. Les commandes sont adaptées à Linux, Termux et PowerShell Windows.
