# mon-secret-cookie

Outil CLI Python pour **Linux (Kali Linux et Ubuntu)**, audit défensif et laboratoire autorisé. Interface interactive TI-LEX noir/vert, avec logo en relief « LE SECRET » vert lime et « COOKIE » orange. Le logo se simplifie dans les petits terminaux ; `NO_COLOR=1` désactive ses couleurs. Python 3.10 minimum.

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
| `device-id` | Identifiant aléatoire applicatif, persistant et indépendant du matériel |
| `scan-local` | Scan TCP des 20 ports courants de localhost et des IP propres à la machine |
| `ports` | Sockets TCP/UDP en écoute via ss ; ports, protocole et nom /etc/services |
| `wifite` | Vérifie la présence de Wifite et affiche les instructions manuelles |
| `wifi-info` | Interface, SSID/BSSID, fréquence, signal et débit disponibles via iw |
| `devices` | Cache voisin du LAN, consultation passive |
| `devices --cidr CIDR --authorized` | Découverte active Nmap sans scan de ports sur une portion du LAN directement connecté |
| `nmap IP [IP ...] --authorized` | Scan TCP des 100 ports courants, maximum 16 IP explicites |
| `cookies --file FICHIER` | Métadonnées d'un fichier Netscape cookies.txt appartenant à votre utilisateur |
| `cookies --search DOSSIER` | Recherche de cookies.txt, profondeur 4, maximum 100 résultats |
| `cookie-lab --output cookies.txt` | Création d'un fichier pédagogique avec cookies fictifs |
| `password-lab --engine john` | Démonstration MD5 avec John the Ripper |
| `password-lab --engine hashcat` | Même démonstration avec Hashcat |
| `flask-lab --port 5000` | Laboratoire web sur 127.0.0.1 uniquement |
| `report --format json --output rapport.json` | Export des résultats déjà enregistrés |
| `report --format txt --output rapport.txt` | Export texte |
| `menu` | Menu interactif TI-LEX |

Sans argument, le menu s'ouvre dans un terminal interactif ; sinon l'aide s'affiche. Toutes les sorties d'audit sont JSON. Les erreurs vont vers stderr et produisent un code non nul. Ctrl+C interrompt l'opération.

## Exemples

```bash
mon-secret-cookie device-id
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

Les cookies sont lus uniquement depuis des fichiers locaux explicitement indiqués. Aucun profil navigateur, trafic réseau, appareil tiers, session, mot de passe ou clé Wi-Fi n'est extrait. Les valeurs des cookies ne sont jamais affichées ni enregistrées dans les rapports ; Secure, HttpOnly, expiration et métadonnées sont analysés. SameSite n'est pas représenté par le format Netscape. La recherche ne suit pas les liens symboliques ; un fichier final symbolique est refusé.

Le laboratoire Flask utilise des cookies fictifs, ne possède aucun mécanisme d'authentification et écoute seulement sur `127.0.0.1`, sans mode debug. Ne pas exposer ce serveur de développement sur Internet. Le cookie est HttpOnly et SameSite=Strict ; Secure reste désactivé pour l'exemple HTTP local et doit être activé dans une application HTTPS réelle.

Le Password Lab utilise des fichiers temporaires privés et un dictionnaire borné ; aucun mot de passe trouvé n'apparaît dans les rapports. Les fichiers temporaires sont supprimés en sortie normale ou en erreur ; une interruption forcée du processus peut laisser des fichiers dans le dossier d'état. John est limité à 60 secondes et Hashcat à 30 secondes de calcul avec un délai global de 60 secondes.

## Stockage et rapports

Identifiant et résultats dans `~/.local/state/mon-secret-cookie` (répertoire 0700, fichiers 0600). `MSC_STATE_DIR` permet un emplacement différent, utile pour les tests. Les rapports ne contiennent pas de valeurs de cookies ou de mots de passe, mais peuvent contenir IP, SSID/BSSID et noms de cookies : choisissez leur destinataire en conséquence. Aucun envoi externe automatique. Les exports et fichiers de démonstration refusent d'écraser un fichier existant.

## Développement et tests

Modules : `core` (état, exécution, rapports), `network`, `cookies`, `passwords`, `lab` (Flask), `cli` (arguments et menu).

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v
bash -n install.sh
```

Tests : persistance et permissions, refus des liens/fichiers non réguliers, masquage des cookies, autorisation des scans, restriction au LAN local, IPv6, rapports et cookie Flask. L'installation apt doit être vérifiée sur une machine Kali/Ubuntu ; les tests Python ne modifient pas vos paquets système.

`device-id` affiche aussi le hostname et les interfaces locales. `scan-local --device-id ID` refuse un ID différent et inclut le Device ID dans le résultat. Cet ID identifie cette installation, ne prouve pas la propriété et ne permet pas de contrôler ou de scanner un appareil distant. Copiez l’ID exact affiché par `device-id`.
