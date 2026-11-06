# Validation surveillance — 2026-11-05

Inspection : ARCHITECTURE.md, README.md, VALIDATION.md, modules CLI, réseau,
stockage privé, intégrations et tests. Aucune instruction AGENTS.md trouvée
sur le chemin du projet. Modifications locales préexistantes préservées.
Sauvegardes des trois fichiers existants modifiés dans backups/network-watch-20261105/.

Commande exécutée : `python3 integration/test_local.py`.
Résultat : 157 tests réussis, rapports de production isolés par le lanceur.
Les sept nouveaux tests couvrent persistance, première/dernière observation,
changement d’IP reconnu par MAC, absence de MAC, entrée FAILED ignorée,
permissions 600/700, lien symbolique refusé, panne de journal bloquante,
intervalle invalide, inventaire sans réseau, menu et lancement simulé du choix 22.
L’inventaire est remplacé atomiquement sous verrou exclusif Unix.

Aide CLI vérifiée : `python3 -m mon_secret_cookie surveillance --help`.
Les exécutables ip, notify-send et terminal-codex sont présents.
Le lancement interactif terminal-codex a été simulé, pas exécuté.

Essai passif réel avec MSC_STATE_DIR temporaire : échec explicite de `ip`
« Cannot open netlink socket: Operation not permitted » dans le bac à sable.
Aucune sonde, aucun scan actif, aucune lecture de navigateur ou secret.
La notification bureau, la visibilité du LAN réel et le fonctionnement depuis
le terminal hôte restent à vérifier. Le cache voisin ne constitue pas un
inventaire exhaustif et peut contenir des observations anciennes.

La surveillance n’a aucun chemin d’analyse active : elle ne fait que lire le
cache et notifier. Le moteur de missions existant conserve la configuration
des périmètres, les tests autorisés, l’expiration et la révocation.
Les choix actifs historiques autonomes restent inchangés et exigent leurs
confirmations ; ils ne sont pas pilotés par la surveillance.

Mise à jour finale : alertes activées par défaut à la demande de l’utilisateur.
L’option `surveillance --no-notifications` désactive les alertes terminal et bureau
sans désactiver l’inventaire ni le journal. Le test adapté passe par le CLI et
vérifie la première alerte, les entrées en double dans un cycle, l’absence de
nouvelle alerte après relecture de l’inventaire, la désactivation explicite pour
un nouvel appareil et l’absence d’alerte rétroactive après réactivation.

Validation exécutée après cette mise à jour : `python3 integration/test_local.py` :
158 tests réussis en 0,530 seconde. Sources réseau et notifications simulées,
rapports de production isolés. Aide CLI vérifiée avec `surveillance --help`.
La livraison effective d’une notification bureau n’a pas été testée.
Sauvegarde de cette révision : `backups/notifications-default-20261105/`.

Dernière demande appliquée : alertes désactivées par défaut ; découverte passive,
inventaire et journal local conservés. Activation facultative par --notifications,
mutuellement exclusive avec --no-notifications. Aucun téléchargement de fichier
ni extraction de cookie sur les appareils découverts.
Validation finale : python3 integration/test_local.py — 159 tests réussis en
0,544 seconde, réseau et notifications simulés. Le test ajouté vérifie qu’une
nouvelle identité est enregistrée et journalisée sans notification par défaut.
Sauvegardes : backups/notifications-disabled-20261105/.

Validation bureau demandée dans la session LexOS : DISPLAY=:0.0,
XDG_SESSION_TYPE=x11, bus utilisateur /run/user/1002/bus présent.
Les appels D-Bus NameHasOwner et GetServerInformation sont refusés :
« Could not connect: Operation not permitted ». La présence du service ne peut
pas être confirmée depuis cet environnement.

Script reproductible : `python3 integration/test_desktop_notification.py`.
Appareil fictif 192.0.2.123 / 02:00:00:00:00:ab, notification explicitement
marquée « TEST — nouvel appareil », réseau simulé, stockage temporaire détruit.
Chaîne détection → inventaire → journal → appel notification et absence de
notification au second passage : réussies. Envoi réel notify-send tenté : code 1,
« Could not connect: Operation not permitted » ; aucun envoi accepté validé.
Affichage visuel : non confirmé. Inventaire et configuration de production non
utilisés ; aucune découverte réelle ni analyse active lancée.
Le script doit être relancé depuis un terminal de la session de bureau LexOS.
