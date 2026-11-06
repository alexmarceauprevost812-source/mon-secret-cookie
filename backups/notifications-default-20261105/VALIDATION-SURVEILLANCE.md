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

Mise à jour : alertes désactivées par défaut à la demande de l’utilisateur.
Le test supplémentaire vérifie l’absence de notification et la conservation de l’inventaire.
