# Validation — version 0.3.0 / Security Pro 2.1

Vérifications effectuées en environnement Linux de développement :

- `python3 -m unittest discover -s tests -q` : 54 tests réussis, dont les
  35 tests existants.
- `python3 -m mon_secret_cookie --help` : toutes les nouvelles commandes présentes.
- `bash -n install.sh install-termux.sh` : syntaxe valide, scripts non exécutés.
- `python3 -m pip wheel --no-deps --no-build-isolation --wheel-dir /tmp/msc-wheel-check .` :
  paquet `mon_secret_cookie-0.3.0-py3-none-any.whl` construit sans téléchargement
  de dépendances.

Les tests ajoutés couvrent la persistance du registre, l'expiration avec fuseau,
la révocation avant et pendant une mission, l'héritage borné des autorisations,
le refus des actifs hors périmètre, les changements d'IP et services, les absences,
les réponses Nmap incomplètes, les erreurs et interruptions sans remplacement de
la référence, l'échec du journal avant toute sonde, les exports sans écrasement,
les diagnostics à arguments fixes, l'authentification API et ses routes en lecture
seule. L'API est exercée avec le client de test Flask, sans service exposé.

Aucun scan réseau réel, installation système, attaque Wi-Fi ou calcul de
récupération de mot de passe n'a été exécuté. Les diagnostics matériels utilisent
des outils externes : leur fonctionnement réel reste à valider sur Kali avec la
carte Wi-Fi et le GPU prévus, ainsi que sur les appareils Windows/Android. Le
tunnel SSH documenté n'a pas été établi et aucun serveur SSH n'a été reconfiguré.
