# Intégration Fusion — préparation approuvée

Cette intégration ajoute un adaptateur local au projet existant, sans installer
de paquet, modifier le PATH global, remplacer les lanceurs V4/V5 ou activer SSH.
Le README principal conserve sa présentation générique pour IA locale.

- `mon_secret_cookie/fusion.py` : registre des exécutables, résolution du venv
  existant, préparation des missions, contrôles de stockage, délégation au moteur
  d'autorisations existant et lecture des rapports.
- `integration/prevost` : lanceur de projet utilisant le Python du venv existant.
- `integration/UTILISATION.md` : commandes, différences entre préparation et
  exécution, accès Wifite dans Kali et limites de l'environnement.
- `integration/TERMUS.md` : prérequis Android, authentification locale et tunnel
  SSH à clé, sans activation automatique du serveur SSH.
- `tests/test_fusion.py` : tests sans sondes réseau ni accès aux données réelles.

Pour V3.2, `prevost outils` inspecte les chemins hôte et lit les métadonnées d'un
conteneur Kali déjà actif via Podman et un programme Python fixe. Les diagnostics
de version nécessitent `--diagnostic`. Les diagnostics Kali nécessitent en plus
`--kali` ; Wifite est limité à son aide, sans démarrage automatique du conteneur.
Une erreur Podman est rapportée, sans changement de
permissions ou réinstallation. Tshark n'est jamais lancé en capture.

`prevost mission --cible AUTH-…` et `prevost scan --cible AUTH-…` préparent un plan
en lecture seule. Un scan exige `--executer`, un espace minimal disponible, Nmap
et des autorisations valides. La sélection n'accepte que des IDs du registre,
sans arguments Nmap libres. Le moteur existant revérifie les autorisations lors
des opérations ; les nouvelles cibles héritent seulement de leur périmètre valide.

La préparation ne crée pas de registre ni de journal. Les scans exécutés sont
journalisés par le moteur existant. Le seuil d'espace bloque uniquement les
opérations actives et n'entraîne jamais de nettoyage automatique.

Préparation locale seulement : aucun scan réel, installation système, changement
Ollama, modèle GGUF, partition Windows ou lanceur installé n'est autorisé ici.
