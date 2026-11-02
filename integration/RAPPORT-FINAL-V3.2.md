# Fusion V3.2 FINAL — commande installée

## Installation effectuée

`~/.local/bin/prevost` était absent avant installation. L'installateur a vérifié
de nouveau cette absence, puis créé le fichier exclusivement, en mode 0700.
Le contenu est identique à `integration/prevost.py` ; aucun fichier existant
n'a été remplacé. Le venv existant reste utilisé sans réinstallation de paquet.

SHA-256 du lanceur installé :

`5280b5ab102fc3726eafc22c812890d4b28bce3475eef8c5e3c37b343a4a5872`

Le lanceur Python utilise le mode isolé du Python du venv, ajoute explicitement
le projet à son chemin d'import et fonctionne indépendamment du dossier courant.
Les profils shell existants incluent déjà `~/.local/bin` : aucun profil modifié.

## Commandes disponibles

`aide`, `outils`, `mission`, `cibles`, `scan`, `nouvelles`, `rapport`,
`diagnostic`, `kali`, `ia`, ainsi que les commandes existantes `tableau`,
`stockage` et `connexion`.

Sans argument, l'aide est affichée. `mission` consulte l'historique ; `--id RUN-…`
sélectionne une mission ; `--cible AUTH-…` prépare une mission et `--executer`
déclenche les mêmes validations que `scan`. Les opérations actives restent
soumises aux autorisations existantes, à leur validité et au périmètre approuvé.

`cibles` et `nouvelles` consultent les données sans créer de registre. La logique
de nouveaux actifs est réutilisée depuis le moteur existant, avec son historique
fourni en lecture seule. Aucun ancien résultat ou autorisation n'est supprimé.

`kali` et `ia` exécutent seulement les lanceurs existants, sans arguments libres.
Leurs appels ont été vérifiés par simulation ; aucune session interactive Kali
ou IA n'a été ouverte automatiquement pendant les tests.

## Tests et vérifications

- Suite Python du projet : **102 tests réussis**.
- Non-régression AUTO V5 : **10 tests réussis** sur des projets temporaires.
- Aides des dix commandes demandées : codes 0.
- Commande installée testée depuis un autre dossier : aide, inventaire des
  outils, tableau, missions, cibles, nouveaux actifs et rapports, codes 0.
- Mission inconnue : refus code 1. Cible inconnue avec `--executer` : refus code 1.
  Scan sans cible : refus argparse code 2. Aucune sonde réelle.
- Rapport JSON exporté dans un répertoire temporaire privé, relu avec succès ;
  second export au même emplacement refusé. Le rapport réel contenait zéro mission.
- Prévisualisation d'installation vérifiée ; les tests couvrent le refus d'un
  fichier existant, d'un lien symbolique et d'une création concurrente.
- Lanceur testé avec PATH minimal, environnement SSH simulé et dossier courant
  contenant un faux module Python : aide fonctionnelle, faux module ignoré.
- Shell de connexion Bash avec PATH initial minimal : `command -v prevost`
  retourne `~/.local/bin/prevost` grâce aux profils déjà présents.
- Nmap et Tshark : diagnostics de version réussis. Lynis et Kali sont signalés
  indisponibles depuis le bac à sable lorsqu'il bloque leurs contrôles, sans
  contournement ni modification de propriétaire.
- Empreintes SHA-256 : les cinq lanceurs conservés (dont les sources V5 et son
  menu) et les deux fichiers d'état présents ont conservé leurs empreintes.

## Termus / SSH

Depuis une session SSH connectée au même compte LexOS :

```bash
prevost aide
prevost outils
prevost mission
prevost cibles
prevost rapport
```

Une session ancienne sans le PATH attendu peut appeler directement
`$HOME/.local/bin/prevost aide`. Aucun Python ou paquet supplémentaire n'est
nécessaire côté Android pour ce mode SSH : la commande s'exécute sur LexOS.

L'opérateur confirme le serveur SSH actif et la connexion Termus réussie.
La validation de ce travail couvre les processus locaux et un environnement SSH
simulé ; aucune nouvelle connexion au téléphone n'a été établie par l'agent.
Aucun second serveur, activation de service, règle UFW ou clé SSH n'a été modifié.

## Préservation et limites

Les documents de validation précédents sont conservés comme historique. Aucun
lanceur existant, fichier personnel, cookie, secret, modèle GGUF, configuration
Ollama ou partition Windows n'a été modifié. Aucun transfert externe de résultat
d'audit, aucune attaque Wi-Fi et aucun scan réel n'a été effectué.

Le code est conservé sur `codex/fusion-v3-2`. L'installation autorisée concerne
le nouveau lanceur de cet utilisateur ; elle ne configure aucun nouveau service.
