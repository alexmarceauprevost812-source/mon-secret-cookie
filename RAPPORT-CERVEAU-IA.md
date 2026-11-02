# Cerveau IA — version de test isolée

## État

Branche locale : `codex/brain-finalization`.
Copie de travail : `~/LexOS-Projets/mon-secret-cookie-brain-test`.
Base : `7e39c731c2145c0e2498168db8545159341e6b13`.

Aucun déploiement ni publication de cette version. Le lanceur `prevost` installé
continue d'utiliser le projet original. Aucun lanceur, modèle GGUF, configuration
Ollama, service, sudoers, partition Windows ou fichier GRUB modifié.

## Existant réutilisé

- Le moteur de missions, les autorisations, les inventaires et la comparaison
  d'actifs de Mon Secret Cookie restent les points d'exécution des audits.
- Les diagnostics et la sélection des environnements hôte/Kali réutilisent le
  registre existant. Aucun outil réinstallé et aucune commande fournie par le
  modèle n'est évaluée dans un shell.
- Le mode programmeur réutilise `auto_project`, `auto_tests` et les contrôles
  d'isolation du fichier AUTO V5 existant, sans le remplacer.
- `prevost-v1` et une mission permanente associée restent introuvables dans
  l'environnement accessible. Aucun remplacement ou migration de cette mission
  n'est inventé ; son raccordement exige son véritable chemin/source.

## Modifications préparées

| Fichier | Rôle |
| --- | --- |
| `mon_secret_cookie/ai_planner.py` | Connecteurs Codex et modèles locaux, réponse JSON contrainte |
| `mon_secret_cookie/brain.py` | Plans persistants, événements, reprise, tâches et boucle d'inventaire |
| `mon_secret_cookie/programmer.py` | Réutilisation AUTO V5, quota de 250 et renouvellement opérateur |
| `mon_secret_cookie/notifications.py` | Notification locale de validation, repli terminal/SSH |
| `mon_secret_cookie/cookie_inventory.py` | Suivi des métadonnées des cookies.txt locaux choisis |
| `mon_secret_cookie/fusion.py` | Raccordement CLI ; anciennes commandes conservées |
| `tests/test_brain.py` | 28 nouveaux tests sans scan réel |

Les nouvelles tables SQLite sont additives : plans, événements, quota et suivi de
fichiers locaux. Elles ne modifient pas les cibles ou historiques existants. La
simple consultation ne crée pas de registre absent. Le journal conserve les
échecs et leurs preuves même après une reprise réussie.

## Planification autonome et reprise

L'IA propose uniquement des tâches parmi : diagnostics hôte, diagnostics Kali,
inventaire autorisé, rapport et tests d'un projet explicitement sélectionné.
Les champs de commande libre, outils inconnus et IDs étrangers sont refusés.
Le choix d'un projet ou dossier de cookies provient de l'opérateur, jamais du modèle.

Un inventaire couvrant tous les IDs sélectionnés est ajouté si le modèle l'omet.
L'exécution réutilise les contrôles existants et revalide les autorisations après
la génération du modèle, avant la reprise et avant chaque tâche active.
Les étapes terminées ne sont pas rejouées lors d'une reprise de plan interrompu.
Un verrou empêche le chevauchement des missions pilotées par cet orchestrateur.

La boucle est désactivée par défaut et reste au premier plan du terminal. Après
chaque cycle terminé, le suivant est prévu **60 secondes après la fin**, puis les
autorisations sont vérifiées de nouveau. Erreur, révocation, expiration, manque
d'espace ou quota épuisé arrêtent l'exécution. Aucun service ou timer n'est installé.
Un nouvel actif ne reçoit que les droits d'un périmètre déjà approuvé. La boucle
ne garantit pas l'apparition d'un nouvel appareil à chaque passage.

## Lots de 250 et sudo

Le quota compte les tentatives de commandes directement lancées par
l'orchestrateur et les contrôles AUTO V5, y compris les tentatives échouées.
La 251e invocation est refusée avant lancement. Les sous-processus créés par un
programme lui-même ne constituent pas un compteur système de tous les execve.
Les notifications d'interface et lectures Python ne consomment pas ce quota.

Un rapport et une notification sont disponibles lorsque le lot est épuisé.
Le renouvellement exige un vrai terminal et appelle `/usr/bin/sudo -k -v`, sans
`-S`, capture de mot de passe ou transmission à l'IA. Après succès, le lot suivant
dispose de 250 invocations. En cas de refus, le compteur est conservé.

**Ce quota applicatif ne donne aucun droit root automatique et ne remplace pas
la politique sudo du système.** Aucun NOPASSWD ni terminal administrateur général
n'est créé. Le mode programmeur fourni lance les tests isolés des projets permis ;
les modifications de code restent soumises aux confirmations de l'AUTO V5 existant.

## Notifications

Une demande de validation utilise `notify-send` si le bureau local est disponible.
En SSH/Termus, un message et une cloche terminal servent de repli, selon les
capacités du client. Aucun message à un tiers, aucun secret dans la notification.
`MSC_NOTIFICATIONS=0` désactive les notifications, notamment pendant les tests.

## Nouveaux appareils et cookies.txt

Les nouveaux actifs proviennent exclusivement des inventaires autorisés existants.
L'option `--cookies-dossier` consulte seulement un dossier local précis choisi par
l'opérateur. La recherche et l'analyse existantes sont réutilisées : maximum
100 fichiers, profondeur 4, refus des liens finaux et fichiers non possédés.
Seules les métadonnées sont retournées ; la mémoire stocke leurs empreintes,
jamais les valeurs de cookies. Aucun accès automatique aux fichiers d'un appareil
découvert, profil navigateur ou session distante.

## Connexions IA : portée réelle de la validation

- Codex est détecté et son interface `exec --ignore-user-config --help` accepte
  les paramètres utilisés. Planification éphémère, schéma JSON, lecture seule
  et outils shell désactivés, conformément à la
  [documentation officielle](https://learn.chatgpt.com/docs/non-interactive-mode).
- Une génération Codex nécessite `--autoriser-codex` : l'objectif et les IDs
  peuvent être transmis au service. Aucun fichier de projet, preuve, cookie ou
  clé n'est joint automatiquement. Les identifiants de connexion existants ne
  sont pas copiés par ce module.
- Les serveurs locaux sont limités à `127.0.0.1:11435` et `127.0.0.1:11434`.
  Proxies et redirections sont refusés. Aucun modèle installé, téléchargé,
  copié ou modifié. Les modèles annoncés distants/cloud sont exclus du catalogue.
- Les requêtes de découverte réelles ont été bloquées par le bac à sable
  (`Operation not permitted`). La génération réelle Codex/locale et la liste
  effective des modèles restent à valider dans le terminal LexOS normal.

## Tests et résultats

**130 tests réussis**, dont les 102 tests du projet avant cette évolution et
28 tests supplémentaires. Les échanges IA, sudo et les scans sont simulés.

Vérifications ajoutées : plan JSON limité, injection refusée, cible inconnue ou
révoquée, mémoire persistante, reprise sélective, conservation des erreurs,
verrouillage, délai de 60 secondes sur horloge virtuelle, révocation pendant
l'attente, quota 250/251, restauration des fonctions après contrôle du quota,
sudo réservé au terminal, compteur inchangé après refus, notifications SSH et
masquage des valeurs de cookies. Aucun scan réel ni commande sudo réelle.

Le succès des tests démontre le comportement du prototype avec les réponses
simulées. Il ne démontre pas une connexion IA réelle, une notification Android
native ou l'exécution réelle d'un projet via bwrap sur le matériel de l'opérateur.
Le contrôle d'isolation V5 reste obligatoire et peut refuser l'exécution.

## Essais après revue, depuis la copie de test

```bash
bash integration/prevost cerveau etat
bash integration/prevost cerveau plans
bash integration/prevost programmeur rapport
bash integration/prevost cerveau planifier 'Inventaire approuvé et rapport' \
  --backend local --modele NOM_LOCAL --cible AUTH-EXISTANT
bash integration/prevost mission --plan-id PLN-EXISTANT
bash integration/prevost cerveau journal PLN-EXISTANT
```

Les commandes précédentes ne lancent aucun scan. Les commandes suivantes sont
des opérations actives ultérieures et n'ont pas été exécutées dans cette mission :

```bash
bash integration/prevost cerveau reprendre PLN-EXISTANT --executer
bash integration/prevost cerveau surveiller PLN-EXISTANT --executer
bash integration/prevost programmeur tester PROJET_AUTORISE --executer
bash integration/prevost programmeur renouveler
```

La commande `prevost` installée n'est pas raccordée à cette copie de test.
Validation de l'opérateur requise avant toute activation ou installation.
