# Correction des demandes de scan Prévost

Branche conservée : `codex/prevost-kali-20261104-200037`.
Sauvegarde avant correction : `~/.local/state/prevost-backups/scan-dialogue-20261104-202026/`.

## Comportement installé

Le lanceur `~/.local/bin/prevost-ia` reconnaît les demandes de scan Nmap avant d'appeler l'IA. Le parcours fonctionne aussi sans modèle connecté. Les questions sur l'utilisation de Nmap et les demandes négatives restent des conversations, sans exécution.

- « fais un nmap complet » sans cible sélectionnée demande exactement **Quelle IP ou quel réseau veux-tu scanner?**
- Une cible littérale présente dans la demande remplace la sélection précédente. `/cible IP-ou-CIDR` sélectionne une cible pour la session ; `/cible` l'efface. Une cible invalide explicite ne déclenche jamais un scan de l'ancienne sélection.
- Le registre existant est consulté en lecture seule. Une autorisation valide couvrant le sous-périmètre demandé et les tests `inventory` + `tcp` est réutilisée, sans nouvelle demande d'autorisation. Les limites explicites de ports, l'expiration, la révocation et le périmètre sont respectés. Les droits de plusieurs entrées ne sont pas fusionnés.
- Si l'autorisation manque, le dialogue propose de l'ajouter. Il demande `AUTORISER périmètre`, le responsable, la preuve et l'expiration. La nouvelle entrée enregistre atomiquement la date, le périmètre, les tests et les limites du profil choisi, sans modifier une ancienne autorisation. Une autorisation enregistrant seulement `tcp` sans limite explicite de ports couvre l'opération TCP ; la couverture « 100 ports » des anciens rapports décrivait l'ancien moteur, pas une limite de ports stockée dans ces entrées.
- Les options sont **complet TCP (1–65535)** et **rapide (100 ports courants)**. L'inventaire précède l'analyse des ports. Les commandes exactes et leurs limites de temps sont affichées. Connexions TCP sans sudo via `--unprivileged -sT` ; ni UDP, scripts NSE, version de services, détection OS ou SYN brut. « Complet » ne promet donc pas un audit de tous les protocoles.
- La confirmation **Exécuter ce scan maintenant?** confirme l'exécution des options présentées ; elle ne redemande pas l'autorisation et ne crée pas de doublon.
- La demande en langage naturel passe par le même `kali_bridge` que `/kali nmap`. Le moteur utilise le Nmap réellement détecté sur l'hôte, sans prétendre exécuter dans un conteneur. Aucun argument libre produit par le modèle ne devient une commande.
- Le registre est revalidé avant chaque invocation et avant publication. Seuls les hôtes observés actifs dans l'inventaire autorisé sont analysés. Les réponses hors périmètre sont enregistrées en attente et ne sont pas analysées.
- Les résultats sont les observations réelles parsées depuis Nmap. Les sorties d'outils restent des données non fiables. Une erreur, un délai dépassé ou un XML invalide produit une mission échouée et son erreur réelle, sans ports ou résultats inventés. Les observations partielles éventuelles restent identifiées dans le rapport.
- Rapports JSON privés : `~/.local/state/mon-secret-cookie/scan-reports/RUN-….json` (dossier 700, fichiers 600), avec profils, arguments, codes de retour, observations et statut. Les missions et observations hors périmètre restent consultables dans le registre existant. Les secrets usuels sont masqués dans les sorties persistées. `cookie.txt` est inchangé, empreinte vérifiée.

## Utilisation

Démarrer ou relancer l'atelier pour charger le correctif :

```sh
/home/ti-lex-al/.local/bin/prevost-ia
```

Puis écrire « fais un nmap complet ». Autres points d'entrée :

```text
/cible 192.168.1.10
/kali nmap
/kali nmap --cible 192.168.1.10 --demande "fais un nmap complet"
/kali proposer "fais un nmap complet"
```

La dernière commande propose seulement et pose aussi la question courte si la cible manque. Les IP ci-dessus sont des exemples ; aucune autorisation n'est ajoutée par la documentation.

## Vérifications

```sh
python3 integration/test_local.py
```

**150 tests réussis**, dont 22 nouveaux cas couvrant le dialogue et les simulations de scan. Les nouveaux tests interdisent tout processus réel par défaut. Nmap, ses retours XML et ses échecs sont simulés : question exacte, cible sélectionnée, autorisation réutilisée, ajout explicite, limites rapide/complet, révocation/expiration, annulation, inventaire avant TCP, sous-périmètre, résultat hors périmètre, rapports privés, code d'erreur, délai dépassé, XML invalide et passage effectif par `/kali` sans appel à l'IA.

Vérifications complémentaires sur le lanceur installé : `prevost proposer 'fais un nmap complet'` renvoie la question exacte sans exécution ; `prevost nmap` avec une réponse vide annule le parcours sans Nmap. Syntaxe vérifiée et `git diff --check` sans erreur.

**Aucun scan réseau réel, ajout d'autorisation réelle, changement de privilèges ni appel à un modèle n'a été effectué pendant cette correction.** Les anciens changements non liés ont été conservés.
