# Adaptateur de projet — commandes Fusion

L'intégration utilise le venv existant. Elle ne remplace pas `prevost-ia`, ne
modifie pas V4/V5 et ne nécessite aucune installation système. Depuis ce dépôt :

```bash
bash integration/prevost outils
bash integration/prevost stockage
bash integration/prevost rapport
```

Pour employer le nom court dans le terminal courant, une fonction suffit :

```bash
prevost() { bash "$HOME/LexOS-Projets/mon-secret-cookie/integration/prevost" "$@"; }
prevost outils
```

Cette fonction n'est pas ajoutée automatiquement au profil shell. Le registre
décrit les exécutables existants et indique Mon Secret Cookie 0.3.0 dans le Python
courant. Il cherche Lynis dans `/usr/sbin` et Codex dans ses installations locales
si nécessaire. Un outil trouvé n'est pas considéré comme fonctionnel avant diagnostic.

## Détection automatique V3.2 et tableau de bord

```bash
prevost tableau
prevost outils
```

Le registre lit le lanceur `~/.local/bin/kali`, reconnaît Distrobox et le nom du
conteneur. Il interroge Podman pour savoir si ce conteneur est déjà actif, puis
lit son `/etc/os-release`, les chemins des outils et leurs versions de paquets
avec un programme Python fixe. Aucun lanceur n'est exécuté ou remplacé ; aucun
conteneur n'est démarré. Les chemins `/usr/sbin` sont recherchés explicitement.

Wifite, Nmap, Tshark, Lynis et Hashcat apparaissent séparément pour Kali. La
version Wifite `2.8.2-2` désigne la version du paquet Debian. Si Podman est bloqué,
les données confirmées par l'opérateur dans `environments.json` figurent sous
`reported`, tandis que l'état réel reste `unverified` : aucune disponibilité
n'est inventée. Ces confirmations ne donnent aucune autorisation de scan.

`tableau` ajoute les nombres d'autorisations et de missions, ainsi que la dernière
mission enregistrée, sans modifier le registre. Mon Secret Cookie conserve sa
version 0.3.0 ; V3.2 désigne l'adaptateur et cette mission d'intégration.

## Diagnostics, sans capture ni attaque

```bash
prevost outils --diagnostic
prevost outils --diagnostic --kali
```

Les diagnostics sont limités à des arguments fixes de version/aide. Aucun mode
de capture Tshark ni attaque Wifite n'est disponible. Le diagnostic Kali exécute
les versions des outils détectés et l'aide Wifite via leurs chemins explicites :
le conteneur doit déjà être démarré. L'écriture de bytecode Python est désactivée.
Un échec Podman, un conteneur arrêté, un outil absent ou un contrôle de
sécurité Lynis sont rapportés, sans correction automatique.

L'opérateur a confirmé Wifite 2.8.2-2 dans Kali, à `/usr/sbin/wifite`.
La vérification automatique reste impossible depuis le bac à sable si Podman
est inaccessible ; le tableau distingue alors cette confirmation de l'observation.
Le lanceur existant `kali` entre dans `kali-lexos` via Distrobox. Ne pas le lancer
automatiquement pour masquer un problème de permissions.

## Missions et autorisations

Créer une autorisation est une décision explicite de l'opérateur, pas une tâche
confiée au modèle. Utiliser le CLI existant depuis son venv :

```bash
.venv/bin/mon-secret-cookie cibles
.venv/bin/mon-secret-cookie autorisations
prevost mission --cible AUTH-IDENTIFIANT_EXISTANT
prevost scan --cible AUTH-IDENTIFIANT_EXISTANT
```

Ces deux dernières commandes préparent le plan et n'envoient aucune sonde. La
préparation lit SQLite en mode lecture seule sans créer de registre absent.
Les autorisations doivent posséder une preuve, un responsable, un périmètre,
une échéance valide et les tests permis ; les autorisations révoquées sont refusées.
Plusieurs sélections sont possibles en répétant `--cible`.

Pour une exécution ultérieure explicitement décidée par l'opérateur :

```bash
prevost scan --cible AUTH-IDENTIFIANT_EXISTANT --executer
prevost rapport --output rapport-mission.json
prevost rapport --mission RUN-IDENTIFIANT_EXISTANT
```

L'exécution exige Nmap et au moins 1 Gio libre sur `/`. Ce seuil est un minimum
technique, pas une estimation garantie du volume des rapports. Le moteur existant
revérifie les autorisations pendant la mission et conserve ses journaux. La
découverte CIDR reste limitée au LAN approuvé ; le TCP teste seulement 100 ports
courants si `tcp` est permis. Aucun argument Nmap libre n'est accepté.

Les nouveaux actifs héritent des seuls droits du périmètre approuvé ; un ID
extérieur n'accorde aucune autorisation. Les rapports ne remplacent pas les
inventaires précédents en cas d'échec. Les exports refusent l'écrasement.

## Préservation et stockage

L'examen initial a observé 92 % d'occupation et 6,1 Go libres sur `/`. Les volumes
importants incluent les GGUF (9,8 Go), les caches utilisateur (6,3 Go, dont pip
2,9 Go), Atelier-IA (5,6 Go) et Android (3 Go). Certaines zones sont inaccessibles,
donc les mesures sont partielles. Aucune de ces données n'a été supprimée ou déplacée.

Cet adaptateur ne nettoie aucun cache, n'installe aucun outil et ne touche pas aux
configurations Ollama, aux modèles GGUF, à Windows ou aux lanceurs installés.
Voir [TERMUS.md](TERMUS.md) pour la préparation de la connexion Android.
