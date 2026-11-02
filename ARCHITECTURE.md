# Architecture — Security Pro 2.1 pour IA locale

Plan approuvé : étendre le CLI existant en préservant ses fonctions, données et
modèles. Aucun installateur ni scan réseau n'est lancé pendant le développement.

## Modules

- `security.py` : registre SQLite privé, preuves d'autorisation, échéances UTC,
  inventaires, actifs nouveaux et journal de missions. Les écritures de mission
  sont obligatoires ; une panne de journalisation interrompt la mission.
- `diagnostics.py` : présence/version Nmap, Wifite et Hashcat, GPU NVIDIA,
  interfaces Wi-Fi et support déclaré du mode monitor. Aucun lancement Wifite
  sans argument, aucune attaque ni démonstration sur des données réelles.
- `server.py` : API Flask en lecture seule, authentification Bearer pour chaque
  route, écoute fixée à 127.0.0.1. Pas de lancement de commandes par HTTP.
- `cli.py` : commandes `cibles`, `autorisations`, `nouvelles`, `scan complet`,
  `outils`, `rapport` et `serveur`, en complément des commandes existantes.

## Autorisations et mission

Chaque autorisation conserve un ID unique, un nom, un responsable, une IP ou un
CIDR IPv4 privé local (/24 maximum), les tests permis (`inventory`, `tcp`),
sa date d'expiration, une preuve textuelle et la dernière analyse. Les domaines
et identifiants restent enregistrables comme références, mais leur résolution
automatique n'autorise pas de scan : une IP ou un CIDR explicite est requis.

Avant toute sonde : vérifier toutes les autorisations sélectionnées, sauvegarder
le début de mission, vérifier le LAN pour la découverte CIDR, puis découvrir.
Un actif découvert dans le périmètre hérite des seuls tests permis et de
l'expiration de cette autorisation. Tout actif extérieur est en attente et ne
reçoit aucune sonde supplémentaire. Un ID seul ne donne aucun droit hors périmètre.
Le scan TCP existant est borné ; il est exécuté seulement si `tcp` figure dans
l'autorisation. Les commandes historiques gardent leurs confirmations existantes
et sont distinctes du moteur de mission avec registre.

Les inventaires sont comparés uniquement pour la même autorisation. Les rapports
présentent les ajouts, absences observées (pas preuve de disparition), IP et
services modifiés. Une mission partielle ou échouée ne remplace pas la référence
du dernier inventaire réussi. Les preuves et instantanés restent locaux.

## Interface IA et serveur LexOS Pro

Le CLI produit du JSON pour l'IA locale. L'API consulte les cibles, diagnostics
et rapports sans outil d'exécution arbitraire. Le modèle n'accorde pas lui-même
les autorisations. Le token provient de `MSC_API_TOKEN` (32 caractères minimum),
n'est jamais affiché et n'est pas placé dans l'URL. Accès distant par tunnel SSH
avec clé, vérification de clé d'hôte et redirection vers loopback uniquement.

## Validation

Tests de refus hors périmètre, expiration, héritage borné, changements, erreurs
Nmap, persistance, authentification et absence de lancement offensif. Les tests
réseau utilisent des réponses simulées. Les validations Kali/GPU/Termux/Windows
sur matériel physique restent distinctes des tests Linux.
