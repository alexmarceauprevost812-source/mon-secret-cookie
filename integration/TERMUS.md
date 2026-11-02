# Préparation Termus / Termux Android

Le serveur local authentifié de Mon Secret Cookie existe déjà. Aucun serveur SSH,
clé ou service n'est installé ou activé par cette intégration. Pour V3.2,
l'opérateur confirme le serveur SSH LexOS actif ; le paquet serveur est détecté.
Le bac à sable peut empêcher l'accès au bus systemd : cette restriction ne prouve
pas l'arrêt du serveur et ne doit pas entraîner de redémarrage automatique.

Prérequis à vérifier :

1. Client SSH disponible dans Termus/Termux et clé privée conservée sur Android.
2. Serveur SSH sur LexOS, accès par clé et restriction au réseau approuvé.
3. Empreinte de la clé d'hôte LexOS vérifiée par un canal indépendant et ajoutée
   à `known_hosts` sur Android. Ne pas désactiver cette vérification.
4. Token API aléatoire d'au moins 32 caractères ASCII, communiqué au client par
   un canal sûr, sans le publier dans un rapport ou un dépôt.

Depuis la console LexOS, relever l'empreinte de la clé publique existante :

```bash
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
```

Comparer cette empreinte par un canal indépendant avant d'accepter la clé sur
Android. Ne pas générer ou remplacer les clés d'hôte existantes. Le serveur
annoncé actif n'implique pas une exposition Internet : ne pas ajouter de
redirection de routeur ou ouvrir de règle réseau pendant cette préparation.

Préparer les arguments du tunnel, sans établir de connexion :

```bash
bash integration/prevost connexion --host utilisateur@lexos.local
```

Lorsque les prérequis sont validés, démarrer l'API dans une session LexOS :

```bash
export MSC_API_TOKEN="$(.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(48))')"
.venv/bin/mon-secret-cookie serveur --port 8765
```

Puis, depuis Android, avec une clé déjà configurée :

```bash
ssh -N -o StrictHostKeyChecking=yes -o ExitOnForwardFailure=yes \
  -o PasswordAuthentication=no -o IdentitiesOnly=yes \
  -i "$HOME/.ssh/id_ed25519" \
  -L 127.0.0.1:8765:127.0.0.1:8765 utilisateur@lexos.local
```

Configurer le client IA Android pour consulter `http://127.0.0.1:8765/api/health`
avec l'en-tête `Authorization: Bearer <token>`. Le token ne doit pas être placé
dans l'URL. Routes de lecture : `cibles`, `autorisations`, `nouvelles`, `rapports`
et `outils` sous `/api/`. L'API ne déclenche aucun scan et ne crée pas d'autorisation.

La liaison HTTP reste sur loopback de chaque côté ; le tunnel transporte les
requêtes via SSH. Ne pas remplacer `127.0.0.1` par `0.0.0.0`. Aucun accès Internet,
redirection de routeur ou règle de pare-feu n'est configuré automatiquement.

Validation prévue : contrôle de clé d'hôte, authentification par clé SSH, accès
API autorisé, refus d'un token absent/incorrect, arrêt du tunnel et de l'API.
Les tests automatisés simulent les échanges ; aucune connexion Android réelle
n'a encore été établie.
