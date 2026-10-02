# Guide des cookies — mon-secret-cookie

Objectif : créer, enregistrer, analyser et effacer un cookie fictif dans votre labo local. Faites une étape à la fois, et vérifiez le résultat avant de continuer. Aucun compte réel ni cookie d'un autre appareil n'est nécessaire.

## Avant de commencer

Ouvrez deux terminaux sur le même appareil. Vérifiez que `mon-secret-cookie` et curl sont installés. Sous Kali/Ubuntu : `sudo apt install curl`. Sous Termux : `pkg install curl`. Dans PowerShell Windows, utilisez **curl.exe** à la place de `curl` dans toutes les commandes de ce guide ; pour lire un fichier, utilisez `Get-Content` à la place de `cat`.

Travaillez dans un dossier de labo : le fichier `cookie-lab-curl.txt` doit être nouveau, car curl peut écraser ce fichier. Il ne contiendra que la valeur fictive `FICTIF`.

## 1. Démarrer le labo

Dans le premier terminal :

```bash
mon-secret-cookie flask-lab --port 8000
```

Attendez l'adresse `http://127.0.0.1:8000`. Laissez ce terminal ouvert. Ce serveur est local, sans débogueur. Le port par défaut est 5000 ; nous choisissons explicitement 8000 pour ce guide.

## 2. Vérifier la page

Dans le deuxième terminal :

```bash
curl --noproxy "*" http://127.0.0.1:8000/
```

Résultat attendu dans le HTML : **Cookie fictif : absent**. Le GET de `/` ne crée aucun cookie. Ainsi, `curl -c cookies.txt http://127.0.0.1:8000/` seul ne donnera pas de cookie du labo.

`--noproxy "*"` évite de faire passer ces requêtes locales par un proxy configuré sur votre système.

## 3. Créer le cookie et voir Set-Cookie

```bash
curl --noproxy "*" -i -c cookie-lab-curl.txt -X POST http://127.0.0.1:8000/set
```

La réponse doit avoir le statut **302** et inclure une ligne ressemblant à :

```text
Set-Cookie: msc_lab=FICTIF; Expires=...; Max-Age=600; HttpOnly; Path=/; SameSite=Strict
```

La date varie. `302` est normal : le labo propose une redirection après la création du cookie. Ne combinez pas ici `-L` et `-X POST` : le guide utilise ensuite une requête GET séparée.

Le cookie expire après dix minutes. Sa valeur n'ouvre aucune session réelle.

## 4. Lire le fichier du labo

Linux / Termux :

```bash
cat cookie-lab-curl.txt
```

Windows PowerShell :

```powershell
Get-Content .\cookie-lab-curl.txt
```

La ligne du cookie commence normalement par `#HttpOnly_127.0.0.1`. Ce préfixe est significatif : ce n'est pas un simple commentaire à ignorer.

Le format comporte sept champs séparés par des tabulations : domaine, inclusion des sous-domaines, chemin, Secure, expiration Unix, nom, valeur. Une expiration `0` désigne un cookie de session. SameSite ne figure pas dans ce fichier.

L'affichage de la valeur est réservé ici au cookie fictif. Pour analyser vos propres fichiers sans montrer les valeurs, utilisez la commande suivante.

## 5. Analyser avec mon-secret-cookie

```bash
mon-secret-cookie cookies --file cookie-lab-curl.txt
```

Résultat attendu : nom `msc_lab`, `http_only: true`, `secure: false`, `expired: false`, et valeurs masquées. Le fichier doit appartenir à votre utilisateur. Un lien symbolique est refusé.

`Secure` est désactivé dans ce labo HTTP. Dans une application réelle en HTTPS, il doit être activé. HttpOnly empêche la lecture par JavaScript dans un navigateur ; cela n'empêche pas votre client curl de gérer le cookie. Le labo déclare SameSite=Strict, mais curl ne reproduit pas le comportement d'un navigateur pour tous les scénarios web.

## 6. Renvoyer le cookie au labo

```bash
curl --noproxy "*" -b cookie-lab-curl.txt http://127.0.0.1:8000/
```

Résultat attendu : **Cookie fictif : présent**.

Le serveur transmet les cookies par `Set-Cookie`; le client les renvoie par `Cookie`. Dans curl, `-c` enregistre un fichier de cookies, `-b` le recharge et `-i` affiche les en-têtes de la réponse. curl n'exécute pas JavaScript.

Si le cookie est absent, vérifiez le fichier, l'expiration et l'adresse : gardez `127.0.0.1` dans toutes les commandes, sans alterner avec `localhost`. Recommencez l'étape 3 si nécessaire.

## 7. Effacer et confirmer

```bash
curl --noproxy "*" -i -b cookie-lab-curl.txt -c cookie-lab-curl.txt -X POST http://127.0.0.1:8000/clear
curl --noproxy "*" -b cookie-lab-curl.txt http://127.0.0.1:8000/
```

La première réponse demande la suppression du cookie ; la seconde doit afficher **Cookie fictif : absent**. Le fichier peut conserver ses commentaires d'en-tête même sans cookie.

Arrêtez ensuite le serveur avec **Ctrl+C** dans le premier terminal.

## Rapport et variante sans serveur

Après l'analyse de l'étape 5, vous pouvez exporter les résultats déjà enregistrés :

```bash
mon-secret-cookie report --format txt --output rapport-cookie-lab.txt
```

Pour apprendre le format sans démarrer Flask :

```bash
mon-secret-cookie cookie-lab --output cookies-demo.txt
mon-secret-cookie cookies --file cookies-demo.txt
```

Cette variante génère uniquement un fichier fictif ; aucun en-tête HTTP n'est échangé.

## Si une étape échoue

- **Connexion refusée** : le serveur doit rester ouvert dans le premier terminal, sur le même appareil et le même port.
- **Port occupé** : choisissez par exemple `--port 8001` et remplacez 8000 dans toutes les URL.
- **405 Method Not Allowed** : `/set` et `/clear` exigent POST, tandis que `/` utilise GET. `curl -I` utilise HEAD et ne crée pas de cookie.
- **Fichier vide ou absent** : vérifiez que vous avez appelé `/set` avec POST et que le dossier est accessible en écriture.
- **curl incorrect dans PowerShell** : appelez `curl.exe` explicitement.
- **Termux** : gardez le projet et les fichiers dans le dossier privé de Termux ; ne demandez pas d'accès aux données d'autres applications.

Ce guide utilise uniquement le serveur local fourni et des cookies fictifs. Il n'inclut aucune interception, extraction de profils navigateur ni réutilisation de sessions d'autres personnes.

Référence pour curl et le format de fichier : [documentation officielle HTTP Cookies](https://curl.se/docs/http-cookies.html), également fournie dans le texte joint. Les commandes du labo correspondent aux routes de ce projet.
