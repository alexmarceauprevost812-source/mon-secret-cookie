# Fusion V3.2 — résultats et limites

Branche dédiée : `codex/fusion-v3-2`. Aucun déploiement ni remplacement des
lanceurs installés. Mon Secret Cookie conserve la version 0.3.0.

## Modifications

- Détection du lanceur Kali/Distrobox existant et du nom de conteneur, sans
  exécuter le lanceur ni démarrer un conteneur.
- Inventaire automatique des chemins et versions de paquets Wifite, Nmap,
  Tshark, Lynis et Hashcat dans Kali déjà actif. Recherche explicite dans
  `/usr/sbin`. Le programme de collecte est fixe et désactive le bytecode Python.
- Wifite confirmé par l'opérateur : `/usr/sbin/wifite`, paquet `2.8.2-2`, Kali
  2026.3. Ces informations figurent sous `reported` tant que l'observation en
  direct n'est pas possible. Elles ne remplacent jamais un résultat de détection.
- Nouveau `tableau` : Mon Secret Cookie, registre des outils hôte/Kali, stockage,
  nombre d'autorisations et historique récent, sans écriture dans le registre.
- Diagnostics de version/aide à arguments fixes. Aucun mode de capture Tshark
  ou d'attaque Wi-Fi. Le diagnostic Lynis est bloqué si les propriétaires visibles
  ne satisfont pas son contrôle initial ; aucune permission n'est contournée.
- Documentation Android mise à jour pour le serveur SSH annoncé actif par
  l'opérateur, avec clé client, contrôle strict d'empreinte et tunnel loopback.

## Validation

**85 tests réussis** dans la suite Python du projet, dont 13 nouveaux tests de
découverte d'environnement. Les tests existants sont conservés ; deux assertions
de l'ancien diagnostic Kali ont été adaptées au nouveau précontrôle du conteneur.

Couverture ajoutée : lanceur Distrobox, distinction du menu hôte, conteneur arrêté,
permissions refusées, vérification Kali, chemin Wifite en sbin, version de paquet,
rejet des chemins inattendus et métadonnées invalides, diagnostic Wifite limité à
l'aide, garde de propriété Lynis et lecture du tableau de bord. Les tests de
périmètre, expiration, révocation, historique et absence d'écrasement restent actifs.

Vérifications réelles sur LexOS :

| Élément | Résultat |
| --- | --- |
| Nmap `--version` | OK, 7.95 |
| Tshark `--version` | OK, 4.4.19 |
| Hashcat `--version` | OK, 6.2.6 ; aucun calcul lancé |
| Lynis | Paquet présent ; diagnostic bloqué par les propriétaires visibles du bac à sable |
| Lanceur Kali | Reconnu, conteneur `kali-lexos` |
| Métadonnées Kali | Inaccessibles ici : répertoire Podman visible en lecture seule |
| OpenSSH serveur | Paquet et exécutable présents ; activité confirmée par l'opérateur, bus systemd inaccessible ici |
| Clé publique SSH ED25519 | Présente ; empreinte calculable localement |
| Syntaxe Bash | Lanceur projet et installateurs valides, aucun installateur exécuté |

L'empreinte locale du serveur ne suffit pas à authentifier une connexion Android :
elle doit encore être comparée sur Android par un canal indépendant. Aucune
connexion SSH, activation de service ou modification réseau n'a été effectuée.

Les tests Kali utilisent des métadonnées simulées : la vérification automatique
sur le terminal hôte normal reste à effectuer avec `outils --diagnostic --kali`.
Un blocage du bac à sable est rapporté sans nier les résultats fournis par
l'opérateur. L'inventaire hôte et le tableau restent utilisables en cas d'erreur Kali.

## Préservation

Le moteur de mission et sa base SQLite ne sont pas modifiés. L'adaptateur conserve
la sélection explicite des autorisations, `--executer`, les vérifications de
validité/périmètre et les journaux existants. Aucun registre absent n'est créé par
la simple consultation. Aucun résultat d'audit réel ou secret n'est ajouté à la
branche. Les rapports locaux V3.1 et leur manifeste restent hors de ce changement.

Aucune réinstallation, attaque Wi-Fi, capture ou scan réel. Aucun changement à
Ollama, aux GGUF, aux lanceurs V4/V5, aux clés SSH ou à Windows. La validation de
cette branche n'active pas sa mise en service globale.

## Essai depuis le projet

```bash
bash integration/prevost tableau
bash integration/prevost outils --diagnostic --kali
bash integration/prevost connexion --host utilisateur@lexos.local
```

Le nom court `prevost` reste une fonction de session optionnelle documentée dans
UTILISATION.md. Aucun profil shell ou lanceur système n'a été installé.
