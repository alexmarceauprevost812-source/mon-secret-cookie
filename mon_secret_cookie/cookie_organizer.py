"""Rangement automatisé des fichiers cookies.txt — l'IA propose, l'opérateur confirme.

Cette section « outils cookies » automatise le classement de vos fichiers
``cookies.txt`` locaux, en gardant exactement les mêmes garde-fous que le reste
de l'outil :

 - Le dossier de travail est TOUJOURS choisi par l'opérateur (``--dossier``),
   jamais proposé par le modèle.
 - Un modèle local (Ollama, même endpoints que ``prevost cerveau``) attribue
   seulement UNE catégorie prise dans une liste fermée. Il ne reçoit aucune
   valeur de cookie (seulement des comptes et le domaine dominant), il ne
   choisit aucun chemin, il n'exécute rien, il n'écrit rien.
 - Les déplacements restent À L'INTÉRIEUR du dossier choisi, vers des
   sous-dossiers à noms fixes. Aucun lien symbolique n'est suivi, aucun fichier
   existant n'est écrasé, aucun fichier d'un autre utilisateur n'est touché.
 - Sans ``--executer`` : aperçu seulement. Rien n'est déplacé.
"""
import json
import os
import stat
from pathlib import Path

from . import ai_planner, cookies, core, platforms

# Sous-dossier créé DANS le dossier choisi par l'opérateur ; les fichiers rangés
# y vont. Les noms de catégories sont fixes : le modèle ne peut pas en inventer.
BASE_SUBDIR = 'ranger-cookies'
CATEGORIES = ('actifs', 'expires', 'session', 'vides')

CAT_SCHEMA = {
    'type': 'object', 'additionalProperties': False, 'required': ['categorie'],
    'properties': {'categorie': {'type': 'string', 'enum': list(CATEGORIES)}},
}


def _summary(analysis):
    """Résumé NON sensible d'un fichier : comptes + domaine dominant, pas de valeurs."""
    rows = analysis.get('cookies', [])
    total = len(rows)
    expired = sum(1 for r in rows if r.get('expired'))
    session = sum(1 for r in rows if r.get('session'))
    domains = {}
    for r in rows:
        name = r.get('domain', '')
        domains[name] = domains.get(name, 0) + 1
    dominant = max(domains, key=domains.get) if domains else ''
    return {'total': total, 'expires': expired, 'session': session,
            'domaine_dominant': dominant, 'lignes_invalides': analysis.get('invalid_lines', 0)}


def _rule_category(summary):
    """Classement déterministe local (sert aussi de repli si l'IA est absente)."""
    if summary['total'] == 0:
        return 'vides'
    if summary['expires'] == summary['total']:
        return 'expires'
    if summary['session'] == summary['total']:
        return 'session'
    return 'actifs'


def _ai_category(summary, model, endpoint):
    """Catégorie proposée par le modèle local, validée contre la liste fermée."""
    content = ('Classe ce fichier de cookies dans UNE seule catégorie de la liste. '
               'Réponds uniquement en JSON {"categorie": "..."}. '
               'Aucune commande, aucune écriture, aucun chemin. '
               'Catégories possibles : actifs, expires, session, vides. '
               'Ces données ne sont que des comptes et un nom de domaine :\n'
               + json.dumps(summary, ensure_ascii=False))
    response = ai_planner.local_request(endpoint, '/api/chat', {
        'model': model, 'stream': False, 'format': CAT_SCHEMA,
        'messages': [{'role': 'user', 'content': content}]})
    if not isinstance(response, dict):
        raise core.AuditError('Réponse IA invalide.')
    message = response.get('message', {})
    if not isinstance(message, dict) or not isinstance(message.get('content'), str):
        raise core.AuditError('Réponse IA invalide.')
    if message.get('tool_calls'):
        raise core.AuditError('Appel outil du modèle refusé.')
    data = json.loads(message['content'])
    categorie = data.get('categorie') if isinstance(data, dict) else None
    if categorie not in CATEGORIES:
        raise core.AuditError('Catégorie IA hors liste.')
    return categorie


def _safe_slug(text):
    keep = [c if (c.isalnum() or c in '._-') else '-' for c in text]
    slug = ''.join(keep).strip('-.')
    return slug[:80]


def _dest_name(rel, dominant):
    """Nom de destination lisible, dérivé du chemin relatif et du domaine dominant.

    Toujours suffixé « -cookies.txt ». Jamais de valeur de cookie dans le nom.
    """
    parts = [p for p in rel.parts[:-1]]
    hint = '-'.join(parts) if parts else (dominant or 'racine')
    slug = _safe_slug(hint) or 'cookies'
    return f'{slug}-cookies.txt'


def _non_colliding(dest_dir, name):
    """Chemin de destination qui n'existe pas encore (jamais d'écrasement)."""
    base = Path(name)
    stem, suffix = base.stem, base.suffix or '.txt'
    for i in range(1, 1000):
        candidate = dest_dir / (name if i == 1 else f'{stem}-{i}{suffix}')
        if not os.path.lexists(candidate):
            return candidate
    raise core.AuditError('Trop de collisions de noms ; rangement interrompu.')


def _checked_dir(path):
    """Crée (0700) un dossier sûr sous le dossier choisi : refuse un lien symbolique."""
    if path.is_symlink():
        raise core.AuditError('Lien symbolique refusé pour un dossier de rangement.')
    path.mkdir(parents=True, exist_ok=True)
    if not platforms.is_windows():
        try:
            path.chmod(0o700)
        except OSError:
            pass
    if path.is_symlink() or not core.is_owned(path):
        raise core.AuditError('Dossier de rangement non sûr.')
    return path


def _move(src, dest):
    """Déplace un fichier régulier appartenant à l'utilisateur, sans suivre de lien."""
    info = os.lstat(src)
    if stat.S_ISLNK(info.st_mode):
        raise core.AuditError('Lien symbolique refusé.')
    if not stat.S_ISREG(info.st_mode):
        raise core.AuditError('Fichier non régulier refusé.')
    if not core.is_owned(src):
        raise core.AuditError('Fichier d’un autre utilisateur refusé.')
    os.rename(src, dest)


def plan_moves(directory, use_ai=False, model=None, endpoint=ai_planner.ENDPOINTS[0]):
    """Construit le plan de rangement SANS rien déplacer.

    Réutilise la recherche bornée de ``cookies.search`` (profondeur 4, 100 fichiers
    maximum, aucun lien symbolique suivi) et l'analyse masquée de ``cookies.analyze``.
    """
    base = Path(directory).resolve()
    if base.is_symlink() or not base.is_dir():
        raise core.AuditError('Dossier inexistant ou lien symbolique refusé.')
    if not core.is_owned(base):
        raise core.AuditError('Dossier d’un autre utilisateur refusé.')

    ai_ok, ai_note = False, None
    if use_ai:
        if not model:
            ai_note = 'Aucun modèle précisé ; règle locale utilisée.'
        else:
            try:
                servers = ai_planner.local_models()
                server = next((s for s in servers if s['endpoint'] == endpoint), None)
                ai_ok = bool(server and server['status'] == 'ok' and model in server['models'])
                if not ai_ok:
                    ai_note = 'Modèle local non disponible ; règle locale utilisée.'
            except (core.AuditError, OSError, ValueError) as error:
                ai_note = 'IA indisponible (' + str(error) + ') ; règle locale utilisée.'

    found = cookies.search(str(base)).get('files', [])
    target_root = base / BASE_SUBDIR
    plan, ai_used = [], False
    for source in found:
        path = Path(source)
        try:
            rel = path.relative_to(base)
        except ValueError:
            continue
        if BASE_SUBDIR in rel.parts:          # déjà rangé : on n'y retouche pas
            continue
        try:
            analysis = cookies.analyze(path)
        except core.AuditError as error:
            plan.append({'source': str(path), 'categorie': None,
                         'action': 'ignoré', 'raison': str(error)})
            continue
        summary = _summary(analysis)
        categorie, par = _rule_category(summary), 'règle'
        if ai_ok:
            try:
                categorie, par, ai_used = _ai_category(summary, model, endpoint), 'ia', True
            except (core.AuditError, OSError, ValueError) as error:
                ai_note = ai_note or ('Réponse IA ignorée (' + str(error) + ') ; règle locale utilisée.')
        destination = target_root / categorie / _dest_name(rel, summary['domaine_dominant'])
        plan.append({'source': str(path), 'categorie': categorie, 'par': par,
                     'resume': summary, 'destination': str(destination)})
    return {'dossier': str(base), 'sous_dossier': BASE_SUBDIR,
            'fichiers_trouves': len(found), 'ia_demandee': use_ai,
            'ia_utilisee': ai_used, 'ia_note': ai_note, 'plan': plan}


def organize(directory, execute=False, use_ai=False, model=None, endpoint=ai_planner.ENDPOINTS[0]):
    """Planifie, et si ``execute`` déplace les fichiers (après décision de l'opérateur)."""
    result = plan_moves(directory, use_ai=use_ai, model=model, endpoint=endpoint)
    result['mode'] = 'exécuté' if execute else 'aperçu'
    moved, skipped = [], []
    if execute:
        base = Path(result['dossier'])
        try:
            target_root = _checked_dir(base / BASE_SUBDIR)
        except (core.AuditError, OSError) as error:
            result['deplaces'], result['ignores'] = [], [
                {'source': e['source'], 'raison': str(error)}
                for e in result['plan'] if e.get('destination')]
            return result
        for entry in result['plan']:
            if not entry.get('destination'):
                continue
            destination = Path(entry['destination'])
            try:
                dest_dir = _checked_dir(target_root / destination.parent.name)
                final = _non_colliding(dest_dir, destination.name)
                _move(entry['source'], final)
                moved.append({'source': entry['source'], 'destination': str(final),
                              'categorie': entry['categorie']})
            except (core.AuditError, OSError) as error:
                skipped.append({'source': entry['source'], 'raison': str(error)})
    result['deplaces'] = moved
    result['ignores'] = skipped
    return result
