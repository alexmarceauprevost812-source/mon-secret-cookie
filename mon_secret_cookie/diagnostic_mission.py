"""Orchestration locale d’aides/versions et rapports typés sans sortie brute."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import subprocess
import uuid
from . import core, menu_tools, watch


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def extract(tool, observed, environment):
    # Ne persister aucun texte libre d’un binaire ou d’une erreur système.
    # Les versions sont limitées à une séquence numérique, jamais une ligne brute.
    text=observed.get('message','')
    if tool not in menu_tools.CHECKS and tool != 'conteneur-kali':
        raise core.AuditError('Outil absent du catalogue fermé.')
    version_text='\n'.join(line for line in text.splitlines() if not re.search(
        r'(?i)cookie|token|secret|password|passwd|authorization|bearer|api[_-]?key',line))
    match=re.search(r'(?<![\w.])v?(\d{1,4}\.\d{1,4}(?:\.\d{1,4}){0,2})(?![\w.])',version_text)
    state=observed.get('etat','erreur')
    if state not in ('disponible','manquant','erreur'):
        state='erreur'
    code=observed.get('code')
    code=code if type(code) is int else None
    reason=None
    if state!='disponible':
        reason='outil_manquant' if state=='manquant' else 'conteneur_indisponible' if tool=='conteneur-kali' else (
            'delai_depasse' if 'timed out' in text.lower() else
            'permissions_insuffisantes' if 'operation not permitted' in text.lower() or 'permission denied' in text.lower() else
            'propriete_incompatible' if 'propriété' in text.lower() else 'execution_indisponible')
    return {'outil':tool,'date':timestamp(),'appareil':environment,'etat':state,
            'constat':'Aide/version exécutée sans analyse réseau.' if state=='disponible' else
                      'Commande absente.' if state=='manquant' else 'Vérification locale échouée ou inaccessible.',
            'version':match.group(1) if match and state=='disponible' else None,
            'erreur':reason,
            'code_retour':code}


def directory():
    path=core.state_dir()/'diagnostics'
    path.mkdir(mode=0o700,exist_ok=True)
    if path.is_symlink() or not path.is_dir() or not core.is_owned(path):
        raise core.AuditError('Dossier de diagnostics non sûr.')
    path.chmod(0o700)
    return path


def notify_finished(identifier, errors):
    tool=core.executable('notify-send')
    message=f'{identifier} — diagnostics locaux terminés ; {errors} vérification(s) indisponible(s).'
    print('MISSION TERMINÉE — '+message,flush=True,file=sys.stderr)
    if not tool:
        return 'terminal'
    try:
        result=subprocess.run([tool,'--','PRÉVOST — diagnostic terminé',message],
                              capture_output=True,timeout=5,check=False)
        return 'service_accepte' if result.returncode==0 else 'terminal_service_indisponible'
    except (OSError,subprocess.TimeoutExpired):
        return 'terminal_service_indisponible'


def run(kali=False, notifications=True, output=None):
    path=directory()
    identifier='DIAG-'+uuid.uuid4().hex
    # Verrou distinct ; le journal est validé avant tout diagnostic.
    import fcntl
    with watch.private_open(path/'.lock') as lock:
        try:
            fcntl.flock(lock.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise core.AuditError('Diagnostic déjà en cours.') from error
        with watch.private_open(path/'cookie.txt') as log:
            log.seek(0,2)
            log.write(f'\nPRÉVOST — {identifier} — début {timestamp()} — aides/versions locales\n')
            log.flush();os.fsync(log.fileno())
            registry=menu_tools.report(verify=True) if kali else local_report()
            rows=[extract(name,item,'LexOS') for name,item in registry['outils_LexOS'].items()]
            if kali:
                rows.extend(extract(name,item,'kali-lexos') for name,item in registry.get('outils_kali',{}).items())
                if registry.get('kali',{}).get('status') != 'available':
                    rows.append(extract('conteneur-kali',{'etat':'erreur'},'kali-lexos'))
            errors=sum(row['etat']!='disponible' for row in rows)
            result={'mission':identifier,'date':timestamp(),'appareil':'LexOS','resultats':rows,
                    'etat':'termine' if not errors else 'partiel','analyses_actives':False,
                    'notification':'desactivee' if not notifications else 'en_attente',
                    'rapport_texte':str(path/'cookie.txt'),'export_json':str(path/(identifier+'.json'))}
            for row in rows:
                log.write(f"{row['date']} | {row['appareil']} | {row['outil']} | {row['etat']} | {row['constat']} | version={row['version']} | erreur={row['erreur']} | code={row['code_retour']}\n")
            log.flush();os.fsync(log.fileno())
            # Export initial avant notification : un échec de stockage arrête la mission.
            export=path/(identifier+'.json')
            core.private_write(export,json.dumps(result,ensure_ascii=False,indent=2)+'\n')
            if output:
                core.private_write(Path(output),json.dumps(result,ensure_ascii=False,indent=2)+'\n')
            if notifications:
                result['notification']=notify_finished(identifier,errors)
            # Publication atomique du résultat final ; aucune sortie brute persistée.
            temporary=path/('.'+uuid.uuid4().hex)
            try:
                core.private_write(temporary,json.dumps(result,ensure_ascii=False,indent=2)+'\n')
                with temporary.open('r') as saved:
                    os.fsync(saved.fileno())
                os.replace(temporary,export)
            finally:
                temporary.unlink(missing_ok=True)
            if output:
                # Le chemin a été réservé exclusivement avant la notification.
                temp_output=Path(output).with_name('.diag-'+uuid.uuid4().hex)
                try:
                    core.private_write(temp_output,json.dumps(result,ensure_ascii=False,indent=2)+'\n')
                    os.replace(temp_output,Path(output))
                finally:
                    temp_output.unlink(missing_ok=True)
            log.write(f"FIN {identifier} | {result['etat']} | notification={result['notification']}\n")
            log.flush();os.fsync(log.fileno())
    return result


def local_report():
    # Aucune interrogation Podman sans sélection explicite --kali.
    return {'outils_LexOS':{name:menu_tools.check(name) for name in menu_tools.CHECKS}}
