"""Sondes locales en lecture seule ; aucune réparation, élévation ou installation."""
import os
from pathlib import Path
import socket
import stat
import subprocess
from . import core

LYNIS_FILES = ('/usr/share/lynis/include/consts', '/usr/share/lynis/include/functions')


def path_info(path):
    try:
        info=Path(path).stat()
        return {'present':True,'uid':info.st_uid,'gid':info.st_gid,
                'mode':oct(stat.S_IMODE(info.st_mode)),
                'lecture_seule':bool(os.statvfs(path).f_flag & os.ST_RDONLY)}
    except OSError as error:
        return {'present':False,'erreur':type(error).__name__,'errno':error.errno}


def runtime_facts():
    facts={'uid':os.getuid(),'gid':os.getgid()}
    try:
        allowed={'NoNewPrivs','Seccomp','CapEff'}
        facts['processus']={key:value.strip() for line in Path('/proc/self/status').read_text().splitlines()
                            if ':' in line for key,value in [line.split(':',1)] if key in allowed}
        facts['uid_map']=Path('/proc/self/uid_map').read_text().strip()
        facts['gid_map']=Path('/proc/self/gid_map').read_text().strip()
    except OSError:
        facts['processus']={}
    runtime=Path(os.environ.get('XDG_RUNTIME_DIR',f'/run/user/{os.getuid()}'))
    facts['runtime']={'path':str(runtime),**path_info(runtime)}
    facts['libpod']={'path':str(runtime/'libpod'),**path_info(runtime/'libpod')}
    facts['conclusion']='Observations de cet environnement uniquement ; état du véritable hôte à confirmer séparément.'
    return facts


def classify_error(text):
    lower=text.lower()
    if 'read-only file system' in lower:
        return 'systeme_fichiers_lecture_seule'
    if 'operation not permitted' in lower or 'permission denied' in lower:
        return 'acces_refuse'
    if 'timed out' in lower:
        return 'delai_depasse'
    return 'erreur_a_confirmer_sur_hote'


def lynis_ownership():
    entries={name:path_info(name) for name in LYNIS_FILES}
    issues=[]
    for name,item in entries.items():
        if not item['present']:
            issues.append(f'{name} : fichier requis absent ou inaccessible')
        elif item['uid'] not in (0,os.getuid()):
            issues.append(f"{name} : UID observé {item['uid']}, UID requis 0 ou {os.getuid()}")
    return {'fichiers':entries,'valide':not issues,
            'message':'; '.join(issues) if issues else 'Propriétaires compatibles ; le contrôle complet reste effectué par Lynis.',
            'verification_hote':'stat -Lc "%n uid=%u gid=%g mode=%a" /usr/share/lynis/include/consts /usr/share/lynis/include/functions'}


def probe(name,args):
    path=core.executable(name)
    if not path:
        return {'etat':'manquant','commande':[name,*args],'code':None,'message':'Commande absente dans cet environnement.'}
    try:
        result=subprocess.run([path,*args],capture_output=True,text=True,encoding='utf-8',errors='replace',
                              stdin=subprocess.DEVNULL,timeout=10,check=False)
        output=(result.stdout+result.stderr)[:16000]
        denied='operation not permitted' in output.lower() or 'permission denied' in output.lower()
        return {'etat':'disponible' if result.returncode==0 and not denied else 'erreur',
                'commande':[path,*args],'code':result.returncode,'message':output,
                'categorie':classify_error(output) if result.returncode or denied else None}
    except (OSError,subprocess.TimeoutExpired) as error:
        return {'etat':'erreur','commande':[path,*args],'code':None,'message':str(error),
                'categorie':classify_error(str(error))}


def socket_access():
    results={}
    for label,family,kind,protocol in (
        ('IPv4_UDP',socket.AF_INET,socket.SOCK_DGRAM,0),
        ('IPv6_UDP',socket.AF_INET6,socket.SOCK_DGRAM,0),
        ('Netlink_ROUTE',socket.AF_NETLINK,socket.SOCK_RAW,socket.NETLINK_ROUTE)):
        try:
            with socket.socket(family,kind,protocol):
                results[label]={'etat':'disponible','paquets_envoyes':0}
        except OSError as error:
            results[label]={'etat':'erreur','errno':error.errno,'message':str(error),'paquets_envoyes':0}
    return results


def report():
    from . import environments, fusion
    detected=environments.discover(fusion.executable,fusion.version_probe)
    return {'contexte':runtime_facts(), 'podman':{
        'liste':probe('podman',['ps','--all','--format','{{.Names}} {{.Status}}']),
        'conteneur':probe('podman',['inspect','--format','{{.State.Status}}','kali-lexos']),
        'socket_api':path_info(Path(os.environ.get('XDG_RUNTIME_DIR',f'/run/user/{os.getuid()}'))/'podman/podman.sock'),
        'note':'Le socket API est facultatif pour le CLI Podman local. Aucun storage.conf, root/runroot, conteneur ou montage modifié.'},
        'dependances_podman':probe('dpkg-query',['-W','-f=${Package} ${Status} ${Version}\n',
                                                'podman','uidmap','conmon','crun','slirp4netns','passt']),
        'dependances_reseau':probe('dpkg-query',['-W','-f=${Package} ${Status} ${Version}\n',
                                                'iproute2','iw','bind9-dnsutils','lynis']),
        'outils_lexos_manquants':{name:{'present':bool(core.executable(name)),'kali_etat':('disponible' if detected['tools'].get(name,{}).get('installed') else 'manquant') if detected.get('status')=='available' else 'non_verifie'} for name in ('wifite','nikto','radare2')},
        'kali':detected,'lynis':lynis_ownership(),'sockets':socket_access(),
        'commandes_locales':{
            'ip':probe('ip',['-j','address','show']),
            'ss':probe('ss',['-H','-lntu']),
            'iw':probe('iw',['list']),
            'dig':probe('dig',['-v']),
            'notifications':probe('gdbus',['call','--session','--dest','org.freedesktop.Notifications',
                                          '--object-path','/org/freedesktop/Notifications',
                                          '--method','org.freedesktop.Notifications.GetServerInformation'])},
        'aucun_scan':True,'installation':False,
        'conclusion':'Un refus ici ne prouve pas un défaut sur LexOS. Relancer prevost acces-hote dans le terminal hôte sans sudo.'}
