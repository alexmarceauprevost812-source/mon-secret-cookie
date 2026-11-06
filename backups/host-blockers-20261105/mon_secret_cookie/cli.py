"""Entrée CLI et menu TI-LEX."""
import os
import argparse
import json
import sys
from . import core, network, cookies, passwords, lab, audit, security, diagnostics, server
import sqlite3
import shutil
import subprocess
from pathlib import Path
from .branding import logo
from . import private_reports

def emit(command, result):
    private_reports.save(command, result)
    print(json.dumps(result,ensure_ascii=False,indent=2))


def parser():
    p=argparse.ArgumentParser(prog='mon-secret-cookie',description='Audit défensif Linux, Termux et Windows ; laboratoires autorisés')
    p.add_argument('--version',action='version',version='mon-secret-cookie 0.3.0')
    s=p.add_subparsers(dest='command')
    for name in ('device-id','ports','wifi-info','wifite','cookie-guide','menu'):
        s.add_parser(name)
    c=s.add_parser('scan-local'); c.add_argument('--device-id',help='ID applicatif attendu de cette machine')
    c=s.add_parser('bilan'); c.add_argument('--format',choices=['txt','json'],default='txt'); c.add_argument('--no-neighbors',action='store_true',help='Ne pas lire le cache de voisinage LAN')
    c.add_argument('--label',help="Étiquette libre pour distinguer vos appareils (ex. telephone-1, pc-bureau)")
    d=s.add_parser('devices'); d.add_argument('--cidr'); d.add_argument('--authorized',action='store_true')
    n=s.add_parser('nmap'); n.add_argument('targets',nargs='+'); n.add_argument('--authorized',action='store_true')
    c=s.add_parser('cookies'); group=c.add_mutually_exclusive_group(required=True)
    group.add_argument('--file'); group.add_argument('--search')
    c.add_argument('--device-id',help='ID applicatif attendu de cette machine')
    c=s.add_parser('cookie-lab'); c.add_argument('--output',default='cookies.txt')
    c=s.add_parser('password-lab'); c.add_argument('--engine',choices=['john','hashcat'],default='john')
    c.add_argument('--hashes'); c.add_argument('--wordlist'); c.add_argument('--authorized',action='store_true')
    c=s.add_parser('flask-lab'); c.add_argument('--port',type=int,default=5000)
    c=s.add_parser('report'); c.add_argument('--format',choices=['json','txt'],default='json'); c.add_argument('--output',required=True)
    c=s.add_parser('multi-report'); c.add_argument('--inputs',nargs='+',required=True,help='Rapports JSON exportés sur vos appareils'); c.add_argument('--output',required=True); c.add_argument('--format',choices=['txt','json'],default='txt')
    c=s.add_parser('cibles',help='Registre des cibles explicitement autorisées')
    sub=c.add_subparsers(dest='target_action')
    add=sub.add_parser('ajouter')
    for field in ('name','owner','scope','expires','proof'):
        add.add_argument('--'+field,required=True)
    add.add_argument('--tests',nargs='+',choices=['inventory','tcp'],default=['inventory'])
    add.add_argument('--reference',action='append',default=[],help='Domaine ou identifiant connu ; aucune résolution automatique')
    revoke=sub.add_parser('revoquer'); revoke.add_argument('id')
    for name in ('nouvelles','autorisations','outils'):
        s.add_parser(name)
    c=s.add_parser('scan',help='Mission avec registre et comparaison')
    c.add_argument('mode',choices=['complet']); c.add_argument('--cible',action='append',help='ID AUTH-… ; répétable')
    c=s.add_parser('rapport'); c.add_argument('--output',required=True); c.add_argument('--format',choices=['json','txt'],default='json')
    c=s.add_parser('serveur'); c.add_argument('--port',type=int,default=8765)
    c=s.add_parser('surveillance', help='Surveillance passive des nouveaux appareils LAN')
    c.add_argument('--once', action='store_true')
    c.add_argument('--inventaire', action='store_true')
    c.add_argument('--interval', type=float, default=30)
    notifications=c.add_mutually_exclusive_group()
    notifications.add_argument('--notifications', action='store_true',
                               help='Activer les alertes locales (désactivées par défaut)')
    notifications.add_argument('--no-notifications', action='store_true',
                               help='Conserver les alertes désactivées ; inventaire et journal conservés')
    s.add_parser('terminal-codex')
    c=s.add_parser('diagnostic-prevost',help='Mission locale PRÉVOST : aides/versions et rapports privés')
    c.add_argument('--kali',action='store_true')
    c.add_argument('--no-notifications',action='store_true')
    c.add_argument('--output')
    c=s.add_parser('installer-outils',help='Installer explicitement les paquets du catalogue')
    c.add_argument('--kali',action='store_true')
    c.add_argument('--executer',action='store_true')
    c=s.add_parser('menu-outils', help='État de chaque entrée et des outils LexOS/Kali')
    c.add_argument('--verify', action='store_true', help='Exécuter uniquement les aides/versions')
    c=s.add_parser('aide-outil', help='Aide locale fermée ; aucune opération active')
    from .menu_tools import CHECKS
    c.add_argument('outil', choices=sorted(CHECKS))
    c.add_argument('--kali', action='store_true')
    return p

def menu():
    choices={'1':['device-id'],'2':['scan-local'],'3':['ports'],'4':['wifi-info'],'5':['devices'],
             '6':['cookie-lab'],'7':['password-lab'],'8':['flask-lab'],'13':['cookie-guide'],'14':['bilan'],
             '16':['menu-outils','--verify'],'17':['cibles'],'18':['nouvelles'],'19':['autorisations'],'20':['scan','complet'],'22':['terminal-codex'],'23':['surveillance'],'24':['surveillance','--inventaire'],'26':['diagnostic-prevost'],'27':['installer-outils']}
    from . import menu_tools
    states=menu_tools.entries()
    while True:
        print('TI-LEXOS KALI')
        print(logo())
        on=sys.stdout.isatty() and 'NO_COLOR' not in os.environ and os.environ.get('TERM') != 'dumb'
        green='\033[40;37m' if on else ''          # texte blanc sur fond noir
        sky='\033[40;1;31m' if on else ''    # numéros rouges
        reset='\033[0m' if on else ''
        def e(n,label):
            return f'{sky}{n}{green} {label}'+(f" [{states[n]['etat']}]" if n in states else '')
        lignes=['TI-LEX — MON-SECRET-COOKIE',
                '— Appareil local —   '+'  '.join([e('1','Device ID'),e('2','Scan local'),e('3','Ports'),e('4','Wi-Fi'),e('14','Bilan (texte)')]),
                '— Réseau (autorisé) — '+'  '.join([e('5','LAN passif'),e('12','LAN actif'),e('9','Nmap autorisé')]),
                '— Cookies —           '+'  '.join([e('10','Cookies locaux'),e('6','Cookie Lab'),e('13','Guide des cookies')]),
                '— Labo —              '+'  '.join([e('7','Password Lab'),e('8','Flask Lab')]),
                '— Rapports —          '+'  '.join([e('11','Rapport'),e('15','Rapport multi-appareils')]),
                '— IA locale / Security Pro — '+'  '.join([e('16','Outils'),e('17','Cibles'),e('18','Nouvelles'),e('19','Autorisations'),e('20','Mission autorisée'),e('21','Rapport missions')]),
                '— Surveillance / IA — '+ '  '.join([e('22','terminal-codex'),e('23','Surveiller le LAN'),e('24','Inventaire connu'),e('25','Aide outil LexOS/Kali'),e('26','Diagnostic PRÉVOST'),e('27','Installer les outils (plan)')]),
                e('0','Quitter')]
        print(green+'\n'.join(lignes)+reset)
        selection=input('TI-LEX > ').strip()
        if selection=='0':
            return
        args=choices.get(selection)
        if selection=='25':
            name=input('Outil du catalogue (nmap, john, hashcat…) : ').strip()
            if name not in menu_tools.CHECKS:
                print('Outil inconnu. Choix 16 : consulter le catalogue.'); continue
            kali=input('Environnement Kali ? OUI, sinon LexOS : ').strip()=='OUI'
            args=['aide-outil', name, *(['--kali'] if kali else [])]
        if selection in ('9','12'):
            target=input('IP(s) séparées par espaces : ' if selection=='9' else 'CIDR de votre LAN : ').strip()
            if input('Autorisation explicite pour ce périmètre ? Tapez OUI : ')!='OUI':
                continue
            args=['nmap',*target.split(),'--authorized'] if selection=='9' else ['devices','--cidr',target,'--authorized']
        elif selection=='10':
            args=['cookies','--file',input('Votre fichier cookies.txt : ').strip()]
        elif selection=='11':
            args=['report','--output',input('Nouveau fichier rapport JSON : ').strip()]
        elif selection=='14':
            name=input('Étiquette de cet appareil (vide = aucune) : ').strip()
            args=['bilan',*(['--label',name] if name else [])]
        elif selection=='15':
            files=input('Rapports JSON à regrouper (séparés par espaces) : ').strip().split()
            out=input('Fichier de sortie : ').strip()
            args=['multi-report','--inputs',*files,'--output',out] if files and out else None
        elif selection=='21':
            out=input('Nouveau fichier rapport des missions JSON : ').strip()
            args=['rapport','--output',out] if out else None
        if args:
            if main(args):
                print('État : erreur — voir le message ci-dessus ; choix 16 pour les dépendances et diagnostics.')
        else:
            print('Choix inconnu ou paramètres incomplets.')

def main(argv=None):
    os.umask(0o077)
    p=parser(); a=p.parse_args(argv)
    try:
        if a.command in (None,'menu'):
            if not sys.stdin.isatty():
                p.print_help(); return 0
            menu(); return 0
        if a.command=='diagnostic-prevost':
            from . import diagnostic_mission
            result=diagnostic_mission.run(a.kali,not a.no_notifications,a.output)
            print(json.dumps(result,ensure_ascii=False,indent=2));return 0
        if a.command=='installer-outils':
            from . import tool_install
            result=tool_install.install(a.kali,a.executer)
            print(json.dumps(result,ensure_ascii=False,indent=2))
            return int(result.get('etat')=='erreur' or bool(result.get('paquets_sans_candidat')))
        if a.command in ('menu-outils','aide-outil'):
            from . import menu_tools
            result=menu_tools.report(a.verify) if a.command=='menu-outils' else menu_tools.check(a.outil,a.kali)
            print(json.dumps(result,ensure_ascii=False,indent=2))
            return int(result.get('etat') in ('erreur','manquant'))
        if a.command=='surveillance':
            from . import watch
            watch.run(a.interval, a.once, a.inventaire, notifications=a.notifications)
            return 0
        if a.command=='terminal-codex':
            executable=shutil.which('terminal-codex')
            fallback=Path(__file__).resolve().parent.parent/'integration/terminal-codex.py'
            if executable:
                result=subprocess.run([executable], check=False).returncode
                if result:
                    raise core.AuditError(f'terminal-codex a échoué (code {result}). Vérifier le lanceur et ses dépendances.')
                return 0
            if fallback.is_file():
                return subprocess.run([sys.executable, str(fallback)], check=False).returncode
            raise core.AuditError('terminal-codex introuvable.')
        if a.command=='cookie-guide':
            from importlib.resources import files
            print(files('mon_secret_cookie').joinpath('GUIDE_COOKIES.md').read_text(encoding='utf-8'))
            return 0
        if a.command=='flask-lab':
            if not 1024<=a.port<=65535:
                raise core.AuditError('Port entre 1024 et 65535 requis.')
            lab.serve(a.port); return 0
        if a.command=='serveur':
            server.serve(a.port); return 0
        if a.command in ('cibles','nouvelles','autorisations','outils','scan','rapport'):
            if a.command=='cibles':
                if a.target_action=='ajouter':
                    result=security.add_target(a.name,a.owner,a.scope,a.tests,a.expires,a.proof,a.reference)
                elif a.target_action=='revoquer':
                    result=security.revoke(a.id)
                else:
                    result={'cibles':security.targets()}
            elif a.command=='scan':
                result=security.scan_complete(a.cible)
            elif a.command=='rapport':
                result=security.export_report(a.output,a.format)
            else:
                result={'nouvelles':security.new_assets,'autorisations':security.authorizations,'outils':diagnostics.tools}[a.command]()
            emit(a.command, result)
            return 0
        if a.command in ('scan-local','cookies') and a.device_id and a.device_id != core.device_id()['device_id']:
            raise core.AuditError('Cet ID ne correspond pas à cette machine. Lancez device-id localement.')
        if a.command=='multi-report':
            result=audit.merge_reports(a.inputs)
            text=json.dumps(result,ensure_ascii=False,indent=2) if a.format=='json' else audit.format_multi_text(result)
            core.private_write(a.output,text if text.endswith('\n') else text+'\n')
            private_reports.save(a.command, result)
            print(json.dumps({'rapport':str(a.output),'fichiers_lus':result['fichiers_lus'],'appareils':len(result['appareils'])},ensure_ascii=False,indent=2))
            return 0
        if a.command=='bilan':
            label=a.label.strip() if a.label else None
            if label and (len(label)>64 or not all(c.isalnum() or c in ' -_.' for c in label)):
                raise core.AuditError('Étiquette : 64 caractères maximum, lettres, chiffres, espace, - _ . uniquement.')
            result=audit.collect(include_neighbors=not a.no_neighbors,label=label)
            core.record('bilan',result)
            private_reports.save(a.command, result)
            print(json.dumps(result,ensure_ascii=False,indent=2) if a.format=='json' else audit.format_text(result))
            return 0
        actions={'device-id':network.local_identity,'scan-local':lambda:{**core.device_id(),**network.scan_local()},'ports':network.ports,
                 'wifi-info':network.wifi_info,'wifite':network.wifite_info,'devices':lambda:network.devices(a.cidr,a.authorized),
                 'nmap':lambda:network.authorized_scan(a.targets,a.authorized),
                 'cookies':lambda:{**core.device_id(),**(cookies.analyze(a.file) if a.file else cookies.search(a.search))},
                 'cookie-lab':lambda:cookies.demo(a.output),
                 'password-lab':lambda:passwords.password_lab(a.engine,a.hashes,a.wordlist,a.authorized),
                 'report':lambda:core.report(a.output,a.format)}
        result=actions[a.command]()
        if a.command!='report':
            core.record(a.command,result)
        emit(a.command, result)
        return 0
    except (core.AuditError,OSError,ValueError,ImportError,sqlite3.Error) as e:
        print(f'Erreur : {core.disk_full_hint(e) or e}',file=sys.stderr); return 1
    except (KeyboardInterrupt,EOFError):
        print('Opération interrompue.',file=sys.stderr); return 130

if __name__=='__main__':
    sys.exit(main())

