"""Entrée CLI et menu TI-LEX."""
import argparse
import json
import sys
from . import core, network, cookies, passwords, lab
from .branding import logo

def parser():
    p=argparse.ArgumentParser(prog='mon-secret-cookie',description='Audit défensif Linux, Termux et Windows ; laboratoires autorisés')
    p.add_argument('--version',action='version',version='mon-secret-cookie 0.2.0')
    s=p.add_subparsers(dest='command')
    for name in ('device-id','ports','wifi-info','wifite','cookie-guide','menu'):
        s.add_parser(name)
    c=s.add_parser('scan-local'); c.add_argument('--device-id',help='ID applicatif attendu de cette machine')
    d=s.add_parser('devices'); d.add_argument('--cidr'); d.add_argument('--authorized',action='store_true')
    n=s.add_parser('nmap'); n.add_argument('targets',nargs='+'); n.add_argument('--authorized',action='store_true')
    c=s.add_parser('cookies'); group=c.add_mutually_exclusive_group(required=True)
    group.add_argument('--file'); group.add_argument('--search')
    c=s.add_parser('cookie-lab'); c.add_argument('--output',default='cookies.txt')
    c=s.add_parser('password-lab'); c.add_argument('--engine',choices=['john','hashcat'],default='john')
    c.add_argument('--hashes'); c.add_argument('--wordlist'); c.add_argument('--authorized',action='store_true')
    c=s.add_parser('flask-lab'); c.add_argument('--port',type=int,default=5000)
    c=s.add_parser('report'); c.add_argument('--format',choices=['json','txt'],default='json'); c.add_argument('--output',required=True)
    return p

def menu():
    choices={'1':['device-id'],'2':['scan-local'],'3':['ports'],'4':['wifi-info'],'5':['devices'],
             '6':['cookie-lab'],'7':['password-lab'],'8':['flask-lab'],'13':['cookie-guide']}
    while True:
        print(logo())
        color='\033[40;32m' if sys.stdout.isatty() else ''
        reset='\033[0m' if color else ''
        print(color+'TI-LEX — MON-SECRET-COOKIE\n1 Device ID  2 Scan local  3 Ports  4 Wi-Fi\n5 LAN passif  6 Cookie Lab  7 Password Lab  8 Flask Lab\n9 Nmap autorisé  10 Cookies locaux  11 Rapport  12 LAN actif\n13 Guide des cookies  0 Quitter'+reset)
        selection=input('TI-LEX > ').strip()
        if selection=='0':
            return
        args=choices.get(selection)
        if selection in ('9','12'):
            target=input('IP(s) séparées par espaces : ' if selection=='9' else 'CIDR de votre LAN : ').strip()
            if input('Autorisation explicite pour ce périmètre ? Tapez OUI : ')!='OUI':
                continue
            args=['nmap',*target.split(),'--authorized'] if selection=='9' else ['devices','--cidr',target,'--authorized']
        elif selection=='10':
            args=['cookies','--file',input('Votre fichier cookies.txt : ').strip()]
        elif selection=='11':
            args=['report','--output',input('Nouveau fichier rapport JSON : ').strip()]
        if args:
            main(args)

def main(argv=None):
    p=parser(); a=p.parse_args(argv)
    try:
        if a.command in (None,'menu'):
            if not sys.stdin.isatty():
                p.print_help(); return 0
            menu(); return 0
        if a.command=='cookie-guide':
            from importlib.resources import files
            print(files('mon_secret_cookie').joinpath('GUIDE_COOKIES.md').read_text(encoding='utf-8'))
            return 0
        if a.command=='flask-lab':
            if not 1024<=a.port<=65535:
                raise core.AuditError('Port entre 1024 et 65535 requis.')
            lab.serve(a.port); return 0
        if a.command=='scan-local' and a.device_id and a.device_id != core.device_id()['device_id']:
            raise core.AuditError('Cet ID ne correspond pas à cette machine. Lancez device-id localement.')
        actions={'device-id':network.local_identity,'scan-local':lambda:{**core.device_id(),**network.scan_local()},'ports':network.ports,
                 'wifi-info':network.wifi_info,'wifite':network.wifite_info,'devices':lambda:network.devices(a.cidr,a.authorized),
                 'nmap':lambda:network.authorized_scan(a.targets,a.authorized),
                 'cookies':lambda:cookies.analyze(a.file) if a.file else cookies.search(a.search),
                 'cookie-lab':lambda:cookies.demo(a.output),
                 'password-lab':lambda:passwords.password_lab(a.engine,a.hashes,a.wordlist,a.authorized),
                 'report':lambda:core.report(a.output,a.format)}
        result=actions[a.command]()
        if a.command!='report':
            core.record(a.command,result)
        print(json.dumps(result,ensure_ascii=False,indent=2))
        return 0
    except (core.AuditError,OSError,ValueError,ImportError) as e:
        print(f'Erreur : {e}',file=sys.stderr); return 1
    except (KeyboardInterrupt,EOFError):
        print('Opération interrompue.',file=sys.stderr); return 130

if __name__=='__main__':
    sys.exit(main())
