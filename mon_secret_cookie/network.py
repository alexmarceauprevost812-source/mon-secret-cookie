"""Inventaire Linux et Nmap sans scripts, capture ni attaque."""
import ipaddress
import json
import socket
import xml.etree.ElementTree as ET
from .core import AuditError, run

def interfaces():
    return json.loads(run(['ip','-j','address','show']))

def local_addresses():
    addresses = {'127.0.0.1','::1'}
    for interface in interfaces():
        for a in interface.get('addr_info',[]):
            value = a.get('local','')
            try:
                ip = ipaddress.ip_address(value)
                if not ip.is_link_local and not ip.is_unspecified:
                    addresses.add(str(ip))
            except ValueError:
                pass
    return sorted(addresses)

def ports():
    listeners=[]
    for line in run(['ss','-H','-lntu']).splitlines():
        fields=line.split()
        if len(fields)<6:
            continue
        protocol, state, _, _, address, peer = fields[:6]
        try:
            port=int(address.rsplit(':',1)[1])
            try:
                service=socket.getservbyport(port,protocol)
            except OSError:
                service='inconnu'
        except (ValueError,IndexError):
            port=None;service='inconnu'
        listeners.append({'protocol':protocol,'state':state,'address':address,'port':port,'service':service})
    return {'listeners':listeners,'service_note':'noms du registre local /etc/services ; logiciel réel non identifié'}

def wifi_info():
    devices = run(['iw','dev'])
    names = [line.strip().split()[1] for line in devices.splitlines() if line.strip().startswith('Interface ')]
    return {'interfaces':[{'interface':name,'link':run(['iw','dev',name,'link'])} for name in names]}

def parse_nmap(text):
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        raise AuditError('Réponse XML Nmap invalide.') from e
    return [{'addresses':[a.attrib for a in h.findall('address')],
             'status':h.find('status').get('state') if h.find('status') is not None else 'unknown',
             'ports':[{'port':p.get('portid'),'protocol':p.get('protocol'),
                       'state':p.find('state').get('state'),
                       'service':p.find('service').get('name') if p.find('service') is not None else None}
                      for p in h.findall('ports/port')]} for h in root.findall('host')]

def scan_address(address, count=100):
    ip = ipaddress.ip_address(address)
    args = ['nmap','-n','-sT','-Pn','--top-ports',str(count),'-T3',
            '--max-retries','1','--host-timeout','30s','-oX','-']
    if ip.version == 6:
        args.append('-6')
    return parse_nmap(run(args+[str(ip)],timeout=40))

def scan_local():
    return {'hosts':[host for address in local_addresses() for host in scan_address(address,20)]}

def authorized_scan(targets, authorized):
    if not authorized:
        raise AuditError("Confirmez l'autorisation avec --authorized.")
    if not 1 <= len(targets) <= 16:
        raise AuditError("Entre 1 et 16 adresses IP explicites requises.")
    addresses = [ipaddress.ip_address(t) for t in targets]
    if any(a.is_multicast or a.is_unspecified for a in addresses):
        raise AuditError("Adresse multicast ou indéfinie refusée.")
    return {'hosts':[h for a in addresses for h in scan_address(str(a))]}

def devices(cidr=None, authorized=False):
    if cidr is None:
        return {'mode':'cache voisin passif','neighbors':json.loads(run(['ip','-j','neigh','show']))}
    if not authorized:
        raise AuditError("Découverte active : --authorized requis pour votre LAN.")
    net = ipaddress.ip_network(cidr,strict=True)
    if net.version != 4 or not net.is_private or net.num_addresses > 256 or net.is_loopback or net.is_link_local:
        raise AuditError("LAN IPv4 privé requis, maximum 256 adresses (/24 ou plus petit).")
    connected=[]
    for interface in interfaces():
        if interface.get('operstate') != 'UP' or interface.get('ifname') == 'lo':
            continue
        for a in interface.get('addr_info',[]):
            if a.get('family') == 'inet':
                connected.append(ipaddress.ip_network(f"{a['local']}/{a['prefixlen']}",strict=False))
    if not any(net.subnet_of(n) for n in connected):
        raise AuditError("Le périmètre doit appartenir à une interface locale active.")
    return {'mode':'découverte Nmap sans scan de ports','hosts':parse_nmap(run(
        ['nmap','-n','-sn','-T3','--max-retries','1','--host-timeout','10s','-oX','-',str(net)],timeout=90))}


def wifite_info():
    import shutil
    executable=shutil.which('wifite')
    return {'installed':bool(executable),'executable':executable,
            'installation':'bash install.sh --with-wifite',
            'manual_help':'wifite --help',
            'scope':'Votre Wi-Fi ou laboratoire explicitement autorisé uniquement.',
            'automation':'Aucune attaque ou capture lancée par mon-secret-cookie.'}
