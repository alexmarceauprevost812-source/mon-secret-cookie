"""Adaptateurs Windows et détection Termux, commandes fixes uniquement."""
import base64
import json
import os
import sys


def is_windows():
    return sys.platform == 'win32'


def is_termux():
    return bool(os.environ.get('TERMUX_VERSION')) or '/com.termux/' in os.environ.get('PREFIX','')


def powershell(script):
    from .core import run
    prelude = "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new(); "
    encoded = base64.b64encode((prelude+script).encode('utf-16le')).decode('ascii')
    return run(['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',encoded])


def ps_rows(script):
    value = json.loads(powershell(script + ' | ConvertTo-Json -Depth 6 -Compress') or 'null')
    return value if isinstance(value,list) else ([] if value is None else [value])


def windows_owner(path):
    # Le chemin est encodé en données ; aucun texte utilisateur interprété par PowerShell.
    encoded = base64.b64encode(str(path).encode('utf-8')).decode('ascii')
    script = f"$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}')); "
    script += "$owner=(Get-Acl -LiteralPath $p).GetOwner([Security.Principal.SecurityIdentifier]).Value; "
    script += "$owner -eq [Security.Principal.WindowsIdentity]::GetCurrent().User.Value"
    return powershell(script).strip().lower() == 'true'


def windows_interfaces():
    rows=ps_rows("Get-NetIPAddress | Select-Object InterfaceAlias,IPAddress,PrefixLength,AddressFamily,InterfaceIndex")
    active={row['InterfaceIndex'] for row in ps_rows("Get-NetIPInterface | Where-Object ConnectionState -eq 'Connected' | Select-Object InterfaceIndex")}
    grouped={}
    for row in rows:
        name=row['InterfaceAlias']
        interface=grouped.setdefault(name,{'ifname':name,'operstate':'UP' if row['InterfaceIndex'] in active else 'DOWN','addr_info':[]})
        interface['addr_info'].append({'local':row['IPAddress'],'prefixlen':row['PrefixLength'],
                                       'family':'inet6' if ':' in row['IPAddress'] else 'inet'})
    return list(grouped.values())


def windows_ports():
    tcp=ps_rows("Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort")
    udp=ps_rows("Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object LocalAddress,LocalPort")
    return {'listeners':[{'protocol':protocol,'address':row['LocalAddress'],'port':row['LocalPort'],
                          'state':'LISTEN' if protocol=='tcp' else 'UNCONN'}
                         for protocol,rows in [('tcp',tcp),('udp',udp)] for row in rows]}


def windows_neighbors():
    return ps_rows("Get-NetNeighbor | Select-Object IPAddress,LinkLayerAddress,State,InterfaceAlias")
