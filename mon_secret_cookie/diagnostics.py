"""Diagnostics fixes et bornés ; aucune attaque ni installation."""
import platform
import shutil
from . import core


def probe(executable, args, timeout=10):
    path = shutil.which(executable)
    result = {'installed': bool(path), 'executable': path}
    if path:
        try:
            result['output'] = core.run([executable, *args], timeout=timeout)[:16000]
            result['status'] = 'ok'
        except (core.AuditError, OSError) as error:
            result.update(status='unavailable', error=str(error))
    else:
        result['status'] = 'missing'
    return result


def tools():
    nmap = probe('nmap', ['--version'])
    # Certaines distributions n'ont pas --version : l'aide indique aussi la version.
    wifite = probe('wifite', ['--help'])
    hashcat = probe('hashcat', ['--version'])
    backend = probe('hashcat', ['-I'], timeout=20)
    gpu = probe('nvidia-smi', ['--query-gpu=name,driver_version', '--format=csv,noheader'])
    wifi = probe('iw', ['list']) if platform.system() == 'Linux' else {
        'status': 'unsupported', 'note': 'Diagnostic radio disponible sous Linux.'}
    output = wifi.get('output', '')
    wifi['monitor_mode_declared'] = any(line.strip() == '* monitor' for line in output.splitlines())
    wifi['compatibility'] = 'support déclaré ; injection et accès radio non testés'
    return {'nmap': nmap, 'wifite': wifite, 'hashcat': hashcat,
            'hashcat_backends': backend, 'nvidia': gpu, 'wifi_hardware': wifi,
            'automation': 'Diagnostics uniquement ; aucune attaque Wi-Fi ou récupération de secrets.'}
