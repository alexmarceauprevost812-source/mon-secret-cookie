"""Notifications locales uniquement ; aucun secret ni message envoyé à un tiers."""
import os
import shutil
import subprocess
import sys


def required(reason='approval'):
    messages = {'approval': 'Un plan attend votre validation dans le terminal.',
                'renewal': 'Le lot de 250 exécutions est terminé. Rapport et validation requis.',
                'blocked': 'Une mission est bloquée. Consulter son rapport.'}
    message = messages[reason]
    if os.environ.get('MSC_NOTIFICATIONS', '1') == '0':
        return {'channel': 'disabled', 'message': message}
    tool = shutil.which('notify-send')
    if tool and not os.environ.get('SSH_CONNECTION'):
        try:
            result = subprocess.run([tool, '--app-name=TI-Prévost', 'Validation requise', message],
                                    stdin=subprocess.DEVNULL, capture_output=True, timeout=3)
            if result.returncode == 0:
                return {'channel': 'desktop', 'message': message}
        except (OSError, subprocess.TimeoutExpired):
            pass
    print('\aValidation requise : '+message, file=sys.stderr)
    return {'channel': 'terminal', 'message': message}
