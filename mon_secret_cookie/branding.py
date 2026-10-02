"""Logo terminal en relief, sans dépendance graphique."""
import os
import shutil
import sys

FONT = {
    'L': ('10000', '10000', '10000', '10000', '11111'),
    'E': ('11111', '10000', '11110', '10000', '11111'),
    'S': ('11111', '10000', '11111', '00001', '11111'),
    'C': ('11111', '10000', '10000', '10000', '11111'),
    'R': ('11110', '10001', '11110', '10010', '10001'),
    'T': ('11111', '00100', '00100', '00100', '00100'),
    'O': ('01110', '10001', '10001', '10001', '01110'),
    'K': ('10001', '10010', '11100', '10010', '10001'),
    'I': ('11111', '00100', '00100', '00100', '11111'),
    ' ': ('000',) * 5,
}


def _word(text, face, shadow, colored):
    pixels = set()
    offset = 0
    for letter in text:
        glyph = FONT[letter]
        for y, row in enumerate(glyph):
            for x, bit in enumerate(row):
                if bit == '1':
                    pixels.add((offset + x, y))
        offset += len(glyph[0]) + 1
    relief = {(x + depth, y + depth) for x, y in pixels for depth in (1, 2)} - pixels
    rows = []
    for y in range(7):
        row = []
        for x in range(offset + 1):
            if (x, y) in pixels:
                row.append((f'\033[1;48;5;16;38;5;{face}m' if colored else '') + '█')
            elif (x, y) in relief:
                row.append((f'\033[48;5;16;38;5;{shadow}m' if colored else '') + '▓')
            else:
                row.append(('\033[48;5;16m' if colored else '') + ' ')
        rows.append(''.join(row) + ('\033[0m' if colored else ''))
    return '\n'.join(rows)


def logo():
    colored = sys.stdout.isatty() and 'NO_COLOR' not in os.environ and os.environ.get('TERM') != 'dumb'
    width = shutil.get_terminal_size(fallback=(80, 24)).columns
    if width < 54:
        lime = '\033[1;40;38;5;154m' if colored else ''
        orange = '\033[1;40;38;5;208m' if colored else ''
        reset = '\033[0m' if colored else ''
        return f'{lime}LE SECRET{reset}\n{orange}COOKIE{reset}\n  ▓▓▓▓▓▓'
    return '\n'.join((_word('LE SECRET', 154, 28, colored), '', _word('COOKIE', 208, 130, colored)))
