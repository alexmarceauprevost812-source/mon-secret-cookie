#!/usr/bin/env bash
set -euo pipefail
if ! command -v pkg >/dev/null || [[ -z ${PREFIX:-} ]]; then
  echo 'Exécutez cet installateur dans Termux sur Android.' >&2
  exit 1
fi
case "${1:-}" in ""|--with-wifi-info) ;; *) echo 'Usage : bash install-termux.sh [--with-wifi-info]'; exit 1 ;; esac
# Clang permet de compiler les dépendances Python sans wheel Android.
pkg install python clang make nmap iproute2
if [[ ${1:-} == --with-wifi-info ]]; then pkg install termux-api; fi
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
venv_dir="$HOME/.local/share/mon-secret-cookie/venv"
python -m venv "$venv_dir"
"$venv_dir/bin/python" -m pip install "$repo_dir"
mkdir -p "$HOME/.local/bin"
ln -sfn "$venv_dir/bin/mon-secret-cookie" "$HOME/.local/bin/mon-secret-cookie"
echo 'Installé. Pour utiliser la commande : export PATH="$HOME/.local/bin:$PATH"'
echo 'Wi-Fi : installer aussi l’application Termux:API compatible et accorder les permissions Android.'
echo 'John/Hashcat/Wifite ne sont pas installés automatiquement sous Android.'
"$HOME/.local/bin/mon-secret-cookie" --version
