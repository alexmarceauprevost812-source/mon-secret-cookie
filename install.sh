#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -eq 0 ]]; then
  echo "Exécutez comme utilisateur normal ; sudo sera utilisé uniquement pour apt." >&2
  exit 1
fi
source /etc/os-release
case "$ID" in kali|ubuntu) ;; *) echo "Installateur prévu pour Kali Linux ou Ubuntu." >&2; exit 1 ;; esac
with_wifite=0
case "${1:-}" in --with-wifite) with_wifite=1 ;; "") ;; *) echo "Usage : ./install.sh [--with-wifite]"; exit 1 ;; esac
packages=(python3 python3-venv python3-pip nmap john hashcat iproute2 iw)
if [[ $with_wifite == 1 ]]; then packages+=(wifite); fi
missing=()
for package in "${packages[@]}"; do
  if ! dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q '^install ok installed$'; then missing+=("$package"); fi
done
if ((${#missing[@]})); then
  sudo apt-get update
  sudo apt-get install -- "${missing[@]}"
fi
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
venv_dir="${XDG_DATA_HOME:-$HOME/.local/share}/mon-secret-cookie/venv"
python3 -m venv "$venv_dir"
"$venv_dir/bin/python" -m pip install "$repo_dir"
mkdir -p "$HOME/.local/bin"
ln -sfn "$venv_dir/bin/mon-secret-cookie" "$HOME/.local/bin/mon-secret-cookie"
echo 'Installé. Ajoutez ~/.local/bin à PATH si nécessaire :'
echo 'export PATH="$HOME/.local/bin:$PATH"'
if [[ $with_wifite == 1 ]]; then echo 'Wifite installé en option ; aucune commande Wifite exécutée par cet outil.'; fi
"$HOME/.local/bin/mon-secret-cookie" --version
