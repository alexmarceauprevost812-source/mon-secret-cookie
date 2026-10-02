# Exécuter depuis PowerShell, comme utilisateur normal.
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Installateur réservé à Windows.' }
$RepoDir = $PSScriptRoot
$InstallDir = Join-Path $env:LOCALAPPDATA 'mon-secret-cookie'
$VenvDir = Join-Path $InstallDir 'venv'
$BinDir = Join-Path $InstallDir 'bin'
$PythonCommand = Get-Command py -ErrorAction SilentlyContinue
if ($PythonCommand) {
    & $PythonCommand.Source -3 -m venv $VenvDir
} else {
    $PythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (!$PythonCommand) { throw 'Installez Python 3.10+ depuis https://www.python.org/downloads/windows/ puis relancez.' }
    & $PythonCommand.Source -m venv $VenvDir
}
if ($LASTEXITCODE -ne 0) { throw "Création de l’environnement Python impossible. Python 3.10+ est nécessaire." }
$VenvPython = Join-Path $VenvDir 'Scripts\python.exe'
& $VenvPython -m pip install $RepoDir
if ($LASTEXITCODE -ne 0) { throw 'Installation Python échouée.' }
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
$CliPath = Join-Path $VenvDir 'Scripts\mon-secret-cookie.exe'
$Launcher = '@echo off' + "`r`n" + '"' + $CliPath + '" %*' + "`r`n"
Set-Content -LiteralPath (Join-Path $BinDir 'mon-secret-cookie.cmd') -Value $Launcher -Encoding Default
$env:Path = "$BinDir;$env:Path"
Write-Host 'Installé. mon-secret-cookie est disponible dans cette session PowerShell.'
Write-Host "Pour les prochaines sessions, ajoutez ce dossier à votre PATH utilisateur : $BinDir"
if (!(Get-Command nmap -ErrorAction SilentlyContinue)) {
    Write-Host 'Nmap absent : installer https://nmap.org/download.html et ajouter son dossier à PATH.'
}
Write-Host 'John/Hashcat sont optionnels : installer leurs distributions Windows officielles et ajouter john.exe/hashcat.exe à PATH.'
Write-Host 'Wifite reste réservé à Kali/Ubuntu ; il ne fonctionne pas en mode natif Windows ici.'
& $CliPath --version
if ($LASTEXITCODE -ne 0) { throw 'Vérification de la commande échouée.' }
