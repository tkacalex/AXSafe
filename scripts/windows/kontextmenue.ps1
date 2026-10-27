<#
.SYNOPSIS
  Explorer-Kontextmenü „Mit AXSafe prüfen“ für den angemeldeten Benutzer
  einrichten oder entfernen (AXS-026). Keine Administratorrechte nötig.

.DESCRIPTION
  Schreibt nur unter HKCU:\Software\Classes (Dateien und Ordner). Der Eintrag
  startet die Oberfläche mit  --scan "<Pfad>" --ausloeser kontextmenue ; der
  Bericht nennt dann „Kontextmenü“ als Auslöser. Bei Mehrfachauswahl startet
  Explorer je Objekt einen eigenen Auftrag (Windows-Verhalten).
  Prüft nach dem Schreiben, dass genau der erwartete Befehl eingetragen ist.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File kontextmenue.ps1
  powershell -ExecutionPolicy Bypass -File kontextmenue.ps1 -Entfernen
#>
[CmdletBinding()]
param(
    [string]$Programm,
    [switch]$Entfernen
)
$ErrorActionPreference = 'Stop'
$Verb = 'AXSafe.Pruefen'
$Keys = @(
    "HKCU:\Software\Classes\*\shell\$Verb",
    "HKCU:\Software\Classes\Directory\shell\$Verb"
)

if ($Entfernen) {
    foreach ($k in $Keys) {
        if (Test-Path -LiteralPath $k) { Remove-Item -LiteralPath $k -Recurse -Force }
        if (Test-Path -LiteralPath $k) { throw "Eintrag nicht entfernt: $k" }
    }
    Write-Host 'Kontextmenü entfernt.'
    exit 0
}

if (-not $Programm) {
    $Programm = Join-Path $PSScriptRoot '..\..\AXSafe.exe'
}
$Programm = [IO.Path]::GetFullPath($Programm)
if (-not (Test-Path -LiteralPath $Programm -PathType Leaf)) {
    throw "AXSafe.exe nicht gefunden: $Programm"
}
$Befehl = '"{0}" --scan "%1" --ausloeser kontextmenue' -f $Programm

foreach ($k in $Keys) {
    # -LiteralPath: „*“ ist hier ein echter Schlüsselname, kein Platzhalter.
    New-Item -Path $k -Force | Out-Null
    New-ItemProperty -LiteralPath $k -Name 'MUIVerb' -Value 'Mit AXSafe prüfen' -PropertyType String -Force | Out-Null
    New-ItemProperty -LiteralPath $k -Name 'Icon' -Value ('"{0}",0' -f $Programm) -PropertyType String -Force | Out-Null
    $c = "$k\command"
    New-Item -Path $c -Force | Out-Null
    Set-ItemProperty -LiteralPath $c -Name '(default)' -Value $Befehl
    $ist = (Get-ItemProperty -LiteralPath $c).'(default)'
    if ($ist -ne $Befehl) { throw "Eintrag $c weicht ab: $ist" }
}
Write-Host "Kontextmenü eingerichtet: $Befehl"
