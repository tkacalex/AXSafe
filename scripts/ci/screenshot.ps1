# Startet AXSafe.exe, wartet und speichert ein Bildschirmfoto des Hauptfensters.
# Nur für CI (Dokumentationsbilder). Keine Systemänderungen außer der optionalen
# Bildschirmauflösung des CI-Runners.
param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [Parameter(Mandatory = $true)][string]$Out,
    [string[]]$AppArgs = @(),
    [int]$WaitSeconds = 12
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class Win {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
}
"@
[Win]::SetProcessDPIAware() | Out-Null

$startArgs = @{ FilePath = $Exe; PassThru = $true }
if ($AppArgs.Count -gt 0) { $startArgs.ArgumentList = $AppArgs }
$p = Start-Process @startArgs
$deadline = (Get-Date).AddSeconds(60)
while ($p.MainWindowHandle -eq 0 -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500; $p.Refresh() }
if ($p.MainWindowHandle -eq 0) { throw "Kein Hauptfenster gefunden" }
[Win]::ShowWindow($p.MainWindowHandle, 3) | Out-Null   # maximieren
[Win]::SetForegroundWindow($p.MainWindowHandle) | Out-Null
Start-Sleep -Seconds $WaitSeconds

$r = New-Object Win+RECT
[Win]::GetWindowRect($p.MainWindowHandle, [ref]$r) | Out-Null
$left = [Math]::Max($r.Left, 0); $top = [Math]::Max($r.Top, 0)
$w = $r.Right - $left; $h = $r.Bottom - $top
$bmp = New-Object System.Drawing.Bitmap $w, $h
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($left, $top, 0, 0, $bmp.Size)
$bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Stop-Process -Id $p.Id -Force
Write-Host "Screenshot gespeichert: $Out ($w x $h)"
