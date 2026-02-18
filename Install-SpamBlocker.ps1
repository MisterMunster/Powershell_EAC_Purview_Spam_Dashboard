# Install-SpamBlocker.ps1
# Run once to install SpamBlocker shortcut on your desktop
# Usage: powershell -ExecutionPolicy Bypass -File Install-SpamBlocker.ps1

Add-Type -AssemblyName System.Drawing

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "  SpamBlocker Installer" -ForegroundColor Cyan
Write-Host "  ----------------------" -ForegroundColor Cyan

# --- Where to install ---
$installDir = "$env:USERPROFILE\SpamBlocker"
$scriptName = "SpamBlocker.ps1"
$scriptSrc  = Join-Path $PSScriptRoot $scriptName
$scriptDest = Join-Path $installDir $scriptName
$desktop    = [Environment]::GetFolderPath("Desktop")
$shortcut   = Join-Path $desktop "SpamCan.lnk"
$iconSrc    = Join-Path $env:USERPROFILE "Downloads\SPAM-Can.jpg"
$iconDest   = Join-Path $installDir "SpamCan.ico"

# --- Check SpamBlocker.ps1 is in same folder ---
if (-not (Test-Path $scriptSrc)) {
    $scriptSrc = Join-Path (Get-Location) $scriptName
    if (-not (Test-Path $scriptSrc)) {
        Write-Host ""
        Write-Host "  ERROR: Cannot find $scriptName" -ForegroundColor Red
        Write-Host "  Make sure Install-SpamBlocker.ps1 and SpamBlocker.ps1 are in the same folder." -ForegroundColor Yellow
        Write-Host ""
        Read-Host "  Press Enter to exit"
        exit 1
    }
}

# --- Create install directory ---
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir | Out-Null
    Write-Host "  Created install folder: $installDir" -ForegroundColor Green
} else {
    Write-Host "  Install folder exists: $installDir" -ForegroundColor Gray
}

# --- Copy script ---
Copy-Item $scriptSrc $scriptDest -Force
Write-Host "  Copied SpamBlocker.ps1 to $installDir" -ForegroundColor Green

# --- Convert SPAM-Can.jpg to ICO ---
$iconLocation = "shell32.dll,23"

if (Test-Path $iconSrc) {
    try {
        Write-Host "  Converting SPAM-Can.jpg to icon..." -ForegroundColor Gray

        $jpg = [System.Drawing.Image]::FromFile($iconSrc)
        $bmp = New-Object System.Drawing.Bitmap 256, 256
        $g   = [System.Drawing.Graphics]::FromImage($bmp)
        $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $g.DrawImage($jpg, 0, 0, 256, 256)
        $g.Dispose()
        $jpg.Dispose()

        $ms = New-Object System.IO.MemoryStream
        $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
        $pngBytes = $ms.ToArray()
        $ms.Dispose()
        $bmp.Dispose()

        $fs = [System.IO.File]::OpenWrite($iconDest)
        $bw = New-Object System.IO.BinaryWriter($fs)
        $bw.Write([uint16]0)
        $bw.Write([uint16]1)
        $bw.Write([uint16]1)
        $bw.Write([byte]0)
        $bw.Write([byte]0)
        $bw.Write([byte]0)
        $bw.Write([byte]0)
        $bw.Write([uint16]1)
        $bw.Write([uint16]32)
        $bw.Write([uint32]$pngBytes.Length)
        $bw.Write([uint32]22)
        $bw.Write($pngBytes)
        $bw.Close()
        $fs.Close()

        $iconLocation = $iconDest
        Write-Host "  Icon created: SpamCan.ico" -ForegroundColor Green
    } catch {
        Write-Host "  Icon conversion failed: $_" -ForegroundColor Yellow
        Write-Host "  Using default icon instead." -ForegroundColor Yellow
    }
} else {
    Write-Host "  SPAM-Can.jpg not found in Downloads - using default icon." -ForegroundColor Yellow
    Write-Host "  (Expected: $iconSrc)" -ForegroundColor Gray
}

# --- Create desktop shortcut ---
$shell = New-Object -ComObject WScript.Shell
$lnk   = $shell.CreateShortcut($shortcut)
$lnk.TargetPath       = "powershell.exe"
$lnk.Arguments        = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptDest`""
$lnk.WorkingDirectory = $installDir
$lnk.Description      = "SpamBlocker - Exchange Online IP Block Tool"
$lnk.WindowStyle      = 1
$lnk.IconLocation     = $iconLocation
$lnk.Save()

Write-Host "  Created desktop shortcut: SpamCan" -ForegroundColor Green
Write-Host ""
Write-Host "  Installation complete!" -ForegroundColor Cyan
Write-Host "  Double-click 'SpamCan' on your desktop to launch SpamBlocker." -ForegroundColor White
Write-Host ""
Read-Host "  Press Enter to exit"
