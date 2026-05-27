# install.ps1 — yass installer for Windows (PowerShell 5+).
#
# Usage:
#   irm https://raw.githubusercontent.com/cisco-sbg-emu/yass/main/install.ps1 | iex
#   & ([scriptblock]::Create((irm '...install.ps1'))) -Version v0.1.0 -InstallDir 'C:\tools'
#
# Default: installs latest tag to %LOCALAPPDATA%\Programs\yass.

[CmdletBinding()]
param(
    [string]$Version = '',
    [string]$InstallDir = '',
    [string]$Repo = 'cisco-sbg-emu/yass'
)

$ErrorActionPreference = 'Stop'

# Arch detection
$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'amd64' }
    'ARM64' { 'arm64' }
    default { throw "unsupported arch: $env:PROCESSOR_ARCHITECTURE" }
}

# TLS 1.2 minimum for old PowerShell hosts
[Net.ServicePointManager]::SecurityProtocol = `
    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

if (-not $Version) {
    try {
        $latest = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" -Headers @{'User-Agent'='yass-installer'}
        $Version = $latest.tag_name
    } catch {
        throw "could not resolve latest version (private repo? pass -Version): $_"
    }
}

if (-not $InstallDir) {
    $InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\yass'
}
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

$binary = "yass-windows-$arch.exe"
$url = "https://github.com/$Repo/releases/download/$Version/$binary"
$sumsUrl = "https://github.com/$Repo/releases/download/$Version/SHA256SUMS"
$tmp = Join-Path $env:TEMP "yass-install-$([guid]::NewGuid())"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

try {
    Write-Host "==> downloading $binary $Version"
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile (Join-Path $tmp $binary)

    Write-Host "==> verifying SHA-256"
    $sumsPath = Join-Path $tmp 'SHA256SUMS'
    Invoke-WebRequest -UseBasicParsing -Uri $sumsUrl -OutFile $sumsPath

    $expectedLine = Get-Content $sumsPath | Where-Object { $_ -match "\*?$([regex]::Escape($binary))$" } | Select-Object -First 1
    if (-not $expectedLine) { throw "no SHA256SUMS entry for $binary" }
    $expected = ($expectedLine -split '\s+')[0].ToLower()
    $actual = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $binary)).Hash.ToLower()
    if ($actual -ne $expected) { throw "checksum mismatch: $actual != $expected" }

    $dest = Join-Path $InstallDir 'yass.exe'
    Move-Item -Force (Join-Path $tmp $binary) $dest
    Write-Host "==> installed yass $Version to $dest"

    # PATH check
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not (($userPath -split ';') -contains $InstallDir)) {
        Write-Host "==> adding $InstallDir to user PATH (open a new shell to pick it up)"
        $newPath = if ($userPath) { "$userPath;$InstallDir" } else { $InstallDir }
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    }

    & $dest --version
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
