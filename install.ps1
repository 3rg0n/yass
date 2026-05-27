# install.ps1 — yass installer for Windows (PowerShell 5.1+ / pwsh 7+).
#
# Usage:
#   irm https://raw.githubusercontent.com/3rg0n/yass/main/install.ps1 | iex
#   & ([scriptblock]::Create((irm '...install.ps1'))) -Version v0.1.0 -InstallDir 'C:\tools'
#
# Default: installs latest tag to %LOCALAPPDATA%\Programs\yass and adds it
# to the user PATH. Verifies SHA-256 against the release's SHA256SUMS.

[CmdletBinding()]
param(
    [string]$Version    = '',
    [string]$InstallDir = '',
    [string]$Repo       = '3rg0n/yass'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step([string]$msg) { Write-Host "==> $msg" }

# TLS 1.2 minimum for old PowerShell hosts.
[Net.ServicePointManager]::SecurityProtocol = `
    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

# Architecture detection
$archEnv = $env:PROCESSOR_ARCHITECTURE
if (-not $archEnv) { $archEnv = 'AMD64' }
$arch = switch ($archEnv) {
    'AMD64' { 'amd64' }
    'ARM64' { 'arm64' }
    'x86'   { throw "32-bit Windows is not supported" }
    default { throw "unsupported arch: $archEnv" }
}

# Resolve version
if (-not $Version) {
    Write-Step "resolving latest release"
    try {
        $headers = @{
            'User-Agent'           = 'yass-installer'
            'Accept'               = 'application/vnd.github+json'
            'X-GitHub-Api-Version' = '2022-11-28'
        }
        $latest = Invoke-RestMethod -Headers $headers `
            -Uri "https://api.github.com/repos/$Repo/releases/latest"
        $Version = $latest.tag_name
    } catch {
        throw "could not resolve latest version (rate-limited? try -Version vX.Y.Z): $($_.Exception.Message)"
    }
}

# Resolve install dir
if (-not $InstallDir) {
    $InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\yass'
}
$null = New-Item -ItemType Directory -Force -Path $InstallDir

# Paths
$binary  = "yass-windows-$arch.exe"
$base    = "https://github.com/$Repo/releases/download/$Version"
$tmp     = Join-Path ([System.IO.Path]::GetTempPath()) "yass-install-$([guid]::NewGuid())"
$null = New-Item -ItemType Directory -Force -Path $tmp

try {
    $binPath  = Join-Path $tmp $binary
    $sumsPath = Join-Path $tmp 'SHA256SUMS'

    Write-Step "downloading $binary $Version"
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$binary"     -OutFile $binPath

    Write-Step "verifying SHA-256"
    Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS"  -OutFile $sumsPath

    $expectedLine = Get-Content $sumsPath |
        Where-Object { $_ -match "\*?$([regex]::Escape($binary))$" } |
        Select-Object -First 1
    if (-not $expectedLine) { throw "no SHA256SUMS entry for $binary" }

    $expected = ($expectedLine -split '\s+')[0].ToLower()
    $actual   = (Get-FileHash -Algorithm SHA256 -Path $binPath).Hash.ToLower()
    if ($actual -ne $expected) {
        throw "checksum mismatch: got $actual, expected $expected"
    }

    $dest = Join-Path $InstallDir 'yass.exe'
    Move-Item -Force -Path $binPath -Destination $dest
    Write-Step "installed yass $Version to $dest"

    # Add to user PATH if missing
    $userPath  = [Environment]::GetEnvironmentVariable('Path', 'User')
    $entries   = if ($userPath) { $userPath -split ';' } else { @() }
    if ($entries -notcontains $InstallDir) {
        Write-Step "adding $InstallDir to user PATH (open a new shell to pick it up)"
        $newPath = if ($userPath) { "$userPath;$InstallDir" } else { $InstallDir }
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        $env:Path = "$env:Path;$InstallDir"
    }

    & $dest --version
} finally {
    Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
}
