# vssh.ps1 — SSH wrapper that fetches keys from Vault
# Keys are loaded from Vault at connection time and never persist on disk.
# On Windows, keys are also automatically added to Pageant (PuTTY agent).
#
# Usage: vssh <host-alias> [extra ssh args...]
# Example: vssh dk
#          vssh dk -L 8080:localhost:80
#
# Configuration in ~/.ssh/config:
#   Global:  # vssh:vault_addr https://vault.example.com
#            # vssh:default_vault_key secret/ssh/default-key
#   Per-host (inside Host block):
#            # vssh:vault_path secret/ssh/some-key

$ErrorActionPreference = "Stop"

$sshConfigPath = Join-Path $env:USERPROFILE ".ssh\config"
$sshConfigLines = Get-Content $sshConfigPath -Encoding UTF8

# Read global vssh settings from SSH config
$vaultAddrLine = $sshConfigLines | Where-Object { $_ -match '^\s*#\s*vssh:vault_addr\s+' } | Select-Object -First 1
if ($vaultAddrLine -match '^\s*#\s*vssh:vault_addr\s+(\S+)') {
    $configVaultAddr = $Matches[1]
}
$env:VAULT_ADDR = if ($env:VAULT_ADDR) { $env:VAULT_ADDR } else { $configVaultAddr }

$defaultKeyLine = $sshConfigLines | Where-Object { $_ -match '^\s*#\s*vssh:default_vault_key\s+' } | Select-Object -First 1
$defaultVaultKey = ""
if ($defaultKeyLine -match '^\s*#\s*vssh:default_vault_key\s+(\S+)') {
    $defaultVaultKey = $Matches[1]
}

if (-not $env:VAULT_ADDR) {
    Write-Host "Error: VAULT_ADDR is not set"
    Write-Host "Set it via environment variable or add '# vssh:vault_addr <url>' to $sshConfigPath"
    exit 1
}

if ($args.Count -eq 0) {
    Write-Host "Usage: vssh <host> [ssh args...]"
    Write-Host ""
    Write-Host "Available hosts:"
    $sshConfigLines | Where-Object { $_ -match '^Host\s+' } | ForEach-Object {
        "  " + ($_ -replace '^Host\s+', '')
    }
    exit 1
}

$Host_ = $args[0]
$ExtraArgs = @()
if ($args.Count -gt 1) {
    $ExtraArgs = $args[1..($args.Count - 1)]
}

# Extract per-host vssh:vault_path from SSH config
function Get-HostVaultPath {
    param([string]$HostName)
    $inHost = $false
    foreach ($line in $sshConfigLines) {
        if ($line -match '^Host\s+(.*)') {
            $hosts = $Matches[1] -split '\s+'
            $inHost = $hosts -contains $HostName
        }
        elseif ($inHost -and $line -match '^\s*#\s*vssh:vault_path\s+(\S+)') {
            return $Matches[1]
        }
    }
    return $null
}

$vaultPath = Get-HostVaultPath $Host_
if (-not $vaultPath) {
    $vaultPath = $defaultVaultKey
}

if (-not $vaultPath) {
    Write-Host "Error: No vault path for host '$Host_' and no default_vault_key set"
    Write-Host "Add '# vssh:vault_path <path>' to the Host block or '# vssh:default_vault_key <path>' at the top of $sshConfigPath"
    exit 1
}

Write-Host "Fetching key from Vault: $vaultPath"

# Create temp file in user profile (avoids permission issues with system temp)
$tmpDir = Join-Path $env:USERPROFILE ".vssh-tmp"
if (-not (Test-Path $tmpDir)) {
    New-Item -ItemType Directory -Path $tmpDir | Out-Null
}
$tmpKey = Join-Path $tmpDir "key-$(Get-Random)"

try {
    # Fetch key from Vault
    $keyData = vault kv get -field=private_key $vaultPath 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: Failed to fetch key from Vault path '$vaultPath'"
        Write-Host "Make sure you are logged in: vault login"
        exit 1
    }

    # Write key with correct encoding (UTF-8 no BOM, LF line endings)
    $keyText = ($keyData -join "`n") + "`n"
    [System.IO.File]::WriteAllText($tmpKey, $keyText, (New-Object System.Text.UTF8Encoding $false))

    # Fix permissions: only current user with full control
    icacls $tmpKey /inheritance:r /grant:r "${env:USERNAME}:(F)" 2>$null | Out-Null

    # Add key to Pageant via SSH agent protocol
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Definition }
    $pageantHelper = Join-Path $scriptDir "vssh-pageant.py"
    if (Test-Path $pageantHelper) {
        $prevEAP = $ErrorActionPreference; $ErrorActionPreference = "Continue"
        $pageantOut = $keyText | python $pageantHelper 2>&1
        $ErrorActionPreference = $prevEAP
        if ($pageantOut -match "added|already") { Write-Host $pageantOut }
    }

    Write-Host "Connecting to $Host_..."

    # Run SSH with the fetched key
    if ($ExtraArgs.Count -gt 0) {
        ssh -i $tmpKey -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new $Host_ @ExtraArgs
    } else {
        ssh -i $tmpKey -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new $Host_
    }
}
finally {
    # Cleanup temp key
    if (Test-Path $tmpKey) {
        Remove-Item $tmpKey -Force -ErrorAction SilentlyContinue
    }
}
