$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
$logDir = Join-Path $repoRoot "logs\socket-firewall-canary"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$logPath = Join-Path $logDir "$stamp.log"

function Write-CanaryLog {
    param([string]$Message)
    $Message | Tee-Object -FilePath $logPath -Append | Out-Null
}

function Run-LoggedCommand {
    param([string]$Label, [string[]]$Command)

    Write-CanaryLog ""
    Write-CanaryLog "## $Label"
    Write-CanaryLog "> $($Command -join ' ')"
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        & $Command[0] @($Command[1..($Command.Length - 1)]) 2>&1 |
            ForEach-Object { $_.ToString() } |
            Tee-Object -FilePath $logPath -Append |
            Out-Null
        return [int]$LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
}

function Write-FileHashObservation {
    param([string]$Label, [string]$Path)

    Write-CanaryLog ""
    Write-CanaryLog "## $Label"
    if (-not (Test-Path $Path)) {
        Write-CanaryLog "Missing: $Path"
        return
    }

    Get-FileHash -Algorithm SHA256 -Path $Path |
        Select-Object Algorithm, Hash, Path |
        Format-List |
        Out-String |
        Tee-Object -FilePath $logPath -Append |
        Out-Null
}

function Write-DirectoryHashObservation {
    param([string]$Label, [string]$Path)

    Write-CanaryLog ""
    Write-CanaryLog "## $Label"
    if (-not (Test-Path $Path)) {
        Write-CanaryLog "Missing: $Path"
        return
    }

    Get-ChildItem -Path $Path -Force -Recurse |
        Sort-Object FullName |
        Select-Object FullName, Length, LastWriteTime |
        Format-List |
        Out-String |
        Tee-Object -FilePath $logPath -Append |
        Out-Null

    Get-ChildItem -Path $Path -Force -Recurse -File |
        Sort-Object FullName |
        Get-FileHash -Algorithm SHA256 |
        Select-Object Algorithm, Hash, Path |
        Format-List |
        Out-String |
        Tee-Object -FilePath $logPath -Append |
        Out-Null
}

Push-Location $repoRoot
try {
    Write-CanaryLog "Socket Firewall canary run"
    Write-CanaryLog "UTC: $((Get-Date).ToUniversalTime().ToString("o"))"
    Write-CanaryLog "Local: $((Get-Date).ToString("o"))"
    Write-CanaryLog "Repo: $repoRoot"

    Run-LoggedCommand "node version" @("node", "--version") | Out-Null
    Run-LoggedCommand "npm version" @("npm", "--version") | Out-Null
    Run-LoggedCommand "sfw command" @("where.exe", "sfw") | Out-Null
    Run-LoggedCommand "sfw npm metadata" @("npm", "view", "sfw", "version", "time", "--json") | Out-Null

    $globalNpmRoot = (& npm root -g 2>$null | Select-Object -First 1)
    if ($globalNpmRoot) {
        $sfwRoot = Join-Path $globalNpmRoot "sfw"
        Write-CanaryLog ""
        Write-CanaryLog "## sfw global package root"
        Write-CanaryLog $sfwRoot
        Write-FileHashObservation "sfw wrapper package hash" (Join-Path $sfwRoot "package.json")
        Write-FileHashObservation "sfw wrapper script hash" (Join-Path $sfwRoot "dist\sfw.mjs")
        Write-DirectoryHashObservation "sfw global cache before canary" (Join-Path $sfwRoot ".sfw-cache")
    } else {
        Write-CanaryLog ""
        Write-CanaryLog "## sfw global package root"
        Write-CanaryLog "Unable to resolve npm root -g."
    }

    $exitCode = Run-LoggedCommand "socket firewall canary" @("npm", "run", "canary:socket-firewall")

    if ($globalNpmRoot) {
        $sfwRoot = Join-Path $globalNpmRoot "sfw"
        Write-DirectoryHashObservation "sfw global cache after canary" (Join-Path $sfwRoot ".sfw-cache")
    }

    Write-CanaryLog ""
    Write-CanaryLog "## cache observation"
    $cachePath = Join-Path $repoRoot ".sfw-cache"
    if (Test-Path $cachePath) {
        Get-ChildItem -Path $cachePath -Force -Recurse |
            Select-Object FullName, Length, LastWriteTime |
            Format-Table -AutoSize | Out-String | Tee-Object -FilePath $logPath -Append
    } else {
        Write-CanaryLog "No .sfw-cache directory observed under repo root."
    }

    Write-CanaryLog ""
    Write-CanaryLog "Exit code: $exitCode"
    exit $exitCode
} finally {
    Pop-Location
}
