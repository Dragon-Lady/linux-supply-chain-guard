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

    $exitCode = Run-LoggedCommand "socket firewall canary" @("npm", "run", "canary:socket-firewall")

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
