[CmdletBinding()]
param(
    [ValidateSet('Plan', 'Install', 'Status', 'Remove')]
    [string] $Action = 'Plan'
)

$ErrorActionPreference = 'Stop'
$guard = Join-Path $PSScriptRoot 'ClaudeNetworkGuard.exe'
if (-not (Test-Path -LiteralPath $guard -PathType Leaf)) {
    throw 'ClaudeNetworkGuard.exe must be next to this script.'
}

$arguments = @($Action.ToLowerInvariant())
if ($Action -in 'Install', 'Remove') {
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Open an administrator PowerShell window to use -Action $Action."
    }
}

if ($Action -in 'Plan', 'Install') {
    $package = @(Get-AppxPackage -Name Claude | Where-Object PackageFamilyName -eq 'Claude_pzs8sxrjxfjjc')
    if ($package.Count -gt 1) {
        throw 'More than one Claude Desktop package was found for this Windows user.'
    }
    $programs = @()
    if ($package.Count -eq 1) {
        $desktopFolder = Join-Path $package[0].InstallLocation 'app'
        if (!(Test-Path -LiteralPath (Join-Path $desktopFolder 'Claude.exe') -PathType Leaf)) {
            throw 'Could not find Claude Desktop in its package folder.'
        }
        $programs += Get-ChildItem -LiteralPath $desktopFolder -Filter '*.exe' -File -Recurse |
            Sort-Object FullName | Select-Object -ExpandProperty FullName
    }
    $cliPaths = @((Join-Path $env:USERPROFILE '.local\bin\claude.exe')) +
        @(Get-Command claude.exe -CommandType Application -All -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
    foreach ($path in ($cliPaths | Select-Object -Unique)) {
        $cli = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
        if ($cli -and $cli.VersionInfo.ProductName -eq 'Claude Code') { $programs += $cli.FullName }
    }
    if (!$programs.Count) { throw 'No supported Claude Desktop package or native Claude Code executable was found.' }
    if (!$package.Count) { $arguments += '--cli-only' }
    $arguments += $programs
}

& $guard @arguments
if ($LASTEXITCODE -ne 0) {
    throw "Claude Network Guard could not complete '$Action' (exit $LASTEXITCODE)."
}
