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
    if ($package.Count -ne 1) {
        throw 'Could not identify one installed Claude Desktop package for this Windows user.'
    }
    $desktopFolder = Join-Path $package[0].InstallLocation 'app'
    if (-not (Test-Path -LiteralPath (Join-Path $desktopFolder 'Claude.exe') -PathType Leaf)) {
        throw 'Could not find Claude Desktop in its package folder.'
    }
    $cli = Join-Path $env:USERPROFILE '.local\bin\claude.exe'
    $cliFile = Get-Item -LiteralPath $cli
    if ($cliFile.VersionInfo.ProductName -ne 'Claude Code') {
        throw 'The expected Claude Code executable could not be identified.'
    }
    $desktopPrograms = Get-ChildItem -LiteralPath $desktopFolder -Filter '*.exe' -File -Recurse |
        Sort-Object FullName | Select-Object -ExpandProperty FullName
    $arguments += @($cli) + @($desktopPrograms)
}

& $guard @arguments
if ($LASTEXITCODE -ne 0) {
    throw "Claude Network Guard could not complete '$Action' (exit $LASTEXITCODE)."
}
