[CmdletBinding()]
param(
    [ValidateSet('Install', 'Remove')]
    [string] $Action = 'Install',
    [switch] $NoStartup
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Protect.Common.ps1')

if ($Action -eq 'Remove') {
    Set-ProtectShortcut -Folder Programs -Remove
    Set-ProtectShortcut -Folder Startup -Remove
    'Removed Protect shortcuts for this Windows user.'
    return
}

foreach ($file in 'Protect.ps1', 'PopCat-Hotspot.ps1', 'ClaudeNetworkGuard.ps1', 'ClaudeNetworkGuard.exe') {
    if (!(Test-Path -LiteralPath (Join-Path $PSScriptRoot $file) -PathType Leaf)) {
        throw "Missing $file. Keep the project files in the same folder."
    }
}

Set-ProtectShortcut -Folder Programs
Set-ProtectShortcut -Folder Startup -Remove:$NoStartup
'Installed the Protect Start menu shortcut. Open Protect from Start to use the panel.'
