function Get-ProtectPopCatAdapter {
    param([guid] $InterfaceGuid = [guid]::Empty)

    $adapters = @(Get-NetAdapter -InterfaceDescription 'PopCat Tunnel' -IncludeHidden -ErrorAction SilentlyContinue |
        Where-Object {
            !$_.HardwareInterface -and
            $(if ($InterfaceGuid -eq [guid]::Empty) { $_.Status -eq 'Up' } else { [guid]$_.InterfaceGuid -eq $InterfaceGuid })
        })
    if ($adapters.Count -eq 1) { $adapters[0] }
}

function Set-ProtectShortcut {
    param(
        [Parameter(Mandatory)] [ValidateSet('Programs', 'Startup')] [string] $Folder,
        [switch] $Remove
    )

    $panel = Join-Path $PSScriptRoot 'Protect.ps1'
    $path = Join-Path ([Environment]::GetFolderPath($Folder)) 'Protect.lnk'
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($path)
    $fileArgument = '-File "{0}"' -f $panel
    if ((Test-Path -LiteralPath $path) -and $shortcut.Arguments.IndexOf($fileArgument, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "A different shortcut already exists at $path."
    }
    if ($Remove) {
        if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path }
        return
    }
    $shortcut.TargetPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $shortcut.Arguments = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass $fileArgument"
    if ($Folder -eq 'Startup') { $shortcut.Arguments += ' -Tray' }
    $shortcut.WorkingDirectory = $PSScriptRoot
    $shortcut.IconLocation = Join-Path $PSScriptRoot 'ClaudeNetworkGuard.exe'
    $shortcut.Description = 'Claude protection and PopCat hotspot controls'
    $shortcut.Save()
}
