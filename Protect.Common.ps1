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
    $shortcut.Arguments = "-NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass $fileArgument"
    if ($Folder -eq 'Startup') { $shortcut.Arguments += ' -Tray' }
    $shortcut.WorkingDirectory = $PSScriptRoot
    $shortcut.IconLocation = Join-Path $PSScriptRoot 'ClaudeNetworkGuard.exe'
    $shortcut.Description = 'Claude protection and PopCat hotspot controls'
    $shortcut.Save()
}

function Get-ProtectStartupTaskName {
    'Protect-' + [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
}

function Test-ProtectStartupEnabled {
    $task = Get-ScheduledTask -TaskPath '\' -TaskName (Get-ProtectStartupTaskName) -ErrorAction SilentlyContinue
    if ($task) { return $task.State -ne 'Disabled' }
    Test-Path -LiteralPath (Join-Path ([Environment]::GetFolderPath('Startup')) 'Protect.lnk') -PathType Leaf
}

function Set-ProtectStartup {
    param([switch] $Remove)

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $taskName = Get-ProtectStartupTaskName
    $task = Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue
    $panelArgument = '-File "{0}"' -f (Join-Path $PSScriptRoot 'Protect.ps1')
    if ($task) {
        $existingArguments = [string]$task.Actions[0].Arguments
        if ($task.Actions.Count -ne 1 -or $existingArguments.IndexOf($panelArgument, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
            throw 'A Protect logon task already points to a different project folder.'
        }
    }
    if ($Remove) {
        if ($task) { Unregister-ScheduledTask -TaskPath '\' -TaskName $taskName -Confirm:$false }
    } else {
        $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $arguments = "-NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass $panelArgument"
        $action = New-ScheduledTaskAction -Execute $powershell -Argument $arguments -WorkingDirectory $PSScriptRoot
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
        $trigger.Delay = 'PT8S'
        $principal = New-ScheduledTaskPrincipal -UserId $identity.User.Value -LogonType Interactive -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
        $null = Register-ScheduledTask -TaskPath '\' -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Open the Protect panel after Windows sign-in' -Force
    }
    $legacy = Join-Path ([Environment]::GetFolderPath('Startup')) 'Protect.lnk'
    if (Test-Path -LiteralPath $legacy -PathType Leaf) { Set-ProtectShortcut -Folder Startup -Remove }
}
