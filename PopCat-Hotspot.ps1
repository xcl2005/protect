[CmdletBinding()]
param(
    [ValidateSet('Start', 'Stop', 'Status')]
    [string] $Action = 'Status'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
. (Join-Path $PSScriptRoot 'Protect.Common.ps1')
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$network = [Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]
$tethering = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]

$popCat = Get-ProtectPopCatAdapter
$profiles = @($network::GetConnectionProfiles() |
    Sort-Object { [int]$_.GetNetworkConnectivityLevel() } -Descending)
$tunnelProfile = if ($popCat) {
    $profiles | Where-Object { $_.NetworkAdapter.NetworkAdapterId -eq [guid]$popCat.InterfaceGuid } |
        Select-Object -First 1
}
if ($Action -eq 'Start' -and !$tunnelProfile) {
    throw 'Connect PopCat TUN before starting the hotspot.'
}

# Query or stop the system hotspot even if the PopCat connection profile has vanished.
$profile = $tunnelProfile
if (!$profile) { $profile = $network::GetInternetConnectionProfile() }
if (!$profile) { $profile = $profiles | Select-Object -First 1 }
if (!$profile) { throw 'No Windows connection profile is available. Use Windows Mobile hotspot settings.' }
$manager = $tethering::CreateFromConnectionProfile($profile)
$state = $manager.TetheringOperationalState.ToString()
if ($Action -eq 'Start' -and $state -ne 'Off') {
    throw 'The hotspot must be off before selecting PopCat as its upstream.'
}
if ($Action -eq 'Start' -or ($Action -eq 'Stop' -and $state -ne 'Off')) {
    $operation = if ($Action -eq 'Start') { $manager.StartTetheringAsync() } else { $manager.StopTetheringAsync() }
    $asTask = [System.WindowsRuntimeSystemExtensions].GetMethods() |
        Where-Object { $_.Name -eq 'AsTask' -and $_.IsGenericMethod -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' } |
        Select-Object -First 1
    $resultType = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]
    $task = $asTask.MakeGenericMethod($resultType).Invoke($null, @($operation))
    if (!$task.Wait(25000)) { throw 'Hotspot operation timed out. Check its current state in Windows Settings.' }
    if ($task.Result.Status -ne 'Success') { throw "Hotspot operation failed: $($task.Result.Status)" }
}

[pscustomobject]@{
    State = $manager.TetheringOperationalState.ToString()
    Clients = $manager.ClientCount
}
