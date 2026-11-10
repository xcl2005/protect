[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('DryRun', 'Live', 'Recover')]
    [string] $Mode,
    [Parameter(Mandatory)]
    [string] $RunDirectory
)

$ErrorActionPreference = 'Stop'
$progressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$root = (Resolve-Path -LiteralPath $RunDirectory).Path
$powerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
. (Join-Path $PSScriptRoot 'Protect.Common.ps1')
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this test as an administrator.' }

function Write-RunLog([string] $Message) {
    $line = "{0:HH:mm:ss.fff} {1}" -f (Get-Date), $Message
    Add-Content -LiteralPath (Join-Path $root "$Mode.log") -Value $line
}

function New-Marker([string] $Name) {
    $null = New-Item -ItemType File -Path (Join-Path $root $Name)
}

function Wait-Marker([string] $Name, [int] $Seconds) {
    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        if (Test-Path -LiteralPath (Join-Path $root $Name)) { return $true }
        Start-Sleep -Milliseconds 150
    } while ($timer.Elapsed.TotalSeconds -lt $Seconds)
    return $false
}

function Get-GoogleRoute {
    Find-NetRoute -RemoteIPAddress '8.8.8.8' -ErrorAction SilentlyContinue |
        Where-Object DestinationPrefix | Select-Object -First 1
}

function Test-PopCatConnectivity {
    $adapter = Get-ProtectPopCatAdapter
    if (!$adapter -or (Get-GoogleRoute).InterfaceIndex -ne $adapter.ifIndex) { return $false }
    $response = & curl.exe --noproxy '*' -4 -s -o NUL -w '%{http_code} %{local_ip}' --max-time 4 https://www.gstatic.com/generate_204
    $ip = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress)
    $parts = $response -split ' '
    return ($parts[0] -eq '204' -and $parts.Count -eq 2 -and $parts[1] -in $ip)
}

function Assert-NoClaude {
    $claude = Get-Process -Name claude,'claude-*','cowork-svc','github-mcp-server','chrome-native-host' -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessName -like 'claude*' -or !$_.Path -or $_.Path -match '\\WindowsApps\\Claude_' }
    if ($claude) { throw 'Claude or a possible Claude helper is running. Disconnect cancelled.' }
}

function Get-PopCatExecutable {
    $paths = @(Get-Process -Name PopCat -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and [IO.Path]::GetFileName($_.Path) -eq 'PopCat.exe' } |
        Select-Object -ExpandProperty Path -Unique)
    if ($paths.Count -ne 1 -or !(Test-Path -LiteralPath $paths[0] -PathType Leaf)) {
        throw 'Could not identify the running PopCat executable for automatic recovery.'
    }
    $paths[0]
}

if ($Mode -eq 'Recover') {
    try {
        $saved = Get-Content -LiteralPath (Join-Path $root 'adapter.json') -Raw | ConvertFrom-Json
        $original = [guid]$saved.InterfaceGuid
        $current = Get-ProtectPopCatAdapter -InterfaceGuid $original
        if (!$current -or $current.Status -ne 'Up') { throw 'The original PopCat adapter could not be resolved.' }
        $popCatExe = Get-PopCatExecutable
        Write-RunLog 'Independent recovery process ready.'
        New-Marker 'rollback-ready'
        if (!(Wait-Marker 'armed' 35)) {
            Write-RunLog 'No disconnect requested. Exiting without changes.'
            exit
        }
        if (!(Wait-Marker 'release' 18)) {
            Write-RunLog 'Test did not release within 18 seconds. Restoring independently.'
            for ($check = 0; $check -lt 12; $check++) {
                if ((Get-ProtectPopCatAdapter -InterfaceGuid $original).Status -ne 'Up') { break }
                Start-Sleep -Milliseconds 250
            }
        }
        $current = Get-ProtectPopCatAdapter -InterfaceGuid $original
        if ($current.Status -eq 'Disabled') {
            Write-RunLog 'Re-enabling the original PopCat virtual adapter.'
            try { Enable-NetAdapter -InputObject $current -Confirm:$false } catch { Write-RunLog $_.Exception.Message }
        }
        $current = Get-ProtectPopCatAdapter -InterfaceGuid $original
        if ((!$current -or $current.Status -eq 'Disabled') -and $saved.PnPDeviceID -like 'SWD\Wintun\*') {
            Write-RunLog 'Attempting to re-enable the saved Wintun device ID.'
            & pnputil.exe /enable-device $saved.PnPDeviceID | Out-Null
        }
        for ($attempt = 0; $attempt -lt 5; $attempt++) {
            if (Test-PopCatConnectivity) {
                Write-RunLog 'Recovered: PopCat route and Google HTTPS 204 verified.'
                New-Marker 'recovered'
                exit
            }
            Start-Sleep -Seconds 1
        }
        if (Test-Path -LiteralPath $popCatExe -PathType Leaf) {
            Write-RunLog 'Adapter recovery did not restore connectivity. Restarting only the verified PopCat app.'
            $running = Get-Process -Name PopCat -ErrorAction SilentlyContinue | Where-Object { $_.Path -eq $popCatExe }
            if ($running) { $running | Stop-Process -ErrorAction Stop }
            Start-Process -FilePath $popCatExe -WindowStyle Hidden
            for ($attempt = 0; $attempt -lt 12; $attempt++) {
                Start-Sleep -Seconds 2
                if (Test-PopCatConnectivity) {
                    Write-RunLog 'Recovered after PopCat restart: Google HTTPS 204 via the tunnel.'
                    if ([guid](Get-ProtectPopCatAdapter).InterfaceGuid -ne $original) {
                        Write-RunLog 'PopCat recreated its adapter. Refresh the Claude guard before starting Claude.'
                    }
                    New-Marker 'recovered'
                    exit
                }
            }
        }
        throw 'Could not verify recovery. Open PopCat and reconnect TUN locally.'
    } catch {
        Write-RunLog ("Recovery error: " + $_.Exception.Message)
        New-Marker 'recovery-failed'
        exit 1
    }
}

$capture = $false
$filter = $false
$armed = $false
if (Get-ChildItem -LiteralPath $root -Force | Select-Object -First 1) { throw 'Use a new, empty local log directory.' }
try {
    Assert-NoClaude
    $adapter = Get-ProtectPopCatAdapter
    if (!$adapter) { throw 'Exactly one PopCat TUN adapter must be connected.' }
    $physical = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
        Where-Object { $_.InterfaceIndex -ne $adapter.ifIndex } | Sort-Object RouteMetric | Select-Object -First 1
    $uplink = if ($physical) { Get-NetAdapter -InterfaceIndex $physical.InterfaceIndex }
    if (!$uplink -or !$uplink.HardwareInterface -or $uplink.Status -ne 'Up') { throw 'Could not verify a separate physical uplink.' }
    if ((& (Join-Path $PSScriptRoot 'PopCat-Hotspot.ps1') -Action Status).State -ne 'Off') { throw 'Turn off Mobile hotspot before the disconnect test.' }
    $online = $false
    for ($attempt = 0; $attempt -lt 3 -and !$online; $attempt++) {
        $online = Test-PopCatConnectivity
    }
    if (!$online) { throw 'PopCat HTTPS baseline failed after three checks.' }
    $guard = Join-Path $PSScriptRoot 'ClaudeNetworkGuard.exe'
    $before = & $guard status
    if ($LASTEXITCODE -or $before -notmatch 'Active: [1-9][0-9]*\.') { throw 'Claude guard must be active before this test.' }
    Write-RunLog $before
    @{
        InterfaceGuid = [string]$adapter.InterfaceGuid
        PnPDeviceID = $adapter.PnPDeviceID
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root 'adapter.json') -Encoding UTF8
    $args = @('-NoProfile','-ExecutionPolicy','Bypass','-File',('"{0}"' -f $PSCommandPath),'-Mode','Recover','-RunDirectory',('"{0}"' -f $root))
    $rollback = Start-Process -FilePath $powerShell -ArgumentList $args -WindowStyle Hidden -PassThru
    if (!(Wait-Marker 'rollback-ready' 8) -or $rollback.HasExited) { throw 'Independent recovery did not become ready.' }
    Write-RunLog "Recovery ready, PID $($rollback.Id)."
    if ($Mode -eq 'Live') {
        $monitor = & pktmon.exe status | Out-String
        $filters = & pktmon.exe filter list | Out-String
        if ($monitor -notmatch 'not running|没有运行|未运行' -or $filters -notmatch '(?im)^\s*(none|无)[。.]?\s*$') {
            throw 'Packet Monitor is not idle or already has filters. Disconnect cancelled.'
        }
        & pktmon.exe filter add ProtectGoogleProbe -i 8.8.8.8 -p 53 | Out-Null
        if ($LASTEXITCODE) { throw 'Unable to set the Google-only capture filter.' }
        $filter = $true
        & pktmon.exe start --capture --comp nics --type flow --pkt-size 64 --file-name (Join-Path $root 'google.etl') | Out-Null
        if ($LASTEXITCODE) { throw 'Unable to start the scoped capture.' }
        $capture = $true
    }
    $probeArgs = @('--log', ('"{0}"' -f (Join-Path $root 'probe.log')), 'probe-google-live',
        ('"{0}"' -f (Join-Path $root 'probe-ready')), ('"{0}"' -f (Join-Path $root 'down')))
    $probe = Start-Process -FilePath $guard -ArgumentList $probeArgs -WindowStyle Hidden -PassThru
    if (!(Wait-Marker 'probe-ready' 10) -or $probe.HasExited) { throw 'The TCP and UDP Google baseline did not become ready.' }
    Write-RunLog 'Google TCP and UDP probe sockets are established.'
    if ($Mode -eq 'DryRun') {
        Stop-Process -InputObject $probe
        Write-RunLog 'Dry run complete. No adapter changed.'
        exit
    }
    Assert-NoClaude
    if ($rollback.HasExited) { throw 'Recovery process stopped. Disconnect cancelled.' }
    New-Marker 'armed'
    $armed = $true
    Disable-NetAdapter -InputObject $adapter -Confirm:$false
    $state = (Get-ProtectPopCatAdapter -InterfaceGuid ([guid]$adapter.InterfaceGuid)).Status
    $route = Get-GoogleRoute
    Write-RunLog "After disable: PopCat=$state; Google route=$($route.InterfaceAlias)."
    if ($state -eq 'Up' -or $route.InterfaceIndex -ne $uplink.ifIndex) { throw 'The probe did not fall back to the physical uplink.' }
    New-Marker 'down'
    if (!$probe.WaitForExit(9000)) { throw 'Google probe exceeded its disconnect window.' }
    if ($probe.ExitCode) { throw "Google probe exited with $($probe.ExitCode)." }
    Write-RunLog 'Offline probe finished.'
} catch {
    Write-RunLog ("Test error: " + $_.Exception.Message)
} finally {
    if ($armed) { New-Marker 'release' }
    if ($capture) { & pktmon.exe stop | Out-Null }
    if ($filter) { & pktmon.exe filter remove | Out-Null }
    if ($capture) {
        & pktmon.exe etl2txt (Join-Path $root 'google.etl') --out (Join-Path $root 'google.txt') | Out-Null
    }
}
