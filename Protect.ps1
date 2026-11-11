[CmdletBinding()]
param(
    [switch] $Tray,
    [switch] $SmokeTest,
    [ValidateSet('Status', 'Install', 'Remove', 'Probe')]
    [string] $GuardAction,
    [guid] $ResultId,
    [string] $ExpectedUserSid
)

$ErrorActionPreference = 'Stop'
$startupLog = Join-Path $env:LOCALAPPDATA 'Protect\startup.log'
trap {
    $failure = $_
    try {
        $null = New-Item -ItemType Directory -Path (Split-Path -Parent $startupLog) -Force
        '{0:yyyy-MM-dd HH:mm:ss} {1}: {2}' -f (Get-Date), $failure.Exception.GetType().Name, $failure.Exception.Message |
            Set-Content -LiteralPath $startupLog -Encoding UTF8
    } catch {}
    if (!$Tray -and !$SmokeTest -and !$GuardAction) {
        try {
            Add-Type -AssemblyName System.Windows.Forms
            $null = [Windows.Forms.MessageBox]::Show("Protect 无法启动。请查看日志：$startupLog", 'Protect', 'OK', 'Error')
        } catch {}
    }
    exit 1
}

$powerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
. (Join-Path $PSScriptRoot 'Protect.Common.ps1')
$guardScript = Join-Path $PSScriptRoot 'ClaudeNetworkGuard.ps1'
$hotspotScript = Join-Path $PSScriptRoot 'PopCat-Hotspot.ps1'

function Read-Guard {
    $line = & $guardScript -Action Status | Select-Object -Last 1
    if ($line -notmatch '^Installed guard filters: (\d+)\. Active: (\d+)\. Exempting loopback: (\d+)\.$') {
        throw '无法识别 WFP 状态。'
    }
    [pscustomobject]@{ Installed = [int]$Matches[1]; Active = [int]$Matches[2]; Exempt = [int]$Matches[3] }
}

function Get-ResultFile([guid] $Id) {
    Join-Path $env:LOCALAPPDATA "Protect-result-$Id.json"
}

if ($GuardAction) {
    if ($ResultId -eq [guid]::Empty) { throw 'Missing result ID.' }
    try {
        if ($ExpectedUserSid -and [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $ExpectedUserSid) {
            throw '请用当前 Windows 账户的管理员权限运行 Protect，避免修改其他用户的 Claude 保护范围。'
        }
        if ($GuardAction -eq 'Probe') {
            $probe = & (Join-Path $PSScriptRoot 'ClaudeNetworkGuard.exe') probe-google
            if ($LASTEXITCODE) { throw "Google 探针执行失败（退出码 $LASTEXITCODE）。" }
            $result = @{ Ok = $true; Probe = ($probe -join [Environment]::NewLine) }
        } else {
            if ($GuardAction -ne 'Status') { & $guardScript -Action $GuardAction | Out-Null }
            $result = @{ Ok = $true; Guard = Read-Guard }
        }
    } catch {
        $result = @{ Ok = $false; Error = $_.Exception.Message }
    }
    $stream = [IO.File]::Open((Get-ResultFile $ResultId), 'CreateNew', 'Write', 'None')
    $writer = [IO.StreamWriter]::new($stream)
    try { $writer.Write(($result | ConvertTo-Json -Compress)) } finally { $writer.Dispose() }
    exit
}

Add-Type -AssemblyName System.Windows.Forms,System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
$mutex = $null
$signal = $null
if (!$SmokeTest) {
    $signal = [Threading.EventWaitHandle]::new($false, 'AutoReset', 'Local\ClaudePopCatProtectShow')
    $mutex = [Threading.Mutex]::new($false, 'Local\ClaudePopCatProtectPanel')
    try {
        $ownsMutex = $mutex.WaitOne(0)
    } catch [Threading.AbandonedMutexException] {
        $ownsMutex = $true
    }
    if (!$ownsMutex) {
        if (!$Tray) { $null = $signal.Set() }
        $signal.Dispose()
        $mutex.Dispose()
        exit
    }
}

$form = [Windows.Forms.Form]::new()
$form.Text = 'Protect · Claude 与 PopCat 热点'
$form.StartPosition = 'CenterScreen'
$form.ClientSize = [Drawing.Size]::new(545, 365)
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.Font = [Drawing.Font]::new('Microsoft YaHei UI', 10)

function Add-Label([string] $Text, [int] $Top, [int] $Height = 26) {
    $label = [Windows.Forms.Label]::new()
    $label.Text = $Text
    $label.SetBounds(18, $Top, 509, $Height)
    $form.Controls.Add($label)
    $label
}

function Add-Button([string] $Text, [int] $Left, [int] $Top, [int] $Width, [scriptblock] $Click) {
    $button = [Windows.Forms.Button]::new()
    $button.Text = $Text
    $button.SetBounds($Left, $Top, $Width, 34)
    $button.Add_Click($Click)
    $form.Controls.Add($button)
    $button
}

$tunnelLabel = Add-Label 'PopCat TUN：正在检查' 16
$guardLabel = Add-Label 'Claude 保护：未检查，读取生效规则需要管理员授权' 52
$guardOn = Add-Button '开启／刷新规则' 18 82 153 { Invoke-GuardAction Install }
$guardOff = Add-Button '关闭保护' 182 82 122 {
    $reply = [Windows.Forms.MessageBox]::Show($form, '关闭后，Claude 可直接通过物理网卡联网。确定关闭保护？',
        '关闭 Claude 保护', 'YesNo', 'Warning', 'Button2')
    if ($reply -eq 'Yes') { Invoke-GuardAction Remove }
}
$guardCheck = Add-Button '检查生效规则' 315 82 140 { Invoke-GuardAction Status }
$hotspotLabel = Add-Label 'Windows 热点：正在检查' 132
$hotspotOn = Add-Button '以 PopCat 开启热点' 18 162 175 { Invoke-HotspotAction Start }
$hotspotOff = Add-Button '关闭热点' 204 162 122 { Invoke-HotspotAction Stop }
$null = Add-Button '刷新' 337 162 76 { Refresh-Status }
$null = Add-Button '断开 PopCat 前检查' 18 207 175 { Show-DisconnectCheck }
$probeButton = Add-Button 'Google 防泄漏探针' 204 207 175 { Invoke-GuardAction Probe }
$startupPath = Join-Path ([Environment]::GetFolderPath('Startup')) 'Protect.lnk'
$startup = [Windows.Forms.CheckBox]::new()
$startup.Text = '登录 Windows 后自动启动面板和提醒'
$startup.SetBounds(18, 253, 509, 28)
$startup.Checked = Test-Path -LiteralPath $startupPath -PathType Leaf
$form.Controls.Add($startup)
$startup.Add_Click({
    try {
        Set-ProtectShortcut -Folder Startup -Remove:(!$startup.Checked)
    } catch {
        $startup.Checked = Test-Path -LiteralPath $startupPath -PathType Leaf
        Show-Problem $_.Exception.Message
    }
})
$null = Add-Label '请在退出 PopCat 前先点「断开 PopCat 前检查」。直接在 PopCat 中断开时，面板只能在检测到变化后提醒。' 292 57

$context = [Windows.Forms.ApplicationContext]::new()
$menu = [Windows.Forms.ContextMenuStrip]::new()
$icon = [Windows.Forms.NotifyIcon]::new()
$icon.Text = 'Protect · Claude 与 PopCat 热点'
$icon.Icon = [Drawing.SystemIcons]::Shield
$icon.ContextMenuStrip = $menu
$null = $menu.Items.Add('打开 Protect 面板', $null, { Show-Panel })
$null = $menu.Items.Add('断开 PopCat 前检查', $null, { Show-DisconnectCheck })
$null = $menu.Items.Add('退出面板和提醒', $null, { $context.ExitThread() })
$icon.Add_DoubleClick({ Show-Panel })
$form.Add_FormClosing({
    param($sender, $eventArgs)
    if ($eventArgs.CloseReason -eq 'UserClosing') {
        $eventArgs.Cancel = $true
        $form.Hide()
    }
})

$noticeForm = [Windows.Forms.Form]::new()
$noticeForm.Text = 'Protect · 网络提醒'
$noticeForm.StartPosition = 'CenterScreen'
$noticeForm.FormBorderStyle = 'FixedDialog'
$noticeForm.ClientSize = [Drawing.Size]::new(410, 125)
$noticeForm.MinimizeBox = $false
$noticeForm.MaximizeBox = $false
$noticeForm.TopMost = $true
$noticeForm.Font = $form.Font
$noticeLabel = [Windows.Forms.Label]::new()
$noticeLabel.SetBounds(16, 14, 378, 55)
$noticeForm.Controls.Add($noticeLabel)
$dismiss = [Windows.Forms.Button]::new()
$dismiss.Text = '知道了'
$dismiss.SetBounds(310, 76, 82, 32)
$dismiss.Add_Click({ $noticeForm.Hide() })
$noticeForm.Controls.Add($dismiss)
$noticeForm.AcceptButton = $dismiss
$noticeForm.Add_FormClosing({
    param($sender, $eventArgs)
    if ($eventArgs.CloseReason -eq 'UserClosing') {
        $eventArgs.Cancel = $true
        $noticeForm.Hide()
    }
})

function Show-Panel {
    $form.Show()
    $form.WindowState = 'Normal'
    $null = $form.Activate()
    Refresh-Status
}

$readStatus = {
    param([string] $Root, [bool] $ReadHotspot)
    $ErrorActionPreference = 'Stop'
    . (Join-Path $Root 'Protect.Common.ps1')
    $state = $null
    $hotspot = $null
    try {
        $processIds = @(Get-Process -Name PopCat -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
        $running = $processIds.Count -gt 0
        $up = $running -and [bool](Get-ProtectPopCatAdapter)
        $state = [pscustomobject]@{ Running = $running; Ready = $up; ProcessIds = $processIds }
    } catch {
        # Keep the last valid state for tunnel change notifications.
    }
    if ($ReadHotspot) {
        try { $hotspot = & (Join-Path $Root 'PopCat-Hotspot.ps1') -Action Status } catch {}
    }
    [pscustomobject]@{ Tunnel = $state; Hotspot = $hotspot; HotspotQueried = $ReadHotspot }
}

function Refresh-Status {
    $script:nextStatus = [DateTime]::MinValue
}

function Show-Status([object] $Snapshot) {
    $state = $Snapshot.Tunnel
    if ($state) {
        $tunnelLabel.Text = if ($state.Ready) { 'PopCat TUN：网卡已连接' } else { 'PopCat TUN：未连接' }
        if ($script:previousState) {
            $notice = Get-TunnelNotice $script:previousState $state
            if ($notice) {
                $noticeLabel.Text = "$notice。热点及 Claude 代理可能中断。"
                if (!$noticeForm.Visible) { $noticeForm.Show() }
                $null = $noticeForm.Activate()
            }
        }
        $script:previousState = $state
    } else {
        $tunnelLabel.Text = 'PopCat TUN：暂时无法读取状态'
    }
    $ready = [bool]($state -and $state.Ready)
    $guardOn.Enabled = $ready
    $probeButton.Enabled = $ready
    if (!$Snapshot.HotspotQueried) { return }

    $hotspot = $Snapshot.Hotspot
    if ($hotspot) {
        $hotspotLabel.Text = switch ($hotspot.State) {
            'On' { "Windows 热点：已开启 · $($hotspot.Clients) 台设备" }
            'Off' { 'Windows 热点：已关闭' }
            default { "Windows 热点：$($hotspot.State)" }
        }
        $hotspotOn.Enabled = $ready -and $hotspot.State -eq 'Off'
        $hotspotOff.Enabled = $hotspot.State -eq 'On'
    } else {
        $hotspotLabel.Text = 'Windows 热点：读取失败，请查看系统设置'
        $hotspotOn.Enabled = $false
        $hotspotOff.Enabled = $false
    }
}

function Show-Problem([string] $Text) {
    $null = [Windows.Forms.MessageBox]::Show($form, $Text, 'Protect', 'OK', 'Warning')
}

function Show-DisconnectCheck {
    $issues = @()
    $claude = Get-Process -Name claude,'claude-*','cowork-svc','github-mcp-server','chrome-native-host' -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessName -like 'claude*' -or $_.Path -match '\\WindowsApps\\Claude_' -or !$_.Path }
    if ($claude) { $issues += '检测到 Claude 或其辅助进程。先保存工作并退出 Claude，再断开 PopCat。' }
    try {
        $hotspot = & $hotspotScript -Action Status
        if ($hotspot.State -eq 'On') { $issues += "热点仍开启，有 $($hotspot.Clients) 台设备连接。先关闭热点或让设备切换网络。" }
        elseif ($hotspot.State -ne 'Off') { $issues += '热点状态不确定，请先到 Windows 设置确认。' }
    } catch {
        $issues += '无法读取热点状态，请先到 Windows 设置确认。'
    }
    if ($issues.Count) {
        Show-Problem ($issues -join ([Environment]::NewLine * 2))
    } else {
        $null = [Windows.Forms.MessageBox]::Show('未发现 Claude 进程，热点已关闭。现在可在 PopCat 中断开。断开期间请勿启动 Claude。',
            '断开 PopCat 前检查', 'OK', 'Information')
    }
}

function Invoke-GuardAction([string] $Action) {
    $id = [guid]::NewGuid()
    $file = Get-ResultFile $id
    $panelPath = Join-Path $PSScriptRoot 'Protect.ps1'
    try {
        $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $panelPath),
            '-GuardAction', $Action, '-ResultId', $id, '-ExpectedUserSid', [Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
        $worker = Start-Process -FilePath $powerShell -ArgumentList $args -Verb RunAs -WindowStyle Hidden -Wait -PassThru
        if ($worker.ExitCode -ne 0 -or !(Test-Path -LiteralPath $file)) { throw '管理员操作没有返回状态。' }
        $result = Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
        if (!$result.Ok) { throw $result.Error }
        if ($Action -eq 'Probe') {
            $note = '仅测试程序向 Google 公共 DNS 发送请求。通过临时规则模拟允许出口消失，PopCat 仍连接。没有明确拒绝或 WFP 拦截事件时，超时只算未判定。'
            $null = [Windows.Forms.MessageBox]::Show($form, "$note`r`n`r`n$($result.Probe)", 'Google 防泄漏探针', 'OK', 'Information')
            return
        }
        $guard = $result.Guard
        $description = if (!$guard.Installed) { '已关闭' }
            elseif ($guard.Active -eq $guard.Installed -and $guard.Exempt -eq $guard.Active) { "已开启 · $($guard.Active) 条规则" }
            else { "规则状态异常 · $($guard.Active)/$($guard.Installed) 条生效" }
        $guardLabel.Text = "Claude 保护：$description · $(Get-Date -Format 'HH:mm:ss') 已检查"
    } catch {
        if ($Action -ne 'Probe') { $guardLabel.Text = 'Claude 保护：本次状态未确认' }
        Show-Problem $_.Exception.Message
    } finally {
        if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file }
    }
}

function Invoke-HotspotAction([string] $Action) {
    $hotspotOn.Enabled = $false
    $hotspotOff.Enabled = $false
    try {
        $null = & $hotspotScript -Action $Action
    } catch {
        Show-Problem $_.Exception.Message
    } finally {
        Refresh-Status
    }
}

function Get-TunnelNotice([object] $Before, [object] $After) {
    if ($Before.Running -and !$After.Running) { return 'PopCat 已退出' }
    if ($Before.Running -and $After.Running -and !($Before.ProcessIds | Where-Object { $_ -in $After.ProcessIds })) {
        return 'PopCat 已重启'
    }
    if ($Before.Ready -and !$After.Ready) { return 'PopCat TUN 已断开' }
}

$statusReader = [PowerShell]::Create()
function Start-StatusRead([bool] $ReadHotspot) {
    $statusReader.Commands.Clear()
    $null = $statusReader.AddScript($readStatus.ToString()).AddArgument($PSScriptRoot).AddArgument($ReadHotspot)
    $statusReader.BeginInvoke()
}

$script:previousState = $null
$script:pendingStatus = $null
$guardOn.Enabled = $false
$probeButton.Enabled = $false
$hotspotOn.Enabled = $false
$hotspotOff.Enabled = $false
if ($SmokeTest) {
    $pending = Start-StatusRead $true
    if (!$pending.AsyncWaitHandle.WaitOne(10000)) { throw 'Background status query timed out.' }
    $status = $statusReader.EndInvoke($pending) | Select-Object -Last 1
    Show-Status $status
    $online = [pscustomobject]@{Running = $true; Ready = $true; ProcessIds = @(1)}
    $offline = [pscustomobject]@{Running = $false; Ready = $false; ProcessIds = @()}
    $restarted = [pscustomobject]@{Running = $true; Ready = $true; ProcessIds = @(2)}
    if (!(Get-TunnelNotice $online $offline) -or !(Get-TunnelNotice $online $restarted) -or
        (Get-TunnelNotice $offline $offline) -or (Get-TunnelNotice $online $online)) { throw 'Transition test failed.' }
    if ($hotspotLabel.Text -like '*读取失败*') { throw 'Hotspot status test failed.' }
    $noticeForm.Dispose()
    $form.Dispose()
    $menu.Dispose()
    $icon.Dispose()
    $context.Dispose()
    $statusReader.Dispose()
    'Protect UI, hotspot status and simulated PopCat exit checks passed.'
    exit
}

Refresh-Status
$timer = [Windows.Forms.Timer]::new()
$timer.Interval = 250
$timer.Add_Tick({
    try {
        if ($signal.WaitOne(0)) { Show-Panel }
        if ($script:pendingStatus -and $script:pendingStatus.IsCompleted) {
            $pending = $script:pendingStatus
            $script:pendingStatus = $null
            $status = $statusReader.EndInvoke($pending) | Select-Object -Last 1
            Show-Status $status
        }
        if (!$script:pendingStatus -and [DateTime]::UtcNow -ge $script:nextStatus) {
            $script:nextStatus = [DateTime]::UtcNow.AddSeconds(3)
            $script:pendingStatus = Start-StatusRead $form.Visible
        }
    } catch {
        $tunnelLabel.Text = 'PopCat TUN：暂时无法读取状态'
    }
})

try {
    $icon.Visible = $true
    if (!$Tray) { Show-Panel }
    $timer.Start()
    [Windows.Forms.Application]::Run($context)
} finally {
    $timer.Dispose()
    $icon.Dispose()
    $menu.Dispose()
    $noticeForm.Dispose()
    $form.Dispose()
    $context.Dispose()
    $signal.Dispose()
    $mutex.ReleaseMutex()
    $mutex.Dispose()
    $statusReader.Dispose()
}
