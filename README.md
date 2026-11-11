# Protect · Claude 与 PopCat 热点

在 Windows 上限制 Claude Desktop 和 Claude Code 的直接出站连接。允许本机回环。对受保护程序的其他连接，Windows 选中的下一跳必须是当前 PopCat 虚拟网卡。规则由 Windows Filtering Platform 执行并持久化。

## 在另一台电脑安装

需要 Windows 11 x64、可用的 PopCat TUN，以及要保护的 Claude Desktop 或 Claude Code。热点功能还需要本机的无线网卡支持 Windows 移动热点。项目包含已编译的 x64 程序，日常使用无需安装 Visual Studio。PopCat 和 Claude 需单独安装并登录，订阅、节点和热点凭据由各台电脑自行配置。

1. 在 Windows PowerShell 中下载整个项目，放到以后不会随意移动的目录。

   ```powershell
   git clone https://github.com/xcl2005/protect.git
   Set-Location protect
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-Protect.ps1
   ```

   也可在 GitHub 下载 ZIP 并完整解压，再从解压目录运行安装命令。安装会为当前用户创建开始菜单和登录启动入口。只想创建开始菜单入口时，给安装命令加 `-NoStartup`。

2. 启动 PopCat 并连上 TUN。可先预览这台电脑上将被保护的程序路径。

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\ClaudeNetworkGuard.ps1 -Action Plan
   ```

   可识别 Claude Desktop 的 Microsoft Store 包，以及用户原生安装目录或 PATH 上标识为 Claude Code 的 `claude.exe`。可以只安装其中一个。第三方包装器或其他安装形式需另外核实。

3. 从开始菜单打开 **Protect**，点 **开启／刷新规则**，用当前 Windows 账户的管理员权限批准，再检查生效规则。每台电脑都要重新安装规则，本机的 WFP 状态不会随 Git 迁移。Claude 更新或 PopCat 重建虚拟网卡后，再执行一次 **开启／刷新规则**。

4. 若要共享热点，先确认 Windows 热点处于关闭状态，再点 **以 PopCat 开启热点**。用手机连接原热点，关闭手机移动数据后分别验证国内外网站。面板和提醒可以自动启动，热点仍由你手动开启。

## Protect 面板

从开始菜单或任务栏通知区域打开 **Protect**。也可以在 Windows PowerShell 中运行 `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Protect.ps1`。加上 `-Tray` 可只在通知区域运行。

- **开启／刷新规则**、**关闭保护**和**检查生效规则**分别调用现有 WFP 安装、移除和查询功能，均通过 Windows 请求管理员授权。已安装的规则在 Windows 重启后继续生效。关闭保护后需手动重新开启。
- **以 PopCat 开启热点**使用 Windows 移动热点 API 选择 PopCat 虚拟网卡作为共享来源，保留热点名称、密码和频段。如果原热点已经开启，请先关闭。热点由用户手动开启。**关闭热点**仅停止热点。
- 准备退出 PopCat 时，先点面板或托盘里的 **断开 PopCat 前检查**，它会检查 Claude 进程和热点状态。直接在 PopCat 界面退出仍会触发事后提示。关闭面板窗口会留在托盘，右键托盘图标可退出面板和提醒。
- **Google 防泄漏探针**需要管理员授权。它只为测试程序创建临时 WFP 规则，用 Google 公共 DNS 地址进行 IPv4 TCP 和 UDP 测试，再模拟允许出口消失，尝试复用已有套接字并建立新套接字。探针退出即清理临时规则。测试期间 PopCat 保持连接，现有 Claude 规则保留原样。只有明确拒绝或收到响应才给出相应结果，超时和其他错误视为未判定。模拟结果无法代替真实的网卡断开抓包。

PopCat 热点转发与 Protect 的应用级过滤作用在不同位置。关闭热点不会撤销 Protect 规则，关闭保护不会重新配置热点。面板中的热点开关状态来自 Windows，外部开启的热点可能使用其他共享来源。

面板内可以勾选或取消 **登录 Windows 后自动启动面板和提醒**。如需恢复用物理 Wi‑Fi 共享，先关热点并断开 PopCat TUN，再到 Windows 移动热点设置选择物理 Wi‑Fi。

登录启动会把 Protect 放在托盘。用开始菜单或托盘图标打开面板时，网卡和热点状态会在后台读取。如果面板本身启动失败，可以查看 `%LOCALAPPDATA%\Protect\startup.log`。

## 真实断开测试

`Test-PopCatRecovery.ps1` 需要管理员权限和一个新的本机日志目录。`DryRun` 只检查 Claude 已退出、保护规则已启用、热点已关闭、Google 探针已连通，以及独立恢复进程已就绪。`Live` 通过同样的检查后，短暂禁用 PopCat 虚拟网卡，并用 Packet Monitor 观察目标为 Google 公共 DNS 的测试流量。

在管理员 Windows PowerShell 中，从项目目录运行演练。

```powershell
$logs = (New-Item -ItemType Directory -Path (Join-Path $env:TEMP "Protect-Dry-$([guid]::NewGuid())")).FullName
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-PopCatRecovery.ps1 -Mode DryRun -RunDirectory $logs
Get-Content (Join-Path $logs 'DryRun.log')
```

需要实际断开测试时，在电脑本机操作，新建一个空日志目录，并将模式改为 `Live`。测试可能中断依赖 PopCat 的连接。独立恢复进程在测试结束或等待超时后重新启用原虚拟网卡，必要时重启 PopCat，并检查 Google HTTPS。结果保存在本机的 `Live.log`、`probe.log`、`Recover.log` 和 Packet Monitor 抓包中。实测范围为 Google 公共 DNS 的 IPv4 TCP 和 UDP。测试期间请保持 Claude 关闭。

## 卸载与回滚

在面板中关闭热点。需要撤销 WFP 保护时点 **关闭保护** 并批准管理员确认，再从托盘退出面板。运行 `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Install-Protect.ps1 -Action Remove` 删除当前用户的 Protect 快捷方式。删除项目文件本身不会移除已经安装的 WFP 规则。

## 规则范围

安装程序把可执行文件的完整路径转换为 WFP 应用标识，并额外添加 Claude Desktop 的应用包 SID。连接建立时，Windows 按应用身份、下一跳网卡和回环标记执行规则。HTTPS 加密状态、域名、端口和请求内容不参与判断。

规则只约束匹配的 Windows 程序直接发起的连接。浏览器、系统 DNS 服务或其他代理进程代发的流量，以及 PopCat 内部的出口选择，分别由那些进程或服务处理。

管理员可运行 `.\ClaudeNetworkGuard.exe self-test`，用本机回环验证例外并读取生效规则。该测试无需访问 Claude。

## 从源码编译

在 Visual Studio 的 x64 Native Tools Command Prompt 中，从仓库根目录运行：

```cmd
cl /nologo /std:c++17 /EHsc /W4 /WX /O2 /MT /FeClaudeNetworkGuard.exe ClaudeNetworkGuard.cpp
```
