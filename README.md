# Claude Network Guard

在 Windows 上限制 Claude Desktop 和 Claude Code 的直接出站连接。允许本机回环。对受保护程序的其他连接，Windows 选中的下一跳必须是当前 PopCat 虚拟网卡。规则由 Windows Filtering Platform 执行并持久化。

## 安装与查看

适用于 Windows x64。将 `ClaudeNetworkGuard.exe` 和 `ClaudeNetworkGuard.ps1` 放在同一个目录。当前安装脚本识别 Microsoft Store 版 Claude Desktop 和 `%USERPROFILE%\.local\bin\claude.exe`。如果安装方式不同，请调整脚本中的识别路径。

先连接 PopCat，再在管理员 PowerShell 中运行：

```powershell
.\ClaudeNetworkGuard.ps1 -Action Install
.\ClaudeNetworkGuard.exe status
```

`Plan` 可预览将被保护的程序，`remove` 可撤销规则。Claude Desktop 更新或 PopCat 重建虚拟网卡后，重新运行 `Install` 刷新程序路径和网卡标识。

## 规则范围

安装程序把可执行文件的完整路径转换为 WFP 应用标识，并额外添加 Claude Desktop 的应用包 SID。连接建立时，Windows 按应用身份、下一跳网卡和回环标记执行规则。HTTPS 加密状态、域名、端口和请求内容不参与判断。

规则只约束匹配的 Windows 程序直接发起的连接。浏览器、系统 DNS 服务或其他代理进程代发的流量，以及 PopCat 内部的出口选择，分别由那些进程或服务处理。

管理员可运行 `.\ClaudeNetworkGuard.exe self-test`，用本机回环验证例外并读取生效规则。该测试无需访问 Claude。

## 从源码编译

在 Visual Studio 的 x64 Native Tools Command Prompt 中，从仓库根目录运行：

```cmd
cl /nologo /std:c++17 /EHsc /W4 /WX /O2 /MT /FeClaudeNetworkGuard.exe ClaudeNetworkGuard.cpp
```
