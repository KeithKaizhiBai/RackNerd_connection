# 用 RackNerd VPS 做 Windows 的 WireGuard 上网网关

这份中文手册从 RackNerd 开通邮件开始，带你在自己的 Ubuntu VPS 和 Windows 电脑之间建立 WireGuard 隧道，最后用中文图形面板连接、查看公网出口、返回原网络。应用和文件都留在 Windows 上，普通 IPv4 连接从 VPS 的公网地址访问互联网。

```text
上网   Windows 应用 → WireGuard 加密隧道 → VPS 转发与 NAT → 互联网
管理   Windows OpenSSH → VPS 公网 SSH
```

**适用环境**为一台新开通、专用、带公网 IPv4 的 Ubuntu 24.04 LTS VPS，以及可使用管理员权限的 64 位 Windows 11 桌面。客户端使用 Windows PowerShell 5.1 和系统加密 DNS。已承担容器转发、路由器或其他 VPN 任务的 VPS 应先进行规则共存设计。请在允许短暂断网的时间试用。

## 从开通走到图形面板

在仓库页面选择 **Code → Download ZIP**，解压到本机文件夹。下面的相对路径均从解压后的仓库根目录开始。也可以使用 Git 克隆仓库。运行下载的脚本前先阅读其内容。若 Windows 针对经审阅的下载文件提示 Internet 来源阻止，可在文件属性中解除该文件的阻止。

| 顺序 | 在哪里做 | 完成标志 |
|---|---|---|
| 1. 核实开通信息，建立 SSH 管理入口 | RackNerd 服务面板、Windows PowerShell、Ubuntu | 已确认主机指纹，第二个独立 SSH 窗口能用自己的管理密钥登录。[首次登录](../docs/first-login.md) |
| 2. 检查并准备服务器 | VPS 的公网 SSH 会话 | 服务器通过前置检查，生成自己的 WireGuard 密钥，并给出**服务器公钥**。[服务器步骤](../server/README.md) |
| 3. 准备 Windows 客户端 | 本机管理员 Windows PowerShell | 已安装官方 WireGuard，客户端在本机生成受保护的密钥，得到**客户端公钥**。 |
| 4. 登记客户端并确认服务器配置 | VPS 的原 SSH 会话及一个新开的公网 SSH 会话 | 定时回滚已先设置，再启用客户端和限源 NAT。在第二个 SSH 登录中确认管理仍可用后提交。 |
| 5. 试用并核验 | Windows 图形面板、浏览器、Python 和桌面应用 | 普通网页正常加载，绕过应用代理的出口为自己的 VPS 公网 IPv4，试用后可恢复原线路。[验收与恢复](../docs/verify-and-recover.md) |

### 准备两端

先按[首次登录指南](../docs/first-login.md)完成公钥 SSH。在服务器上按[服务端指南](../server/README.md)安装工具并执行 `preflight` 和 `prepare`，取得服务器公钥。服务器脚本为专用 VPS 提供可撤回的转发策略，自动识别公网接口，不替换公网 SSH 的监听配置。

Windows 先安装[官方 WireGuard for Windows](https://www.wireguard.com/install/)。在仓库根目录打开 **64 位管理员 Windows PowerShell**，输入自己的公网地址和刚才取得的服务器公钥。

```powershell
$VpsIPv4 = Read-Host '你的 VPS 公网 IPv4'
$ServerPublicKey = Read-Host '服务器 WireGuard 公钥'
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\windows\Install-Client.ps1 -EndpointIPv4 $VpsIPv4 -ServerPublicKey $ServerPublicKey -Port 51820
```

记下安装程序给出的**客户端公钥**。返回公网 SSH 会话，按服务器指南运行 `stage`，参数使用这把客户端公钥。在回滚期限内，通过新的独立公网 SSH 登录运行 `commit`。确认成功后退出工作站上连向该 VPS 的活动 SSH 会话，再开始 Windows 的限时试用。这样可以分别验证服务器能管理、Windows 能上网。

WireGuard 的两把私钥在各自机器生成。SSH 管理密钥用于登录服务器。只有两端的 WireGuard **公钥**需要互换。[WireGuard 密钥与握手说明](https://www.wireguard.com/quickstart/)

### 日常操作

双击 [gui/RackNerd-Network.cmd](../gui/RackNerd-Network.cmd)，按面板提示操作。查看状态可用普通权限。切换和恢复时，请使用同一个已登录的 Windows 管理员账户确认提权，系统代理按该桌面用户保存和还原。

| 用途 | 做法 |
|---|---|
| 第一次试用 | 如在使用 v2rayN，先关闭“启用 TUN”，然后选择 **试用 15 分钟**。核验出口和实际应用，再点 **返回原网络**，或等待定时还原。检查并恢复成功后即可使用日常连接。 |
| 日常上网 | 选择 **连接 RackNerd**。当面板显示出口已经核验时，用原来的浏览器、Python 或其他桌面程序访问互联网。 |
| 确认是否生效 | 在面板查看本机线路、网卡、实测公网出口和核验时间。绿色需要本机 WireGuard 路由和绕过应用代理的真实出口同时符合预期。 |
| 回原网络 | 选择 **返回原网络**。如果原来使用 v2rayN TUN，重新打开它。 |

Windows 保留物理网关到 VPS 公网端点的路径，再用两条 `/1` 路由覆盖普通 IPv4 流量。系统加密 DNS 经隧道发送。此配置采用 IPv4 出口，运行期间限制其他公网 IPv6 路径。切换工具负责保存并恢复 Windows 的代理、DNS 和专用路由。v2rayN 客户端可以退出，它的 TUN 开关由用户操作。

只想从终端查看状态时，在仓库根目录运行 `.\gui\RackNerd-Network.cmd Status`。面板最小化后可从托盘打开，关闭窗口后隧道继续按所选模式运行。

## 公开版与实际部署

这套流程来自一次完成过浏览器、Python、桌面应用以及原网络恢复验证的部署。公开版使用独立的隧道名称 `rn-public` 和示例私网地址，服务器为 `10.203.84.1`，Windows 为 `10.203.84.2`。部署前先确认这两个地址不会与自己的本地网络或机构 VPN 冲突。UDP 端口默认 `51820`，自定义时两端和托管平台的防火墙都要一致，并避开客户端 DNS 策略使用的 `53` 和 `853`。

仓库提供通用源码和操作说明。每位部署者都需要在自己的线路上完成限时试用、出口、应用及回退验收。开通邮件、订阅凭据、生成的密钥、运行配置、日志和实际网络截图应留在自己的设备上。若需提交问题单，请先替换公网地址、主机名、用户名、密钥和本机路径。
