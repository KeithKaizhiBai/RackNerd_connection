# 核验出口、应用与恢复

开始前保存工作，选择可以短暂断网的时段。先在原网络记下出口、网卡、系统代理和 DNS。进入 RackNerd 的限时试用后做同一组检查，最后恢复原网络并对照。每个阶段的检查都在该模式稳定时完成。

## Windows 是否真正经 VPS 上网

在普通 PowerShell 运行。公网查询使用 HTTPS，禁用 curl 的配置文件和应用代理，以 Windows 的实际 IPv4 路由访问目标。第三方出口服务会看到这一次请求的公网源地址。将回显地址与你自己服务面板中的 VPS 公网 IPv4 比较。

```powershell
curl.exe --disable --ipv4 --fail --silent --show-error --noproxy '*' --max-time 10 https://api.ipify.org
curl.exe --disable --ipv4 --fail --silent --show-error --noproxy '*' --max-time 10 https://www.cloudflare.com/cdn-cgi/trace |
    Select-String '^ip='
Find-NetRoute -RemoteIPAddress '1.1.1.1'
Find-NetRoute -RemoteIPAddress '208.67.222.222'
Find-NetRoute -RemoteIPAddress $VpsIPv4
Resolve-DnsName www.python.org -Type A -DnsOnly
ping -4 10.203.84.1
```

两个公网目标应分别选中覆盖 IPv4 地址空间两半的 WireGuard 路由，本地源地址是 `10.203.84.2`。VPS 公网地址本身应走物理网卡，这样 WireGuard 的外层 UDP 数据包能到达 VPS。在近端可查看 Windows DNS 客户端的有效策略和加密 DNS 设置。在远端用 `rn-gateway status` 检查握手及收发量，用 `nft list table ip rn_public_gateway` 对照公网请求前后的转发与 NAT 计数。

```powershell
Get-DnsClientNrptPolicy -Effective | Select-Object Namespace,NameServers
Get-DnsClientDohServerAddress -ServerAddress '1.1.1.1','9.9.9.9' |
    Select-Object ServerAddress,AutoUpgrade,AllowFallbackToUdp
```

本方案的互联网出口为 IPv4。模式启用时检查 IPv6 数字地址同样重要，因为只查询 AAAA 记录无法判断 IPv6 是否能出网。若在启用模式期间以下请求仍显示其他公网 IPv6，应恢复原网络，排查其他接口和代理。

```powershell
Test-NetConnection -ComputerName '2606:4700:4700::1111' -Port 443 -InformationLevel Quiet
curl.exe --disable --ipv6 --fail --silent --show-error --noproxy '*' --max-time 8 https://api6.ipify.org
```

## 验收实际应用

| 应用 | 操作 | 通过条件 |
|---|---|---|
| 日常浏览器 | 在普通窗口分别打开 `example.com`、`www.python.org` 和公网 IP 检查页 | 页面实际渲染，浏览器出口与 VPS 公网 IPv4 一致。 |
| Python | 执行下方命令，请求 PyPI 的公开文件 | 禁用应用代理后收到 HTTP 200。 |
| 桌面应用，例如 Gemini | 在自己的账户中主动发起一次普通操作 | 收到新的服务响应。可同时看该应用联网进程的新连接是否来自隧道地址。 |

```powershell
python -c "import urllib.request as u; h=u.build_opener(u.ProxyHandler({})); r=h.open('https://pypi.org/robots.txt',timeout=12); print(r.status); r.close()"
```

已有长连接可能继续使用之前的线路。普通浏览器和终端出口不一致时，查看浏览器扩展、应用专用代理或 PAC。桌面应用登录、账户地区限制和 HTTP 鉴权响应应单独记录，避免把它们误判为隧道故障。

## 看懂故障现象

| 观察 | 下一项检查 |
|---|---|
| SSH 能登录，WireGuard 没握手 | 核对双方公钥、端点地址和 UDP 端口。检查控制面板及系统防火墙的 UDP 入站。 |
| 能 ping VPS 私网，公网不通 | 核对客户端的两条 IPv4 路由、VPS 的 IPv4 转发、限源转发规则和 NAT 回包计数。 |
| 已知地址的 HTTPS 能通，普通域名失败 | 核对 Windows 有效 DNS 策略和加密 DNS 的路由。若 v2rayN TUN 已启用，先恢复原网络，再关闭该开关后重新试用。其 DNS 过滤可能在另一个接口被选中时仍然生效。 |
| 窗口显示隧道已启用、出口待确认 | 点击面板的出口核验，或运行上面两个独立检查，确认本机 DNS、公网出口服务和线路可达。 |
| 时延高、网页载入慢 | 分开测物理网关、VPS 公网、隧道私网和应用 HTTPS。将 TCP 建连、TLS、服务器首字节和总用时分别记录。 |

```powershell
curl.exe --disable --ipv4 --noproxy '*' --silent --show-error --max-time 15 -o NUL -w 'DNS=%{time_namelookup} TCP=%{time_connect} TLS=%{time_appconnect} first=%{time_starttransfer} total=%{time_total}\n' https://www.iana.org/robots.txt
```

这些时间均从请求开始计算，相邻值相减可估算各阶段耗时。比较下载和上传时使用同一文件大小、服务及时间段，记下本地源接口。剔除跨越自动恢复的样本。原有代理可能代答 ICMP，测试 VPS 的物理路径时先检查实际选中的网卡。VPS 的地理距离和运营商路由都会反映在往返时延中。

## 退出试用及意外断线

1. 在本机面板选择 **返回原网络**，或用本机管理员 Windows PowerShell 运行下方恢复命令。限时试用有独立于面板和 SSH 的本机恢复任务。
2. 如果试用前在 v2rayN 中手动关闭了“启用 TUN”，此时重新打开。逐项对照原路由、接口 DNS、桌面代理，以及先前正在运行的应用。原出口是动态地址时，以网卡、代理及可用性为准。
3. 如只需返回原网络，到这里即可。若需要撤回服务器端的网关配置，通过原有公网 SSH 按[服务器回滚说明](../server/README.md)执行。VNC 是 SSH 管理同时不可用时的独立入口。

```powershell
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File "$env:ProgramFiles\RackNerd-Connection\Gateway-Mode.ps1" -Action Original
```

全隧道路由按需启用。隧道仍有路由但没有回包时，上网可能暂停。隧道路由消失时，Windows 可能改走另一条可用 IPv4 路由。本流程没有启用系统级断网保护。

短暂断网和重启要分开验收。前者可在允许中断的窗口断开再接回同一网络，观察新握手、私网连通性、出口和应用响应。后者应先保存工作；本面板在 Windows 重启和桌面登录时恢复原网络，VPS 已提交的网关会随服务器启动。重新登录 Windows 后先检查面板状态，再按需连接并核验出口。
