# macOS 应用、恢复和性能验收

每次测试分别记录：测试时间、使用的客户端、目标、实际结果和未验证项。密钥、真实地址、截图和原始日志保存在本机被忽略的目录。离线源码测试与真实网络验收分别记录。

## 服务器变更前后都核验 Windows

每次安装服务器增量、添加 peer、提交持久化或撤回 peer 的前后，在 Windows 原控制器中查看实际状态，并在同一台 Windows 上运行两个绕过应用代理的出口检查：

```powershell
curl.exe --disable --noproxy '*' -4fsS --max-time 10 https://api.ipify.org
curl.exe --disable --noproxy '*' -4fsS --max-time 10 https://ipv4.icanhazip.com
```

两个结果都应为自己的 VPS 公网 IPv4，再实际打开普通网页。保存原 Windows 公钥、隧道地址、服务名称、配置文件摘要、接口状态，以及服务端对应 peer 的 AllowedIPs、握手与收发量。服务端观察只能辅助证明，Windows 应用和出口必须在 Windows 上确认。没有可用 Windows 测试通道时，服务器变更保持待执行。

## Mac 验收记录

| 检查 | 方法 | 通过依据 |
|---|---|---|
| 原网络 | `rn-mac snapshot`，普通浏览和 Python 请求 | 原网络可用，完整 DNS、代理和路由可以读取 |
| 独立恢复 | 未启用隧道的 `recovery-test`，随后 Probe 的限时启用与自动停止 | 独立恢复进程运行，停止后网络基线恢复 |
| 握手 | 服务器 `wg show LIVE_INTERFACE latest-handshakes` 与 `transfer` | 新 Mac 公钥出现近期握手，收发量随测试增加 |
| 隧道 IPv4 | ping 实际服务器隧道地址 | 隧道 ICMP 往返，并与服务器计数一致 |
| 公网 IPv4 | `rn-mac verify` 的两个独立 HTTPS 服务 | 两者均返回 VPS 公网地址 |
| 多目标 HTTPS | example.com、python.org、pypi.org | 三个目标均有正确 HTTPS 响应，保留阶段用时 |
| Python | `ProxyHandler({})` 的真实 HTTPS 请求 | 正常证书校验下收到 HTTP 200 |
| 系统 DNS | 系统解析器查询、`scutil --dns`、到 resolver 的实际路由 | 原生 DNS 正常，目标 resolver 经 WireGuard |
| DNS 泄漏 | 物理接口抓包和隧道/VPS 计数对照 | 原生查询的 DNS 流量经过预期通道；记录浏览器 DoH 设置 |
| Chrome | 普通窗口打开三个无关网站及出口页，刷新并实际操作 | 页面渲染、导航及新的 HTTPS 请求成功，出口为 VPS |
| Safari | 同上 | Safari 的实际页面可用，出口为 VPS |
| ChatGPT | 实际已登录应用中发送一次简短请求 | 收到本次新响应；记录其应用与时间 |
| Codex | 当前会话继续执行工具或在桌面应用完成一次实际请求 | 收到新的服务端响应；与当前隧道时段对应 |
| IPv6 | 数字 IPv6 TCP、HTTPS、多目标路由和物理接口抓包 | 公网 IPv6 请求不从物理接口泄漏；IPv4 应用正常回退 |
| 禁用后恢复 | 原生停用和独立计时器到期分别测试 | 路由、DNS、代理对照原基线，普通网络和应用恢复 |

自动 IPv6 检查只探测一个数字目标。其失败不能单独证明所有 IPv6 目的地都被正确捕获，仍须查看路由和物理接口。浏览器 DoH、应用专用代理、机构 DNS 或另一个活动 VPN 也需要单独核对。

实际桌面浏览器可以通过授权的桌面控制测试。若只有隔离的浏览器环境，应请求用户在本机 Chrome/Safari 完成表中最小测试，并将用户确认和自动结果分开记录。

## 性能测量

`rn-mac measure` 记录原始结果。curl 的时间字段从请求开始累计：

| 指标 | 记录与解释 |
|---|---|
| Mac → VPS 公网 RTT、丢包 | 确认物理端点路径后 ping 公网地址；保留样本数和丢包率 |
| Mac → VPS 隧道 RTT、丢包 | 同一时段 ping 隧道 IPv4，与公网 RTT 对照 |
| DNS 延迟 | 系统 DNS 与显式 resolver 查询分别记录，说明缓存和传输方式 |
| TCP 用时 | `time_connect - time_namelookup` |
| TLS 用时 | `time_appconnect - time_connect` |
| 首字节与总响应 | `time_starttransfer`、`time_total`；区分服务器处理与路径延迟 |
| 下载、上传 | 使用已核实的公开测速服务或授权 iperf3 对端，记录字节数、用时和方向 |

同一时段、同一目标重复取样。公网与隧道 RTT 同时偏高时，结合地理距离、运营商路由和拥塞分析；小包正常但 HTTPS/下载异常时，再检查 MTU 和丢包。带其他代理的样本单独标记。

## 短暂中断和持久化

在独立恢复已验证、可接受短暂中断的窗口，通过官方客户端停用/重新启用 Mac 隧道，检查新的握手、DNS、出口和应用请求。这验证隧道重连。无线网络中断后的重连需要另行进行短暂、可恢复的断网试验，并单独记录；两者不能互相替代。

持久化通过保存文件、启用的服务和启动函数进行源码/状态检查。实际 VPS 重启恢复必须另行批准后验证。Mac 和 VPS 的本次流程均不自动重启。
