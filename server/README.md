# 在 Ubuntu 24.04 VPS 上部署 WireGuard 上网网关

这一阶段把一台专用 VPS 配置为一台 Windows 电脑的 IPv4 出口。管理仍走原公网 SSH。客户端只需交换 WireGuard 公钥。

| 项目 | 设置 |
|---|---|
| VPS 接口和隧道地址 | `rn-public`，`10.203.84.1/32` |
| Windows 隧道地址 | `10.203.84.2/32`，服务器只接受此源地址 |
| 公网监听 | UDP `51820`，可选其他空闲端口，排除 DNS 保留端口 `53`、`853` |
| 管理与恢复 | 原公网 SSH 地址和 TCP 端口。RackNerd Console 用于人工应急 |
| 首次试用 | 最多 10 分钟，从新的公网 SSH 连接确认后才启用开机启动 |

## 开始之前

先按[首次登录指南](../docs/first-login.md)验证管理密钥和 SSH 主机指纹。以下示例使用自己的 VPS 公网 IPv4 及已有 SSH 端口。`203.0.113.10` 是文档保留地址，实际部署时填写面板给出的地址。确认隧道的两个私网地址在自己的 Windows LAN、公司 VPN 和 VPS 上空闲。

本脚本适用于刚开通的 Ubuntu 24.04 公网 IPv4 专用 VPS，要求 systemd、回环接口、单一公网接口、一个直接配置在该接口上的公网 IPv4，以及一条普通 IPv4 默认路由。脚本检查策略路由、现有防火墙和内核转发状态。对于已有 UFW、nftables、Docker、其他 VPN、额外网卡或自定义路由的机器，请看文末的规则集成说明。

RackNerd 面板的入站过滤由服务商管理。如果已启用，仅按需增加所选端口的 **UDP 入站**，保留现有 SSH TCP 规则。从独立 SSH 窗口确认管理通道后再继续。页面可以关闭。Ubuntu 的现有防火墙状态仍须单独检查。

## 1. 上传并预检

在**仓库根目录的 Windows PowerShell** 中运行。下例复用首次登录指南中的 `$Login`、`$AdminKey` 和 `$SshPort`。只有文件 `server/rn-gateway` 需要上传。脚本使用 Linux 换行。

```powershell
scp -P $SshPort -i $AdminKey -o IdentitiesOnly=yes -o PreferredAuthentications=publickey -o StrictHostKeyChecking=yes .\server\rn-gateway "${Login}:/root/rn-gateway.upload"
ssh @SshOptions $Login
```

在 **VPS 的 root SSH shell** 安装工具和脚本，检查是否可用。`install` 的目的路径仅用于本项目。如该路径已经有其他软件，先核实文件归属；同一份脚本无需重复覆盖。

```bash
apt-get update
apt-get install --no-install-recommends python3 iproute2 iptables nftables wireguard-tools
install -o root -g root -m 0755 /root/rn-gateway.upload /usr/local/sbin/rn-gateway
rn-gateway preflight
```

`preflight` 在通过时输出公网网卡名称和所选 UDP 端口。遇到冲突会指出原因。无需启动 `nftables.service` 或加载系统的完整规则文件。[Ubuntu 防火墙文档](https://documentation.ubuntu.com/security/security-features/network/firewall/)

## 2. 生成并交换 WireGuard 公钥

在 **VPS** 上运行下行，保存输出的**服务器公钥**供 Windows 安装程序使用。

```bash
rn-gateway prepare
```

如选择其他端口，改为依次执行 `rn-gateway preflight --port 51821` 和 `rn-gateway prepare --port 51821`，再把 Windows 安装参数、面板 UDP 放行端口改成相同数字。`prepare` 将本机私钥存放于 root 专用的 `/var/lib/rn-public-gateway/server.key`。重复执行会复用已有密钥。以后可随时运行 `rn-gateway public-key` 单独读取服务器公钥。

按[根目录的客户端安装步骤](../README.md)在 Windows 上生成另一对密钥。取安装程序输出的**客户端公钥**，在下一步登记。[WireGuard 密钥和接口说明](https://www.wireguard.com/quickstart/)

## 3. 试用服务器并从第二条公网 SSH 连接确认

在 **VPS 的第一条公网 SSH 连接**内执行。提示出现时粘贴完整的客户端公钥，包括末尾的等号。请在直接 SSH shell 中执行 `stage` 和 `commit`，这两个命令会核验各自的 SSH 连接。

```bash
read -r -p 'Windows WireGuard public key: ' client_pub
rn-gateway stage "$client_pub"
unset client_pub
rn-gateway status
```

当 `stage` 显示试用已启动，独立的 systemd 计时器已经生效。此时服务器配置在运行，开机启动仍关闭。第一条 SSH 连接意外断开也会按时回滚。在试用中重启 VPS 会清除临时网络状态，启动后可重新执行 `stage`。重复执行同一有效试用不会延长期限。

在第一条连接之外，打开**另一个 Windows PowerShell 窗口**，按首次登录指南设置同一组 `$Login` 和 `$SshOptions`。其中 `ControlMaster=no` 和 `ControlPath=none` 用来新建 TCP 连接。等 `stage` 成功返回后，再打开这个 SSH 登录。

```powershell
ssh @SshOptions $Login 'rn-gateway commit'
ssh @SshOptions $Login 'rn-gateway status'
```

`commit` 核对目标公网 IPv4、原 SSH 端口、不同的 TCP 来源连接，以及新的 sshd 会话进程启动时间，还会检查单一客户端公钥、隧道路由和转发。通过后，服务器网关及转发设置随系统启动恢复。若跳过这一步，10 分钟后网关停止。

**此时只完成了服务器管理与持久化确认。** 可关闭工作站上连向该 VPS 的 SSH 会话，再开始 Windows 面板的限时试用。客户端实际外网出口、应用、DNS 及切回原线路都在后面单独验收。两端的试用计时器互相独立。

## 4. 验证隧道与出口

1. 在 Windows 面板开始试用，运行 `ping -4 10.203.84.1`。服务器只允许已登记的客户端向该内网地址发起 ICMP 回显。也可以在完整切换之前使用已有客户端密钥、相同端点和 `AllowedIPs = 10.203.84.1/32` 做一次仅内网测试；同一客户端密钥同时只启动一个配置。
2. 按[验收与恢复指南](../docs/verify-and-recover.md)检查网页、Windows 程序的实测公网 IPv4、DNS、IPv6 防漏以及返回原网络。实测出口应是自己的 VPS 公网 IPv4。网卡已启动或内网 ping 成功只说明其中一段可用。
3. 从公网 SSH 运行 `rn-gateway status`。最近握手时间戳首次握手前为 `0`，实际传输后收发计数应增长。用 `nft list table ip rn_public_gateway` 检查专用转发表与 NAT 计数。NAT 链主要计数新建连接的首包。

## 回滚、日志与故障定位

在公网 SSH 运行以下命令可立即回滚试用或已提交的配置。

```bash
rn-gateway rollback
rn-gateway status
```

回滚会关闭服务开机启动、恢复原公网接口的 IPv4 转发值，删除本脚本创建且带本次所有权标记的 WireGuard 接口、客户端路由和 nftables 表。安装包、已停用的服务文件、服务器密钥和端口选择保留，下次可以复用。`status` 预期显示已准备但网关未运行。之后需要换 Windows 公钥时，用新公钥再次 `stage`，从新 SSH 会话 `commit`。

| 现象 | 查看与处理 |
|---|---|
| 试用期间 SSH 断开 | 用原公网地址和管理密钥重连，执行 `rn-gateway status`。如仍在试用，可在符合条件的新登录中提交；超时后可重新试用。 |
| 二次确认失败 | 检查新连接在 `stage` 完成后建立，目标是相同公网 IPv4 与 SSH 端口；从 Windows 直接启动新 SSH 进程。 |
| 服务启动失败 | `journalctl -u rn-public-gateway.service -b --no-pager -n 60`。试用计时器可用 `systemctl list-timers 'rn-public-trial-*'` 检查。故障恢复后重新执行预检。 |
| 握手持续为 0 | 核对两端互换的公钥、VPS 公网 IPv4 和 UDP 端口，再查 RackNerd 面板过滤。TCP 端口探测无法验证 WireGuard UDP 握手。 |
| 有握手，无法上网 | 先确认隧道 ping，再查看 Windows 出口路由、DNS 和原代理的过滤规则。观察服务器 `forward` 与 `wan_masquerade` 计数能区分客户端发包、服务器放行及回包。 |
| SSH 本身无法恢复 | 等待试用回滚；仍不可达时从 RackNerd Console 登录，核对主机并运行 `rn-gateway rollback`，然后检查原 SSH 服务和服务商防火墙。 |

## 转发范围和已有防火墙

脚本只接受 `rn-public` 上来自 `10.203.84.2/32` 的流量，经识别出的公网网卡发送到允许的 IPv4 目的地，并对此来源做 masquerade。回程只放行与既有连接相关的包。私有、链路本地、共享、组播、文档保留等特殊地址，以及 VPS 上联网关和直接连接的网段被排除。发往 VPS 自己的内网访问只放行上述 ping，公网 SSH 仍使用原入口。此模板不提供 IPv6 出口。

IPv4 转发按两个接收接口启用，由同一 systemd 服务在开机时重新应用，并在清理时先关闭公网接口转发再撤除过滤规则。系统级 `net.ipv4.ip_forward` 可继续显示 `0`。要检查活动网关的两个开关，在 Bash 中执行以下命令，第二行使用预检输出的真实公网网卡名。[Linux 内核的每接口 forwarding 定义](https://www.kernel.org/doc/html/v6.8/networking/ip-sysctl.html)

```bash
cat /proc/sys/net/ipv4/conf/rn-public/forwarding
read -r -p 'Uplink name reported by preflight: ' uplink
cat "/proc/sys/net/ipv4/conf/$uplink/forwarding"
```

已有防火墙或其他转发服务时，可先用 `nft list ruleset`、`iptables-legacy-save`、`ip -4 rule show`、`ip -4 route show table all` 与 `sysctl net.ipv4.ip_forward` 了解现状。管理员应在原有防火墙管理器内增加所选 UDP 入站、仅匹配此客户端和指定出口的转发与 NAT、私网和宿主访问限制，以及对应的已建立回程。保留原有 SSH 与其他业务规则，将这些增量放进原管理器的持久化机制。先准备只撤回本次增量的限时回滚，再用新的公网 SSH 登录验证。此自动脚本的按接口转发和回滚假定 VPS 原先不承担路由职责，无法安全识别的部署会在变更前退出。[nftables 规则与事务](https://netfilter.org/projects/nftables/manpage.html)
