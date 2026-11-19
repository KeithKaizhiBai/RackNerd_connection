# Windows 与 macOS 的网关架构

目标是让 Windows 和 Mac 各自通过同一个 VPS 上网。两台客户端分别持有密钥和隧道地址，独立连接、断开。公网 SSH 保持为服务器管理入口。

## 源码核对结果

本次审查基于上游版本 `d27da0a01be1d7b9c69c3362a91dfd876c49e046`。原 Windows 与 GUI 文件保持原样。公开源码中的地址、服务和防火墙名称，与当前 VPS 是否一致，需要通过实时检查确认。

| 层次 | 公开版 Windows 实现 | macOS 接入方式 |
|---|---|---|
| 数据通道 | 官方 WireGuard 的 `WireGuardTunnel$rn-public` 服务 | 官方 WireGuard macOS 应用及 NetworkExtension |
| 本地控制 | `Gateway-Mode.ps1` 调用服务、路由、DNS、代理和恢复函数 | 官方界面负责日常连接；`rn-mac` 用于准备、检查和限时试验 |
| 图形界面 | `gui/Gateway-Panel.ps1` 调用 PowerShell 控制器并轮询实际线路 | 使用官方 WireGuard 界面 |
| 私钥 | Windows 本机生成，DPAPI 保护的配置由 SYSTEM 使用 | Mac 本机独立生成；导入官方应用，准备文件限制为当前用户可读写 |
| IPv4 路由 | 两条 `/1` 加物理网卡到 VPS 的 `/32` | NetworkExtension 使用 IPv4 默认路由；试连时核验外层 UDP 的物理路径 |
| DNS | NRPT、系统加密 DNS、Windows 防火墙限制隧道外 DNS | 隧道配置指定 DNS，另行核查原生解析器、路由及 DNS 实际出口 |
| IPv6 | 临时 Windows 防火墙规则限制公网 IPv6 | 配置本地 ULA 地址及两条 IPv6 半默认路由，服务器仅授权 Mac IPv4 源地址；须验证没有物理出口泄漏 |
| 恢复 | SYSTEM 与桌面用户的计划任务分别恢复网络和代理 | 先验证 launchd 中独立运行的恢复进程；到期调用原生 VPN 断开接口 |
| 原网络 | 保存并恢复 Windows 的代理、DNS 和专用规则 | NetworkExtension 移除自己的路由、DNS；原服务配置保留，并与试验前状态对照 |

## 服务端需要扩展的具体位置

`server/rn-gateway` 的原始实现有以下关联，新增 peer 时必须一起处理。

| 位置 | 原有约定 | 本地扩展 |
|---|---|---|
| `IFACE`、`SERVER`、`CLIENT` | `rn-public`、`10.203.84.1/32`、Windows `10.203.84.2/32` | 保留原身份；额外 peer 使用经核实的独立 `/32` |
| `up()` | 设置唯一 peer 和唯一客户端主机路由 | 启动时另外加载已提交的 peer 和主机路由 |
| `nft_rules()` | Windows 源地址的 ICMP、转发、回包和 NAT | 保留原规则，追加生成额外 peer 的四条限源规则 |
| `verify_live()` | 整个 AllowedIPs 输出必须恰好为 Windows 一个 peer | 验证原 Windows 记录与每个额外 peer；拒绝额外未知记录 |
| `active.json` | 保存原 peer、端口和服务归属 | 原字段不变；新 peer 单独保存在 `peers.json` |
| `rollback()` | 停止整台网关，影响所有客户端 | 新增 `peer-cancel`、`peer-remove`，只撤回额外 peer |
| 端口限制 | 53、853 为 Windows DNS 策略保留 | 继续保持这项兼容约定 |

原服务使用 `rn-public-gateway.service`，启动时从保存的数据重建接口、主机路由、IPv4 转发和独立 nftables 表。它要求专用 VPS，并且会检查服务文件、规则归属、其他防火墙及路由管理者。其 `preflight` 是首次部署前检查，已经运行的服务器不应重新执行首次部署流程。

新增 peer 的实时更新顺序是：核对已有运行状态 → 先安排定向回滚 → 增加四条带 peer 标记的规则 → 增加该 peer 的主机路由 → 用 `wg set` 加入该 peer → 再次核对原身份和所有 peer。整个过程无需重启接口或 gateway 服务。

Mac 到其他 peer 的流量继续经过已有私网目标丢弃规则。新规则只允许 Mac 到公网接口的互联网转发，以及已建立连接的回包。

## 实际部署分支

自定义 `wg0` 网关可采用专用的 `rn-mac` 接口。部署前检查实际服务、规则和地址，步骤见 [macOS 指南](../macos/README.md)。

| 实时检查结果 | 下一步 |
|---|---|
| 与公开版一致的 `rn-public` 服务、程序和规则归属 | 审阅增量源码，备份旧程序和状态，再使用新的 peer 子命令 |
| `wg0` 和 `wg-quick@wg0` | 按实际配置文件与 firewall owner 集成，保留现有服务、地址、密钥和 Windows peer；公开版脚本不接管该接口 |
| 自定义启动脚本、其他 nftables/iptables/UFW 管理 | 先阅读实际持久化来源，再制作对应增量；保留其原有管理方式 |

`inspect-live.py` 使用明确的公开字段选择器。它不会调用会导出私钥的 `wg showconf` 或 `wg ... dump`，也不会输出配置文件中的私钥、预共享密钥或任意 hook 命令内容。报告仍包含内部地址和防火墙拓扑，应保存在被忽略的本机目录。

## 后续 Mac 到 Windows

以后可在现有独立身份上增加以下内容：Mac 的目标路由、VPS 对 Mac `/32` → Windows `/32` 的指定端口转发、Windows 对该来源的主机防火墙规则，以及 SSH/RDP 等服务本身的认证。若仍使用本项目的私网目标阻断策略，需要在其前面增加准确的端口例外。每个方向和端口分别验收并准备撤回。

本阶段的规则继续隔离客户端。SSH、RDP、VS Code Remote SSH 和文件传输服务均留待后续任务配置。
