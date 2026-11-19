# macOS WireGuard 客户端

日常使用官方 WireGuard 应用。在隧道列表选择 `RackNerd2`，点击“启用”连接，点击“停用”恢复原网络。桌面 RackNerd 面板可打开 WireGuard 或查询公网 IPv4。只关闭面板窗口会保留当前连接。

## 独立接口部署

以下命令在 macOS 的仓库根目录运行。此路径针对 Ubuntu 上由 `wg-quick@wg0` 和自定义 `racknerd-gateway.service` 管理的双 peer 网关，要求原有公网接口为 `eth0`。上游启动时恢复一个 peer，网关服务再添加 Windows 出口 peer。工具会对照实际源码、服务、路由和防火墙。新建的 `rn-public` 网关使用[基础网关文档](../server/README.md)中的配置，拓扑选择见[架构说明](../docs/macos-architecture.md)。

1. 安装[官方 WireGuard macOS 应用](https://www.wireguard.com/install/)、Python 3.9+，以及用于 X25519 的 Homebrew OpenSSL 3。通过 VPS 控制台等可信渠道核对 SSH 主机指纹，并在终端完成首次 SSH 登录。下文的变量由使用者在本机填写。

2. 保存私有参考资料。输入实际公网 IPv4 和规划的空闲 Mac 隧道 IPv4。该网关控制器要求 Mac 地址等于旧 wg0 服务端地址加三，新的服务端隧道地址等于 Mac 地址加一。检查两者均空闲。采集结果包含机器信息，仅保存在本机。

   ```sh
   umask 077
   mkdir -p .local/reference
   printf 'VPS IPv4: '; read -r VPS_IP
   printf 'Mac tunnel IPv4: '; read -r MAC_IP
   ssh -T -o StrictHostKeyChecking=yes "root@$VPS_IP" 'python3 -B -' < server/inspect-live.py > .local/reference/inventory.json
   ssh -T -o StrictHostKeyChecking=yes "root@$VPS_IP" 'python3 -B -' < server/inspect-gateway-source.py > .local/reference/source.json
   python3 macos/rn-mac configure --endpoint "$VPS_IP"
   python3 macos/rn-mac keygen
   python3 macos/rn-mac profile --inventory .local/reference/inventory.json --interface wg0 --address "$MAC_IP"
   ```

3. 审阅上述清单和上游服务后，断开其他全隧道 VPN，保持 Wi-Fi 或以太网连接，执行 `python3 macos/check-independent.py --prepare`。该步骤核对网关并暂存专用密钥和文件。在 WireGuard 的“从文件导入隧道”中选择 `.local/macos/independent/` 里的两份配置，导入后先保持停用。

4. 先运行 `python3 macos/probe-independent.py`，确认握手、自动断开和清理成功。再运行 `python3 macos/probe-independent.py --full`，在短时全隧道期间验证浏览器、ChatGPT 和 Codex。测试会检查系统代理及终端代理环境。停用 WireGuard 可提前恢复。若现有 Windows 服务存在中断风险，先完成离线验证，推迟服务器变更。

5. 两次试验通过后运行 `python3 macos/deploy-independent.py`。脚本为 Mac 建立 UDP 51821 的独立接口；先验证停止和恢复，再启用开机服务。终端确认 active、enabled 后即可日常连接。需要撤回时，在 VPS 上运行 `systemctl disable --now racknerd-mac-independent.service`。

## 桌面入口与验证

在已配置 VPS 地址的 Mac 上运行以下命令构建桌面面板。生成的应用含本机配置，只在这台机器上使用。

```sh
sh macos/build-panel.sh "$HOME/Desktop/RackNerd.app"
```

连接后点“验证公网出口”，将结果与自己的 VPS 公网 IPv4 对照。配置示例见 [RackNerd-Mac.conf.example](RackNerd-Mac.conf.example)。该示例展示基础 profile；独立接口的可导入文件由第 3 步生成。稳定性、DNS 和 IPv6 的验收方法见[验证流程](../docs/macos-verification.md)。

离线测试：`python3 -B -m unittest discover -s tests`。本机配置文件、密钥、已编译应用和现场报告均在公开源码包之外。
