# RackNerd WireGuard 网关

Windows 和 macOS 可以用各自的 WireGuard 密钥连接 Ubuntu VPS，让 IPv4 流量从 VPS 公网地址访问互联网。

| 平台 | 安装与日常操作 | 源码位置 |
| --- | --- | --- |
| Windows | [Windows 部署与使用指南](windows/README.md) | [PowerShell 控制器](windows/) · [Windows 图形面板](gui/) |
| macOS | [Mac 部署与使用指南](macos/README.md) | [官方客户端配置、桌面面板源码与恢复工具](macos/) |
| Ubuntu VPS | [基础网关](server/README.md) · [已有 wg0 的独立 Mac 接口](macos/README.md#独立接口部署) | [服务端脚本和 systemd 单元](server/) |

新建网关可从 Windows 指南开始。已有网关先识别接口、peer 和防火墙的实际管理方式，再选择相应的 Mac 部署路径。两个平台的启停、密钥管理和故障恢复见[架构说明](docs/macos-architecture.md)。应用与出口测试见[macOS 验证流程](docs/macos-verification.md)。

从 GitHub 的 **Code → Download ZIP** 下载源码。客户端配置与桌面应用在本机生成。
