# 从 RackNerd 开通邮件到可恢复的 SSH 登录

本步骤在新 VPS 上建立管理通道。随后 WireGuard 即使停用，也可以继续用公网 SSH 管理服务器。

## 1. 找到 VPS 和独立控制台

在 RackNerd 客户区打开已开通的 VPS，核实系统是 Ubuntu 24.04 LTS，并从开通邮件或服务面板取得 **VPS 的公网 IPv4、SSH 用户、SSH 端口、初始登录方式**。把凭据保存在自己的密码管理器。客户区账号、VPS 控制台和 Linux 登录是三个不同的入口。[RackNerd 开通说明](https://blog.racknerd.com/how-to-order-vps-hosting-at-racknerd/)

从该服务的管理页打开 **Console / VNC**。在 Linux 提示符自行登录，运行下面两行，记下正确的主机和 SSH 主机公钥指纹。控制台可随后关闭。日常操作走 SSH，控制台用于 SSH 确实不可用时恢复。[RackNerd 控制台说明](https://www.racknerd.com/ctrl-control-panel)

```bash
hostname
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

## 2. 在 Windows 建立专用管理密钥

在普通 PowerShell 中运行。公网地址在本地输入。下面的变量保留在这个 PowerShell 窗口中。

```powershell
$VpsIPv4 = Read-Host '输入你自己的 VPS 公网 IPv4'
$SshPort = 22                 # 如果服务商给了其他管理端口，在这里填写
$Login = "root@$VpsIPv4"      # 此教程以新 VPS 的初始 root 登录为例
$SshDir = Join-Path $env:USERPROFILE '.ssh'
$AdminKey = Join-Path $SshDir 'rn-vps-admin'
if (-not (Test-Path -LiteralPath $SshDir)) {
    New-Item -ItemType Directory -Path $SshDir | Out-Null
}
if (-not (Test-Path -LiteralPath $AdminKey) -and -not (Test-Path -LiteralPath ($AdminKey + '.pub'))) {
    ssh-keygen -t ed25519 -f $AdminKey -C 'vps-admin'
}
Get-Content -LiteralPath ($AdminKey + '.pub')
```

为新私钥设置口令。最后一行显示的是可安装到服务器的 **SSH 公钥**。没有 `.pub` 后缀的文件是私钥，留在本机。如果同名文件已经存在，请确认它属于你正在使用的管理密钥。[Windows OpenSSH 密钥管理](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement)

## 3. 首次登录和第二次验证

先打开第一个 SSH 窗口。首次连接时，将 OpenSSH 显示的 ED25519 指纹与控制台记录逐字核对。只在本机 OpenSSH 的登录提示里输入初始凭据。

```powershell
ssh -p $SshPort -o HostKeyAlgorithms=ssh-ed25519 -o StrictHostKeyChecking=ask -o ConnectTimeout=45 $Login
```

在 **VPS 的 Bash** 运行以下代码，并在提示处粘贴刚才的**整行 SSH 公钥**。这会保留已有授权条目。

```bash
umask 077
mkdir -p "$HOME/.ssh"
touch "$HOME/.ssh/authorized_keys"
chmod 700 "$HOME/.ssh"
chmod 600 "$HOME/.ssh/authorized_keys"
read -r -p 'Paste your SSH public key: ' admin_pub
if [[ "$admin_pub" == ssh-ed25519\ * ]] && printf '%s\n' "$admin_pub" | ssh-keygen -lf - >/dev/null; then
    if ! grep -Fqx -- "$admin_pub" "$HOME/.ssh/authorized_keys"; then
        printf '\n%s\n' "$admin_pub" >> "$HOME/.ssh/authorized_keys"
    fi
else
    printf '%s\n' 'Invalid SSH public key; no entry added.' >&2
fi
unset admin_pub
```

保留第一个 SSH 窗口。在另一个本地 PowerShell 中重新定义第 2 步的 `$VpsIPv4`、`$SshPort`、`$Login`、`$AdminKey`。以下参数用于后续独立 SSH 登录。私钥有口令时，OpenSSH 可向你询问本机密钥口令。

```powershell
$SshOptions = @('-p', "$SshPort", '-i', $AdminKey,
    '-o', 'IdentitiesOnly=yes', '-o', 'PreferredAuthentications=publickey',
    '-o', 'StrictHostKeyChecking=yes', '-o', 'ServerAliveInterval=15',
    '-o', 'ServerAliveCountMax=4', '-o', 'ConnectTimeout=45',
    '-o', 'ControlMaster=no', '-o', 'ControlPath=none')
ssh @SshOptions $Login 'hostname; id -u'
```

成功返回主机名且此处的 root 用户 ID 为 `0` 后，再继续安装。SSH 的公钥和下一阶段的两把 **WireGuard 公钥**用于不同协议。WireGuard 公钥稍后由两个端点分别生成。

## 4. 切换网络前留下对照

在 **Windows PowerShell** 查看正常上网时使用的网卡、默认路由、DNS 及代理开关。这些结果可能含真实地址，只在本机保存。

```powershell
Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' |
    Select-Object InterfaceAlias, NextHop, RouteMetric
Get-DnsClientServerAddress -AddressFamily IPv4 |
    Where-Object ServerAddresses | Select-Object InterfaceAlias, ServerAddresses
(Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings').ProxyEnable
```

在 **VPS** 核对现有监听端口、物理默认路由、转发和防火墙。托管平台的入站防火墙和 Ubuntu 的防火墙是两层独立设置。若平台已启用入站过滤，保留目前可用的 SSH TCP 规则，并按自己选择的端口允许 WireGuard UDP。变更后另开一个 SSH 窗口验证管理入口。使用已有防火墙、Docker 转发或其他 VPN 的 VPS 需要先规划规则共存，见[服务器适用条件](../server/README.md)。[Ubuntu 防火墙说明](https://documentation.ubuntu.com/security/security-features/network/firewall/)

```bash
ip -br address
ip -4 route show default
ss -lntu
sysctl net.ipv4.ip_forward
command -v nft >/dev/null && nft list ruleset
```

SSH 偶尔中断时，在重连后用 `uptime -s`、`journalctl --list-boots` 和 `journalctl -u ssh --since '30 minutes ago'` 区分 VPS 重启、服务退出和网络中断。较慢的安装可在 `tmux new -As rn-setup` 中执行，重连后用 `tmux attach -t rn-setup` 回到同一任务。服务器的 `stage` 与 `commit` 按[服务器指南](../server/README.md)在各自的独立公网 SSH 会话执行。
