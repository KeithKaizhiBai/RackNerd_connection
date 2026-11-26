#Requires -Version 5.1
# Pure presentation helpers. No network or privileged operations.
function Protect-RnFailureText([string]$Text) {
    if($Text.Length -gt 8192){$Text=$Text.Substring(0,8192)}
    $Text=$Text -replace '(?s)-----BEGIN .*?PRIVATE KEY-----.*','[private key removed]'
    $Text=$Text -replace '(?i)(?:[A-Z]:[\\/]|\\\\)[^\r\n"<>|]*','[local path]'
    $Text=$Text -replace '\b(?:\d{1,3}\.){3}\d{1,3}\b','[IP]'
    $Text=$Text -replace '(?i)(?<!\w)(?:[a-f0-9]{0,4}:){2,}[a-f0-9:.%]*','[IPv6]'
    $Text=$Text -replace 'S-1-5-21-(?:\d+-)*\d+','[user]'
    $Text=$Text -replace '(?i)["'']?(?:PrivateKey|PresharedKey|password|token)["'']?\s*[=:]\s*(?:"(?:\\.|[^"\\\r\n])*(?:"|$)|''(?:\\.|[^''\\\r\n])*(?:''|$)|[^\s,;}]+)','[credential redacted]'
    $Text=$Text -replace '(?i)(https?://)[^\s/:@]+:[^\s/@]+@','$1[credential]@'
    $Text=$Text -replace '(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43,}={0,2}','[key]'
    $Text=$Text -replace '[\x00-\x08\x0b\x0c\x0e-\x1f]',' '
    if($Text.Length -gt 700){$Text=$Text.Substring(0,700)+'…'}
    return $Text.Trim()
}

function Get-RnFailureInfo([string]$Message) {
    $code='Unknown';$reason='操作发生错误。';$help='查看下方错误详情。若线路未恢复，点击“返回原网络”，再检查本机诊断日志。'
    switch -Regex ($Message) {
        'Endpoint route creation was not confirmed|Endpoint route adapter identity is ambiguous during recovery' {
            $code='Recovery';$reason='无法确认端点路由归属，已保留该路由；恢复状态需要核验。';$help='检查 VPS 端点现有的 /32 路由和本次会话状态。确认其创建来源后再处理，不要删除其他软件的路由。';break
        }
        'Cleanup failed|recovery.*fail|restor.*fail|still present|still needs rollback|restoration failed|Resolver settings changed externally|flags differ' {
            $code='Recovery';$reason='恢复相关操作报错，最终状态需要核验。';$help='先查看当前线路，再点击“返回原网络”确认恢复，使用最初连接时的 Windows 账户操作。确认恢复后再开启其他 TUN。';break
        }
        'Xray TUN|VPN or TUN|virtual network is active|active VPN|competing VPN' {
            $code='Tun';$reason='其他 VPN 或 TUN 正在占用网络。';$help='先在 v2rayN 或对应 VPN 客户端中关闭 TUN/断开连接，再点击连接 RackNerd。';break
        }
        'Windows endpoint route.*(failed|ambiguous|incomplete|disconnected|no usable)|unambiguous physical|default gateway' {
            $code='Gateway';$reason='Windows 未能确定可用的 VPS 物理出口。';$help='确认以太网或 WLAN 的 IPv4 已连接。两张物理网卡可以同时在线，工具会采用 Windows 实际选路；等待网络稳定后重试。旧版单网关提示需要更新控制器。';break
        }
        'endpoint route changed|endpoint route points to a local' {
            $code='Route';$reason='VPS 端点路径在切换中发生变化，或配置指向本机。';$help='先返回原网络，核对 VPS 地址，待网卡连接和地址稳定后重试。工具不会替换现有路由，也不会切换其他 VPN。';break
        }
        'specific endpoint route|half-default|/1 routes|routed prefixes|route.*lost|Unexpected route|management endpoint|Tunnel identity' {
            $code='Route';$reason='现有路由或隧道与本次连接冲突。';$help='先点击“返回原网络”，确认其他 VPN 已退出，再重试。仍失败时检查相关路由和隧道状态。';break
        }
        'DNS policy|DNS-over-HTTPS|native.*DNS|Resolve-DnsName|Resolver template' {
            $code='Dns';$reason='系统 DNS 检查失败。';$help='确认其他 TUN 已关闭，然后恢复原网络并重试。若设备由单位管理，请核对现有 DNS 策略。';break
        }
        'no-proxy IPv4 exit|public.*IP.*verif' {
            $code='Exit';$reason='无法确认互联网流量已从 VPS 出口发出。';$help='检查本机网络和 WireGuard 握手，再核对端点、UDP 端口及 VPS 转发状态。出口检测服务暂时不可达时可稍后重试。';break
        }
        'handshake' {
            $code='Handshake';$reason='未检测到预期服务器的有效握手。';$help='核对两端公钥、端点和 UDP 端口，检查当前网络是否可达服务器。';break
        }
        'WireGuard startup|Timed out waiting|SCM|service.*start|Start failed|manual service' {
            $code='Service';$reason='本机 WireGuard 服务未能就绪。';$help='点击“返回原网络”后重试，检查官方 WireGuard 是否正常安装，以及是否有其他隧道占用。';break
        }
        'session is still open|No session state|Stale recovery|Local recovery requested|being used by another process' {
            $code='Session';$reason='上一次切换或恢复仍未完成。';$help='等待正在进行的操作结束，点击“返回原网络”确认恢复，再重新连接。';break
        }
        'trial|qualification|qualified|rehears|verified real application|Run Test and restore' {
            $code='Trial';$reason='首次试用或恢复验证尚未完成。';$help='先选择“试用 15 分钟”，核验出口和应用，再点击“返回原网络”。验证通过后使用日常连接。';break
        }
        'SSH session' {
            $code='Ssh';$reason='检测到正在使用的公网 SSH 管理连接。';$help='先完成并退出该 SSH 会话，再切换上网线路。';break
        }
        'signature|publisher|encrypted.*configuration|public.*key|profile.*missing|setup record|public.json|unsafe|ownership|owner|permissions|Access.*denied|拒绝访问|UnauthorizedAccess' {
            $code='Setup';$reason='本机配置、签名或权限检查失败。';$help='核对官方 WireGuard 安装和受保护的连接工具文件，使用同一桌面管理员账户操作。保留现有密钥，再根据下方错误修复。';break
        }
        'firewall' {
            $code='Firewall';$reason='Windows 防火墙检查未通过。';$help='检查系统防火墙是否正常运行，以及设备策略是否允许本工具的规则。';break
        }
    }
    [pscustomobject]@{Code=$code;Reason=$reason;Help=$help;Detail=(Protect-RnFailureText $Message)}
}

function Invoke-RnPanelOperation([scriptblock]$Operation) {
    try { & $Operation | Out-Null; [pscustomobject]@{Success=$true;Failure=$null} }
    catch { [pscustomobject]@{Success=$false;Failure=(Get-RnFailureInfo $_.Exception.Message)} }
}

function Read-RnPanelResult([string]$Base,[string]$RequestId,[string]$Action,[datetime]$Started,[int]$ExitCode) {
    try {
        if($RequestId -cnotmatch '^[a-f0-9]{32}$'){throw 'Invalid request'}
        $path=Join-Path (Join-Path $Base 'PanelResults') ($RequestId+'.json')
        $item=Get-Item -LiteralPath $path -ErrorAction Stop
        if($item.Length -gt 16384 -or $item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Invalid result file'}
        $r=[IO.File]::ReadAllText($path) | ConvertFrom-Json -ErrorAction Stop
        $at=if($r.At -is [datetime]){$r.At.ToUniversalTime()}else{([datetimeoffset]::Parse([string]$r.At)).UtcDateTime}
        if($r.RequestId -cne $RequestId -or $r.Action -cne $Action -or $r.Success -isnot [bool] -or
            $at -lt $Started.ToUniversalTime().AddSeconds(-2) -or $at -gt [datetime]::UtcNow.AddSeconds(10)) {throw 'Stale or invalid result'}
        if($r.Success -and $ExitCode -ne 0){throw 'Inconsistent exit'}
        if(-not $r.Success -and (-not $r.Failure.Reason -or -not $r.Failure.Help)){throw 'Incomplete error'}
        return $r
    } catch {
        [pscustomobject]@{Success=$false;Failure=[pscustomobject]@{Code='ResultMissing';Reason='未收到本次操作的完整结果。';Help='先查看当前线路。核对是否已更新面板和安装目录中的反馈组件；若线路异常，点击“返回原网络”。';Detail=('进程退出码 '+$ExitCode)}}
    }
}

function Format-RnFailure($Failure) {
    return ($Failure.Reason+"`r`n处理方法　"+$Failure.Help+"`r`n错误详情　"+$Failure.Detail)
}
