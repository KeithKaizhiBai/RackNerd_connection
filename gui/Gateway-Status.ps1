#requires -Version 5.1
# Shared by the graphical panel and its read-only Status command.
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'windows\Gateway-Routes.ps1')
$script:RnInstallRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'RackNerd-Connection'
$script:RnTunnelName = 'rn-public'
$script:RnClientAddress = '10.203.84.2'

function Test-RnIPv4Literal([string]$Value) {
    $ip = $null
    [ipaddress]::TryParse($Value, [ref]$ip) -and
        $ip.AddressFamily -eq 'InterNetwork' -and $ip.ToString() -ceq $Value
}

function Get-RnSettings([string]$Path = (Join-Path $script:RnInstallRoot 'public.json')) {
    try {
        $text = [IO.File]::ReadAllText($Path)
    } catch [IO.FileNotFoundException] {
        return [pscustomobject]@{State='Missing'; Endpoint=$null}
    } catch [IO.DirectoryNotFoundException] {
        return [pscustomobject]@{State='Missing'; Endpoint=$null}
    } catch {
        return [pscustomobject]@{State='Unreadable'; Endpoint=$null}
    }
    try {
        $endpoint = ($text | ConvertFrom-Json -ErrorAction Stop).EndpointIPv4
        if ($endpoint -isnot [string] -or -not (Test-RnIPv4Literal $endpoint)) {
            throw 'EndpointIPv4 must be a dotted-decimal IPv4 address.'
        }
        return [pscustomobject]@{State='Ready'; Endpoint=$endpoint}
    } catch {
        return [pscustomobject]@{State='Invalid'; Endpoint=$null}
    }
}

function Get-RnProxyFlags {
    # WinINet (current user's LAN/default connection). Request only flags. A PAC
    # URL, proxy address, bypass list or credentials never leave the provider.
    if (-not ('RackNerd.Connection.PanelProxy' -as [type])) {
        Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace RackNerd.Connection {
    public static class PanelProxy {
        [StructLayout(LayoutKind.Explicit)] struct Value {
            [FieldOffset(0)] public uint Flags;
            [FieldOffset(0)] public IntPtr Pointer;
            [FieldOffset(0)] public System.Runtime.InteropServices.ComTypes.FILETIME FileTime;
        }
        [StructLayout(LayoutKind.Sequential)] struct Option { public uint Id; public Value Value; }
        [StructLayout(LayoutKind.Sequential)] struct OptionList {
            public uint Size; public IntPtr Connection; public uint Count, Error; public IntPtr Options;
        }
        [DllImport("wininet.dll", ExactSpelling=true, SetLastError=true)]
        static extern bool InternetQueryOptionW(IntPtr h, uint opt, ref OptionList list, ref uint size);
        static uint Read(uint id) {
            OptionList list = new OptionList();
            list.Size = (uint)Marshal.SizeOf(typeof(OptionList));
            list.Count = 1;
            list.Options = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Option)));
            try {
                Option option = new Option(); option.Id = id;
                Marshal.StructureToPtr(option, list.Options, false);
                uint size = list.Size;
                if (!InternetQueryOptionW(IntPtr.Zero, 75, ref list, ref size))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return ((Option)Marshal.PtrToStructure(list.Options, typeof(Option))).Value.Flags;
            } finally { Marshal.FreeHGlobal(list.Options); }
        }
        public static uint CurrentFlags() {
            try { return Read(10); } // INTERNET_PER_CONN_FLAGS_UI
            catch (Win32Exception e) {
                if (e.NativeErrorCode != 12009 && e.NativeErrorCode != 87 && e.NativeErrorCode != 50) throw;
                return Read(1); // compatibility with systems supporting only INTERNET_PER_CONN_FLAGS
            }
        }
    }
}
'@
    }
    return [int][RackNerd.Connection.PanelProxy]::CurrentFlags()
}

function Get-RnProxyText($Flags) {
    if ($null -eq $Flags -or $Flags -lt 1 -or $Flags -gt 15) { return '未知' }
    if ($Flags -eq 1) { return '直连' }
    $modes = @(
        if ($Flags -band 2) { '手动代理' }
        if ($Flags -band 4) { '代理脚本' }
        if ($Flags -band 8) { '自动检测' }
    )
    return ($modes -join '、')
}

function Get-RnLocalPath($Settings) {
    $now = [datetime]::Now
    if ($Settings.State -ne 'Ready') {
        return [pscustomobject]@{Key=$Settings.State; At=$now; Config=$Settings.State; Route='—'; Proxy='—'}
    }

    $interfaces = @(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object ConnectionState -eq 'Connected')
    $allRoutes = @(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop)
    $routes = @($allRoutes | Where-Object { $_.InterfaceIndex -in $interfaces.InterfaceIndex -and
        $_.DestinationPrefix -notmatch ':' })
    $used = @()
    $identity = @($Settings.Endpoint)
    $adapters = @(Get-NetAdapter -ErrorAction Stop)
    $physical = @($adapters | Where-Object { $_.HardwareInterface -and $_.Status -eq 'Up' -and
        $_.ifIndex -in $interfaces.InterfaceIndex })
    $tunnel = $adapters | Where-Object Name -eq $script:RnTunnelName | Select-Object -First 1
    $serviceName = 'WireGuardTunnel$' + $script:RnTunnelName
    $service = Get-Service -Name 'WireGuardTunnel$*' -ErrorAction Stop |
        Where-Object Name -eq $serviceName | Select-Object -First 1
    $serviceState = if ($service) { [string]$service.Status } else { 'Absent' }
    $source = $false
    if ($tunnel -and $tunnel.Status -eq 'Up') {
        $addresses = @(Get-NetIPAddress -InterfaceIndex $tunnel.ifIndex -AddressFamily IPv4 -ErrorAction Stop)
        $source = [bool]($addresses | Where-Object { $_.IPAddress -eq $script:RnClientAddress -and
            $_.AddressState -eq 'Preferred' -and -not $_.SkipAsSource })
    }

    # Both halves still belong to the peer's AllowedIPs. Their Windows routes
    # exclude one address so ordinary SSH and outer UDP can follow Windows uplink changes.
    $both = Test-RnRoamingRoutes -Endpoint $Settings.Endpoint -TunnelName $script:RnTunnelName
    $targets = @('1.1.1.1', '9.9.9.9', '208.67.222.222') | Where-Object { $_ -ne $Settings.Endpoint }
    foreach ($target in $targets) {
        $answer = @(Find-NetRoute -RemoteIPAddress $target -ErrorAction Stop)
        $chosen = @($answer | Where-Object DestinationPrefix)
        $chosenSource = @($answer | Where-Object IPAddress)
        $used += @($chosen | ForEach-Object InterfaceAlias)
        foreach ($r in $chosen) { $identity += @($target, $r.DestinationPrefix, $r.InterfaceIndex, $r.NextHop, $r.RouteMetric) }
        foreach ($s in $chosenSource) { $identity += @($s.InterfaceIndex, $s.IPAddress, $s.AddressState, $s.SkipAsSource) }
        if ($chosen.Count -ne 1 -or $chosenSource.Count -ne 1 -or -not $tunnel -or
            $chosen[0].InterfaceIndex -ne $tunnel.ifIndex -or $chosen[0].InterfaceAlias -ne $script:RnTunnelName -or
            $chosenSource[0].InterfaceIndex -ne $tunnel.ifIndex -or $chosenSource[0].IPAddress -ne $script:RnClientAddress -or
            $chosenSource[0].AddressState -ne 'Preferred' -or $chosenSource[0].SkipAsSource -ne $false) { $both = $false }
    }

    $endpointAnswer = @(Find-NetRoute -RemoteIPAddress $Settings.Endpoint -ErrorAction Stop)
    $endpointRoutes = @($endpointAnswer | Where-Object DestinationPrefix)
    $endpointSources = @($endpointAnswer | Where-Object IPAddress)
    $endpoint = if ($endpointRoutes.Count -eq 1) { $endpointRoutes[0] } else { $null }
    $endpointSource = if ($endpointSources.Count -eq 1) { $endpointSources[0] } else { $null }
    # A leftover or externally supplied endpoint /32 must not masquerade as a
    # roaming route. Enumerate both stores without an IPv4 provider filter.
    $endpointPrefix = $Settings.Endpoint + '/32'
    $persistentRoutes = @(Get-NetRoute -PolicyStore PersistentStore -ErrorAction Stop)
    $hasPin = [bool](@($allRoutes + $persistentRoutes) | Where-Object DestinationPrefix -eq $endpointPrefix)
    $physicalEndpoint = $endpoint -and $endpointSource -and
        -not $hasPin -and $endpoint.DestinationPrefix -ne $endpointPrefix -and
        $endpoint.InterfaceIndex -in $physical.ifIndex -and $endpointSource.InterfaceIndex -eq $endpoint.InterfaceIndex -and
        $endpointSource.AddressState -eq 'Preferred' -and $endpointSource.SkipAsSource -eq $false -and
        (Test-RnIPv4Literal ([string]$endpointSource.IPAddress)) -and
        (Test-RnIPv4Literal ([string]$endpoint.NextHop)) -and $endpointSource.IPAddress -ne $Settings.Endpoint
    $endpointAdapter = @($physical | Where-Object ifIndex -eq $endpoint.InterfaceIndex)
    if ($endpointAdapter.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$endpointAdapter[0].InterfaceGuid)) { $physicalEndpoint=$false }
    $used = @($used | Select-Object -Unique)
    $otherTun = [bool]($adapters | Where-Object {
        $driver = $_.Name + ' ' + $_.InterfaceDescription
        $knownTunnel = $driver -match 'xray_tun|wintun|wireguard|openvpn|tap-windows|tailscale|zerotier'
        $tunnelRoute = $_.Name -in $routes.InterfaceAlias -and $_.InterfaceType -in 23, 53, 131
        $_.Status -eq 'Up' -and $_.Name -ne $script:RnTunnelName -and ($knownTunnel -or $tunnelRoute)
    })
    try { $flags = Get-RnProxyFlags } catch { $flags = $null }
    $hasGateway = ($tunnel -and $tunnel.Status -eq 'Up') -or
        ($service -and $service.Status -ne 'Stopped') -or $script:RnTunnelName -in $used
    $identity += @($serviceState, $flags, $hasGateway, $both, $source, $physicalEndpoint, $otherTun, $hasPin,
        $endpoint.InterfaceIndex, $endpoint.DestinationPrefix, $endpoint.NextHop, $endpointSource.IPAddress,
        $endpointAdapter.InterfaceGuid, $endpointRoutes.Count, $endpointSources.Count)
    $routeText = $used -join ' / '
    if ($hasGateway -and $physicalEndpoint) { $routeText += ' → ' + $endpointAdapter[0].Name }
    [pscustomobject]@{
        Key=($identity -join '|'); At=$now; Config='Ready'; Endpoint=$Settings.Endpoint
        Service=$serviceState; HasGateway=$hasGateway; Both=$both; HasSource=$source
        PhysicalEndpoint=[bool]$physicalEndpoint; OtherTun=$otherTun; Direct=($flags -eq 1)
        Proxy=(Get-RnProxyText $flags); Route=$routeText
    }
}

function Get-RnPublicProbe([string]$Key) {
    $curl = Join-Path ([Environment]::SystemDirectory) 'curl.exe'
    $ip = $null
    $source = $null
    if (Test-Path -LiteralPath $curl -PathType Leaf) {
        foreach ($url in 'https://api.ipify.org', 'https://ipv4.icanhazip.com') {
            $response = @(& $curl --disable --noproxy '*' --ipv4 --fail --silent --connect-timeout 4 --max-time 6 --max-filesize 1024 --write-out '\n%{local_ip}' $url)
            if ($LASTEXITCODE -ne 0) { continue }
            $fields = @($response | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
            if ($fields.Count -eq 2 -and (Test-RnIPv4Literal $fields[0]) -and (Test-RnIPv4Literal $fields[1])) {
                $ip=$fields[0]; $source=$fields[1]; break
            }
        }
    }
    [pscustomobject]@{Key=$Key; At=[datetime]::Now; Ip=$ip; Source=$source}
}

function Get-RnPanelSample([bool]$Verify) {
    try {
        $localPath = Get-RnLocalPath (Get-RnSettings)
        $check = $null
        if ($Verify -and $localPath.Config -eq 'Ready') {
            $check = Get-RnPublicProbe $localPath.Key
            $localPath = Get-RnLocalPath (Get-RnSettings)
            if ($check.Key -ne $localPath.Key) { $check=$null }
        }
        [pscustomobject]@{Local=$localPath; Check=$check; ErrorText=$null}
    } catch {
        [pscustomobject]@{Local=$null; Check=$null; ErrorText='无法读取 Windows 当前的 IPv4 网络状态。'}
    }
}

function Get-RnPanelView($Local, $Check) {
    if (-not $Local) {
        return [pscustomobject]@{Kind='Unknown'; Title='无法读取当前线路'; Hint='请确认 Windows 网络可用，面板会自动重试。'; Ip='未知'; Checked='—'}
    }
    if ($Local.Config -ne 'Ready') {
        $title = if ($Local.Config -eq 'Missing') { '尚未安装客户端配置' } else { '客户端配置无法读取' }
        $hint = if ($Local.Config -eq 'Missing') { '请先按 README 运行 windows\Install-Client.ps1 配置自己的 VPS。' }
            else { '请检查安装目录中的 public.json 和 EndpointIPv4，必要时重新运行安装程序。' }
        return [pscustomobject]@{Kind='Setup'; Title=$title; Hint=$hint; Ip='—'; Checked='—'}
    }
    if ($Check) {
        $age = ([datetime]::Now - $Check.At).TotalSeconds
        if ($Check.Key -ne $Local.Key -or $age -gt 75 -or $age -lt 0) { $Check=$null }
    }
    $ip = if (-not $Check) { '等待核验' } elseif ($Check.Ip) { $Check.Ip } else { '检测超时或失败' }
    $checked = if ($Check) { $Check.At.ToString('HH:mm:ss') } else { '—' }
    if (-not $Local.HasGateway) {
        $kind='Off'; $title='正在使用原网络'
        $hint = if ($Local.OtherTun) { '切换前请先关闭正在使用的其他 TUN 或 VPN。' }
            else { '首次使用请先试用并恢复，通过检查后可使用「连接」。' }
    } elseif ($Local.Service -ne 'Running' -or -not $Local.Both -or -not $Local.HasSource -or -not $Local.PhysicalEndpoint) {
        $kind='Warning'; $title='全隧道线路不完整'; $hint='请检查隧道服务、客户端 IPv4 和 VPS 端点路由。'
    } elseif ($Local.OtherTun -or -not $Local.Direct) {
        $kind='Warning'; $title='隧道已启用，请检查代理'; $hint='请检查 Windows 系统代理和其他 TUN 的设置。'
    } elseif (-not $Check -or -not $Check.Ip) {
        $kind='Pending'; $title='隧道已启用，出口待确认'; $hint='可点「核验出口」重新检测。'
    } elseif ($Check.Ip -ne $Local.Endpoint -or $Check.Source -ne $script:RnClientAddress) {
        $kind='Warning'; $title='实测出口与配置不符'; $hint='实测公网 IPv4 或请求源地址与客户端配置不符。'
    } else {
        $kind='Verified'; $title='已连接 RackNerd'; $hint='普通 IPv4 流量经 WireGuard，公网出口已验证。'
    }
    [pscustomobject]@{Kind=$kind; Title=$title; Hint=$hint; Ip=$ip; Checked=$checked}
}
