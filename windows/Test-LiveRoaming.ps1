#Requires -Version 5.1
# Observe a user's Ethernet unplug/replug while an existing gateway session keeps running.
# This script queries state and sends bounded public requests. It does not change adapters or routes.
[CmdletBinding()]
param(
    [ValidateRange(30,600)][int]$TransitionTimeoutSeconds=180,
    [ValidateRange(15,90)][int]$InternetTimeoutSeconds=40,
    [switch]$SelfTest
)
$ErrorActionPreference='Stop'

function Assert-RoamingIdentity($Expected,$Actual) {
    if($Actual.Session -cne $Expected.Session -or $Actual.Process -ne $Expected.Process -or
       $Actual.Started -cne $Expected.Started -or -not $Actual.Running){
        throw 'WireGuard 服务进程或控制器会话已变化，本次连续性验收未通过。'
    }
}
function Invoke-InternetCheck([guid[]]$Allowed,[string]$Phase) {
    $deadline=[datetime]::UtcNow.AddSeconds($InternetTimeoutSeconds)
    $lastFailure='尚未取得成功的联网样本。'
    do {
        # A restarted service or changed session fails immediately, outside network retries.
        Assert-RoamingIdentity $script:initialIdentity (Read-RoamingIdentity)
        $succeeded=$false
        try{Test-InternetAttempt $Allowed $deadline;$succeeded=$true}
        catch{$lastFailure=Protect-RnFailureText $_.Exception.Message}
        Assert-RoamingIdentity $script:initialIdentity (Read-RoamingIdentity)
        if($succeeded){
            Write-Host ($Phase+'通过。会话和进程保持连续，新收发流量、公网出口、请求源、DNS 和 HTTPS 均已核验。')
            return
        }
        if([datetime]::UtcNow -ge $deadline){break}
        Write-Host ($Phase+'等待网络稳定后重试。'+$lastFailure)
        Start-Sleep -Seconds 2
    }while([datetime]::UtcNow -lt $deadline)
    throw ($Phase+'联网核验超时。'+$lastFailure)
}

if($SelfTest){
    & {
        $script:initialIdentity=[pscustomobject]@{Session='offline';Process=123;Started='2026-01-01';Running=$true}
        $script:attempts=0; $script:identityReads=0; $script:replaceProcess=$false
        function Read-RoamingIdentity {
            $script:identityReads++
            $value=$script:initialIdentity.PSObject.Copy()
            if($script:replaceProcess -and $script:identityReads -ge 2){$value.Process=124}
            return $value
        }
        function Test-InternetAttempt {
            $script:attempts++
            if($script:attempts -eq 1){throw 'Synthetic negotiation delay'}
        }
        function Protect-RnFailureText([string]$Text){$Text}
        function Start-Sleep {}
        function Write-Host {}
        Invoke-InternetCheck @([guid]'00000000-0000-0000-0000-000000000021') 'Offline'
        if($script:attempts -ne 2){throw 'Transient connectivity failure was not retried.'}
        $script:attempts=0; $script:identityReads=0; $script:replaceProcess=$true
        $rejected=$false
        try{Invoke-InternetCheck @([guid]'00000000-0000-0000-0000-000000000021') 'Offline'}catch{$rejected=$true}
        if(-not $rejected -or $script:attempts -ne 1){throw 'A changed process was incorrectly treated as a retryable network failure.'}
    }
    'PASS: transient failures retry; service/session continuity is checked outside retries.'
    return
}

$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if(-not [Environment]::Is64BitProcess -or -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    throw '请使用最初连接时的桌面账户打开 64 位管理员 Windows PowerShell。'
}
. (Join-Path $PSScriptRoot 'Gateway-Common.ps1')
. (Join-Path $PSScriptRoot 'Gateway-Feedback.ps1')
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'gui\Gateway-Status.ps1')
$base=Get-RnPackageRoot
$controller=Join-Path $base 'Gateway-Mode.ps1'
$wg=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'WireGuard\wg.exe'
$curl=Join-Path ([Environment]::SystemDirectory) 'curl.exe'
$script:configuration=Get-RnSettings

function Read-RoamingIdentity {
    $state=@(& $controller -Action Status | Where-Object Id)
    $service=@(Get-CimInstance Win32_Service -Filter 'Name="WireGuardTunnel$rn-public"' -ErrorAction Stop)
    if($state.Count -ne 1 -or $state[0].Mode -notin 'Test','RackNerd' -or
       $state[0].MachineRestored -or $state[0].UserRestored -or $service.Count -ne 1 -or
       $service[0].State -ne 'Running' -or $service[0].ProcessId -le 0){
        throw '请先在面板启用更新后的网关，并等到连接核验通过。'
    }
    $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$service[0].ProcessId) -ErrorAction Stop
    [pscustomobject]@{Session=$state[0].Id;Process=[int]$service[0].ProcessId;Started=$process.CreationDate.ToUniversalTime().ToString('o');Running=$true}
}
function Read-PhysicalPath {
    $sample=Get-RnLocalPath $script:configuration
    if(-not $sample.Both -or -not $sample.HasSource -or -not $sample.PhysicalEndpoint -or
       $sample.OtherTun -or -not $sample.Direct){
        throw '当前隧道路由、物理出口或系统代理尚未满足漫游条件。'
    }
    $answer=@(Find-NetRoute -RemoteIPAddress $script:configuration.Endpoint -ErrorAction Stop)
    $routes=@($answer | Where-Object DestinationPrefix)
    $sources=@($answer | Where-Object IPAddress)
    if($routes.Count -ne 1 -or $sources.Count -ne 1 -or $routes[0].InterfaceIndex -ne $sources[0].InterfaceIndex){
        throw 'Windows 当前物理出口与源地址不明确。'
    }
    $adapter=@(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object ifIndex -eq $routes[0].InterfaceIndex)
    if($adapter.Count -ne 1 -or $adapter[0].Status -ne 'Up'){throw 'Windows 选中的物理网卡尚未连接。'}
    [pscustomobject]@{Guid=[guid]$adapter[0].InterfaceGuid;Type=$adapter[0].InterfaceType}
}
function Read-PeerTraffic {
    $handshakes=@(& $wg show rn-public latest-handshakes 2>$null)
    if($LASTEXITCODE -ne 0 -or $handshakes.Count -ne 1){throw '无法读取 WireGuard 握手状态。'}
    $times=@($handshakes[0] -split '\s+')
    $transfers=@(& $wg show rn-public transfer 2>$null)
    if($LASTEXITCODE -ne 0 -or $transfers.Count -ne 1){throw '无法读取 WireGuard 收发计数。'}
    $counts=@($transfers[0] -split '\s+')
    if($times.Count -ne 2 -or $counts.Count -ne 3){throw 'WireGuard 对端统计格式异常。'}
    [pscustomobject]@{Handshake=[long]$times[1];Received=[long]$counts[1];Sent=[long]$counts[2]}
}
function Get-RequestTimeout([datetime]$Deadline) {
    $remaining=[int][math]::Floor(($Deadline-[datetime]::UtcNow).TotalSeconds)
    if($remaining -lt 1){throw '本阶段联网核验时间已用完。'}
    return [math]::Min(7,$remaining)
}
function Test-InternetAttempt([guid[]]$Allowed,[datetime]$Deadline) {
    if((Read-PhysicalPath).Guid -notin $Allowed){throw '物理线路仍在切换。'}
    $before=Read-PeerTraffic
    $dns=@(Resolve-DnsName www.python.org -Type A -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object IPAddress)
    if(-not $dns.Count){throw 'Windows DNS 尚未返回 IPv4 结果。'}
    $publicVerified=$false
    foreach($url in 'https://api.ipify.org','https://ipv4.icanhazip.com'){
        $seconds=Get-RequestTimeout $Deadline
        $response=@(& $curl --disable --noproxy '*' --ipv4 --silent --fail --connect-timeout 3 --max-time $seconds --max-filesize 1024 --write-out '\n%{local_ip}' $url 2>$null)
        if($LASTEXITCODE -ne 0){continue}
        $fields=@($response | ForEach-Object {$_.Trim()} | Where-Object {$_})
        if($fields.Count -eq 2 -and $fields[0] -ceq $script:configuration.Endpoint -and $fields[1] -ceq $script:RnClientAddress){
            $publicVerified=$true;break
        }
    }
    if(-not $publicVerified){throw '公网出口或隧道请求源尚未核验通过。'}
    $seconds=Get-RequestTimeout $Deadline
    $http=& $curl --disable --noproxy '*' --ipv4 --silent --connect-timeout 3 --max-time $seconds --output NUL --write-out '%{http_code}' https://pypi.org/robots.txt 2>$null
    if($LASTEXITCODE -ne 0 -or "$http" -cne '200'){throw 'PyPI HTTPS 请求暂未成功。'}
    $after=Read-PeerTraffic
    $now=[datetimeoffset]::UtcNow.ToUnixTimeSeconds()
    if($after.Handshake -lt $before.Handshake -or $after.Handshake -gt $now -or $now-$after.Handshake -gt 180 -or
       $after.Received -le $before.Received -or $after.Sent -le $before.Sent){
        throw '尚未确认近期握手和新的双向 WireGuard 流量。'
    }
    if((Read-PhysicalPath).Guid -notin $Allowed){throw '物理线路在联网检查期间再次变化。'}
}
function Wait-PhysicalPath([guid[]]$Allowed,[string]$Phase) {
    $deadline=[datetime]::UtcNow.AddSeconds($TransitionTimeoutSeconds)
    $lastFailure='Windows 尚未选择预期网卡。'
    do {
        Assert-RoamingIdentity $script:initialIdentity (Read-RoamingIdentity)
        try{if((Read-PhysicalPath).Guid -in $Allowed){return}}
        catch{$lastFailure=Protect-RnFailureText $_.Exception.Message}
        Start-Sleep -Seconds 2
    }while([datetime]::UtcNow -lt $deadline)
    throw ($Phase+'超时。'+$lastFailure)
}

try{
    if($script:configuration.State -ne 'Ready'){throw '请先运行 Install-Client.ps1 配置自己的 VPS。'}
    Assert-RnProtectedPath $controller
    $script:initialIdentity=Read-RoamingIdentity
    $initial=Read-PhysicalPath
    if($initial.Type -ne 6){throw '开始测试时，Windows 到 VPS 的当前出口应为有线网卡。'}
    $connected=@(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop | Where-Object ConnectionState -eq 'Connected')
    $defaults=@(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop | Where-Object DestinationPrefix -eq '0.0.0.0/0')
    $wifi=@(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object {
        $_.InterfaceType -eq 71 -and $_.Status -eq 'Up' -and $_.ifIndex -in $connected.InterfaceIndex -and $_.ifIndex -in $defaults.InterfaceIndex
    } | ForEach-Object {[guid]$_.InterfaceGuid})
    if(-not $wifi.Count){throw '请先连接可用的 Wi-Fi IPv4 网络。'}
    Invoke-InternetCheck @($initial.Guid) '初始有线线路'
    Write-Host '请拔下当前有线网线，保持 WireGuard 连接。'
    Wait-PhysicalPath $wifi '切换到 Wi-Fi'
    Invoke-InternetCheck $wifi 'Wi-Fi 接续'
    Write-Host '请重新插入网线，等待 Windows 重新选路。'
    Wait-PhysicalPath @($initial.Guid) '回到初始有线线路'
    Invoke-InternetCheck @($initial.Guid) '有线回切'
    Write-Host '验收通过。三阶段使用同一 WireGuard 会话和进程。'
}catch{
    Write-Host ('验收未通过。'+(Protect-RnFailureText $_.Exception.Message))
    Write-Host '请确认网线已插回，查看面板当前状态。需要恢复时选择“返回原网络”。'
    exit 1
}
