#Requires -Version 5.1
# Run the protected installed copy in native Windows PowerShell.
[CmdletBinding()]
param([ValidateSet('Test','RackNerd','Original','Status','MachineUndo','UserUndo')][string]$Action='Status',[string]$Id)
$ErrorActionPreference='Stop'
if ($PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess) { throw 'Use native Windows PowerShell 5.1.' }
$base=Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'RackNerd-Connection'
$installed=Join-Path $base 'Gateway-Mode.ps1'
if ($PSCommandPath -ine $installed) { throw "Use the installed controller: $installed" }
. (Join-Path $base 'Gateway-Common.ps1')
$cfg=Get-RnPublicMetadata $base
$endpoint=$cfg.EndpointIPv4
$endpointPrefix=$endpoint+'/32'
$psExe=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($Action -eq 'Status' -and -not $admin) {
    $s=Get-Service -Name 'WireGuardTunnel$rn-public' -ErrorAction SilentlyContinue
    [pscustomobject]@{Tunnel='rn-public';Service=if($s){[string]$s.Status}else{'Absent'};EndpointIPv4=$endpoint;Port=$cfg.Port}
    return
}
if (-not $admin) {throw 'Use an elevated local Windows PowerShell under the signed-in desktop account.'}
$store=Join-Path $base 'State'
Assert-RnProtectedPath $store -Private
foreach ($helper in 'Gateway-Mode.ps1','Gateway-Service.ps1','Gateway-WinInet.ps1','Gateway-Routes.ps1') {Assert-RnProtectedPath (Join-Path $base $helper)}
. (Join-Path $base 'Gateway-WinInet.ps1')
. (Join-Path $base 'Gateway-Service.ps1')
. (Join-Path $base 'Gateway-Routes.ps1')
function New-SessionDirectory([string]$path) {
    if(Test-Path -LiteralPath $path){throw 'Unexpected state directory collision'}
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)')
    ([IO.DirectoryInfo]$path).Create($acl)
    Assert-RnProtectedPath $path -Private
}
$current=Join-Path $store 'current.id'
function Trace-Line($message){
    [IO.File]::AppendAllText((Join-Path $td 'events.log'),([datetime]::UtcNow.ToString('o')+' '+$message+[Environment]::NewLine))
}
function Mark($name){[IO.File]::WriteAllText((Join-Path $td $name),[datetime]::UtcNow.ToString('o'))}
function Has($name){Test-Path -LiteralPath (Join-Path $td $name)}
function TaskName($role){'RNPublic-'+$role+'-'+$Id}
function NetBaseline {
    $routes=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -PolicyStore ActiveStore | ForEach-Object {"$($_.InterfaceAlias)|$($_.NextHop)|$($_.RouteMetric)"} | Sort-Object)
    $dns=@(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses -and $_.InterfaceAlias -ne 'rn-public'} | ForEach-Object {"$($_.InterfaceAlias)|$($_.ServerAddresses -join ',')"} | Sort-Object)
    [pscustomobject]@{defaults=$routes;dns=$dns}
}
function Register-Recovery($role,$when){
    $task=TaskName $role
    if(Get-ScheduledTask -TaskPath '\' -TaskName $task -ErrorAction SilentlyContinue){throw "Task collision: $task"}
    $arg='-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy RemoteSigned -File "'+$installed+'" -Action '+$role+'Undo -Id '+$Id
    $job=New-ScheduledTaskAction -Execute $psExe -Argument $arg
    $tr=@(New-ScheduledTaskTrigger -Once -At $when)
    if($role -eq 'Machine'){$tr+=New-ScheduledTaskTrigger -AtStartup;$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest}
    else{$tr+=New-ScheduledTaskTrigger -AtLogOn -User $st.UserSid; $principal=New-ScheduledTaskPrincipal -UserId $st.UserSid -LogonType Interactive -RunLevel Highest}
    $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 4) -RestartCount 4 -RestartInterval (New-TimeSpan -Minutes 1)
    Register-ScheduledTask -TaskPath '\' -TaskName $task -Action $job -Principal $principal -Trigger $tr -Settings $settings | Out-Null
    $check=Get-ScheduledTask -TaskPath '\' -TaskName $task
    if($check.State -eq 'Disabled' -or @($check.Actions).Count -ne 1 -or $check.Actions[0].Execute -ine $psExe -or $check.Actions[0].Arguments -cne $arg -or @($check.Triggers).Count -ne 2){throw 'Recovery task verification failed'}
    $expected=if($role -eq 'Machine'){'S-1-5-18'}else{$st.UserSid}
    Assert-RnTaskPrincipal $check.Principal $expected
}
function Remove-OwnTask($role){
    $name=TaskName $role; $t=Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction SilentlyContinue
    if($t){if(@($t.Actions).Count -ne 1 -or $t.Actions[0].Execute -ine $psExe -or $t.Actions[0].Arguments -cne ('-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy RemoteSigned -File "'+$installed+'" -Action '+$role+'Undo -Id '+$Id)){throw 'Recovery task ownership mismatch'}
        $expected=if($role -eq 'Machine'){'S-1-5-18'}else{$st.UserSid}; Assert-RnTaskPrincipal $t.Principal $expected
        try{Unregister-ScheduledTask -TaskPath '\' -TaskName $name -Confirm:$false}
        catch{if(Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction SilentlyContinue){throw}}}
}
function Test-RnTrialQualifies {
    return ($st.Kind -eq 'Test' -and (Has 'gateway.ok') -and (Has 'machine.ok') -and (Has 'user.ok') -and (Has 'baseline.ok'))
}
function Complete-Tasks {
    if ((Has 'machine.ok') -and (Has 'user.ok')) {
        Remove-OwnTask 'Machine'; Remove-OwnTask 'User'
        if (Test-RnTrialQualifies) {
            [IO.File]::WriteAllText((Join-Path $store 'qualified.ok'), $Id)
        }
    }
}
function Open-SessionLock {
    $lock=$null
    $until=[datetime]::UtcNow.AddSeconds(115)
    while(-not $lock){
        try{$lock=[IO.File]::Open((Join-Path $td 'recovery.lock'),'OpenOrCreate','ReadWrite','None')}
        catch [IO.IOException]{if([datetime]::UtcNow -ge $until){throw};Start-Sleep -Milliseconds 300}
    }
    return $lock
}
function GuardedRecovery([bool]$desktop) {
    if ($desktop -and $sid -ne $st.UserSid) { throw 'Use the original signed-in desktop user to restore its proxy.' }
    Mark 'stop.requested'
    $lock=Open-SessionLock
    try {
        if ($desktop){try {UndoMachine} finally {UndoUser}} else {UndoMachine}
        Complete-Tasks
    } finally {$lock.Dispose()}
}
function Get-OwnFirewallRules {
    # Enumerate once with a terminating error: "store unavailable" must never mean "nothing to undo".
    Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object Group -eq $st.Tag
}
function Remove-RnEndpointRoute {
    if(-not (Has 'route.intent') -or
        (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o') -ne $st.Boot) {return}
    $adapter=@(Get-NetAdapter -ErrorAction Stop | Where-Object ifIndex -eq $st.K)
    if($adapter.Count -gt 1) {throw 'Endpoint route adapter identity is ambiguous during recovery.'}
    if(-not $adapter.Count -or [string]$adapter[0].InterfaceGuid -ne $st.AdapterGuid) {return}
    $candidate=@(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {
        $_.DestinationPrefix -eq $endpointPrefix -and $_.InterfaceIndex -eq $st.K -and
        $_.NextHop -eq $st.GW -and $_.RouteMetric -eq $st.RouteMetric
    })
    if(-not $candidate.Count) {return}
    # In older sessions svc.intent was written only after New-NetRoute succeeded.
    # An intent-only record cannot establish ownership, regardless of its version.
    $confirmed=(Has 'route.created') -or ($st.RouteOwnershipVersion -lt 2 -and (Has 'svc.intent'))
    if($candidate.Count -ne 1 -or -not $confirmed) {
        throw 'Endpoint route creation was not confirmed; the existing route was preserved.'
    }
    $candidate | Remove-NetRoute -Confirm:$false
    if(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {
        $_.DestinationPrefix -eq $endpointPrefix -and $_.InterfaceIndex -eq $st.K -and
        $_.NextHop -eq $st.GW -and $_.RouteMetric -eq $st.RouteMetric
    }) {throw 'Endpoint route still present after recovery.'}
}
function UndoMachine{
    if(Has 'machine.ok'){return}
        $issues=@()
        try{if(Has 'svc.intent'){Stop-RnManualTunnel | Out-Null}}catch{$issues+='Service: '+$_.Exception.Message}
        try{foreach($rule in @(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object Comment -eq $st.Tag)){
            Remove-DnsClientNrptRule -Name $rule.Name -Force
        }}catch{$issues+='DNS: '+$_.Exception.Message}
        try{if(Has 'doh.intent'){foreach($old in $st.Doh){
            $live=Get-DnsClientDohServerAddress -ServerAddress $old.ServerAddress
            if($live.DohTemplate -cne $old.DohTemplate -or
                (-not ($live.AutoUpgrade -and -not $live.AllowFallbackToUdp) -and
                ($live.AutoUpgrade -ne $old.AutoUpgrade -or $live.AllowFallbackToUdp -ne $old.AllowFallbackToUdp))){throw 'Resolver settings changed externally'}
            Set-DnsClientDohServerAddress -ServerAddress $old.ServerAddress -AutoUpgrade ([bool]$old.AutoUpgrade) -AllowFallbackToUdp ([bool]$old.AllowFallbackToUdp)
            $v=Get-DnsClientDohServerAddress -ServerAddress $old.ServerAddress
            if($v.AutoUpgrade -ne $old.AutoUpgrade -or $v.AllowFallbackToUdp -ne $old.AllowFallbackToUdp){throw 'Resolver restoration failed'}
        }}}catch{$issues+='Encrypted DNS: '+$_.Exception.Message}
        try{foreach($rule in @(Get-OwnFirewallRules)){
            if($rule.Name -notin @(($st.Tag+'-v6'),($st.Tag+'-udp'),($st.Tag+'-tcp'))){throw 'Unexpected rule in owned group'}
            Remove-NetFirewallRule -PolicyStore PersistentStore -Name $rule.Name
        }}catch{$issues+='Firewall: '+$_.Exception.Message}
        try{Remove-RnEndpointRoute}catch{$issues+='Endpoint route: '+$_.Exception.Message}
        if($issues.Count){throw ($issues -join '; ')}
        if((Get-DnsClientNrptRule | Where-Object Comment -eq $st.Tag) -or (Get-OwnFirewallRules)){throw 'Owned DNS or firewall rules still present'}
        if(Get-NetRoute -AddressFamily IPv4 -InterfaceAlias rn-public -ErrorAction SilentlyContinue){throw 'New tunnel route still present'}
    Clear-DnsClientCache
    $now=NetBaseline
    if(($now | ConvertTo-Json -Compress) -ne ($st.Net | ConvertTo-Json -Compress)){
        Trace-Line 'Other/default network or DNS has changed since snapshot; left externally owned settings untouched.'
    } else {Trace-Line 'Original default routes and interface DNS match.'; Mark 'baseline.ok'}
    Trace-Line "Machine recovery ok ($sid)"; Mark 'machine.ok'
}
function UndoUser{
    if(Has 'user.ok'){return}
    if($sid -ne $st.UserSid){throw 'Restore must run as the original desktop user'}
    if(Has 'proxy.intent'){Restore-RnProxySnapshot -Snapshot $st.Proxy | Out-Null}
    $after=Get-RnProxySnapshot -ExpectedSid $st.UserSid
    if($after.Flags -ne $st.Proxy.Flags){throw 'WinINET flags differ from original'}
    Trace-Line "Desktop proxy recovery ok ($sid)"; Mark 'user.ok'
}
function Get-RnEndpointPath([string]$RemoteIPAddress) {
    # Ask Windows for its actual route AND source address. Do not reproduce route
    # selection by ranking adapter/default-route metrics (which misses host routes).
    try {$answer=@(Find-NetRoute -RemoteIPAddress $RemoteIPAddress -ErrorAction Stop)}
    catch {throw 'Windows endpoint route lookup failed. Check the physical network and retry.'}
    $chosen=@($answer | Where-Object DestinationPrefix)
    $source=@($answer | Where-Object IPAddress)
    if($chosen.Count -ne 1 -or $source.Count -ne 1 -or
        $chosen[0].InterfaceIndex -ne $source[0].InterfaceIndex) {
        throw 'Windows endpoint route selection is ambiguous or incomplete.'
    }
    $route=$chosen[0]; $address=$source[0]
    $adapters=@(Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction Stop)
    $interfaces=@(Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex -ErrorAction Stop)
    if($adapters.Count -ne 1 -or -not $adapters[0].HardwareInterface) {throw 'Windows endpoint route uses a VPN or TUN instead of a physical adapter.'}
    if($adapters[0].Status -ne 'Up' -or $interfaces.Count -ne 1 -or $interfaces[0].ConnectionState -ne 'Connected') {
        throw 'Windows endpoint route uses a disconnected physical IPv4 interface.'
    }
    $local=$null; $next=$null
    if($address.AddressState -ne 'Preferred' -or $address.SkipAsSource -ne $false -or
        -not [ipaddress]::TryParse([string]$address.IPAddress,[ref]$local) -or $local.AddressFamily -ne 'InterNetwork' -or
        -not [ipaddress]::TryParse([string]$route.NextHop,[ref]$next) -or $next.AddressFamily -ne 'InterNetwork' -or
        [string]::IsNullOrWhiteSpace([string]$adapters[0].InterfaceGuid)) {
        throw 'Windows endpoint route has no usable IPv4 source or next hop.'
    }
    if($RemoteIPAddress -ceq [string]$address.IPAddress) {throw 'The endpoint route points to a local workstation address.'}
    [pscustomobject]@{
        RemoteIPAddress=$RemoteIPAddress;InterfaceIndex=[int]$route.InterfaceIndex
        InterfaceAlias=[string]$adapters[0].Name;AdapterGuid=[string]$adapters[0].InterfaceGuid
        NextHop=[string]$route.NextHop;SourceAddress=[string]$address.IPAddress
        DestinationPrefix=[string]$route.DestinationPrefix;RouteMetric=[int]$route.RouteMetric
    }
}
function Assert-RnEndpointRouteAvailable {
    foreach($scope in 'ActiveStore','PersistentStore') {
        # Do not filter the provider by IPv4: an empty family can raise a CIM
        # "no matching objects" error. The exact /32 match is evaluated locally.
        if(Get-NetRoute -PolicyStore $scope -ErrorAction Stop | Where-Object DestinationPrefix -eq $endpointPrefix) {
            throw ('A specific endpoint route already exists in '+$scope+'; it will not be replaced.')
        }
    }
}
function Assert-RnCurrentUplink {
    # No physical /32 is installed. The OS may select a different physical
    # adapter/source/next hop at any time, including while setup is in progress.
    Assert-RnEndpointRouteAvailable
    $path=Get-RnEndpointPath $endpoint
    if($path.DestinationPrefix -eq $endpointPrefix){throw 'A specific endpoint route already exists; it will not be replaced.'}
}
function Assert-RnInternetRoutes {
    if(-not (Test-RnRoamingRoutes -Endpoint $endpoint -TunnelName 'rn-public')) {
        throw 'Unexpected route: WireGuard routes do not exclude the VPS endpoint correctly.'
    }
    Assert-RnCurrentUplink
    $targets=@('1.1.1.1','9.9.9.9','208.67.222.222') | Where-Object {$_ -ne $endpoint}
    foreach($target in $targets) {
        $path=@(Find-NetRoute -RemoteIPAddress $target -ErrorAction Stop | Where-Object DestinationPrefix)
        if($path.Count -ne 1 -or $path[0].InterfaceAlias -ne 'rn-public') {throw "Unexpected route to $target"}
    }
}
function NewState($kind){
    if(Test-Path -LiteralPath $current){
        $last=(Get-Content -LiteralPath $current -Raw).Trim()
        if($last -notmatch '^[a-f0-9]{32}$'){throw 'Invalid previous state'}
        $prev=Join-Path $store $last
        if(-not ((Test-Path -LiteralPath (Join-Path $prev 'machine.ok')) -and (Test-Path -LiteralPath (Join-Path $prev 'user.ok')))){throw 'A session is still open. Restore Original first.'}
    }
    $routes=@(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore)
    $adapters=@(Get-NetAdapter)
    # ActiveStore can retain default routes for disconnected adapters.
    $connectedIPv4=@(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object ConnectionState -eq 'Connected' | ForEach-Object InterfaceIndex)
    $onlineAdapters=@($adapters | Where-Object Status -eq 'Up' | ForEach-Object ifIndex)
    $gateways=@($routes | Where-Object {
        $_.DestinationPrefix -eq '0.0.0.0/0' -and
        $_.InterfaceIndex -in $connectedIPv4 -and $_.InterfaceIndex -in $onlineAdapters
    })
    $physicalIndexes=@($adapters | Where-Object HardwareInterface | ForEach-Object ifIndex)
    if($gateways | Where-Object {$_.InterfaceIndex -notin $physicalIndexes}) {throw 'Another VPN or TUN default route is active. Disconnect it before switching.'}
    Assert-RnEndpointRouteAvailable
    if (($routes | Where-Object DestinationPrefix -in '0.0.0.0/1','128.0.0.0/1') -or
        (Get-Service -Name 'WireGuardTunnel$rn-public' -ErrorAction SilentlyContinue) -or
        (Get-NetIPAddress -IPAddress '10.203.84.2' -ErrorAction SilentlyContinue)) {throw 'Tunnel identity, address, or half-default routes already in use.'}
    $vpns=@(Get-VpnConnection -ErrorAction Stop; Get-VpnConnection -AllUserConnection -ErrorAction Stop)
    if ($vpns | Where-Object ConnectionStatus -eq 'Connected') {throw 'Disconnect the active VPN before switching.'}
    foreach ($a in @($adapters | Where-Object {$_.Status -eq 'Up' -and -not $_.HardwareInterface})) {
        $idx=$a.ifIndex
        $foreign=@($routes | Where-Object {$_.InterfaceIndex -eq $idx -and $_.NextHop -ne '0.0.0.0'})
        if ($foreign.Count -or ($a.Name+' '+$a.InterfaceDescription) -match '(?i)wireguard|wintun|openvpn|tailscale|zerotier|xray|sing.box|clash|mihomo|tun(?:nel)?|tap.windows|vpn') {
            throw 'Another VPN or TUN adapter is active. Switch it off in its own client first and turn it back on yourself after Original.'
        }
    }
    # An arbitrary more-specific route through a different gateway can defeat both /1 routes.
    if ($routes | Where-Object {$_.DestinationPrefix -ne '0.0.0.0/0' -and $_.NextHop -ne '0.0.0.0'}) {throw 'Existing routed prefixes require individual review before enabling a full gateway.'}
    $selectedEndpoint=Get-RnEndpointPath $endpoint
    if($selectedEndpoint.DestinationPrefix -eq $endpointPrefix) {throw 'A specific endpoint route already exists; it will not be replaced.'}
    if($selectedEndpoint.DestinationPrefix -ne '0.0.0.0/0' -and $selectedEndpoint.NextHop -ne '0.0.0.0') {throw 'Existing routed prefixes require individual review before enabling a full gateway.'}
    foreach ($tunnelAddress in '10.203.84.1','10.203.84.2') {
        $selected=@(Find-NetRoute -RemoteIPAddress $tunnelAddress | Where-Object DestinationPrefix)
        if ($selected.Count -ne 1 -or $selected[0].DestinationPrefix -ne '0.0.0.0/0') {throw 'An existing network already routes the private tunnel addresses. No settings were changed.'}
    }
    if (@(Get-DnsClientNrptPolicy -Effective).Where({$_ -and $_.Namespace}).Count) {throw 'Managed DNS policy detected; existing policy was preserved.'}
    if (Get-NetFirewallProfile -PolicyStore ActiveStore | Where-Object {$_.Enabled -ne 'True' -or $_.AllowLocalFirewallRules -eq 'False'}) {throw 'Windows Firewall must enforce local DNS and IP rules for every profile.'}
    $proxy=Get-RnProxySnapshot -ExpectedSid $sid
    $doh=@(Get-DnsClientDohServerAddress -ServerAddress '1.1.1.1','9.9.9.9' | Select-Object ServerAddress,DohTemplate,AutoUpgrade,AllowFallbackToUdp)
    if($doh.Count -ne 2 -or ($doh | Where-Object {$_.DohTemplate -notin 'https://cloudflare-dns.com/dns-query','https://dns.quad9.net/dns-query'})){throw 'Unexpected native DNS-over-HTTPS templates'}
    Assert-RnCurrentUplink
    $script:Id=[guid]::NewGuid().ToString('N'); $script:td=Join-Path $store $Id; New-SessionDirectory $td
    $script:st=[pscustomobject]@{Id=$Id;Kind=$kind;UserSid=$sid;RouteMode='EndpointExclusion';Tag="RNPublic-$Id";Proxy=$proxy;Net=(NetBaseline);Boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')}
    Add-Member -InputObject $st -NotePropertyName EndpointPath -NotePropertyValue $selectedEndpoint
    Add-Member -InputObject $st -NotePropertyName Doh -NotePropertyValue $doh
    $st | Export-Clixml -LiteralPath (Join-Path $td 'baseline.xml')
    [IO.File]::WriteAllText($current,$Id)
}
function LoadState{
    if(-not (Test-Path -LiteralPath $current)){throw 'No session state'}
    $active=(Get-Content -LiteralPath $current -Raw).Trim()
    if($Id -and $Id -ne $active){throw 'Stale recovery invocation refused'}
    if($active -notmatch '^[a-f0-9]{32}$'){throw 'Invalid session ID'}
    $script:Id=$active; $script:td=Join-Path $store $active
    $script:st=Import-Clixml -LiteralPath (Join-Path $td 'baseline.xml')
    if($st.Id -ne $Id){throw 'Snapshot mismatch'}
}
function EnableMode{
    if (Has 'stop.requested'){throw 'Local recovery requested'}
    Assert-RnCurrentUplink
    # Bind the outside guards to all currently installed non-tunnel adapters, including disconnected ones.
    $aliases=@(Get-NetAdapter | Where-Object {$_.Name -ne 'rn-public'} | ForEach-Object Name)
    if (-not $aliases.Count -or ($aliases | Where-Object {[Management.Automation.WildcardPattern]::ContainsWildcardCharacters($_)})) {throw 'Unsupported interface alias.'}
    foreach($proto in 'udp','tcp'){
        $argsFw=@{Name=($st.Tag+'-'+$proto);DisplayName=('RackNerd Connection: DNS outside tunnel ('+$proto+')');Group=$st.Tag;Direction='Outbound';Action='Block';Profile='Any';Protocol=$proto;RemotePort=@('53','853');InterfaceAlias=$aliases;PolicyStore='PersistentStore'}
        New-NetFirewallRule @argsFw | Out-Null
    }
    # All IPv6 unicast except loopback / link-local; leave local discovery and IPv4 intact.
    New-NetFirewallRule -Name ($st.Tag+'-v6') -DisplayName 'RackNerd Connection: IPv4-only Internet' -Group $st.Tag -Direction Outbound -Action Block -Profile Any -RemoteAddress '::2-fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff','fec0::/10' -PolicyStore PersistentStore | Out-Null
    if(@(Get-NetFirewallRule -PolicyStore ActiveStore -Group $st.Tag | Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Block' }).Count -ne 3){throw 'Effective DNS and IPv6 firewall rules incomplete'}
    Mark 'svc.intent'; Start-RnManualTunnel | Out-Null
    if(Has 'stop.requested'){throw 'Local recovery requested'}
    Enable-RnRoamingRoutes -Endpoint $endpoint -TunnelName 'rn-public'
    if(Has 'stop.requested'){throw 'Local recovery requested'}
    Assert-RnInternetRoutes
    Mark 'doh.intent'
    foreach($old in $st.Doh){Set-DnsClientDohServerAddress -ServerAddress $old.ServerAddress -AutoUpgrade $true -AllowFallbackToUdp $false}
    Add-DnsClientNrptRule -Namespace '.' -NameServers '1.1.1.1','9.9.9.9' -Comment $st.Tag -DisplayName $st.Tag
    # The DNS Client may publish its effective policy a few seconds after the registry rule is added.
    $policyDeadline=[DateTime]::UtcNow.AddSeconds(20)
    $expectedDns=@('1.1.1.1','9.9.9.9')
    do{
        $effective=@(Get-DnsClientNrptPolicy -Effective | Where-Object { @($_.Namespace) -contains '.' })
        $seenDns=@($effective | ForEach-Object { $_.NameServers } | ForEach-Object { "$_" -split '[;,\s]+' } | Where-Object {$_} | Sort-Object -Unique)
        $policyOK=$effective.Count -eq 1 -and ($seenDns -join ',') -eq ($expectedDns -join ',')
        if($policyOK){break}
        if(Has 'stop.requested'){throw 'Local recovery requested'}
        Start-Sleep -Milliseconds 400
    }while([DateTime]::UtcNow -lt $policyDeadline)
    if(-not $policyOK){throw ('DNS policy not effective after 20 seconds; matching rules='+$effective.Count+' resolvers='+($seenDns -join ','))}
    Mark 'proxy.intent'; Set-RnProxyDirect -Snapshot $st.Proxy | Out-Null
    Clear-DnsClientCache
    Assert-RnInternetRoutes
    $good=$false
    foreach($url in 'https://api.ipify.org','https://www.cloudflare.com/cdn-cgi/trace','https://ipv4.icanhazip.com'){
        if(Has 'stop.requested'){throw 'Local recovery requested'}
        $v=& "$env:SystemRoot\System32\curl.exe" --disable --noproxy '*' -4fs --connect-timeout 12 --max-time 22 $url
        $rc=$LASTEXITCODE
        if($rc -eq 0 -and (@($v) -contains ('ip='+$endpoint) -or "$v".Trim() -eq $endpoint)){$good=$true;break}
        Trace-Line ("Direct public-IP check: "+([uri]$url).Host+" curl exit="+$rc+"; expected IP not verified")
    }
    if(-not $good){throw 'Could not verify the VPS as the no-proxy IPv4 exit'}
    $w=Join-Path (Split-Path -Parent $base) 'WireGuard\wg.exe'
    $hand=@(& $w show rn-public latest-handshakes)
    if ($LASTEXITCODE -ne 0 -or $hand.Count -ne 1) {throw 'Could not verify a WireGuard handshake.'}
    $pair=@($hand[0].Trim() -split '\s+')
    if ($pair.Count -ne 2 -or $pair[0] -cne $cfg.ServerPublicKey -or $pair[1] -notmatch '^\d+$') {throw 'Unexpected handshake record.'}
    $age=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()-[long]$pair[1]
    if ($age -lt 0 -or $age -gt 180) {throw 'No recent handshake with the enrolled server.'}
    if (-not @(Resolve-DnsName -Name 'example.com' -Type A -DnsOnly -NoHostsFile -ErrorAction Stop | Where-Object IPAddress).Count) { throw 'Native Windows DNS did not return an IPv4 address.' }
    Assert-RnInternetRoutes
    Trace-Line 'Physical endpoint, WireGuard handshake, native DNS and direct public IPv4 exit verified.'
}
switch($Action){
    'Status' {
        if (Test-Path -LiteralPath $current) {
            LoadState; $machine=Has 'machine.ok'; $user=Has 'user.ok'
            $mode=if($machine -and $user){'Original'}elseif(Has 'stop.requested'){'Restoring'}elseif(Has 'gateway.ok'){$st.Kind}else{'Starting'}
            [pscustomobject]@{Id=$Id;Mode=$mode;MachineRestored=$machine;UserRestored=$user;Qualified=(Test-Path -LiteralPath (Join-Path $store 'qualified.ok'));Log=(Join-Path $td 'events.log')}
        }
        else {[pscustomobject]@{Mode='Original';Qualified=$false;EndpointIPv4=$endpoint}}
        return
    }
    'MachineUndo' {if ($sid -ne 'S-1-5-18') {throw 'The machine recovery action is reserved for SYSTEM.'}; LoadState; GuardedRecovery $false; return}
    'UserUndo' {LoadState; GuardedRecovery $true;return}
    'Original' {if(-not (Test-Path -LiteralPath $current)){'No gateway session.';return}; LoadState; GuardedRecovery $true; 'Original network restored.';return}
}
if ($Action -eq 'RackNerd' -and -not (Test-Path -LiteralPath (Join-Path $store 'qualified.ok'))) {throw 'Run Test and restore Original successfully before daily use.'}
$enterLock=[IO.File]::Open((Join-Path $store 'enter.lock'),'OpenOrCreate','ReadWrite','None')
try {
    NewState $Action
    try{
        $when=(Get-Date).AddMinutes(15)
        Register-Recovery Machine $when; Register-Recovery User $when
        Trace-Line ('Machine and desktop recovery armed for '+$when.ToString('o'))
        $applyLock=Open-SessionLock
        try{
            EnableMode
            if (Has 'stop.requested'){throw 'Local recovery requested'}
            Mark 'gateway.ok'
            if($Action -eq 'RackNerd'){
                # Daily use is manual. Leave the reboot and desktop logon recovery triggers in place.
                Set-ScheduledTask -TaskPath '\' -TaskName (TaskName Machine) -Trigger (New-ScheduledTaskTrigger -AtStartup) | Out-Null
                Set-ScheduledTask -TaskPath '\' -TaskName (TaskName User) -Trigger (New-ScheduledTaskTrigger -AtLogOn -User $sid) | Out-Null
                'RackNerd mode active. Choose Original before enabling any other TUN.'
            }else{"Test active until $($when.ToString('HH:mm:ss')); Original restores early."}
        }finally{$applyLock.Dispose()}
    }catch{
        $failure=$_.Exception.Message; Trace-Line ('Stopped: '+$failure)
        GuardedRecovery $true; throw $failure
    }
}finally{$enterLock.Dispose()}
