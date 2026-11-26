#Requires -Version 5.1
# Offline checks: no elevation, network, keys, files written, tasks, services or OS changes.
[CmdletBinding()]param()
$ErrorActionPreference='Stop'
$root=$PSScriptRoot
. (Join-Path $root 'Gateway-Common.ps1')
function Check($Condition,[string]$Message) { if (-not $Condition) {throw $Message} }
function Rejected([scriptblock]$Attempt,[string]$Text) {
    try { & $Attempt | Out-Null } catch { if ($_.Exception.Message -like ('*'+$Text+'*')) {return}; throw }
    throw "Expected refusal: $Text"
}
function Read-TestFunction([string]$File,[string]$Name) {
    $errors=$null; $tokens=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root $File),[ref]$tokens,[ref]$errors)
    if ($errors.Count) {throw "Parser error in $File"}
    $item=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $Name},$true)
    if (-not $item) {throw "Missing test subject: $Name"}
    return [scriptblock]::Create($item.Extent.Text)
}
foreach ($f in Get-ChildItem -LiteralPath $root -Filter '*.ps1' -File) {
    $tokens=$null;$errors=$null
    [void][Management.Automation.Language.Parser]::ParseFile($f.FullName,[ref]$tokens,[ref]$errors)
    if ($errors.Count) {throw ("Parse failed in "+$f.Name+": "+$errors[0].Message)}
}
Assert-RnPublicEndpoint '1.1.1.1'
foreach ($bad in 'localhost','127.0.0.1','10.203.84.1','198.51.100.8','001.001.001.001','1.1.1.1; extra','::1') {Rejected {Assert-RnPublicEndpoint $bad} 'IPv4'}
$keyShape=[Convert]::ToBase64String([byte[]](1..32))
Assert-RnPublicKey $keyShape
Rejected {Assert-RnPublicKey 'wrong'} 'public key'
Rejected {Assert-RnPublicKey ([Convert]::ToBase64String((New-Object byte[] 32)))} 'public key'
foreach ($n in 1,51820,65535) { Assert-RnUdpPort $n }
foreach ($n in 0,65536,53,853) { Rejected {Assert-RnUdpPort $n} 'port' }

& {
    . (Read-TestFunction 'Prepare-Profile.ps1' 'ConfigText')
    $request=[pscustomobject]@{EndpointIPv4='198.51.100.8';Port=51821}
    $t=ConfigText 'dummy-text' 'dummy-peer'
    Check ($t -match '(?m)^Endpoint = 198\.51\.100\.8:51821$') 'Custom endpoint binding failed'
    Check ($t -match '(?m)^AllowedIPs = 0\.0\.0\.0/1, 128\.0\.0\.0/1$' -and $t -notmatch '(?m)^AllowedIPs = .+::') 'Incorrect split-default route plan'
    Check ($t -match '(?m)^Address = 10\.203\.84\.2/32$' -and $t -match '(?m)^DNS = 1\.1\.1\.1, 9\.9\.9\.9$') 'Unexpected client plan'
}

& {
    # Load function definitions only. All Task Scheduler commands below are in-memory stand-ins.
    foreach ($n in 'TaskName','Register-Recovery','Remove-OwnTask') { . (Read-TestFunction 'Gateway-Mode.ps1' $n) }
    $id='fixture';$st=[pscustomobject]@{UserSid='S-1-5-32-544'};$jobs=@{}
    $psExe='fixture-powershell'; $installed='fixture-controller'
    function Get-ScheduledTask($TaskPath,$TaskName,$ErrorAction) { $jobs[$TaskName] }
    function New-ScheduledTaskAction($Execute,$Argument) {[pscustomobject]@{Execute=$Execute;Arguments=$Argument}}
    function New-ScheduledTaskTrigger([switch]$Once,$At,[switch]$AtStartup,[switch]$AtLogOn,$User) {[pscustomobject]@{Once=[bool]$Once;At=$At;Startup=[bool]$AtStartup;Logon=[bool]$AtLogOn;User=$User}}
    function New-ScheduledTaskPrincipal($UserId,$LogonType,$RunLevel) {[pscustomobject]@{UserId=$UserId;LogonType=$LogonType;RunLevel=$RunLevel}}
    function New-ScheduledTaskSettingsSet([switch]$StartWhenAvailable,[switch]$AllowStartIfOnBatteries,[switch]$DontStopIfGoingOnBatteries,$ExecutionTimeLimit,$RestartCount,$RestartInterval) {'mock-settings'}
    function Register-ScheduledTask($TaskPath,$TaskName,$Action,$Principal,$Trigger,$Settings) {$jobs[$TaskName]=[pscustomobject]@{State='Ready';Actions=@($Action);Triggers=$Trigger;Principal=$Principal}}
    function Unregister-ScheduledTask($TaskPath,$TaskName,[switch]$Confirm) {$jobs.Remove($TaskName)}
    $when=[datetime]::UtcNow.AddMinutes(15)
    Register-Recovery 'Machine' $when; Register-Recovery 'User' $when
    $m=$jobs[(TaskName 'Machine')];$u=$jobs[(TaskName 'User')]
    Check ($m.Principal.UserId -ceq 'SYSTEM' -and $m.Triggers[0].At -eq $when -and $m.Triggers[1].Startup) 'Machine triggers or identity incorrect'
    Check ($u.Principal.UserId -ceq $st.UserSid -and $u.Triggers[0].At -eq $when -and $u.Triggers[1].Logon) 'Desktop triggers or identity incorrect'
    Check ($u.Actions[0].Arguments -match ' -ExecutionPolicy RemoteSigned -File ' -and $m.Actions[0].Arguments -match ' -ExecutionPolicy RemoteSigned -File ') 'Rollback process policy not explicit'
    Rejected {Register-Recovery 'Machine' $when} 'collision'
    $u.Actions[0].Execute='other-program'
    Rejected {Remove-OwnTask 'User'} 'ownership'
    Check ($jobs.Count -eq 2) 'Foreign tasks must be retained'
    $u.Actions[0].Execute=$psExe
    Remove-OwnTask 'Machine';Remove-OwnTask 'User'
    Check ($jobs.Count -eq 0) 'Owned recovery tasks did not clean up'
}

& {
    # Full preflight reaches an in-memory snapshot only. All platform reads use
    # fixtures; the stop in Export-Clixml occurs before a state file can be written.
    foreach($n in 'Get-RnEndpointPath','Assert-RnCurrentUplink','Assert-RnEndpointRouteAvailable','NewState') { . (Read-TestFunction 'Gateway-Mode.ps1' $n) }
    $current='fixture-state';$store='fixture-root';$endpoint='198.51.100.8';$endpointPrefix=$endpoint+'/32';$sid='fixture-user'
    $net=@(
        [pscustomobject]@{DestinationPrefix='0.0.0.0/0';NextHop='192.0.2.1';InterfaceIndex=7;RouteMetric=1},
        [pscustomobject]@{DestinationPrefix='0.0.0.0/0';NextHop='192.0.2.2';InterfaceIndex=8;RouteMetric=900}
    )
    $persistent=@()
    $devices=@(
        [pscustomobject]@{ifIndex=7;InterfaceGuid='fixture-ethernet-id';HardwareInterface=$true;Status='Up';Name='fixture-ethernet';InterfaceDescription='Ethernet'},
        [pscustomobject]@{ifIndex=8;InterfaceGuid='fixture-wlan-id';HardwareInterface=$true;Status='Up';Name='fixture-wlan';InterfaceDescription='Wi-Fi'}
    )
    $interfaces=@(
        [pscustomobject]@{InterfaceIndex=7;ConnectionState='Connected';InterfaceMetric=1},
        [pscustomobject]@{InterfaceIndex=8;ConnectionState='Connected';InterfaceMetric=900}
    )
    $selectedIndex=7; $selectedHop='192.0.2.1';$selectedPrefix='0.0.0.0/0';$selectedMetric=1;$sourceIndex=0
    $sourceOverride='';$sourceState='Preferred';$sourceSkipped=$false
    $replyMode='Normal';$changeOnSecond=$false;$vpn=$false
    $observations=[Collections.Generic.List[string]]::new()
    function Test-Path($LiteralPath) {$false}
    function Get-NetRoute($AddressFamily,$PolicyStore,$ErrorAction) {
        if($PolicyStore -ceq 'PersistentStore') {
            Check (-not $PSBoundParameters.ContainsKey('AddressFamily') -and $ErrorAction -ceq 'Stop') 'An empty persistent store must not become an IPv4 provider failure'
            $persistent
        }else{
            Check ($PolicyStore -ceq 'ActiveStore' -and (-not $AddressFamily -or $AddressFamily -ceq 'IPv4')) 'Unexpected route query'
            $net
        }
    }
    function Get-NetAdapter($InterfaceIndex,$ErrorAction) {
        if($PSBoundParameters.ContainsKey('InterfaceIndex')) {$devices | Where-Object ifIndex -eq $InterfaceIndex}
        else {$devices}
    }
    function Get-NetIPInterface($AddressFamily,$InterfaceIndex,$ErrorAction) {
        Check ($AddressFamily -ceq 'IPv4' -and $ErrorAction -ceq 'Stop') 'Interface query must fail on errors'
        if($PSBoundParameters.ContainsKey('InterfaceIndex')) {$interfaces | Where-Object InterfaceIndex -eq $InterfaceIndex}
        else {$interfaces}
    }
    function Get-Service($Name,$ErrorAction) {}
    function Get-NetIPAddress($IPAddress,$ErrorAction) {}
    function Get-VpnConnection([switch]$AllUserConnection,$ErrorAction) {if($vpn){[pscustomobject]@{ConnectionStatus='Connected'}}}
    function Find-NetRoute($RemoteIPAddress,$ErrorAction) {
        if($RemoteIPAddress -ne $endpoint) {
            Check ($RemoteIPAddress -in '10.203.84.1','10.203.84.2') 'Unexpected lookup target'
            [pscustomobject]@{DestinationPrefix='0.0.0.0/0';InterfaceIndex=7;NextHop='192.0.2.1'};return
        }
        Check ($ErrorAction -ceq 'Stop') 'Endpoint provider errors must terminate'
        [void]$observations.Add($RemoteIPAddress)
        if($replyMode -eq 'Failure'){throw 'Fixture provider error'}
        if($replyMode -eq 'Empty'){return}
        $idx=if($changeOnSecond -and $observations.Count -gt 1){8}else{$selectedIndex}
        $hop=if($changeOnSecond -and $observations.Count -gt 1){'192.0.2.2'}else{$selectedHop}
        $route=[pscustomobject]@{DestinationPrefix=$selectedPrefix;InterfaceIndex=$idx;NextHop=$hop;RouteMetric=$selectedMetric}
        $source=[pscustomobject]@{
            IPAddress=if($sourceOverride){$sourceOverride}else{'192.0.2.'+([string]($idx+10))}
            InterfaceIndex=if($sourceIndex){$sourceIndex}else{$idx};AddressState=$sourceState;SkipAsSource=$sourceSkipped
        }
        $route
        if($replyMode -ne 'NoSource'){$source}
        if($replyMode -eq 'DuplicateRoute'){$route}
        if($replyMode -eq 'DuplicateSource'){$source}
    }
    function Get-DnsClientNrptPolicy {}
    function Get-NetFirewallProfile {}
    function Get-RnProxySnapshot($ExpectedSid) {[pscustomobject]@{Flags=1}}
    function Get-DnsClientDohServerAddress($ServerAddress) {
        [pscustomobject]@{ServerAddress='1.1.1.1';DohTemplate='https://cloudflare-dns.com/dns-query'}
        [pscustomobject]@{ServerAddress='9.9.9.9';DohTemplate='https://dns.quad9.net/dns-query'}
    }
    function New-SessionDirectory($Path) {}
    function NetBaseline {[pscustomobject]@{defaults=@('fixture')}}
    function Get-CimInstance($ClassName) {[pscustomobject]@{LastBootUpTime=[datetime]'2020-01-01'}}
    function Export-Clixml {throw 'Fixture: captured snapshot without disk writes'}
    function Assert-Snapshot([int]$Index,[string]$Hop) {
        $observations.Clear()
        Rejected {NewState 'Test'} 'Fixture: captured snapshot'
        Check ($script:st.EndpointPath.InterfaceIndex -eq $Index -and $script:st.EndpointPath.NextHop -ceq $Hop) 'Did not observe Windows actual endpoint route'
        Check ($script:st.RouteMode -ceq 'EndpointExclusion' -and -not $script:st.PSObject.Properties['RouteMetric'] -and -not $script:st.PSObject.Properties['K']) 'A new session must not plan a physical endpoint pin'
        Check ($observations.Count -eq 2) 'Endpoint path was not rechecked before snapshot'
    }
    Assert-Snapshot 7 '192.0.2.1'
    $selectedIndex=8;$selectedHop='192.0.2.2'
    Assert-Snapshot 8 '192.0.2.2' # Deliberately higher cost: never rank metrics ourselves.
    $selectedIndex=7;$selectedHop='192.0.2.1'
    $devices[1].Status='Disconnected';$interfaces[1].ConnectionState='Disconnected'
    Assert-Snapshot 7 '192.0.2.1'
    $devices[1].Status='Up'
    Assert-Snapshot 7 '192.0.2.1'
    $devices[1].Status='Disconnected';$interfaces[1].ConnectionState='Connected'
    Assert-Snapshot 7 '192.0.2.1'
    $devices[1].Status='Up'
    $selectedHop='0.0.0.0';$selectedPrefix='198.51.100.0/24'
    $net+=[pscustomobject]@{DestinationPrefix=$selectedPrefix;NextHop='0.0.0.0';InterfaceIndex=7}
    Assert-Snapshot 7 '0.0.0.0' # On-link endpoint: preserve the actual zero next hop.
    $net=$net[0..1];$selectedHop='192.0.2.1';$selectedPrefix='0.0.0.0/0'
    foreach($replyMode in 'DuplicateRoute','DuplicateSource','NoSource','Empty') {Rejected {Get-RnEndpointPath $endpoint} 'ambiguous or incomplete'}
    $replyMode='Failure';Rejected {Get-RnEndpointPath $endpoint} 'lookup failed'
    $replyMode='Normal'
    $sourceIndex=8;Rejected {Get-RnEndpointPath $endpoint} 'ambiguous or incomplete';$sourceIndex=0
    $sourceState='Tentative';Rejected {Get-RnEndpointPath $endpoint} 'no usable';$sourceState='Preferred'
    $sourceSkipped=$true;Rejected {Get-RnEndpointPath $endpoint} 'no usable';$sourceSkipped=$false
    $sourceOverride='::1';Rejected {Get-RnEndpointPath $endpoint} 'no usable';$sourceOverride=''
    $devices[0].Status='Disconnected';Rejected {Get-RnEndpointPath $endpoint} 'disconnected';$devices[0].Status='Up'
    $interfaces[0].ConnectionState='Disconnected';Rejected {Get-RnEndpointPath $endpoint} 'disconnected';$interfaces[0].ConnectionState='Connected'
    $devices[0].HardwareInterface=$false;Rejected {Get-RnEndpointPath $endpoint} 'VPN or TUN';$devices[0].HardwareInterface=$true
    $sourceOverride='192.0.2.123';Assert-RnCurrentUplink;$sourceOverride=''
    $devices[0].InterfaceGuid='fixture-reused-index';Assert-RnCurrentUplink;$devices[0].InterfaceGuid='fixture-ethernet-id'
    $selectedHop='192.0.2.2';Assert-RnCurrentUplink;$selectedHop='192.0.2.1'
    $changeOnSecond=$true;Assert-Snapshot 7 '192.0.2.1';$changeOnSecond=$false
    # A new native choice is accepted, but a pin found only by the final lookup
    # (after store enumeration) must still fail the no-pin invariant.
    $selectedIndex=8;Assert-RnCurrentUplink;$selectedIndex=7
    $selectedPrefix=$endpointPrefix;Rejected {Assert-RnCurrentUplink} 'specific endpoint'
    $selectedPrefix='0.0.0.0/0'
    $vpn=$true;Rejected {NewState 'Test'} 'active VPN';$vpn=$false
    $devices[1].HardwareInterface=$false;Rejected {NewState 'Test'} 'VPN or TUN';$devices[1].HardwareInterface=$true
    $net+=[pscustomobject]@{DestinationPrefix='128.0.0.0/1';NextHop='0.0.0.0';InterfaceIndex=8}
    Rejected {NewState 'Test'} 'half-default';$net=$net[0..1]
    $net+=[pscustomobject]@{DestinationPrefix='203.0.113.0/24';NextHop='192.0.2.1';InterfaceIndex=7}
    Rejected {NewState 'Test'} 'routed prefixes';$net=$net[0..1]
    $net+=[pscustomobject]@{DestinationPrefix=$endpointPrefix;NextHop='192.0.2.1';InterfaceIndex=7}
    Rejected {NewState 'Test'} 'specific endpoint';$net=$net[0..1]
    $persistent=@([pscustomobject]@{DestinationPrefix=$endpointPrefix;NextHop='192.0.2.1';InterfaceIndex=8})
    Rejected {NewState 'Test'} 'specific endpoint route already exists in PersistentStore'
    Check ($persistent.Count -eq 1) 'Persistent endpoint route was modified'
    $persistent=@([pscustomobject]@{DestinationPrefix='2001:db8::/32'})
    Assert-Snapshot 7 '192.0.2.1' # No IPv4 routes in PersistentStore is a valid state.
    Check ($net[0].RouteMetric -eq 1 -and $net[1].RouteMetric -eq 900) 'Preflight changed existing routes'
}
& {
    # Validate the controller's ongoing checks against a moving native uplink.
    foreach($n in 'Assert-RnCurrentUplink','Assert-RnEndpointRouteAvailable','Assert-RnInternetRoutes') {. (Read-TestFunction 'Gateway-Mode.ps1' $n)}
    $endpoint='198.51.100.8';$endpointPrefix=$endpoint+'/32'
    $complete=$true;$chosenIndex=7;$chosenPrefix='0.0.0.0/0';$probeAlias='rn-public';$duplicate=$false
    $pinStore='';$reads=[Collections.Generic.List[string]]::new()
    function Test-RnRoamingRoutes($Endpoint,$TunnelName){Check ($TunnelName -ceq 'rn-public') 'Wrong tunnel checked';$complete}
    function Get-NetRoute($PolicyStore,$ErrorAction){
        Check ($ErrorAction -ceq 'Stop') 'Uplink store reads must surface errors'
        if($PolicyStore -ceq $pinStore){[pscustomobject]@{DestinationPrefix=$endpointPrefix}}
    }
    function Get-RnEndpointPath($RemoteIPAddress){
        Check ($RemoteIPAddress -ceq $endpoint) 'Wrong endpoint checked'
        [pscustomobject]@{InterfaceIndex=$chosenIndex;DestinationPrefix=$chosenPrefix}
    }
    function Find-NetRoute($RemoteIPAddress,$ErrorAction){
        Check ($ErrorAction -ceq 'Stop' -and $RemoteIPAddress -ne $endpoint) 'Endpoint must not be a tunneled traffic probe'
        [void]$reads.Add($RemoteIPAddress)
        [pscustomobject]@{DestinationPrefix='fixture-prefix';InterfaceAlias=$probeAlias}
        if($duplicate){[pscustomobject]@{DestinationPrefix='fixture-prefix';InterfaceAlias=$probeAlias}}
    }
    Assert-RnInternetRoutes
    $chosenIndex=8;Assert-RnInternetRoutes
    Check ($reads.Count -eq 6) 'Ongoing checks did not follow physical uplink changes'
    $complete=$false;Rejected {Assert-RnInternetRoutes} 'do not exclude';$complete=$true
    $probeAlias='fixture-physical';Rejected {Assert-RnInternetRoutes} 'Unexpected route to';$probeAlias='rn-public'
    $duplicate=$true;Rejected {Assert-RnInternetRoutes} 'Unexpected route to';$duplicate=$false
    foreach($pinStore in 'ActiveStore','PersistentStore'){Rejected {Assert-RnInternetRoutes} 'specific endpoint'}
    $pinStore='';$chosenPrefix=$endpointPrefix;Rejected {Assert-RnInternetRoutes} 'specific endpoint';$chosenPrefix='0.0.0.0/0'
    $endpoint='1.1.1.1';$endpointPrefix=$endpoint+'/32';$reads.Clear()
    Assert-RnInternetRoutes
    Check ($reads.Count -eq 2 -and $reads -notcontains $endpoint) 'An endpoint equal to a probe must remain direct'
}
& {
    # Execute real startup orchestration only up to the DNS step. All writes are
    # fixtures, and no external executable or machine API can be reached.
    . (Read-TestFunction 'Gateway-Mode.ps1' 'EnableMode')
    $endpoint='198.51.100.8';$st=[pscustomobject]@{Tag='fixture';Doh=@([pscustomobject]@{ServerAddress='1.1.1.1'})}
    $events=[Collections.Generic.List[string]]::new();$routeFailure=$false;$stopAfter=''
    function Has($Name){$Name -ceq 'stop.requested' -and $stopAfter -and $events.Contains($stopAfter)}
    function Assert-RnCurrentUplink{[void]$events.Add('physical')}
    function Get-NetAdapter{[pscustomobject]@{Name='fixture-physical'}}
    function New-NetFirewallRule{[void]$events.Add('guard')}
    function Get-NetFirewallRule{foreach($n in 1..3){[pscustomobject]@{Enabled='True';Action='Block'}}}
    function Mark($Name){[void]$events.Add($Name)}
    function Start-RnManualTunnel{[void]$events.Add('start')}
    function Enable-RnRoamingRoutes($Endpoint,$TunnelName){
        Check ($Endpoint -ceq $endpoint -and $TunnelName -ceq 'rn-public') 'Wrong conversion target'
        [void]$events.Add('exclude');if($routeFailure){throw 'Fixture route conversion failed'}
    }
    function Assert-RnInternetRoutes{[void]$events.Add('verify')}
    function Set-DnsClientDohServerAddress{throw 'Fixture stop before DNS mutation'}
    function New-NetRoute{throw 'A physical pin must never be created'}
    Rejected {EnableMode} 'Fixture stop before DNS mutation'
    Check (($events -join ',') -ceq 'physical,guard,guard,guard,svc.intent,start,exclude,verify,doh.intent') 'Route conversion must immediately follow service start'
    $events.Clear();$routeFailure=$true
    Rejected {EnableMode} 'Fixture route conversion failed'
    Check (($events -join ',') -ceq 'physical,guard,guard,guard,svc.intent,start,exclude') 'Failed conversion continued configuration'
    $events.Clear();$routeFailure=$false;$stopAfter='start'
    Rejected {EnableMode} 'Local recovery requested'
    Check (($events -join ',') -ceq 'physical,guard,guard,guard,svc.intent,start') 'Recovery requested during startup still changed routes'
    $events.Clear();$stopAfter='exclude'
    Rejected {EnableMode} 'Local recovery requested'
    Check (($events -join ',') -ceq 'physical,guard,guard,guard,svc.intent,start,exclude') 'Recovery requested during conversion still changed DNS or proxy'
}
& {
    . (Read-TestFunction 'Gateway-Mode.ps1' 'Test-RnTrialQualifies')
    $st=[pscustomobject]@{Kind='Test'}
    $marks=@{'gateway.ok'=$true;'machine.ok'=$true;'user.ok'=$true;'baseline.ok'=$true}
    function Has($n) {[bool]$marks[$n]}
    Check (Test-RnTrialQualifies) 'Completed trial was not accepted'
    foreach ($name in @($marks.Keys)) {$marks[$name]=$false;Check (-not (Test-RnTrialQualifies)) ('Incomplete trial accepted: '+$name);$marks[$name]=$true}
    $st.Kind='RackNerd';Check (-not (Test-RnTrialQualifies)) 'A daily session cannot qualify itself'
}
& {
    # Simulate restore on a new boot: no live Net* command is called. Foreign rules must survive.
    foreach ($n in 'UndoMachine','UndoUser','Get-OwnFirewallRules','Remove-RnEndpointRoute') {. (Read-TestFunction 'Gateway-Mode.ps1' $n)}
    $sid='fixture-desktop'
    $st=[pscustomobject]@{Tag='owned';Boot='older';UserSid=$sid;Net=[pscustomobject]@{iface='fixture'};Proxy=[pscustomobject]@{Flags=7}}
    $marks=@{'svc.intent'=$true;'route.intent'=$true;'proxy.intent'=$true}
    function Has($n) {[bool]$marks[$n]}
    function Mark($n) {$marks[$n]=$true}
    function Trace-Line($message) {}
    function NetBaseline {$st.Net}
    $events=[Collections.Generic.List[string]]::new()
    $dns=@{'mine'=[pscustomobject]@{Name='mine';Comment='owned'};'other'=[pscustomobject]@{Name='other';Comment='foreign'}}
    $fw=@{'owned-udp'=[pscustomobject]@{Name='owned-udp';Group='owned'};'external'=[pscustomobject]@{Name='external';Group='foreign'}}
    function Stop-RnManualTunnel {[void]$events.Add('service')}
    function Get-DnsClientNrptRule($ErrorAction) {$dns.Values}
    function Remove-DnsClientNrptRule($Name,[switch]$Force) {$dns.Remove($Name)}
    function Get-NetFirewallRule($PolicyStore,$ErrorAction) {$fw.Values}
    function Remove-NetFirewallRule($PolicyStore,$Name) {$fw.Remove($Name)}
    function Get-CimInstance($ClassName) {[pscustomobject]@{LastBootUpTime=[datetime]::UtcNow}}
    function Get-NetRoute($AddressFamily,$InterfaceAlias,$ErrorAction) {if ($InterfaceAlias -cne 'rn-public') {throw 'Attempted to change a route from another boot'}}
    function Clear-DnsClientCache {[void]$events.Add('cache')}
    function Restore-RnProxySnapshot($Snapshot) {[void]$events.Add('proxy')}
    function Get-RnProxySnapshot($ExpectedSid) {$st.Proxy}
    UndoMachine; UndoUser; UndoMachine; UndoUser
    Check ($marks['machine.ok'] -and $marks['user.ok'] -and $marks['baseline.ok']) 'Verified rollback markers missing'
    Check ($dns.Count -eq 1 -and $dns.ContainsKey('other') -and $fw.Count -eq 1 -and $fw.ContainsKey('external')) 'Rollback touched a foreign rule'
    Check (($events -join ',') -ceq 'service,cache,proxy') 'Rollback was not idempotent'
}
& {
    # Old sessions retain their exact pin ownership and recovery rules. New
    # roaming sessions have no route.intent and cannot delete physical routes.
    foreach($n in 'Assert-RnEndpointRouteAvailable','Remove-RnEndpointRoute','UndoMachine') {. (Read-TestFunction 'Gateway-Mode.ps1' $n)}
    $endpointPrefix='198.51.100.8/32';$boot=[datetime]'2020-01-01'
    $st=[pscustomobject]@{K=8;GW='0.0.0.0';RouteMetric=9000;AdapterGuid='fixture-wlan';Boot=$boot.ToUniversalTime().ToString('o');RouteOwnershipVersion=2;EndpointPath='fixture'}
    $net=[Collections.Generic.List[object]]::new()
    $original=[pscustomobject]@{DestinationPrefix='0.0.0.0/0';InterfaceIndex=8;NextHop='192.0.2.1';RouteMetric=99}
    $net.Add($original)
    $persistent=@()
    $marks=@{}
    $providerFailure=$false;$adapterFailure=$false;$retainRoute=$false;$actualGuid='fixture-wlan'
    function Has($n) {[bool]$marks[$n]}
    function Mark($n) {$marks[$n]=$true}
    function Get-NetRoute($AddressFamily,$PolicyStore,$ErrorAction) {
        Check (-not $PSBoundParameters.ContainsKey('AddressFamily')) 'Empty route stores must use unfiltered provider enumeration'
        if($providerFailure){throw 'Fixture route provider unavailable'}
        if($PolicyStore -eq 'PersistentStore') {
            Check (-not $PSBoundParameters.ContainsKey('AddressFamily')) 'Persistent route query filtered an absent family'
            $persistent
        }else{$net}
    }
    function Add-FixturePin{$net.Add([pscustomobject]@{DestinationPrefix=$endpointPrefix;InterfaceIndex=8;NextHop='0.0.0.0';RouteMetric=9000})}
    function Get-CimInstance($ClassName) {[pscustomobject]@{LastBootUpTime=$boot}}
    function Get-NetAdapter($ErrorAction) {
        Check ($ErrorAction -ceq 'Stop') 'Recovery must distinguish a failed adapter provider from absence'
        if($adapterFailure){throw 'Fixture adapter provider unavailable'}
        [pscustomobject]@{ifIndex=$st.K;InterfaceGuid=$actualGuid}
    }
    function Remove-NetRoute {
        [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject,[switch]$Confirm)
        process {Check ($InputObject.DestinationPrefix -ceq $endpointPrefix) 'Touched an unrelated route';if(-not $retainRoute){[void]$net.Remove($InputObject)}}
    }
    Add-FixturePin
    Remove-RnEndpointRoute
    Check ($net.Count -eq 2) 'A new roaming session acquired ownership of a physical route'
    $marks['route.intent']=$true;$marks['route.created']=$true
    Remove-RnEndpointRoute;Remove-RnEndpointRoute
    Check ($net.Count -eq 1 -and [object]::ReferenceEquals($net[0],$original)) 'Recovery changed the existing default'
    $persistent=@([pscustomobject]@{DestinationPrefix=$endpointPrefix;InterfaceIndex=8;NextHop='192.0.2.1';RouteMetric=8})
    Rejected {Assert-RnEndpointRouteAvailable} 'specific endpoint route already exists in PersistentStore'
    Check ($net.Count -eq 1 -and $persistent.Count -eq 1) 'Persistent route was overwritten'
    $persistent=@()
    $marks.Clear();$marks['route.intent']=$true;Add-FixturePin
    Rejected {Remove-RnEndpointRoute} 'creation was not confirmed'
    Check ($net.Count -eq 2) 'Concurrent route was removed after failed creation'
    $marks['route.created']=$true
    $net[1].RouteMetric=8999;Remove-RnEndpointRoute
    Check ($net.Count -eq 2) 'Different metric route was removed'
    $net[1].RouteMetric=9000;$actualGuid='replacement-adapter';Remove-RnEndpointRoute
    Check ($net.Count -eq 2) 'A recycled interface index gained ownership'
    $actualGuid='fixture-wlan';$boot=$boot.AddDays(1);Remove-RnEndpointRoute
    Check ($net.Count -eq 2) 'Recovery touched a route from a newer boot'
    $boot=$boot.AddDays(-1);$providerFailure=$true
    Rejected {Remove-RnEndpointRoute} 'Fixture route provider unavailable'
    $providerFailure=$false
    function Stop-RnManualTunnel {}
    function Get-DnsClientNrptRule {}
    function Get-OwnFirewallRules {}
    function Clear-DnsClientCache {}
    function NetBaseline {$null}
    function Trace-Line($Text) {}
    $adapterFailure=$true
    Rejected {UndoMachine} 'Fixture adapter provider unavailable'
    Check (-not $marks['machine.ok'] -and $net.Count -eq 2) 'Adapter query failure was reported as restored'
    $adapterFailure=$false
    $retainRoute=$true
    Rejected {UndoMachine} 'Endpoint route still present after recovery'
    Check (-not $marks['machine.ok']) 'An unremoved endpoint route was reported as restored'
    $retainRoute=$false
    $marks.Remove('route.created');$st.PSObject.Properties.Remove('RouteOwnershipVersion')
    Rejected {Remove-RnEndpointRoute} 'creation was not confirmed'
    Check ($net.Count -eq 2) 'An old intent-only record acquired route ownership'
    $marks['svc.intent']=$true
    Remove-RnEndpointRoute
    Check ($net.Count -eq 1) 'Legacy saved sessions cannot restore their original route'
    $net.Clear()
    Remove-RnEndpointRoute # A disconnected machine may expose no IPv4 rows.
    Check ($net.Count -eq 0) 'Empty ActiveStore recovery changed routes'
}
'Offline validation passed: native uplink changes, endpoint exclusion orchestration, conflicts, legacy ownership, rollback and existing setup checks.'
