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
    . (Read-TestFunction 'Gateway-Mode.ps1' 'NewState')
    $current='fixture-state';$endpointPrefix='198.51.100.8/32'
    function Test-Path($LiteralPath) {$false}
    $net=@([pscustomobject]@{DestinationPrefix='0.0.0.0/0';NextHop='192.0.2.1';InterfaceIndex=7})
    function Get-NetRoute($AddressFamily,$PolicyStore) {$net}
    $devices=@([pscustomobject]@{ifIndex=7;HardwareInterface=$true;Status='Up';Name='fixture-ethernet';InterfaceDescription='Ethernet'},
        [pscustomobject]@{ifIndex=12;HardwareInterface=$false;Status='Up';Name='fixture-tun';InterfaceDescription='virtual tunnel'})
    function Get-NetAdapter {$devices}
    function Get-Service($Name,$ErrorAction) {}
    function Get-NetIPAddress($IPAddress,$ErrorAction) {}
    function Get-VpnConnection([switch]$AllUserConnection,$ErrorAction) {}
    Rejected {NewState 'Test'} 'VPN or TUN'
    $net+=[pscustomobject]@{DestinationPrefix='128.0.0.0/1';NextHop='0.0.0.0';InterfaceIndex=12}
    Rejected {NewState 'Test'} 'half-default'
    $net+= [pscustomobject]@{DestinationPrefix='198.51.100.8/32';NextHop='192.0.2.1';InterfaceIndex=7}
    Rejected {NewState 'Test'} 'specific endpoint'
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
    foreach ($n in 'UndoMachine','UndoUser','Get-OwnFirewallRules') {. (Read-TestFunction 'Gateway-Mode.ps1' $n)}
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
'Offline validation passed: parsing, inputs, profile, scheduled rollback, TUN conflicts, trial qualification and scoped cleanup.'
