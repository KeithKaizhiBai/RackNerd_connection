#requires -Version 5.1
# Offline regression checks. Network, service and public-IP reads below are local fixtures.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Gateway-Status.ps1')

function Assert-Equal($Expected, $Actual, [string]$Case) {
    if ($Expected -cne $Actual) { throw "$Case expected [$Expected], got [$Actual]." }
}
Assert-Equal 'Missing' (Get-RnSettings (Join-Path $PSScriptRoot ([guid]::NewGuid().ToString()+'.json'))).State 'Missing configuration'
Assert-Equal 'Invalid' (Get-RnSettings $PSCommandPath).State 'Invalid configuration'
Assert-Equal '未知' (Get-RnProxyText $null) 'Unreadable proxy'
Assert-Equal '直连' (Get-RnProxyText 1) 'Direct WinINet'
Assert-Equal '手动代理、代理脚本、自动检测' (Get-RnProxyText 15) 'Manual, PAC and autodetect flags'
Assert-Equal '未知' (Get-RnProxyText 0) 'Empty proxy flags'

$script:fixtureState = 'Ready'
$script:fixtureIp = '203.0.113.10'
$script:fixtureProxy = 1
$script:fixturePhysical = $true
$script:fixtureCompetition = $false
$script:fixtureRunning = $true
$script:fixturePublic = $script:fixtureIp
$script:fixtureSource = '10.203.84.2'
$script:fixtureEndpointIndex = 12
$script:fixtureEndpointHop = '192.0.2.1'
$script:fixtureEndpointAmbiguous = $false
$script:fixtureEndpointSourceMode = 'Normal'
$script:fixtureWlanConnected = $true
$script:fixtureEndpointChange = $false
$script:publicRequests = 0
function Get-NetIPInterface {
    [pscustomobject]@{InterfaceIndex=12; InterfaceMetric=5; ConnectionState='Connected'}
    [pscustomobject]@{InterfaceIndex=14; InterfaceMetric=5; ConnectionState='Connected'}
    [pscustomobject]@{InterfaceIndex=16; InterfaceMetric=500; ConnectionState=if($script:fixtureWlanConnected){'Connected'}else{'Disconnected'}}
}
function New-TestRoute([string]$Prefix, [int]$Index, [string]$Adapter) {
    [pscustomobject]@{DestinationPrefix=$Prefix; InterfaceIndex=$Index; InterfaceAlias=$Adapter; RouteMetric=1; NextHop='0.0.0.0'}
}
function Get-NetRoute {
    New-TestRoute '0.0.0.0/0' 12 'Ethernet'
    New-TestRoute '0.0.0.0/0' 16 'WLAN'
    if (-not $script:fixtureRunning) { return }
    New-TestRoute '0.0.0.0/1' 14 'rn-public'
    New-TestRoute '128.0.0.0/1' 14 'rn-public'
    if ($script:fixtureCompetition) { New-TestRoute '0.0.0.0/1' 12 'Ethernet' }
}
function Get-NetAdapter {
    [pscustomobject]@{Name='Ethernet'; HardwareInterface=$true; Status='Up'; ifIndex=12; InterfaceGuid='fixture-ethernet'}
    [pscustomobject]@{Name='WLAN'; HardwareInterface=$true; Status='Up'; ifIndex=16; InterfaceGuid='fixture-wlan'}
    $state = if ($script:fixtureRunning) { 'Up' } else { 'Disconnected' }
    [pscustomobject]@{Name='rn-public'; HardwareInterface=$false; Status=$state; ifIndex=14}
}
function Get-Service {
    $state = if ($script:fixtureRunning) { 'Running' } else { 'Stopped' }
    [pscustomobject]@{Name='WireGuardTunnel$rn-public'; Status=$state}
}
function Get-NetIPAddress { [pscustomobject]@{IPAddress='10.203.84.2'; AddressState='Preferred'; SkipAsSource=$false} }
function Get-RnProxyFlags {
    if ($null -eq $script:fixtureProxy) { throw 'Simulated WinINet failure' }
    $script:fixtureProxy
}
function Find-NetRoute([string]$RemoteIPAddress) {
    Assert-Equal $script:fixtureIp $RemoteIPAddress 'Endpoint from public settings'
    if ($script:fixturePhysical) {
        $name=if($script:fixtureEndpointIndex -eq 12){'Ethernet'}else{'WLAN'}
        $route=New-TestRoute ($RemoteIPAddress+'/32') $script:fixtureEndpointIndex $name
        $route.NextHop=$script:fixtureEndpointHop
    } else {$route=New-TestRoute '128.0.0.0/1' 14 'rn-public'}
    $route
    if($script:fixtureEndpointAmbiguous){$route}
    if($script:fixtureEndpointSourceMode -ne 'Missing'){
        $src=[pscustomobject]@{IPAddress='192.0.2.'+$script:fixtureEndpointIndex;InterfaceIndex=$script:fixtureEndpointIndex;AddressState='Preferred';SkipAsSource=$false}
        if($script:fixtureEndpointSourceMode -eq 'WrongInterface'){$src.InterfaceIndex=99}
        if($script:fixtureEndpointSourceMode -eq 'Tentative'){$src.AddressState='Tentative'}
        $src
        if($script:fixtureEndpointSourceMode -eq 'Duplicate'){$src}
    }
}
function Get-RnSettings { [pscustomobject]@{State=$script:fixtureState; Endpoint=$script:fixtureIp} }
function Get-RnPublicProbe([string]$Key) {
    $script:publicRequests++
    if($script:fixtureEndpointChange){$script:fixtureEndpointIndex=16}
    [pscustomobject]@{Key=$Key; At=[datetime]::Now; Ip=$script:fixturePublic; Source=$script:fixtureSource}
}
function Read-TestView {
    $sample = Get-RnPanelSample $true
    if ($sample.ErrorText) { throw $sample.ErrorText }
    Get-RnPanelView $sample.Local $sample.Check
}

Assert-Equal 'Verified' (Read-TestView).Kind 'Matching routes, source, endpoint and public IP'
$script:fixtureEndpointIndex=16
Assert-Equal 'Verified' (Read-TestView).Kind 'Windows selected WLAN while both physical adapters are online'
$script:fixtureEndpointHop='0.0.0.0'
Assert-Equal 'Verified' (Read-TestView).Kind 'Actual physical endpoint is on-link'
$script:fixtureEndpointHop='192.0.2.1'
$script:fixtureWlanConnected=$false
Assert-Equal 'Warning' (Read-TestView).Kind 'Endpoint cannot use IPv4-disconnected WLAN'
$script:fixtureWlanConnected=$true
$script:fixtureEndpointAmbiguous=$true
Assert-Equal 'Warning' (Read-TestView).Kind 'Ambiguous endpoint selection cannot be green'
$script:fixtureEndpointAmbiguous=$false
foreach($script:fixtureEndpointSourceMode in 'Missing','Duplicate','WrongInterface','Tentative'){
    Assert-Equal 'Warning' (Read-TestView).Kind ('Invalid endpoint source: '+$script:fixtureEndpointSourceMode)
}
$script:fixtureEndpointSourceMode='Normal'
$script:fixtureEndpointIndex=12;$script:fixtureEndpointChange=$true
Assert-Equal 'Pending' (Read-TestView).Kind 'Physical endpoint changed during public probe'
$script:fixtureEndpointChange=$false
$script:fixtureProxy = $null
Assert-Equal 'Warning' (Read-TestView).Kind 'Uncertain system proxy'
$script:fixtureProxy = 9
Assert-Equal 'Warning' (Read-TestView).Kind 'Automatic discovery is enabled'
$script:fixtureProxy = 1
$script:fixtureCompetition = $true
Assert-Equal 'Warning' (Read-TestView).Kind 'Equal-cost competing route'
$script:fixtureCompetition = $false
$script:fixturePhysical = $false
Assert-Equal 'Warning' (Read-TestView).Kind 'Endpoint inside the tunnel'
$script:fixturePhysical = $true
$script:fixturePublic = '203.0.113.11'
Assert-Equal 'Warning' (Read-TestView).Kind 'Different public IP'
$script:fixturePublic = $script:fixtureIp
$script:fixtureSource = '203.0.113.12'
Assert-Equal 'Warning' (Read-TestView).Kind 'Wrong local source'
$script:fixtureSource = '10.203.84.2'
$s = Get-RnPanelSample $true
$s.Check.At = [datetime]::Now.AddMinutes(-5)
Assert-Equal 'Pending' (Get-RnPanelView $s.Local $s.Check).Kind 'Expired probe'
$s.Check.At = [datetime]::Now
$s.Check.Key = 'previous route'
Assert-Equal 'Pending' (Get-RnPanelView $s.Local $s.Check).Kind 'Changed route'
$script:fixtureRunning = $false
Assert-Equal 'Off' (Read-TestView).Kind 'Stopped service with an inactive adapter and ordinary route'

$before = $script:publicRequests
$script:fixtureState = 'Missing'
Assert-Equal 'Setup' (Read-TestView).Kind 'Missing configuration is actionable'
Assert-Equal $before $script:publicRequests 'No public probe before configuration'
'Offline panel status tests passed.'
