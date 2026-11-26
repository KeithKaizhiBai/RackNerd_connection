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
$script:fixtureLegacyRoutes = $false
$script:fixtureMissingPrefix = $false
$script:fixturePinStore = ''
$script:fixtureEndpointPrefix = '0.0.0.0/0'
$script:fixtureProviderFailure = $false
$script:publicRequests = 0
function Get-NetIPInterface {
    [pscustomobject]@{InterfaceIndex=12; InterfaceMetric=5; ConnectionState='Connected'}
    [pscustomobject]@{InterfaceIndex=14; InterfaceMetric=5; ConnectionState='Connected'}
    [pscustomobject]@{InterfaceIndex=16; InterfaceMetric=500; ConnectionState=if($script:fixtureWlanConnected){'Connected'}else{'Disconnected'}}
}
function New-TestRoute([string]$Prefix, [int]$Index, [string]$Adapter) {
    [pscustomobject]@{DestinationPrefix=$Prefix; InterfaceIndex=$Index; InterfaceAlias=$Adapter; RouteMetric=1; NextHop='0.0.0.0'}
}
function Get-NetRoute($PolicyStore,$AddressFamily,$ErrorAction) {
    Assert-Equal 'Stop' $ErrorAction 'Route read errors must be visible'
    Assert-Equal $false $PSBoundParameters.ContainsKey('AddressFamily') 'Empty IPv4 stores are enumerated safely'
    if($script:fixtureProviderFailure){throw 'Fixture route provider failed'}
    if($PolicyStore -eq $script:fixturePinStore){New-TestRoute ($script:fixtureIp+'/32') 12 'Ethernet'}
    if($PolicyStore -eq 'PersistentStore'){return}
    New-TestRoute '0.0.0.0/0' 12 'Ethernet'
    New-TestRoute '0.0.0.0/0' 16 'WLAN'
    if (-not $script:fixtureRunning) { return }
    if($script:fixtureLegacyRoutes){
        New-TestRoute '0.0.0.0/1' 14 'rn-public'
        New-TestRoute '128.0.0.0/1' 14 'rn-public'
    }else{
        $prefixes=@(Get-RnInternetPrefixes $script:fixtureIp)
        if($script:fixtureMissingPrefix){$prefixes=$prefixes[0..30]}
        foreach($prefix in $prefixes){New-TestRoute $prefix 14 'rn-public'}
    }
    if ($script:fixtureCompetition) { New-TestRoute '0.0.0.0/1' 12 'Ethernet' }
}
function Get-NetAdapter {
    [pscustomobject]@{Name='Ethernet'; HardwareInterface=$true; Status='Up'; ifIndex=12; InterfaceGuid='fixture-ethernet'}
    [pscustomobject]@{Name='WLAN'; HardwareInterface=$true; Status='Up'; ifIndex=16; InterfaceGuid='fixture-wlan'}
    $state = if ($script:fixtureRunning) { 'Up' } else { 'Disconnected' }
    [pscustomobject]@{Name='rn-public'; HardwareInterface=$false; Status=$state; ifIndex=14;InterfaceDescription='WireGuard Tunnel'}
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
    if($RemoteIPAddress -ne $script:fixtureIp){
        Assert-Equal $true ($RemoteIPAddress -in '1.1.1.1','9.9.9.9','208.67.222.222') 'Ordinary IPv4 route target'
        if($script:fixtureRunning -and -not $script:fixtureCompetition){
            $prefix=@(Get-RnInternetPrefixes $script:fixtureIp | Where-Object {Test-RnPrefixContains $_ $RemoteIPAddress})
            Assert-Equal 1 $prefix.Count 'Probe has one expected roaming prefix'
            New-TestRoute $prefix[0] 14 'rn-public'
            [pscustomobject]@{IPAddress='10.203.84.2';InterfaceIndex=14;AddressState='Preferred';SkipAsSource=$false}
        }else{
            New-TestRoute '0.0.0.0/0' 12 'Ethernet'
            [pscustomobject]@{IPAddress='192.0.2.12';InterfaceIndex=12;AddressState='Preferred';SkipAsSource=$false}
        }
        return
    }
    if ($script:fixturePhysical) {
        $name=if($script:fixtureEndpointIndex -eq 12){'Ethernet'}else{'WLAN'}
        $route=New-TestRoute $script:fixtureEndpointPrefix $script:fixtureEndpointIndex $name
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

Assert-Equal 'Verified' (Read-TestView).Kind 'Endpoint-excluding routes, physical default, source and public IP'
Assert-Equal 'rn-public → Ethernet' (Get-RnLocalPath (Get-RnSettings)).Route 'Status reports current physical uplink'
$script:fixtureEndpointIndex=16
Assert-Equal 'Verified' (Read-TestView).Kind 'Windows selected WLAN while both physical adapters are online'
Assert-Equal 'rn-public → WLAN' (Get-RnLocalPath (Get-RnSettings)).Route 'Status follows native selected WLAN'
$script:fixtureEndpointHop='0.0.0.0'
$script:fixtureEndpointPrefix='203.0.113.0/24'
Assert-Equal 'Verified' (Read-TestView).Kind 'Actual physical endpoint is on-link'
$script:fixtureEndpointHop='192.0.2.1'
$script:fixtureEndpointPrefix='0.0.0.0/0'
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
Assert-Equal 'Verified' (Read-TestView).Kind 'Fresh public probe accepts the changed physical uplink'
foreach($script:fixturePinStore in 'ActiveStore','PersistentStore'){
    Assert-Equal 'Warning' (Read-TestView).Kind ('Endpoint pin retained in '+$script:fixturePinStore)
}
$script:fixturePinStore=''
$script:fixtureEndpointPrefix=$script:fixtureIp+'/32'
Assert-Equal 'Warning' (Read-TestView).Kind 'Native lookup still finds a pin'
$script:fixtureEndpointPrefix='0.0.0.0/0'
$script:fixtureLegacyRoutes=$true
Assert-Equal 'Warning' (Read-TestView).Kind 'Unconverted pair of half-defaults still covers the endpoint'
$script:fixtureLegacyRoutes=$false
$script:fixtureMissingPrefix=$true
Assert-Equal 'Warning' (Read-TestView).Kind 'Missing narrow sibling route is not a complete gateway'
$script:fixtureMissingPrefix=$false
$script:fixtureProviderFailure=$true
$unreadable=Get-RnPanelSample $true
Assert-Equal 'Unknown' (Get-RnPanelView $unreadable.Local $unreadable.Check).Kind 'Route provider failures cannot report a good path'
$script:fixtureProviderFailure=$false
$script:fixtureProxy = $null
Assert-Equal 'Warning' (Read-TestView).Kind 'Uncertain system proxy'
$script:fixtureProxy = 9
Assert-Equal 'Warning' (Read-TestView).Kind 'Automatic discovery is enabled'
$script:fixtureProxy = 1
$script:fixtureCompetition = $true
Assert-Equal 'Warning' (Read-TestView).Kind 'Windows selects a competing route for ordinary traffic'
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
