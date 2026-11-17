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
$script:publicRequests = 0
function Get-NetIPInterface {
    [pscustomobject]@{InterfaceIndex=12; InterfaceMetric=5; ConnectionState='Connected'}
    [pscustomobject]@{InterfaceIndex=14; InterfaceMetric=5; ConnectionState='Connected'}
}
function New-TestRoute([string]$Prefix, [int]$Index, [string]$Adapter) {
    [pscustomobject]@{DestinationPrefix=$Prefix; InterfaceIndex=$Index; InterfaceAlias=$Adapter; RouteMetric=1; NextHop='0.0.0.0'}
}
function Get-NetRoute {
    New-TestRoute '0.0.0.0/0' 12 'Ethernet'
    if (-not $script:fixtureRunning) { return }
    New-TestRoute '0.0.0.0/1' 14 'rn-public'
    New-TestRoute '128.0.0.0/1' 14 'rn-public'
    if ($script:fixtureCompetition) { New-TestRoute '0.0.0.0/1' 12 'Ethernet' }
}
function Get-NetAdapter {
    [pscustomobject]@{Name='Ethernet'; HardwareInterface=$true; Status='Up'; ifIndex=12}
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
    if ($script:fixturePhysical) { New-TestRoute ($RemoteIPAddress+'/32') 12 'Ethernet' }
    else { New-TestRoute '128.0.0.0/1' 14 'rn-public' }
}
function Get-RnSettings { [pscustomobject]@{State=$script:fixtureState; Endpoint=$script:fixtureIp} }
function Get-RnPublicProbe([string]$Key) {
    $script:publicRequests++
    [pscustomobject]@{Key=$Key; At=[datetime]::Now; Ip=$script:fixturePublic; Source=$script:fixtureSource}
}
function Read-TestView {
    $sample = Get-RnPanelSample $true
    if ($sample.ErrorText) { throw $sample.ErrorText }
    Get-RnPanelView $sample.Local $sample.Check
}

Assert-Equal 'Verified' (Read-TestView).Kind 'Matching routes, source, endpoint and public IP'
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
