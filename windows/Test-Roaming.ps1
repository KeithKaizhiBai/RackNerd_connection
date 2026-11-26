#Requires -Version 5.1
# Offline fixtures. No operating-system route or adapter is touched.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Gateway-Routes.ps1')
function Check([bool]$condition,[string]$message){if(-not $condition){throw $message}}
foreach($endpoint in '0.0.0.0','255.255.255.255','192.0.2.10','203.0.113.255','128.0.0.0'){
    $cover=@(Get-RnInternetPrefixes $endpoint)
    Check ($cover.Count -eq 32) 'Unexpected prefix count'
    $size=0L
    for($i=0;$i -lt $cover.Count;$i++){
        $prefix=$cover[$i];$length=$i+1
        Check ($prefix.EndsWith('/'+$length)) 'Incorrect prefix length'
        Check (-not (Test-RnPrefixContains $prefix $endpoint)) 'Endpoint is covered'
        $address=$prefix.Split('/')[0]
        for($j=0;$j -lt $i;$j++){Check (-not (Test-RnPrefixContains $cover[$j] $address)) 'Prefix intersection'}
        $size+=[long][Math]::Pow(2,32-$length)
    }
    Check ($size -eq 4294967295L) 'Cover leaves a second address outside the tunnel'
}
$endpoint='192.0.2.10'
$physical=@(
    [pscustomobject]@{InterfaceIndex=1;DestinationPrefix='0.0.0.0/0';NextHop='203.0.113.1';RouteMetric=5}
    [pscustomobject]@{InterfaceIndex=2;DestinationPrefix='0.0.0.0/0';NextHop='198.51.100.1';RouteMetric=10}
)
$adapter=[pscustomobject]@{ifIndex=7;Name='fixture';Status='Up';HardwareInterface=$false;InterfaceDescription='WireGuard Tunnel'}
function Get-NetAdapter($ErrorAction){$adapter}
function Get-NetRoute($PolicyStore,$ErrorAction){Check ($PolicyStore -eq 'ActiveStore') 'Incorrect route store';$physical;$tunnel.ToArray()}
function New-NetRoute($AddressFamily,$InterfaceIndex,$DestinationPrefix,$NextHop,$RouteMetric,$PolicyStore,$ErrorAction){
    Check ($InterfaceIndex -eq $adapter.ifIndex -and $PolicyStore -eq 'ActiveStore' -and $AddressFamily -eq 'IPv4') 'Route created outside session adapter'
    if($DestinationPrefix -eq $failOn){throw 'Injected creation failure'}
    $tunnel.Add([pscustomobject]@{InterfaceIndex=$InterfaceIndex;DestinationPrefix=$DestinationPrefix;NextHop=$NextHop;RouteMetric=$RouteMetric;Protocol='NetMgmt'})
}
function Remove-NetRoute {
    param([Parameter(ValueFromPipeline)]$InputObject,$Confirm)
    process {Check ($InputObject.InterfaceIndex -eq 7) 'Removed a physical route';[void]$tunnel.Remove($InputObject)}
}
function Reset-Fixture {
    $script:tunnel=[Collections.Generic.List[object]]::new()
    foreach($prefix in '0.0.0.0/1','128.0.0.0/1'){New-NetRoute IPv4 7 $prefix '0.0.0.0' 0 ActiveStore Stop}
}
Reset-Fixture
$conflict=[pscustomobject]@{InterfaceIndex=1;DestinationPrefix='192.0.2.0/24';NextHop='0.0.0.0';RouteMetric=0}
$physical+=$conflict
try{Enable-RnRoamingRoutes $endpoint 'fixture';throw 'Uncaught overlap'}catch{if($_.Exception.Message -notlike '*overlaps*'){throw}}
Check ($tunnel.Count -eq 2) 'Changed routes on a rejected layout'
$physical=@($physical | Where-Object {$_ -ne $conflict})
$failOn='192.0.2.11/32'
try{Enable-RnRoamingRoutes $endpoint 'fixture';throw 'Failure injection missed'}catch{if($_.Exception.Message -ne 'Injected creation failure'){throw}}
Check ('128.0.0.0/1' -in $tunnel.DestinationPrefix) 'Partial apply removed the parent route'
$failOn=$null
Enable-RnRoamingRoutes $endpoint 'fixture'
Enable-RnRoamingRoutes $endpoint 'fixture'
Check ($tunnel.Count -eq 32 -and (Test-RnRoamingRoutes $endpoint 'fixture')) 'Conversion or retry failed'
Check ($physical.Count -eq 2 -and $physical[0].RouteMetric -eq 5 -and $physical[1].RouteMetric -eq 10) 'Physical routing changed'
$tunnel.RemoveAt(0)
Check (-not (Test-RnRoamingRoutes $endpoint 'fixture')) 'Incomplete coverage reported ready'
'PASS: one-address exclusion, coverage, LAN preservation, safe retry, adapter-only changes and missing-route detection.'
