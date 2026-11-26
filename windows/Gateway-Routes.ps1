#Requires -Version 5.1
# These functions change only ActiveStore routes on the session's WireGuard adapter.
function Get-RnInternetPrefixes([string]$Endpoint) {
    $ip=$null
    if(-not [ipaddress]::TryParse($Endpoint,[ref]$ip) -or $ip.AddressFamily -ne 'InterNetwork' -or
        $ip.ToString() -cne $Endpoint){throw 'A canonical IPv4 endpoint is required.'}
    $bytes=$ip.GetAddressBytes()
    # At each bit keep the sibling subnet. The only leaf never included is the endpoint itself.
    $prefix=[byte[]]::new(4)
    for($bit=0;$bit -lt 32;$bit++){
        $octet=$bit -shr 3
        $mask=128 -shr ($bit % 8)
        $prefix[$octet]=$prefix[$octet] -bor ($bytes[$octet] -band $mask)
        $sibling=$prefix.Clone()
        $sibling[$octet]=$sibling[$octet] -bxor $mask
        ($sibling -join '.')+'/'+($bit+1)
    }
}

function Test-RnPrefixContains([string]$Network,[string]$Address) {
    $items=$Network.Split('/')
    $networkBytes=([ipaddress]$items[0]).GetAddressBytes()
    $addressBytes=([ipaddress]$Address).GetAddressBytes()
    $remaining=[int]$items[1]
    for($i=0;$remaining -gt 0;$i++){
        $bits=[Math]::Min(8,$remaining)
        if(($networkBytes[$i] -shr (8-$bits)) -ne ($addressBytes[$i] -shr (8-$bits))){return $false}
        $remaining-=$bits
    }
    return $true
}

function Get-RnRoamingAdapter([string]$TunnelName) {
    $a=@(Get-NetAdapter -ErrorAction Stop | Where-Object Name -eq $TunnelName)
    if($a.Count -eq 1 -and $a[0].Status -eq 'Up' -and -not $a[0].HardwareInterface -and
        $a[0].InterfaceDescription -match '^WireGuard Tunnel(?: #\d+)?$'){return $a[0]}
}

function Test-RnRoamingRoutes([string]$Endpoint,[string]$TunnelName) {
    $adapter=Get-RnRoamingAdapter $TunnelName
    if(-not $adapter){return $false}
    $routes=@(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop | Where-Object {
        $_.InterfaceIndex -eq $adapter.ifIndex -and $_.DestinationPrefix -notmatch ':'
    })
    $seen=@{}
    foreach($route in $routes){
        if(Test-RnPrefixContains $route.DestinationPrefix $Endpoint){return $false}
        if($route.NextHop -eq '0.0.0.0'){$seen[$route.DestinationPrefix]=$true}
    }
    foreach($prefix in (Get-RnInternetPrefixes $Endpoint)){
        if(-not $seen.ContainsKey($prefix)){return $false}
    }
    return $true
}

function Enable-RnRoamingRoutes([string]$Endpoint,[string]$TunnelName) {
    $adapter=Get-RnRoamingAdapter $TunnelName
    if(-not $adapter){throw 'WireGuard adapter is not ready for endpoint routing.'}
    $plans=@(Get-RnInternetPrefixes $Endpoint)
    $all=@(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop | Where-Object DestinationPrefix -NotMatch ':')
    $own=@($all | Where-Object InterfaceIndex -eq $adapter.ifIndex)
    $halves=@($own | Where-Object DestinationPrefix -in '0.0.0.0/1','128.0.0.0/1')
    if($halves.Count -ne 2){
        if(Test-RnRoamingRoutes $Endpoint $TunnelName){return}
        throw 'WireGuard default halves are incomplete before endpoint routing.'
    }
    $cover=@($halves | Where-Object {Test-RnPrefixContains $_.DestinationPrefix $Endpoint})
    if($cover.Count -ne 1 -or @($halves | Where-Object NextHop -ne '0.0.0.0').Count){
        throw 'Unexpected WireGuard endpoint route configuration.'
    }
    $children=@($plans | Select-Object -Skip 1)
    # Refuse a layout that would give a new subnet precedence over an existing LAN or VPN route.
    $others=@($all | Where-Object {$_.InterfaceIndex -ne $adapter.ifIndex -and $_.DestinationPrefix -ne '0.0.0.0/0'})
    foreach($child in $children){
        $parts=$child.Split('/')
        foreach($r in $others){
            $length=[int]($r.DestinationPrefix.Split('/')[1])
            if($length -le [int]$parts[1] -and (Test-RnPrefixContains $r.DestinationPrefix $parts[0])){
                throw 'Endpoint subnet overlaps an existing physical or VPN route; original routing must be preserved.'
            }
        }
    }
    # Install the replacement coverage before removing its parent. A failed start
    # is recovered by the controller, which tears down this session's adapter.
    foreach($child in $children){
        $existing=@($own | Where-Object DestinationPrefix -eq $child)
        if($existing.Count){
            if($existing.Count -ne 1 -or $existing[0].NextHop -ne '0.0.0.0' -or
                $existing[0].RouteMetric -ne $cover[0].RouteMetric -or $existing[0].Protocol -ne 'NetMgmt'){
                throw 'Unexpected existing WireGuard route during endpoint routing.'
            }
            continue
        }
        New-NetRoute -AddressFamily IPv4 -InterfaceIndex $adapter.ifIndex -DestinationPrefix $child -NextHop '0.0.0.0' -RouteMetric $cover[0].RouteMetric -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
    }
    $cover[0] | Remove-NetRoute -Confirm:$false -ErrorAction Stop
    if(-not (Test-RnRoamingRoutes $Endpoint $TunnelName)){throw 'Endpoint routing verification failed.'}
}
