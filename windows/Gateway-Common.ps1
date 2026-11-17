# Pure input checks and read-only helpers for Windows PowerShell 5.1.
function Get-RnPackageRoot {
    if (-not [Environment]::Is64BitProcess) { throw 'Use native 64-bit Windows PowerShell.' }
    Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)) 'RackNerd-Connection'
}

function Assert-RnPublicEndpoint([string]$Value) {
    $ip = [Net.IPAddress]::None
    if (-not [Net.IPAddress]::TryParse($Value,[ref]$ip) -or
        $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $ip.ToString() -cne $Value) {
        throw 'Enter a canonical dotted-decimal public IPv4 address.'
    }
    $b=$ip.GetAddressBytes()
    if ($b[0] -in 0,10,127 -or $b[0] -ge 224 -or
        ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) -or
        ($b[0] -eq 169 -and $b[1] -eq 254) -or
        ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or
        ($b[0] -eq 192 -and ($b[1] -eq 168 -or ($b[1] -eq 0 -and $b[2] -in 0,2) -or ($b[1] -eq 88 -and $b[2] -eq 99))) -or
        ($b[0] -eq 198 -and ($b[1] -in 18,19 -or ($b[1] -eq 51 -and $b[2] -eq 100))) -or
        ($b[0] -eq 203 -and $b[1] -eq 0 -and $b[2] -eq 113)) {
        throw 'A globally routable unicast VPS IPv4 address is required.'
    }
}

function Assert-RnPublicKey([string]$Value) {
    if ($Value -cnotmatch '^[A-Za-z0-9+/]{43}=$') { throw 'Invalid WireGuard public key.' }
    $buf=[Convert]::FromBase64String($Value)
    if ($buf.Length -ne 32 -or [Convert]::ToBase64String($buf) -cne $Value -or -not ($buf | Where-Object { $_ -ne 0 })) {
        throw 'Invalid WireGuard public key.'
    }
}

function Assert-RnUdpPort([int]$Port) {
    if ($Port -lt 1 -or $Port -gt 65535) {throw 'UDP port must be in the range 1..65535.'}
    if ($Port -in 53,853) {throw 'Choose a WireGuard UDP port other than 53 or 853. Off-tunnel DNS on those ports is blocked in gateway mode.'}
}

function Assert-RnTaskPrincipal($Principal,[string]$ExpectedSid) {
    $name=[string]$Principal.UserId
    if ($name -in 'SYSTEM','NT AUTHORITY\SYSTEM','S-1-5-18') {$actual='S-1-5-18'}
    elseif ($name -match '^S-(?:[0-9]+-)+[0-9]+$') {$actual=$name}
    else {$actual=([Security.Principal.NTAccount]::new($name)).Translate([Security.Principal.SecurityIdentifier]).Value}
    $logon=[string]$Principal.LogonType
    if ($actual -cne $ExpectedSid -or [string]$Principal.RunLevel -notin 'Highest','HighestAvailable' -or
        ($ExpectedSid -eq 'S-1-5-18' -and $logon -ne 'ServiceAccount') -or
        ($ExpectedSid -ne 'S-1-5-18' -and $logon -notin 'Interactive','InteractiveToken')) {throw 'Scheduled task principal ownership mismatch.'}
}

function Assert-RnProtectedPath([string]$Path,[switch]$Private) {
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Unexpected filesystem link: $Path" }
    $id=[Security.Principal.SecurityIdentifier]
    $trusted=@('S-1-5-18','S-1-5-32-544')
    if (-not $Private) { $trusted+='S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' }
    $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
    if ($acl.GetOwner($id).Value -notin $trusted) { throw "Unexpected owner: $Path" }
    $write=[Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
    foreach ($rule in $acl.GetAccessRules($true,$true,$id)) {
        if ($rule.AccessControlType -ne 'Allow' -or $rule.IdentityReference.Value -in $trusted -or
            ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
        if ($Private -or ($rule.FileSystemRights -band $write)) { throw "Unsafe permissions: $Path" }
    }
}

function Get-RnPublicMetadata([string]$Base) {
    Assert-RnProtectedPath (Split-Path -Parent $Base)
    Assert-RnProtectedPath $Base
    $p=Join-Path $Base 'public.json'
    Assert-RnProtectedPath $p
    $v=[IO.File]::ReadAllText($p) | ConvertFrom-Json -ErrorAction Stop
    Assert-RnPublicEndpoint $v.EndpointIPv4
    Assert-RnPublicKey $v.ServerPublicKey
    Assert-RnPublicKey $v.ClientPublicKey
    if ($v.ServerPublicKey -ceq $v.ClientPublicKey -or $v.Port -isnot [ValueType] -or [int]$v.Port -ne $v.Port -or $v.Port -lt 1 -or $v.Port -gt 65535) { throw 'Invalid public setup record.' }
    Assert-RnUdpPort $v.Port
    return $v
}
