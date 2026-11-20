#Requires -Version 5.1
#Requires -RunAsAdministrator
# Run from a reviewed local release in native Windows PowerShell (powershell.exe).
# Install official WireGuard for Windows first. This setup does not start any tunnel.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$EndpointIPv4,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ServerPublicKey,
    [ValidateRange(1,65535)][int]$Port=51820
)
$ErrorActionPreference='Stop'
if ($PSVersionTable.PSEdition -ne 'Desktop' -or -not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell 5.1.' }
. (Join-Path $PSScriptRoot 'Gateway-Common.ps1')
Assert-RnPublicEndpoint $EndpointIPv4
Assert-RnPublicKey $ServerPublicKey
Assert-RnUdpPort $Port
$base=Get-RnPackageRoot
$programs=Split-Path -Parent $base
Assert-RnProtectedPath $programs
$wg=Join-Path $programs 'WireGuard'
foreach ($f in 'wireguard.exe','wg.exe') {
    $bin=Join-Path $wg $f
    if (-not [IO.File]::Exists($bin)) { throw 'Install the signed WireGuard for Windows client from https://www.wireguard.com/install/ first.' }
    Assert-RnProtectedPath $wg
    Assert-RnProtectedPath $bin
    $sig=Get-AuthenticodeSignature -LiteralPath $bin
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch '(?:^|, )CN=WireGuard LLC(?:,|$)') { throw 'WireGuard publisher verification failed.' }
}
function New-RnDirectory([string]$Path,[bool]$Readable) {
    if (-not (Test-Path -LiteralPath $Path)) {
        $sddl='O:BAG:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)'
        if ($Readable) { $sddl+='(A;OICI;GRGX;;;BU)' }
        $acl=New-Object Security.AccessControl.DirectorySecurity
        $acl.SetSecurityDescriptorSddlForm($sddl)
        ([IO.DirectoryInfo]$Path).Create($acl)
    }
    Assert-RnProtectedPath $Path -Private:(-not $Readable)
}
function Write-RnNew([string]$Path,[byte[]]$Bytes) {
    $tmp=Join-Path ([IO.Path]::GetDirectoryName($Path)) ([guid]::NewGuid().ToString('N')+'.pending')
    try {
        $s=[IO.File]::Open($tmp,'CreateNew','Write','None')
        try {$s.Write($Bytes,0,$Bytes.Length);$s.Flush($true)} finally {$s.Dispose()}
        [IO.File]::Move($tmp,$Path)
    } finally {if ([IO.File]::Exists($tmp)) {[IO.File]::Delete($tmp)}}
}
$marker=Join-Path $base 'package.id'
$tag='RackNerd-Connection/windows/v1'
if (Test-Path -LiteralPath $base) {
    Assert-RnProtectedPath $base
    Assert-RnProtectedPath $marker
    if ([IO.File]::ReadAllText($marker) -cne $tag) {throw 'The install directory belongs to another package.'}
} else {
    New-RnDirectory $base $true
    Write-RnNew $marker ([Text.Encoding]::ASCII.GetBytes($tag))
}
$vault=Join-Path $base 'GatewayProfile'
$state=Join-Path $base 'State'
New-RnDirectory $vault $false
New-RnDirectory $state $false
$lock=[IO.File]::Open((Join-Path $vault 'install.lock'),'OpenOrCreate','ReadWrite','None')
try {
    # Same-release repair is idempotent. Do not replace code used by a session or by pending recovery tasks.
    $files=@('Gateway-Common.ps1','Gateway-Service.ps1','Gateway-WinInet.ps1','Prepare-Profile.ps1','Gateway-Mode.ps1','Gateway-Feedback.ps1','Gateway-PanelAction.ps1')
    foreach ($name in $files) {
        $src=Join-Path $PSScriptRoot $name; $dest=Join-Path $base $name
        $sourceItem=Get-Item -Force -LiteralPath $src -ErrorAction Stop
        if ($sourceItem.PSIsContainer -or ($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'Unexpected source type.'}
        if (Test-Path -LiteralPath $dest) {
            Assert-RnProtectedPath $dest
            if ((Get-FileHash -LiteralPath $dest).Hash -cne (Get-FileHash -LiteralPath $src).Hash) { throw "Installed $name differs. Do not update an existing controller in place." }
        } else { Write-RnNew $dest ([IO.File]::ReadAllBytes($src)) }
        Assert-RnProtectedPath $dest
        if ((Get-FileHash -LiteralPath $dest).Hash -cne (Get-FileHash -LiteralPath $src).Hash) { throw 'Installed helper verification failed.' }
    }
    $requestPath=Join-Path $vault 'setup.json'
    $request=[ordered]@{EndpointIPv4=$EndpointIPv4;ServerPublicKey=$ServerPublicKey;Port=$Port}
    if (-not [IO.File]::Exists($requestPath)) { Write-RnNew $requestPath ([Text.Encoding]::ASCII.GetBytes(($request | ConvertTo-Json -Compress))) }
    Assert-RnProtectedPath $requestPath -Private
    $old=[IO.File]::ReadAllText($requestPath) | ConvertFrom-Json
    if ($old.EndpointIPv4 -cne $EndpointIPv4 -or $old.Port -ne $Port -or $old.ServerPublicKey -cne $ServerPublicKey) { throw 'This installation is already bound to another endpoint or peer. Existing keys were retained.' }
    $prepared=& (Join-Path $base 'Prepare-Profile.ps1')
    Assert-RnPublicKey $prepared.PublicKey
    $publicPath=Join-Path $base 'public.json'
    $public=[ordered]@{EndpointIPv4=$EndpointIPv4;Port=$Port;ServerPublicKey=$ServerPublicKey;ClientPublicKey=[string]$prepared.PublicKey}
    if (-not [IO.File]::Exists($publicPath)) { Write-RnNew $publicPath ([Text.Encoding]::ASCII.GetBytes(($public | ConvertTo-Json -Compress))) }
    $verified=Get-RnPublicMetadata $base
    foreach ($k in $public.Keys) { if ([string]$verified.$k -cne [string]$public[$k]) { throw 'Public enrollment data conflicts with the encrypted profile.' } }
    [pscustomobject]@{ClientPublicKey=$verified.ClientPublicKey;ClientTunnelIPv4='10.203.84.2/32';PublicSettings=$publicPath;Controller=(Join-Path $base 'Gateway-Mode.ps1')}
} finally {$lock.Dispose()}
