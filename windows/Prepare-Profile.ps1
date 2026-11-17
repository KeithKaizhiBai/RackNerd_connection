#Requires -Version 5.1
#Requires -RunAsAdministrator
# Creates an offline WireGuard profile. WireGuard reads named, SYSTEM-encrypted
# DPAPI files directly; its manager only watches its own Configurations folder.
[CmdletBinding()]
param([switch]$SystemWorker)

$ErrorActionPreference = 'Stop'
$programs = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$setup = Join-Path $programs 'RackNerd-Connection'
$vault = Join-Path $setup 'GatewayProfile'
$config = Join-Path $vault 'rn-public.conf.dpapi'
$publicRecord = Join-Path $vault 'windows.pub'
$wgDir = Join-Path $programs 'WireGuard'
$keyPattern = '^[A-Za-z0-9+/]{43}=$'
$systemSid = 'S-1-5-18'
$adminSid = 'S-1-5-32-544'
$installerSid = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'

function Assert-SafePath([string]$Path, [switch]$Private) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Unexpected link: $Path" }
    $acl = Get-Acl -LiteralPath $Path
    $sidType = [Security.Principal.SecurityIdentifier]
    if ($acl.GetOwner($sidType).Value -notin @($systemSid,$adminSid,$installerSid)) { throw "Unexpected owner: $Path" }
    $trusted = @($systemSid,$adminSid)
    if (-not $Private) { $trusted += $installerSid }
    $rights = [Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
    foreach ($ace in $acl.GetAccessRules($true,$true,$sidType)) {
        if ($ace.AccessControlType -ne 'Allow' -or $ace.IdentityReference.Value -in $trusted) { continue }
        if ($ace.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        if ($Private -or ($ace.FileSystemRights -band $rights)) { throw "Unexpected permissions: $Path" }
    }
}

function Save-NewFile([string]$Path,[byte[]]$Bytes) {
    $folder = [IO.Path]::GetDirectoryName($Path)
    $pending = Join-Path $folder ([guid]::NewGuid().ToString('N') + '.pending')
    try {
        $stream = [IO.File]::Open($pending, 'CreateNew', 'Write', 'None')
        try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        [IO.File]::Move($pending, $Path)
    } finally {
        if ([IO.File]::Exists($pending)) { [IO.File]::Delete($pending) }
    }
}

function Read-PublicKey([string]$Path) {
    Assert-SafePath $Path
    $pub = [IO.File]::ReadAllText($Path).Trim()
    if ($pub -cnotmatch $keyPattern) { throw "Bad public key: $Path" }
    return $pub
}

function ConfigText([string]$PrivateKey, [string]$Peer) {
    return @(
        '[Interface]', "PrivateKey = $PrivateKey", 'Address = 10.203.84.2/32',
        'DNS = 1.1.1.1, 9.9.9.9', 'MTU = 1380', '', '[Peer]', "PublicKey = $Peer",
        "Endpoint = $($request.EndpointIPv4):$($request.Port)", 'AllowedIPs = 0.0.0.0/1, 128.0.0.0/1',
        'PersistentKeepalive = 25', ''
    ) -join "`n"
}

Assert-SafePath $programs
Assert-SafePath $setup
if (-not (Test-Path -LiteralPath $vault)) {
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    ([IO.DirectoryInfo]$vault).Create($security)
}
Assert-SafePath $vault -Private
$expected = Join-Path $setup 'Prepare-Profile.ps1'
if ($PSCommandPath -ine $expected) { throw 'Use the installed, protected helper.' }
Assert-SafePath $expected
Assert-SafePath (Join-Path $setup 'Gateway-Common.ps1')
. (Join-Path $setup 'Gateway-Common.ps1')
if ($SystemWorker) {
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $systemSid) { throw 'The DPAPI worker needs LocalSystem.' }
    $phase = 'validate prerequisites'
    try {
        Assert-SafePath $wgDir
        $wg = Join-Path $wgDir 'wg.exe'
        Assert-SafePath $wg
        $sig = Get-AuthenticodeSignature -LiteralPath $wg
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch '(?:^|, )CN=WireGuard LLC(?:,|$)') {
            throw 'WireGuard tool signature verification failed'
        }
        $requestPath = Join-Path $vault 'setup.json'
        Assert-SafePath $requestPath -Private
        $request = [IO.File]::ReadAllText($requestPath) | ConvertFrom-Json
        $server = [string]$request.ServerPublicKey
        Assert-RnPublicKey $server
        Assert-RnPublicEndpoint $request.EndpointIPv4
        if ($request.Port -isnot [ValueType] -or [int]$request.Port -ne $request.Port -or $request.Port -lt 1 -or $request.Port -gt 65535) {throw 'Invalid UDP port.'}
        Assert-RnUdpPort $request.Port
        $lockPath = Join-Path $vault 'prepare.lock'
        if (Test-Path -LiteralPath $lockPath) { Assert-SafePath $lockPath -Private }
        $lock = [IO.File]::Open($lockPath, 'OpenOrCreate', 'ReadWrite', 'None')
        try {
            $phase = 'initialize WireGuard DPAPI'
            # WireGuard conf/dpapi uses the profile name as the DPAPI description,
            # no entropy, and the current LocalSystem identity. Both paths stay in RAM.
            Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class RackNerdProfileDpapi {
    [StructLayout(LayoutKind.Sequential)]
    private struct Blob { public int Size; public IntPtr Data; }
    [DllImport("crypt32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool CryptProtectData(ref Blob input, string name, IntPtr entropy,
        IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("crypt32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool CryptUnprotectData(ref Blob input, out IntPtr name, IntPtr entropy,
        IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr memory);
    public static byte[] Convert(byte[] bytes, string name, bool protect) {
        var pinned = GCHandle.Alloc(bytes, GCHandleType.Pinned);
        var input = new Blob { Size = bytes.Length, Data = pinned.AddrOfPinnedObject() };
        var output = new Blob(); IntPtr label = IntPtr.Zero, none = IntPtr.Zero;
        try {
            bool ok = protect ? CryptProtectData(ref input, name, none, none, none, 1, out output)
                : CryptUnprotectData(ref input, out label, none, none, none, 1, out output);
            if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (!protect && !String.Equals(Marshal.PtrToStringUni(label), name, StringComparison.Ordinal))
                throw new InvalidOperationException("WireGuard profile name mismatch");
            var result = new byte[output.Size]; Marshal.Copy(output.Data, result, 0, result.Length);
            return result;
        } finally {
            if (output.Data != none) {
                if (!protect) Marshal.Copy(new byte[output.Size], 0, output.Data, output.Size);
                LocalFree(output.Data);
            }
            if (label != none) LocalFree(label);
            pinned.Free();
        }
    }
}
'@
            $name = 'rn-public'
            if (-not (Test-Path -LiteralPath $config)) {
                $phase = 'create independent profile'
                $managerDir = Join-Path $wgDir 'Data\Configurations'
                foreach ($conflict in @($publicRecord, (Join-Path $managerDir 'rn-public.conf'), (Join-Path $managerDir 'rn-public.conf.dpapi'), (Join-Path $vault 'rn-public.conf'))) {
                    if (Test-Path -LiteralPath $conflict) { throw "Existing file for this identity: $conflict" }
                }
                if (Get-Service -Name 'WireGuardTunnel$rn-public' -ErrorAction SilentlyContinue) { throw 'Tunnel service name already in use' }
                if (Get-NetIPAddress -IPAddress '10.203.84.2' -ErrorAction SilentlyContinue) { throw 'Candidate client address already in use' }
                $secret = & $wg genkey
                if ($LASTEXITCODE -ne 0 -or $secret -cnotmatch $keyPattern) { throw 'Key generation failed' }
                $clear = [Text.Encoding]::UTF8.GetBytes((ConfigText $secret $server))
                try {
                    $sealed = [RackNerdProfileDpapi]::Convert($clear, $name, $true)
                    Save-NewFile $config $sealed
                } finally { [Array]::Clear($clear,0,$clear.Length); $secret = $null }
            }
            $phase = 'read back encrypted candidate'
            Assert-SafePath $config -Private
            $clear = [RackNerdProfileDpapi]::Convert([IO.File]::ReadAllBytes($config), $name, $false)
            try {
                $actual = [Text.Encoding]::UTF8.GetString($clear)
                $secret = [regex]::Match($actual, '(?m)^PrivateKey = ([A-Za-z0-9+/]{43}=)$').Groups[1].Value
                if ($secret -cnotmatch $keyPattern -or $actual -cne (ConfigText $secret $server)) { throw 'Existing candidate has different settings' }
                $public = $secret | & $wg pubkey
                if ($LASTEXITCODE -ne 0 -or $public -cnotmatch $keyPattern -or $public -ceq $server) {
                    throw 'Independent public identity check failed'
                }
            } finally { [Array]::Clear($clear,0,$clear.Length); $secret = $null; $actual = $null }
            $phase = 'publish public key'
            if (-not (Test-Path -LiteralPath $publicRecord)) { Save-NewFile $publicRecord ([Text.Encoding]::ASCII.GetBytes($public+"`n")) }
            if ((Read-PublicKey $publicRecord) -cne $public) { throw 'Candidate and public enrollment record disagree' }
        } finally { $lock.Dispose() }
    } catch {
        # Record only the stage and a fixed diagnostic. Do not serialize exceptions from the key pipeline.
        $errorPath = Join-Path $vault 'last-worker-error.txt'
        if (Test-Path -LiteralPath $errorPath) { Assert-SafePath $errorPath -Private }
        [IO.File]::WriteAllText($errorPath, ($phase+'; '+$_.Exception.GetType().Name +'; source line '+$_.InvocationInfo.ScriptLineNumber))
        exit 1
    }
    exit 0
}

# A triggerless, one-time SYSTEM task uses the same identity as the eventual
# tunnel service. A scheduled worker runs only from an administrator-owned path.
$run = [guid]::NewGuid().ToString('N')
$worker = $expected
$task = 'RNPublic-Prepare-'+$run
$registered = $false
function Assert-PrepareTask {
    $t=Get-ScheduledTask -TaskPath '\' -TaskName $task -ErrorAction Stop
    if (@($t.Actions).Count -ne 1 -or $t.Actions[0].Execute -ine $powershell -or $t.Actions[0].Arguments -cne $workerArgs) {throw 'Preparation task action ownership mismatch.'}
    Assert-RnTaskPrincipal $t.Principal 'S-1-5-18'
}
try {
    $powershell = Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $workerArgs='-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy RemoteSigned -File "'+$worker+'" -SystemWorker'
    $action = New-ScheduledTaskAction -Execute $powershell -Argument $workerArgs
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::FromMinutes(2)) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskPath '\' -TaskName $task -Principal $principal -Action $action -Settings $settings | Out-Null
    $registered = $true
    Assert-PrepareTask
    Start-ScheduledTask -TaskPath '\' -TaskName $task
    $end = [DateTime]::UtcNow.AddSeconds(120)
    do {
        Start-Sleep -Milliseconds 350
        $info = Get-ScheduledTaskInfo -TaskPath '\' -TaskName $task
        $state = (Get-ScheduledTask -TaskPath '\' -TaskName $task).State
        if ($state -eq 'Ready' -and $info.LastRunTime.Year -ge 2020 -and $info.LastTaskResult -ne 267009) { break }
        if ([DateTime]::UtcNow -gt $end) { throw 'Offline preparation timed out' }
    } while ($true)
    if ($info.LastTaskResult -ne 0) { throw "Offline preparation failed, status $($info.LastTaskResult). Check the protected worker diagnostic." }
    [pscustomobject]@{Profile='rn-public'; EncryptedConfig=$config; PublicKey=(Read-PublicKey $publicRecord)}
} finally {
    if ($registered) { Assert-PrepareTask; Unregister-ScheduledTask -TaskPath '\' -TaskName $task -Confirm:$false }
}
