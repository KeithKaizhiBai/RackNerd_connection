# Dot-source from native 64-bit, elevated Windows PowerShell.
# The caller owns the endpoint route, DNS/IPv6 policy, rollback and approval.
# Dot-sourcing only defines functions. Neither public function accepts a service,
# executable, configuration path, or key supplied by its caller.

function Get-RnTunnelServiceSpec {
    # A fresh powershell.exe in Task Scheduler may not have loaded this assembly.
    Add-Type -AssemblyName System.ServiceProcess -ErrorAction Stop
    $programs = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    if (-not [Environment]::Is64BitProcess) { throw 'Use native 64-bit PowerShell.' }
    $setup = Join-Path $programs 'RackNerd-Connection'
    $vault = Join-Path $setup 'GatewayProfile'
    $wireguard = Join-Path $programs 'WireGuard'
    $application = Join-Path $wireguard 'wireguard.exe'
    $configuration = Join-Path $vault 'rn-public.conf.dpapi'
    [pscustomobject]@{
        Name='WireGuardTunnel$rn-public'; Registry='SYSTEM\CurrentControlSet\Services\WireGuardTunnel$rn-public'
        Programs=$programs; Setup=$setup; Vault=$vault; WGDir=$wireguard; App=$application
        Config=$configuration; WG=(Join-Path $wireguard 'wg.exe')
        Public=(Join-Path $setup 'public.json')
        Marker=(Join-Path $vault 'manual-service-owner.id')
        Command=('"'+$application+'" /tunnelservice "'+$configuration+'"')
    }
}

function Assert-RnTunnelServicePath([string]$Path, [switch]$Private) {
    $item = Get-Item -Force -LiteralPath $Path -ErrorAction Stop
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Unexpected link: $Path" }
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $sid = [Security.Principal.SecurityIdentifier]
    $trusted = @('S-1-5-18','S-1-5-32-544')
    if (-not $Private) { $trusted += 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' }
    if ($acl.GetOwner($sid).Value -notin $trusted) { throw "Unexpected owner: $Path" }
    $write = [Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
    foreach ($ace in $acl.GetAccessRules($true,$true,$sid)) {
        if ($ace.AccessControlType -ne 'Allow' -or $ace.IdentityReference.Value -in $trusted) { continue }
        if ($ace.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
        if ($Private -or ($ace.FileSystemRights -band $write)) { throw "Unexpected permissions: $Path" }
    }
}

function Get-RnTunnelServiceMarker($Spec,[switch]$Create) {
    foreach ($dir in @($Spec.Programs,$Spec.Setup)) { Assert-RnTunnelServicePath $dir }
    Assert-RnTunnelServicePath $Spec.Vault -Private
    if (-not [IO.File]::Exists($Spec.Marker) -and $Create) {
        if (Test-Path -LiteralPath ('HKLM:\'+$Spec.Registry) -ErrorAction Stop) { throw 'Existing rn-public service lacks an ownership record.' }
        $candidate = Join-Path $Spec.Vault ([guid]::NewGuid().ToString('N')+'.service-id.pending')
        try {
            [IO.File]::WriteAllText($candidate,[guid]::NewGuid().ToString('N'))
            [IO.File]::Move($candidate,$Spec.Marker)
        } catch [IO.IOException] {
            if (-not [IO.File]::Exists($Spec.Marker)) { throw }
        } finally {
            if ([IO.File]::Exists($candidate)) { [IO.File]::Delete($candidate) }
        }
    }
    Assert-RnTunnelServicePath $Spec.Marker -Private
    $id = [IO.File]::ReadAllText($Spec.Marker).Trim()
    if ($id -cnotmatch '^[a-f0-9]{32}$') { throw 'Invalid manual service ownership record.' }
    return ('RackNerd WireGuard Gateway ['+$id+']')
}

function Get-RnTunnelServiceDefinition($Spec, [string]$Display, [switch]$AllowUnfinished) {
    # Ensure an exact service match before starting, stopping, or deleting anything.
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Spec.Registry)
    if ($null -eq $key) { return }
    try {
        $dependencies = @($key.GetValue('DependOnService',@()) | Sort-Object)
        if ($key.GetValue('DisplayName') -cne $Display -or
            $key.GetValue('ImagePath') -ine $Spec.Command -or
            $key.GetValue('ObjectName') -ine 'LocalSystem' -or
            $key.GetValue('Type') -ne 16 -or $key.GetValue('Start') -ne 3 -or
            ($dependencies -join '|') -ine 'Nsi|TcpIp') {
            throw 'Service definition differs from the owned manual WireGuard service.'
        }
        $sidType = $key.GetValue('ServiceSidType',0)
        if ($sidType -ne 1 -and -not ($AllowUnfinished -and $sidType -eq 0)) {
            throw 'Unexpected WireGuard service SID type.'
        }
        [pscustomobject]@{SidType=$sidType}
    } finally { $key.Dispose() }
}

function Get-RnTunnelServiceStatus($Spec) {
    $controller = [ServiceProcess.ServiceController]::new($Spec.Name)
    # The PowerShell property adapter turns a failed property getter into $null.
    # Call the getter explicitly so we retain SCM error 1060/1072 on disappearance.
    try { return $controller.get_Status().ToString() }
    catch {
        $root = $_.Exception.GetBaseException()
        if ($root -is [ComponentModel.Win32Exception] -and $root.NativeErrorCode -in @(1060,1072)) { return 'Absent' }
        throw
    } finally { $controller.Dispose() }
}

function Invoke-RnTunnelServiceControl([ValidateSet('start','stop','delete','sidtype')][string]$Operation) {
    # sc.exe sends one bounded SCM request, unlike Stop-Service's wait for the service.
    $client = [Diagnostics.ProcessStartInfo]::new()
    $client.FileName = Join-Path ([Environment]::SystemDirectory) 'sc.exe'
    $client.Arguments = $Operation+' WireGuardTunnel$rn-public'
    if ($Operation -eq 'sidtype') { $client.Arguments += ' unrestricted' }
    $client.UseShellExecute = $false
    $client.CreateNoWindow = $true
    $client.RedirectStandardOutput = $true
    $client.RedirectStandardError = $true
    $proc = [Diagnostics.Process]::Start($client)
    try {
        if (-not $proc.WaitForExit(6000)) { $proc.Kill(); throw ('SCM timed out: '+$Operation) }
        return $proc.ExitCode
    } finally { $proc.Dispose() }
}

function Stop-RnManualTunnel {
    [CmdletBinding()]
    param([ValidateRange(10,90)][int]$TimeoutSeconds=40)
    $spec = Get-RnTunnelServiceSpec
    $registryPath = 'HKLM:\'+$spec.Registry
    if (-not (Test-Path -LiteralPath $registryPath -ErrorAction Stop) -and (Get-RnTunnelServiceStatus $spec) -eq 'Absent') { return }
    $display = Get-RnTunnelServiceMarker $spec
    $end = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        $definition = Get-RnTunnelServiceDefinition $spec $display -AllowUnfinished
        $status = Get-RnTunnelServiceStatus $spec
        if ($null -eq $definition -and $status -eq 'Absent') { return }
        if ($definition -and $status -eq 'Stopped') {
            $rc = Invoke-RnTunnelServiceControl delete
            if ($rc -notin @(0,1060,1072)) { throw "SCM delete failed ($rc)." }
        } elseif ($definition -and $status -in @('StartPending','Running','Paused','PausePending','ContinuePending')) {
            $rc = Invoke-RnTunnelServiceControl stop
            if ($rc -notin @(0,1060,1061,1062,1072)) { throw "SCM stop failed ($rc)." }
        }
        Start-Sleep -Milliseconds 300
    } while ([DateTime]::UtcNow -lt $end)
    throw 'The manual WireGuard service has not finished removal. Retry Stop-RnManualTunnel.'
}

function Start-RnManualTunnel {
    [CmdletBinding()]
    param([ValidateRange(10,90)][int]$TimeoutSeconds=40)
    $spec = Get-RnTunnelServiceSpec
    foreach ($path in @($spec.Programs,$spec.Setup,$spec.WGDir,$spec.App,$spec.WG,$spec.Public)) {
        Assert-RnTunnelServicePath $path
    }
    Assert-RnTunnelServicePath $spec.Vault -Private
    Assert-RnTunnelServicePath $spec.Config -Private
    if (-not [IO.File]::Exists($spec.Config) -or (Get-Item -LiteralPath $spec.Config -Force).Length -lt 64) { throw 'Encrypted gateway configuration is missing or incomplete.' }
    foreach ($exe in @($spec.App,$spec.WG)) {
        $sig = Get-AuthenticodeSignature -LiteralPath $exe -ErrorAction Stop
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch '(?:^|, )CN=WireGuard LLC(?:,|$)') {
            throw 'WireGuard signature verification failed.'
        }
    }
    $settings = [IO.File]::ReadAllText($spec.Public) | ConvertFrom-Json
    $peer = $settings.ServerPublicKey
    $client = $settings.ClientPublicKey
    if ($peer -cnotmatch '^[A-Za-z0-9+/]{43}=$' -or $client -cnotmatch '^[A-Za-z0-9+/]{43}=$' -or $client -ceq $peer) {
        throw 'Invalid known public keys.'
    }
    $display = Get-RnTunnelServiceMarker $spec -Create
    $definition = Get-RnTunnelServiceDefinition $spec $display -AllowUnfinished
    $undo = $false
    try {
        if (-not $definition) {
            $created = New-Service -Name $spec.Name -DisplayName $display -BinaryPathName $spec.Command -StartupType Manual -DependsOn @('Nsi','TcpIp') -ErrorAction Stop
            $undo = $true
            $created.Dispose()
            $definition = Get-RnTunnelServiceDefinition $spec $display -AllowUnfinished
            if (-not $definition) { throw 'New manual service disappeared before initialization.' }
        }
        if ($definition.SidType -eq 0) {
            if ((Get-RnTunnelServiceStatus $spec) -ne 'Stopped') { throw 'Incomplete service is not stopped.' }
            $rc = Invoke-RnTunnelServiceControl sidtype
            if ($rc -ne 0) { throw "SCM service SID setup failed ($rc)." }
        }
        if (-not (Get-RnTunnelServiceDefinition $spec $display)) { throw 'Manual service is unavailable.' }
        $status = Get-RnTunnelServiceStatus $spec
        if ($status -eq 'Stopped') {
            $undo = $true
            $rc = Invoke-RnTunnelServiceControl start
            if ($rc -notin @(0,1056)) { throw "SCM start failed ($rc)." }
        } elseif ($status -notin @('Running','StartPending')) { throw "Manual service cannot start in state $status." }
        $end = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
        do {
            $status = Get-RnTunnelServiceStatus $spec
            if ($status -in @('Stopped','Absent','StopPending')) { throw "WireGuard startup ended in state $status." }
            $addresses = @(Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias 'rn-public' -ErrorAction SilentlyContinue)
            $ready = @($addresses | Where-Object { $_.IPAddress -eq '10.203.84.2' -and $_.PrefixLength -eq 32 -and $_.AddressState -eq 'Preferred' })
            if ($status -eq 'Running' -and $ready.Count -eq 1) {
                $routes = @(Get-NetRoute -InterfaceIndex $ready[0].InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop | ForEach-Object DestinationPrefix)
                if ('0.0.0.0/1' -in $routes -and '128.0.0.0/1' -in $routes) {
                    $liveClient = & $spec.WG show rn-public public-key
                    if ($LASTEXITCODE -ne 0 -or $liveClient -cne $client) { throw 'Running WireGuard client identity differs.' }
                    $row = @(& $spec.WG show rn-public allowed-ips)
                    if ($LASTEXITCODE -ne 0 -or $row.Count -ne 1) { throw 'Unexpected running peer count.' }
                    $fields = @($row[0].Trim() -split '[\s,]+')
                    if ($fields.Count -ne 3 -or $fields[0] -cne $peer -or
                        '0.0.0.0/1' -notin $fields[1..2] -or '128.0.0.0/1' -notin $fields[1..2]) {
                        throw 'Running WireGuard peer or AllowedIPs differs.'
                    }
                    return
                }
            }
            Start-Sleep -Milliseconds 300
        } while ([DateTime]::UtcNow -lt $end)
        throw 'Timed out waiting for the gateway address and both IPv4 routes.'
    } catch {
        $failure = $_
        if ($undo) {
            try { Stop-RnManualTunnel -TimeoutSeconds 25 } catch { throw ("Start failed: {0}. Cleanup failed: {1}" -f $failure.Exception.Message,$_.Exception.Message) }
        }
        throw $failure
    }
}
