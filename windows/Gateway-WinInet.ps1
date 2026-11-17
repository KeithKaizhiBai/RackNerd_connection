# Dot-source only. Windows PowerShell 5.1+ / PowerShell 7, native architecture.
# $s=Get-RnProxySnapshot; Set-RnProxyDirect -Snapshot $s; Restore-RnProxySnapshot -Snapshot $s
# LAN/default WinINET connection of the signed-in user only. Never writes WinHTTP,
# named VPN/RAS profiles, environment variables, browser policy or credentials.
function Initialize-RnWinInet {
    if ('RackNerd.PublicGateway.WinInetV1' -as [type]) { return }
    if ([Environment]::OSVersion.Platform -ne 'Win32NT' -or
        ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess)) { throw 'Use a native Windows PowerShell process.' }
    Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
namespace RackNerd.PublicGateway {
  public sealed class ProxyValues {
    public uint Flags;
    public string Proxy, Bypass, Pac;
  }
  public static class WinInetV1 {
    [StructLayout(LayoutKind.Explicit)] struct Val {
      [FieldOffset(0)] public uint Number;
      [FieldOffset(0)] public IntPtr Text;
      [FieldOffset(0)] public System.Runtime.InteropServices.ComTypes.FILETIME FileTime;
    }
    [StructLayout(LayoutKind.Sequential)] struct Option { public uint Id; public Val Value; }
    [StructLayout(LayoutKind.Sequential)] struct OptList { public uint Size; public IntPtr Connection; public uint Count, Error; public IntPtr Options; }
    [DllImport("wininet.dll", ExactSpelling=true, SetLastError=true)]
    static extern bool InternetQueryOptionW(IntPtr h, uint opt, ref OptList list, ref uint len);
    [DllImport("wininet.dll", ExactSpelling=true, SetLastError=true)]
    static extern bool InternetSetOptionW(IntPtr h, uint opt, ref OptList list, uint len);
    [DllImport("wininet.dll", EntryPoint="InternetSetOptionW", ExactSpelling=true, SetLastError=true)]
    static extern bool Notify(IntPtr h, uint opt, IntPtr unused, uint zero);
    [DllImport("kernel32.dll")] static extern IntPtr GlobalFree(IntPtr p);
    [DllImport("wtsapi32.dll", ExactSpelling=true, SetLastError=true)]
    static extern bool WTSQuerySessionInformationW(IntPtr server, int session, int info, out IntPtr data, out int len);
    [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr data);
    static readonly int stride=Marshal.SizeOf(typeof(Option));
    static IntPtr At(OptList l,int i) { return IntPtr.Add(l.Options, stride*i); }
    static Option Get(OptList l,int i) { return (Option)Marshal.PtrToStructure(At(l,i),typeof(Option)); }
    static OptList Build(uint[] ids) {
      OptList l=new OptList(); l.Size=(uint)Marshal.SizeOf(typeof(OptList)); l.Count=(uint)ids.Length;
      l.Options=Marshal.AllocHGlobal(stride*ids.Length);
      for(int i=0;i<ids.Length;i++) { Option o=new Option(); o.Id=ids[i]; Marshal.StructureToPtr(o,At(l,i),false); }
      return l; // null Connection selects the LAN/default connection
    }
    static ProxyValues ReadWith(uint flagOption) {
      OptList l=Build(new uint[]{flagOption,2,3,4}); uint len=l.Size;
      try {
        if(!InternetQueryOptionW(IntPtr.Zero,75,ref l,ref len)) throw new Win32Exception(Marshal.GetLastWin32Error());
        ProxyValues v=new ProxyValues(); v.Flags=Get(l,0).Value.Number;
        v.Proxy=Marshal.PtrToStringUni(Get(l,1).Value.Text);
        v.Bypass=Marshal.PtrToStringUni(Get(l,2).Value.Text);
        v.Pac=Marshal.PtrToStringUni(Get(l,3).Value.Text);
        return v;
      } finally {
        for(int i=1;i<4;i++){IntPtr p=Get(l,i).Value.Text;if(p!=IntPtr.Zero)GlobalFree(p);}
        Marshal.FreeHGlobal(l.Options);
      }
    }
    public static ProxyValues Read() {
      try {return ReadWith(10);} // INTERNET_PER_CONN_FLAGS_UI (Microsoft's preferred query)
      catch(Win32Exception e){if(e.NativeErrorCode!=12009 && e.NativeErrorCode!=87 && e.NativeErrorCode!=50)throw;return ReadWith(1);}
    }
    public static void Set(uint flags,bool all,string proxy,string bypass,string pac) {
      if(flags==0 || (flags & ~15u)!=0) throw new ArgumentException("Unsupported WinINET connection flags.");
      OptList l=Build(all?new uint[]{1,2,3,4}:new uint[]{1}); string[] vals={proxy,bypass,pac};
      IntPtr[] allocated=new IntPtr[3];
      try {
        Option first=Get(l,0);first.Value.Number=flags;Marshal.StructureToPtr(first,At(l,0),false);
        if(all) for(int i=1;i<4;i++) {
          Option o=Get(l,i);allocated[i-1]=String.IsNullOrEmpty(vals[i-1])?IntPtr.Zero:Marshal.StringToHGlobalUni(vals[i-1]);
          o.Value.Text=allocated[i-1];Marshal.StructureToPtr(o,At(l,i),false);
        }
        if(!InternetSetOptionW(IntPtr.Zero,75,ref l,l.Size))throw new Win32Exception(Marshal.GetLastWin32Error());
      } finally {foreach(IntPtr p in allocated) if(p!=IntPtr.Zero)Marshal.FreeHGlobal(p); Marshal.FreeHGlobal(l.Options);}
      if(!Notify(IntPtr.Zero,39,IntPtr.Zero,0) || !Notify(IntPtr.Zero,37,IntPtr.Zero,0))
        throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    static string Wts(int sid,int kind) {
      IntPtr p;int cb;
      if(!WTSQuerySessionInformationW(IntPtr.Zero,sid,kind,out p,out cb))throw new Win32Exception(Marshal.GetLastWin32Error());
      try {return p==IntPtr.Zero?"":Marshal.PtrToStringUni(p);}finally{if(p!=IntPtr.Zero)WTSFreeMemory(p);}
    }
    public static string SessionAccount() {
      int session=Process.GetCurrentProcess().SessionId;if(session==0)throw new InvalidOperationException("An interactive user session is required.");
      string name=Wts(session,5),domain=Wts(session,7);
      if(String.IsNullOrEmpty(name))throw new InvalidOperationException("No signed-in desktop user in this session.");
      return String.IsNullOrEmpty(domain)?name:domain+"\\"+name;
    }
  }
}
'@
}

function Get-RnCheckedUser([string]$ExpectedSid) {
    Initialize-RnWinInet
    $me=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $account=[Security.Principal.NTAccount]::new([RackNerd.PublicGateway.WinInetV1]::SessionAccount())
    if ($me -ne $account.Translate([Security.Principal.SecurityIdentifier]).Value -or ($ExpectedSid -and $ExpectedSid -ne $me)) {
        throw 'The process, desktop, and snapshot must belong to the same signed-in Windows user.'
    }
    # Check both mandatory user/device ADMX trees, including machine-wide settings.
    foreach ($hive in @([Microsoft.Win32.Registry]::CurrentUser,[Microsoft.Win32.Registry]::LocalMachine)) {
        $k=$hive.OpenSubKey('Software\Policies\Microsoft\Internet Explorer\Control Panel')
        if ($k) { try { foreach($n in 'Proxy','AutoConfig','ConnectionsTab'){if($k.GetValue($n,0) -ne 0){throw 'Windows policy restricts proxy changes.'}} } finally { $k.Dispose() } }
        $k=$hive.OpenSubKey('Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings')
        if ($k) { try {
            if ($k.GetValue('ProxySettingsPerUser',1) -ne 1 -or @($k.GetValueNames() | Where-Object {$_ -in 'ProxyEnable','ProxyServer','ProxyOverride','AutoConfigURL','AutoDetect'}).Count -gt 0) {
                throw 'Per-machine or managed proxy is outside the scope of this operation.'
            }
            $c=$k.OpenSubKey('Connections'); if($c){try{if($c.GetValueNames() -contains 'DefaultConnectionSettings'){throw 'Default connection is managed by policy.'}}finally{$c.Dispose()}}
        } finally { $k.Dispose() } }
    }
    # An effective MDM NetworkProxy policy is device-wide. Do not try to override it.
    $mdm=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\PolicyManager\current\device\NetworkProxy')
    if ($mdm) { try {
        if ($mdm.ValueCount -or $mdm.SubKeyCount) {throw 'A device NetworkProxy policy is outside this user-only operation.'}
    } finally { $mdm.Dispose() } }
    return $me
}

function Get-RnProxySnapshot {
    param([string]$ExpectedSid)
    $sid=Get-RnCheckedUser $ExpectedSid
    $v=[RackNerd.PublicGateway.WinInetV1]::Read()
    if ($v.Flags -lt 1 -or $v.Flags -gt 15) {throw 'Unsupported WinINET flags.'}
    # Server/PAC strings can contain credentials. They never appear as properties
    # or in error messages. ConvertFrom-SecureString uses current-user Windows DPAPI.
    $json=[ordered]@{UserSid=$sid;Flags=$v.Flags;Proxy=$v.Proxy;Bypass=$v.Bypass;Pac=$v.Pac} | ConvertTo-Json -Compress
    $secure=ConvertTo-SecureString -String $json -AsPlainText -Force
    try { $sealed=ConvertFrom-SecureString -SecureString $secure -ErrorAction Stop } finally { $secure.Dispose() }
    [pscustomobject]@{Schema='RN-WinINET-LAN/1';UserSid=$sid;Flags=$v.Flags;HasProxy=[bool]$v.Proxy;HasBypass=[bool]$v.Bypass;HasPac=[bool]$v.Pac;ProtectedValues=$sealed}
}

function Open-RnProxySnapshot($Snapshot) {
    if ($Snapshot.Schema -cne 'RN-WinINET-LAN/1' -or -not $Snapshot.UserSid -or -not $Snapshot.ProtectedValues) {throw 'Missing or unsupported proxy snapshot.'}
    $sid=Get-RnCheckedUser ([string]$Snapshot.UserSid)
    $s=ConvertTo-SecureString -String $Snapshot.ProtectedValues -ErrorAction Stop
    $b=[IntPtr]::Zero
    try {
        $b=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($s)
        $v=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) | ConvertFrom-Json -ErrorAction Stop
    } finally { if($b -ne [IntPtr]::Zero){[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b)}; $s.Dispose() }
    if ($v.UserSid -ne $sid -or $v.Flags -ne $Snapshot.Flags -or $v.Flags -lt 1 -or $v.Flags -gt 15) {throw 'Proxy snapshot metadata does not match its protected values.'}
    return $v
}

function Test-RnProxyFieldsMatch($Left,$Right,[switch]$AllowHidden) {
    foreach($p in 'Proxy','Bypass','Pac'){
        # Some configurations do not expose dormant proxy/PAC fields while DIRECT
        # is selected. The original values are still in the authenticated snapshot.
        if ($AllowHidden -and $Left.Flags -eq 1 -and [string]::IsNullOrEmpty($Left.$p)) {continue}
        if(-not [string]::Equals([string]$Left.$p,[string]$Right.$p,[StringComparison]::Ordinal)){return $false}
    }
    return $true
}

function Set-RnProxyDirect {
    [CmdletBinding()]param([Parameter(Mandatory)]$Snapshot)
    $v=Open-RnProxySnapshot $Snapshot
    $now=[RackNerd.PublicGateway.WinInetV1]::Read()
    if(-not (Test-RnProxyFieldsMatch $now $v -AllowHidden) -or ($now.Flags -ne 1 -and $now.Flags -ne $v.Flags)){throw 'Proxy settings changed since capture; the switch was not applied.'}
    if($now.Flags -eq 1){return}
    try {
        [RackNerd.PublicGateway.WinInetV1]::Set(1,$false,$null,$null,$null)
        $now=[RackNerd.PublicGateway.WinInetV1]::Read()
        if($now.Flags -ne 1 -or -not (Test-RnProxyFieldsMatch $now $v -AllowHidden)){throw 'WinINET direct mode did not preserve the saved fields.'}
    } catch {
        [RackNerd.PublicGateway.WinInetV1]::Set($v.Flags,$true,$v.Proxy,$v.Bypass,$v.Pac)
        $now=[RackNerd.PublicGateway.WinInetV1]::Read()
        if($now.Flags -ne $v.Flags -or -not (Test-RnProxyFieldsMatch $now $v)){throw 'Proxy switch failed and local restoration could not be verified.'}
        throw 'Proxy switch failed; the original settings were restored and verified.'
    }
}

function Restore-RnProxySnapshot {
    [CmdletBinding()]param([Parameter(Mandatory)]$Snapshot)
    $v=Open-RnProxySnapshot $Snapshot
    $now=[RackNerd.PublicGateway.WinInetV1]::Read()
    if(-not (Test-RnProxyFieldsMatch $now $v -AllowHidden) -or ($now.Flags -ne 1 -and $now.Flags -ne $v.Flags)){throw 'Unrelated proxy settings changed; refusing to overwrite them.'}
    $exact=Test-RnProxyFieldsMatch $now $v
    if($now.Flags -eq $v.Flags -and $exact){return}
    [RackNerd.PublicGateway.WinInetV1]::Set($v.Flags,(-not $exact),$v.Proxy,$v.Bypass,$v.Pac)
    $now=[RackNerd.PublicGateway.WinInetV1]::Read()
    if($now.Flags -ne $v.Flags -or -not (Test-RnProxyFieldsMatch $now $v)){throw 'Proxy restore could not be verified.'}
}
