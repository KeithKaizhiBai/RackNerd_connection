#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Test','RackNerd','Original')][string]$Action,
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{32}$')][string]$RequestId
)
$ErrorActionPreference='Stop'
$base=$PSScriptRoot
# Validate the full install path before loading any sibling code.
function Assert-PanelPath([string]$Path) {
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Unexpected link in panel installation'}
    $sid=[Security.Principal.SecurityIdentifier]
    $trusted=@('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $acl=Get-Acl -LiteralPath $Path
    if($acl.GetOwner($sid).Value -notin $trusted){throw 'Unexpected panel installation owner'}
    $write=[Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
    foreach($rule in $acl.GetAccessRules($true,$true,$sid)){
        if($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin $trusted -and
            -not ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
            ($rule.FileSystemRights -band $write)){throw 'Panel installation is writable by an untrusted account'}
    }
}
$programs=[Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
if(-not $base.StartsWith($programs+'\',[StringComparison]::OrdinalIgnoreCase)){throw 'Use the protected installed panel action'}
$ancestor=$base
while($ancestor.Length -ge $programs.Length){Assert-PanelPath $ancestor;$ancestor=Split-Path $ancestor}
foreach($p in @($PSCommandPath,(Join-Path $base 'Gateway-Mode.ps1'),(Join-Path $base 'Gateway-Feedback.ps1'))){Assert-PanelPath $p}
. (Join-Path $base 'Gateway-Feedback.ps1')
$folder=Join-Path $base 'PanelResults'
if(-not (Test-Path -LiteralPath $folder)){
    $acl=[Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;GRGX;;;BU)')
    ([IO.DirectoryInfo]$folder).Create($acl)
}
Assert-PanelPath $folder
$destination=Join-Path $folder ($RequestId+'.json')
# Reserve this unique result before switching. Never overwrite an existing path.
$output=[IO.File]::Open($destination,'CreateNew','Write','None')
try {
    $result=Invoke-RnPanelOperation { & (Join-Path $base 'Gateway-Mode.ps1') -Action $Action }
    $record=[ordered]@{RequestId=$RequestId;Action=$Action;At=[datetime]::UtcNow.ToString('o');Success=$result.Success;Failure=$result.Failure}
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes(($record | ConvertTo-Json -Depth 5))
    $output.Write($bytes,0,$bytes.Length);$output.Flush($true)
}finally{$output.Dispose()}
if(-not $result.Success){exit 1}
