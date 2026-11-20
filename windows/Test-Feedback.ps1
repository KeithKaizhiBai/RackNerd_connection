#Requires -Version 5.1
# Offline error and result tests. Uses only synthetic data in a new temporary directory.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Gateway-Feedback.ps1')
function Check($Condition,[string]$Message){if(-not $Condition){throw $Message}}
$cases=@{
    'Need one unambiguous physical IPv4 default route'='Gateway'
    'The active Xray TUN enforces its own DNS'='Tun'
    'Another VPN or TUN adapter is active'='Tun'
    'A specific endpoint route already exists'='Route'
    'DNS policy not effective after 20 seconds'='Dns'
    'Could not verify the VPS as the no-proxy IPv4 exit'='Exit'
    'No recent handshake with the enrolled server'='Handshake'
    'WireGuard startup ended in state Stopped'='Service'
    'A session is still open. Restore Original first.'='Session'
    'Run Test and restore Original successfully before daily use.'='Trial'
    'A verified real application trial is required first'='Trial'
    'An existing public SSH session would be affected'='Ssh'
    'WireGuard signature verification failed'='Setup'
    'Effective firewall must enforce local IPv6/DNS rules'='Firewall'
    'Resolver restoration failed'='Recovery'
    'An unrecognized fixture failure'='Unknown'
}
foreach($message in $cases.Keys){
    $r=Invoke-RnPanelOperation {throw $message}
    Check (-not $r.Success -and $r.Failure.Code -ceq $cases[$message]) ('Wrong error classification: '+$message)
    Check ($r.Failure.Reason -and $r.Failure.Help -and $r.Failure.Detail) 'Failure missing actionable detail'
}
$r=Invoke-RnPanelOperation {'fixture output'}
Check ($r.Success -and $null -eq $r.Failure) 'Successful operation reported as failed'
$fakeKey=[Convert]::ToBase64String([byte[]](1..32))
$safe=Protect-RnFailureText ('Endpoint 198.51.100.8, peer '+$fakeKey+' token=fixture-secret')
Check (-not $safe.Contains('198.51.100.8') -and -not $safe.Contains($fakeKey) -and -not $safe.Contains('fixture-secret')) 'Sensitive details not removed'
foreach($text in @('{"password":"fixture-secret","token":"fixture-token"}','password = "fixture secret with spaces"',"token='fixture secret with spaces'",'https://fixture:fixture-secret@example.invalid/')){
    Check (-not (Protect-RnFailureText $text).Contains('fixture')) 'Quoted credential or URL login leaked'
}
$escaped=([ordered]@{password='fixture-prefix"fixture-suffix';token='fixture\"token'} | ConvertTo-Json -Compress)
Check (-not (Protect-RnFailureText $escaped).Contains('fixture')) 'Escaped JSON credentials leaked'
Check (-not (Protect-RnFailureText ('password="'+('fixture '*1300))).Contains('fixture')) 'Truncated quoted credential leaked'
Check ((Protect-RnFailureText ('x'*9000)).Length -le 701) 'Failure detail is unbounded'
$base=Join-Path ([IO.Path]::GetTempPath()) ('rn-feedback-test-'+[guid]::NewGuid().ToString('N'))
$folder=Join-Path $base 'PanelResults';[void][IO.Directory]::CreateDirectory($folder)
$id=[guid]::NewGuid().ToString('N');$path=Join-Path $folder ($id+'.json');$started=[datetime]::UtcNow
try {
    $record=[ordered]@{RequestId=$id;Action='Test';At=$started.ToString('o');Success=$false;Failure=(Get-RnFailureInfo 'Need one unambiguous physical IPv4 default route')}
    function Save-Fixture {[IO.File]::WriteAllText($path,($record | ConvertTo-Json -Depth 5))}
    Save-Fixture
    $r=Read-RnPanelResult $base $id 'Test' $started 1
    Check ($r.Failure.Code -ceq 'Gateway') 'Current correlated failure lost'
    $record.RequestId=[guid]::NewGuid().ToString('N');Save-Fixture
    Check ((Read-RnPanelResult $base $id 'Test' $started 1).Failure.Code -ceq 'ResultMissing') 'Wrong request accepted'
    $record.RequestId=$id;$record.Action='Original';Save-Fixture
    Check ((Read-RnPanelResult $base $id 'Test' $started 1).Failure.Code -ceq 'ResultMissing') 'Wrong action accepted'
    $record.Action='Test';$record.At=$started.AddMinutes(-5).ToString('o');Save-Fixture
    Check ((Read-RnPanelResult $base $id 'Test' $started 1).Failure.Code -ceq 'ResultMissing') 'Stale result accepted'
    $record.At=$started.ToString('o');$record.Success=$true;$record.Failure=$null;Save-Fixture
    Check ((Read-RnPanelResult $base $id 'Test' $started 0).Success) 'Success result rejected'
    Check ((Read-RnPanelResult $base $id 'Test' $started 1).Failure.Code -ceq 'ResultMissing') 'Contradictory exit accepted'
    [IO.File]::WriteAllText($path,'{unfinished')
    Check ((Read-RnPanelResult $base $id 'Test' $started 1).Failure.Code -ceq 'ResultMissing') 'Partial result accepted'
    Check ((Read-RnPanelResult $base ([guid]::NewGuid().ToString('N')) 'Test' $started 0).Failure.Code -ceq 'ResultMissing') 'Missing result treated as success'
}finally{
    [IO.File]::Delete($path);[IO.Directory]::Delete($folder);[IO.Directory]::Delete($base)
}
& {
    # Run the real panel completion handler with in-memory controls and process results.
    $tokens=$null;$errors=$null
    $panel=Join-Path (Split-Path $PSScriptRoot) 'gui\Gateway-Panel.ps1'
    $ast=[Management.Automation.Language.Parser]::ParseFile($panel,[ref]$tokens,[ref]$errors)
    if($errors.Count){throw 'Panel syntax failed'}
    $fn=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Update-Panel'},$true)
    . ([scriptblock]::Create($fn.Extent.Text))
    $showSignal=[pscustomobject]@{}
    $showSignal | Add-Member ScriptMethod WaitOne {$false}
    $script:reader=$null;$script:version=0;$script:activeAction='RackNerd'
    $script:requestId='fixture';$script:requestStarted=[datetime]::UtcNow
    $controller=Join-Path $PSScriptRoot 'fixture-controller.ps1'
    $note=[pscustomobject]@{Text=''};$defaultNote='fixture-default'
    function Paint-State {}
    function Start-PanelRead($Public) {}
    $failure=Get-RnFailureInfo 'Need one unambiguous physical IPv4 default route'
    $script:fixtureResult=[pscustomobject]@{Success=$false;Failure=$failure}
    function Read-RnPanelResult {$script:fixtureResult}
    function New-FixtureProcess([int]$Code){
        $p=[pscustomobject]@{HasExited=$true;ExitCode=$Code}
        $p | Add-Member ScriptMethod Dispose {}
        return $p
    }
    $script:change=New-FixtureProcess 1
    Update-Panel
    Check ($script:operationFailure.Code -ceq 'Gateway' -and $note.Text -ceq (Format-RnFailure $failure)) 'Failure lost on process completion'
    Update-Panel
    Check ($script:operationFailure.Code -ceq 'Gateway' -and $note.Text -ceq (Format-RnFailure $failure)) 'Polling overwrote failure guidance'
    $script:fixtureResult=[pscustomobject]@{Success=$true;Failure=$null}
    $script:change=New-FixtureProcess 0
    Update-Panel
    Check ($null -eq $script:operationFailure -and $note.Text -ceq $defaultNote) 'Later success did not clear earlier failure'
}
'Offline feedback tests passed: error propagation, guidance, redaction, result correlation, persistent panel errors and later success.'
