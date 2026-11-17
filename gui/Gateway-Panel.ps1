#requires -Version 5.1
[CmdletBinding()]
param([switch]$StatusOnly)
$ErrorActionPreference = 'Stop'
$statusLibrary = Join-Path $PSScriptRoot 'Gateway-Status.ps1'
. $statusLibrary
if ($StatusOnly) {
    $sample = Get-RnPanelSample $true
    $view = Get-RnPanelView $sample.Local $sample.Check
    $view.Title
    if ($sample.Local -and $sample.Local.Config -eq 'Ready') {
        "公网出口  $($view.Ip)    核验时间  $($view.Checked)"
        "IPv4 网卡  $($sample.Local.Route)    系统代理  $($sample.Local.Proxy)"
        $view.Hint
    } elseif ($sample.Local) { $view.Hint; exit 2 } else { $sample.ErrorText; exit 1 }
    exit 0
}

$signalName='Local\RackNerd.Connection.Panel.'+[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$firstWindow=$false
$showSignal=[Threading.EventWaitHandle]::new($false,[Threading.EventResetMode]::AutoReset,$signalName,[ref]$firstWindow)
if (-not $firstWindow) {
    $null=$showSignal.Set(); $showSignal.Dispose(); return
}
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()
$form = [Windows.Forms.Form]::new()
$form.Text = 'RackNerd 网络'
$form.Font = [Drawing.Font]::new('Microsoft YaHei UI',10)
$form.BackColor = [Drawing.Color]::White
$form.AutoScaleMode = 'Dpi'
$form.StartPosition = 'CenterScreen'
$form.ClientSize = [Drawing.Size]::new(680,366)
$form.MinimumSize = $form.Size
$form.KeyPreview = $true
$grid = [Windows.Forms.TableLayoutPanel]::new()
$grid.Dock = 'Fill'
$grid.Padding = [Windows.Forms.Padding]::new(22,14,22,12)
$grid.ColumnCount = 2
$grid.RowCount = 8
$null=$grid.ColumnStyles.Add([Windows.Forms.ColumnStyle]::new('Absolute',105))
$null=$grid.ColumnStyles.Add([Windows.Forms.ColumnStyle]::new('Percent',100))
foreach ($height in 48,46,29,29,29,29,57) {
    $null=$grid.RowStyles.Add([Windows.Forms.RowStyle]::new('Absolute',$height))
}
$null=$grid.RowStyles.Add([Windows.Forms.RowStyle]::new('Percent',100))
$form.Controls.Add($grid)

function Add-PanelLabel($Name,$Text,$Row,$Col,[int]$Span=1) {
    $label=[Windows.Forms.Label]::new()
    $label.Name=$Name; $label.Text=$Text; $label.Dock='Fill'; $label.TextAlign='MiddleLeft'
    $label.AutoEllipsis=$true; $label.UseMnemonic=$false
    $grid.Controls.Add($label,$Col,$Row); $grid.SetColumnSpan($label,$Span)
    return $label
}
$title=Add-PanelLabel 'ConnectionState' '正在检测线路…' 0 0 2
$title.Font=[Drawing.Font]::new($form.Font.FontFamily,20,[Drawing.FontStyle]::Bold)
$hint=Add-PanelLabel 'ConnectionHint' '' 1 0 2
$values=@()
$captions=@('公网出口','IPv4 网卡','系统代理','检测时间')
foreach ($i in 0..3) {
    $caption=Add-PanelLabel ('Caption'+$i) $captions[$i] ($i+2) 0
    $caption.ForeColor=[Drawing.Color]::FromArgb(84,98,111)
    $values+=Add-PanelLabel ('Value'+$i) '—' ($i+2) 1
}
$values[0].Font=[Drawing.Font]::new($form.Font.FontFamily,12,[Drawing.FontStyle]::Bold)
$actions=[Windows.Forms.FlowLayoutPanel]::new()
$actions.Dock='Fill'; $actions.WrapContents=$false; $actions.Padding=[Windows.Forms.Padding]::new(0,9,0,0)
$grid.Controls.Add($actions,0,6); $grid.SetColumnSpan($actions,2)
function Add-PanelButton($Name,$Text,$Width) {
    $b=[Windows.Forms.Button]::new()
    $b.Name=$Name; $b.Text=$Text; $b.Width=$Width; $b.Height=35
    $b.UseVisualStyleBackColor=$true
    $actions.Controls.Add($b)
    return $b
}
$connect=Add-PanelButton 'Connect' '连接 RackNerd (R)' 150
$restore=Add-PanelButton 'Restore' '返回原网络 (O)' 131
$trial=Add-PanelButton 'Trial' '试用 15 分钟 (T)' 131
$verify=Add-PanelButton 'Verify' '核验出口' 98
$defaultNote='最小化可在系统托盘查看状态。关闭面板后，当前连接继续运行。'
$note=Add-PanelLabel 'OperationResult' $defaultNote 7 0 2
$note.ForeColor=[Drawing.Color]::FromArgb(71,85,98)

# Small persistent set of tray icons. Clone each managed icon before releasing its native handle.
Add-Type -Namespace RackNerd.Connection.Panel -Name Icons -MemberDefinition '[System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool DestroyIcon(System.IntPtr h);'
function New-PanelIcon($Color,$Glyph) {
    $bmp=[Drawing.Bitmap]::new(32,32)
    $g=[Drawing.Graphics]::FromImage($bmp)
    $brush=[Drawing.SolidBrush]::new($Color)
    $pen=[Drawing.Pen]::new([Drawing.Color]::White,3)
    try {
        $g.SmoothingMode='AntiAlias'; $g.FillEllipse($brush,1,1,30,30)
        if ($Glyph -eq 'ok') { $g.DrawLine($pen,8,16,14,22); $g.DrawLine($pen,14,22,24,10) }
        elseif ($Glyph -eq 'off') { $g.DrawLine($pen,8,16,24,16) }
        else { $g.DrawLine($pen,16,7,16,18); $g.DrawLine($pen,16,21,16,24) }
        $handle=$bmp.GetHicon()
        try { return ([Drawing.Icon]::FromHandle($handle)).Clone() }
        finally { $null=[RackNerd.Connection.Panel.Icons]::DestroyIcon($handle) }
    } finally { $pen.Dispose(); $brush.Dispose(); $g.Dispose(); $bmp.Dispose() }
}
$green=[Drawing.Color]::FromArgb(10,111,78)
$grey=[Drawing.Color]::FromArgb(70,88,104)
$amber=[Drawing.Color]::FromArgb(155,86,15)
$icons=@{Good=(New-PanelIcon $green 'ok'); Off=(New-PanelIcon $grey 'off'); Wait=(New-PanelIcon $amber 'wait')}
$tray=[Windows.Forms.NotifyIcon]::new()
$tray.Icon=$icons.Wait; $tray.Text='RackNerd · 正在检测'; $tray.Visible=$true
$context=[Windows.Forms.ContextMenuStrip]::new()
$openItem=$context.Items.Add('打开状态面板')
$exitItem=$context.Items.Add('退出面板')
$tray.ContextMenuStrip=$context
function Show-Panel { $form.Show(); $form.WindowState='Normal'; $form.Activate() }
$tray.Add_DoubleClick({Show-Panel})
$openItem.Add_Click({Show-Panel}); $exitItem.Add_Click({$form.Close()})
$form.Add_Resize({if ($form.WindowState -eq 'Minimized') { $form.Hide() }})

$controller=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'RackNerd-Connection\Gateway-Mode.ps1'
$winPS=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
$space=[runspacefactory]::CreateRunspace()
$space.Open()
$timer=[Windows.Forms.Timer]::new()
$timer.Interval=350
$script:currentPath=$null; $script:check=$null; $script:reader=$null; $script:change=$null
$script:nextRead=[datetime]::MinValue; $script:wantCheck=$false; $script:version=0
$script:changingText=''; $script:activeAction=''; $script:readError=$null

function Paint-State {
    $v=Get-RnPanelView $script:currentPath $script:check
    $c=$grey; $icon=$icons.Off
    if ($v.Kind -eq 'Verified') { $c=$green; $icon=$icons.Good }
    elseif ($v.Kind -ne 'Off') { $c=$amber; $icon=$icons.Wait }
    $heading=$v.Title
    if ($script:change) { $heading=$script:changingText; $c=$amber; $icon=$icons.Wait }
    $title.Text=$heading; $title.ForeColor=$c; $tray.Icon=$icon; $form.Icon=$icon
    $tray.Text="RackNerd · $heading"
    $hint.Text=$v.Hint
    if ($script:readError) { $hint.Text='无法读取当前 Windows 网络，稍后将自动重试。' }
    $values[0].Text=$v.Ip
    $values[1].Text=if ($script:currentPath) { $script:currentPath.Route } else { '未知' }
    $values[2].Text=if ($script:currentPath) { $script:currentPath.Proxy } else { '未知' }
    $values[3].Text=if ($script:currentPath) { '线路 '+$script:currentPath.At.ToString('HH:mm:ss')+'     出口 '+$v.Checked } else { '—' }
    $canSwitch=-not $script:change -and (Test-Path -LiteralPath $controller -PathType Leaf)
    $connect.Enabled=$canSwitch -and $v.Kind -eq 'Off' -and -not $script:currentPath.OtherTun
    $trial.Enabled=$connect.Enabled
    # Local recovery remains available even when no route can be read.
    $restore.Enabled=$canSwitch
    $verify.Enabled=$script:currentPath.Config -eq 'Ready' -and -not $script:change -and -not ($script:reader -and $script:readingPublic)
}

function Start-PanelRead([bool]$Public) {
    $script:reader=[powershell]::Create(); $script:reader.Runspace=$space
    $null=$script:reader.AddScript('param($library,$verify); $ErrorActionPreference="Stop"; . $library; Get-RnPanelSample $verify').AddArgument($statusLibrary).AddArgument($Public)
    $script:readingPublic=$Public; $script:readVersion=$script:version
    $script:pending=$script:reader.BeginInvoke()
}

function Request-PanelChange([ValidateSet('RackNerd','Test','Original')][string]$Action) {
    if ($script:change) { return }
    try {
        # Only the preinstalled controller is elevated. Paths and actions are fixed.
        $arguments='-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "'+$controller+'" -Action '+$Action
        $script:change=Start-Process -FilePath $winPS -Verb RunAs -WindowStyle Hidden -ArgumentList $arguments -PassThru -ErrorAction Stop
        $script:activeAction=$Action; $script:version++; $script:check=$null
        $script:changingText=if ($Action -eq 'Original') {'正在恢复原网络…'} else {'正在连接 RackNerd…'}
        $note.Text='正在应用你的选择。'
    } catch { $note.Text='切换未启动。请确认 Windows 管理员提示后重试。' }
    Paint-State
}
$connect.Add_Click({Request-PanelChange 'RackNerd'})
$trial.Add_Click({Request-PanelChange 'Test'})
$restore.Add_Click({Request-PanelChange 'Original'})
$verify.Add_Click({$script:wantCheck=$true; $script:check=$null; $script:nextRead=[datetime]::MinValue; Paint-State})
$form.Add_KeyDown({
    param($sender,$event)
    if ($event.Modifiers -ne 'None') { return }
    switch ($event.KeyCode.ToString()) {
        'R' { $connect.PerformClick() }; 'O' { $restore.PerformClick() }; 'T' { $trial.PerformClick() }
    }
})

function Update-Panel {
    if ($showSignal.WaitOne(0)) { Show-Panel }
    if ($script:change -and $script:change.HasExited) {
        $code=$script:change.ExitCode; $script:change.Dispose(); $script:change=$null
        $script:version++; $script:check=$null; $script:wantCheck=$true; $script:nextRead=[datetime]::MinValue
        $note.Text=if ($code -ne 0) { '切换未完成。请查看当前线路，必要时点「返回原网络」。' }
            elseif ($script:activeAction -eq 'Original') { '已恢复 Windows 设置。原网络需要其他 VPN 或 TUN 时，可重新开启它。' }
            elseif ($script:activeAction -eq 'Test') { '试用已开始。15 分钟后自动还原，也可提前点「返回原网络」。' }
            else { $defaultNote }
        Paint-State
    }
    if ($script:reader -and $script:pending.IsCompleted) {
        $completedPublic=$script:readingPublic
        try { $result=@($script:reader.EndInvoke($script:pending))[-1] }
        catch { $result=[pscustomobject]@{Local=$null;Check=$null;ErrorText=$_.Exception.Message} }
        finally { $script:reader.Dispose(); $script:reader=$null }
        if ($script:readVersion -eq $script:version -and -not $script:change) {
            $script:currentPath=$result.Local; $script:readError=$result.ErrorText
            if ($completedPublic -or -not $result.Local -or $script:check.Key -ne $result.Local.Key) { $script:check=$result.Check }
            $script:nextRead=[datetime]::UtcNow.AddSeconds(5)
            Paint-State
            $due=-not $script:check -or ([datetime]::Now-$script:check.At).TotalSeconds -ge 60
            if ($result.Local.Config -eq 'Ready' -and -not $completedPublic -and ($due -or $script:wantCheck)) {
                $script:wantCheck=$false; Start-PanelRead $true
            }
        }
    }
    if (-not $script:reader -and -not $script:change -and [datetime]::UtcNow -ge $script:nextRead) { Start-PanelRead $false }
}
$timer.Add_Tick({Update-Panel})
$form.Add_Shown({$connect.Enabled=$false; $trial.Enabled=$false; $verify.Focus() | Out-Null; $timer.Start(); Update-Panel})
try { [Windows.Forms.Application]::Run($form) }
finally {
    $timer.Stop(); $timer.Dispose(); $tray.Visible=$false; $tray.Dispose(); $context.Dispose()
    if ($script:reader) { $script:reader.Stop(); $script:reader.Dispose() }
    if ($script:change) { $script:change.Dispose() }
    $space.Dispose(); $form.Dispose(); $showSignal.Dispose()
    foreach ($icon in $icons.Values) { $icon.Dispose() }
}
