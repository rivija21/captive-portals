<#
  Sets up (or with -Uninstall, removes) automatic UoM Wi-Fi login on Windows.
  Run through "Set Up.bat" / "Uninstall.bat". Safe to run again any time.

  Installs:  %LOCALAPPDATA%\UoMAutoLogin\uom_autologin.ps1   the login script
             %LOCALAPPDATA%\UoMAutoLogin\credential.xml      your login, DPAPI-encrypted
             Task Scheduler task "UoM WiFi Auto-Login"       runs the script in the background

  Plain ASCII only (Windows PowerShell 5.1 misreads other characters).
#>
param([switch]$Uninstall)

$ErrorActionPreference = 'Stop'
$TaskName = 'UoM WiFi Auto-Login'
$AppDir = Join-Path $env:LOCALAPPDATA 'UoMAutoLogin'
$ScriptPath = Join-Path $AppDir 'uom_autologin.ps1'
$CredFile = Join-Path $AppDir 'credential.xml'

if ($Uninstall) {
    $answer = Read-Host 'Turn off automatic UoM Wi-Fi login and delete the saved password? (y/n)'
    if ($answer -notmatch '^\s*y') { Write-Host 'Cancelled. Nothing was changed.'; exit 1 }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $AppDir -ErrorAction SilentlyContinue
    Write-Host 'Done: automatic UoM Wi-Fi login is turned off and removed.'
    exit 0
}

Write-Host '== UoM Wi-Fi Auto-Login setup =='

# 1. Ask for the login and save it encrypted (only this Windows account can decrypt it).
$prompt = @{ Message = 'Your UoM Wi-Fi username and password (what you type on the UoM Wi-Fi login page). They are saved encrypted, readable only by your Windows account.' }
if (Test-Path $CredFile) {
    try { $prompt.UserName = (Import-Clixml $CredFile).UserName } catch { }  # pre-fill when changing the password
}
$cred = Get-Credential @prompt
if (-not $cred) { Write-Host 'Cancelled. Nothing was changed.'; exit 1 }
$user = $cred.UserName.TrimStart('\').Trim()
if (-not $user -or $cred.Password.Length -eq 0) { Write-Host 'Username or password was empty. Nothing was changed.'; exit 1 }
New-Item -ItemType Directory -Force -Path $AppDir | Out-Null
New-Object Management.Automation.PSCredential($user, $cred.Password) | Export-Clixml -Path $CredFile
Write-Host 'OK  Saved your login (encrypted)'

# 2. Install the script where the background task can always find it.
Copy-Item -Force (Join-Path $PSScriptRoot 'uom_autologin.ps1') $ScriptPath
Unblock-File $ScriptPath
Remove-Item -Force (Join-Path $AppDir 'last-failure.txt') -ErrorAction SilentlyContinue
Write-Host "OK  Installed the script in $AppDir"

# 3. Run it when Windows connects to a network or wakes up, at sign-in, and every 2 minutes.
function New-EventTrigger([string]$Log, [string]$Filter) {
    $query = "<QueryList><Query Id=`"0`" Path=`"$Log`"><Select Path=`"$Log`">$Filter</Select></Query></QueryList>"
    "<EventTrigger><Enabled>true</Enabled><Subscription>$([Security.SecurityElement]::Escape($query))</Subscription></EventTrigger>"
}

function Get-TaskXml([bool]$WithEvents) {
    $account = [Security.SecurityElement]::Escape([Security.Principal.WindowsIdentity]::GetCurrent().Name)
    $powershell = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ScriptPath`""
    # conhost --headless (Windows 10 1809+) runs PowerShell without flashing a window.
    if ([Environment]::OSVersion.Version.Build -ge 17763) {
        $command = 'conhost.exe'
        $arguments = "--headless $powershell"
    } else {
        $command = 'powershell.exe'
        $arguments = $powershell.Substring('powershell.exe '.Length)
    }
    $events = ''
    if ($WithEvents) {
        $events = (New-EventTrigger 'Microsoft-Windows-NetworkProfile/Operational' '*[System[(EventID=10000)]]') +
                  (New-EventTrigger 'System' "*[System[Provider[@Name='Microsoft-Windows-Power-Troubleshooter'] and (EventID=1)]]")
    }
    $start = (Get-Date).ToString('s')  # culture-independent yyyy-MM-ddTHH:mm:ss
    @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Logs in to the UoM Wi-Fi (wlan.uom.lk) automatically. Remove it with Uninstall.bat.</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled><UserId>$account</UserId></LogonTrigger>
    <TimeTrigger>
      <Enabled>true</Enabled>
      <StartBoundary>$start</StartBoundary>
      <Repetition><Interval>PT2M</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>
    </TimeTrigger>
    $events
  </Triggers>
  <Principals>
    <Principal id="Author"><UserId>$account</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT3M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec><Command>$command</Command><Arguments>$([Security.SecurityElement]::Escape($arguments))</Arguments></Exec>
  </Actions>
</Task>
"@
}

try {
    Register-ScheduledTask -TaskName $TaskName -Xml (Get-TaskXml $true) -Force | Out-Null
    Write-Host 'OK  Turned on automatic login (runs after every wake-up and network change)'
} catch {
    # Some managed PCs don't let ordinary users watch the event logs; time-based checks still work.
    Write-Host "Note: couldn't watch for wake-ups directly ($($_.Exception.Message))"
    Register-ScheduledTask -TaskName $TaskName -Xml (Get-TaskXml $false) -Force | Out-Null
    Write-Host 'OK  Turned on automatic login (checks every 2 minutes and at sign-in)'
}

# 4. Try it once right now.
Write-Host ''
Write-Host 'Checking the connection now...'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ScriptPath -Now
Write-Host ''
Write-Host 'All set! Windows will now log in to UoM Wi-Fi by itself after waking up.'
Write-Host 'To change your password later, just run Set Up again.'
