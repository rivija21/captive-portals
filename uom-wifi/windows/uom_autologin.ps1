<#
  Automatic login for the University of Moratuwa Wi-Fi (UoM_Wireless) - Windows version.

  A scheduled task runs this when Windows connects to a network or resumes from
  sleep, at sign-in, and every 2 minutes as a backstop. A normal run costs one tiny
  request to Microsoft's connectivity check. Only when that check fails *and* the PC
  is on the UoM campus network does it fill in the Cisco login page at wlan.uom.lk,
  using the username and password that "Set Up.bat" saved (encrypted with Windows
  DPAPI, so only your Windows account can read them).

  Windows PowerShell 5.1 (built into Windows 10/11). Keep this file plain ASCII:
  PowerShell 5.1 misreads other characters in files without a byte-order mark.

  -Now   ignore the 10-minute pause after a rejected login, and print progress
#>
param([switch]$Now)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

function Get-Setting([string]$Name, [string]$Default) {
    $value = [Environment]::GetEnvironmentVariable($Name)
    if ($value) { $value } else { $Default }
}

# UOM_* environment variables exist only for the offline test harness.
$PortalUrl = Get-Setting 'UOM_PORTAL_URL' 'https://wlan.uom.lk/login.html'
$CheckUrl = Get-Setting 'UOM_CHECK_URL' 'http://www.msftconnecttest.com/connecttest.txt'
# The campus DHCP hands out the DNS suffix wifi.uom.lk. A cafe hotspot won't, so
# the password is never sent to a login page anywhere else.
$CampusDomain = 'uom.lk'
$TestHosts = @((Get-Setting 'UOM_TEST_HOSTS' '') -split ',' | Where-Object { $_ })
$DataDir = Get-Setting 'UOM_DATA_DIR' ''
if (-not $DataDir) { $DataDir = Join-Path $env:LOCALAPPDATA 'UoMAutoLogin' }
$LogDir = Join-Path $DataDir 'Logs'
$LogFile = Join-Path $LogDir 'autologin.log'
$CredFile = Get-Setting 'UOM_CRED_FILE' (Join-Path $DataDir 'credential.xml')
$FailFile = Join-Path $DataDir 'last-failure.txt'
$FailBackoff = 10 * 60  # after the portal rejects the login, wait before trying again
$UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36'

$protocols = [Net.SecurityProtocolType]::Tls12
if ([Enum]::GetNames([Net.SecurityProtocolType]) -contains 'Tls13') { $protocols = $protocols -bor [Net.SecurityProtocolType]'Tls13' }
[Net.ServicePointManager]::SecurityProtocol = $protocols


# ---------------------------------------------------------------- utilities

function Write-Log([string]$Message, [switch]$Quiet) {
    if ($Now) { Write-Host $Message }
    if ($Quiet) { return }
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    if ((Test-Path $LogFile) -and (Get-Item $LogFile).Length -gt 256KB) {
        Move-Item -Force $LogFile "$LogFile.old"
    }
    Add-Content -Path $LogFile -Value ((Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '  ' + $Message)
}

function Show-Notification([string]$Text) {
    try {
        $null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
        $template = [Windows.UI.Notifications.ToastTemplateType]::ToastText02
        $xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent($template)
        $lines = $xml.GetElementsByTagName('text')
        $null = $lines.Item(0).AppendChild($xml.CreateTextNode('UoM Wi-Fi'))
        $null = $lines.Item(1).AppendChild($xml.CreateTextNode($Text))
        $appId = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
        $toast = [Windows.UI.Notifications.ToastNotification]::new($xml)
        [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)
    } catch {
        # Notifications are a nicety; never let them break the login.
    }
}

function Save-Snapshot([string]$Name, [string]$Html) {
    # Keeps the last portal page on disk so the login can be debugged later.
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
    Set-Content -Path (Join-Path $LogDir $Name) -Value $Html -Encoding UTF8
}

function Get-ErrorText($ErrorRecord) {
    $ex = $ErrorRecord.Exception
    while ($ex.InnerException) { $ex = $ex.InnerException }
    $ex.Message
}

function Get-UnixTime { [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() }

function Get-SavedLogin {
    # Returns @(username, password) from the DPAPI-encrypted file, or $null.
    if (-not (Test-Path $CredFile)) { return $null }
    try {
        $cred = Import-Clixml -Path $CredFile
        return @($cred.UserName, $cred.GetNetworkCredential().Password)
    } catch {
        return $null
    }
}


# ------------------------------------------------------------ network checks

function Test-OnCampus {
    foreach ($nic in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($nic.OperationalStatus -ne 'Up') { continue }
        try { $suffix = [string]$nic.GetIPProperties().DnsSuffix } catch { continue }
        $suffix = $suffix.ToLower()
        if ($suffix -eq $CampusDomain -or $suffix.EndsWith('.' + $CampusDomain)) { return $true }
    }
    return $false
}

function Test-TrustedPortal([string]$Url) {
    # True only for a *.uom.lk address while on the campus network.
    $hostName = ([Uri]$Url).Host.ToLower()
    if ($TestHosts -contains $hostName) { return $true }
    (Test-OnCampus) -and ($hostName -eq $CampusDomain -or $hostName.EndsWith('.' + $CampusDomain))
}

function ConvertTo-FormBody($Data) {
    ($Data | ForEach-Object { [Uri]::EscapeDataString($_.Name) + '=' + [Uri]::EscapeDataString($_.Value) }) -join '&'
}

function Invoke-Http([string]$Url, $Form = $null, [string]$Referer = '', [switch]$NoRedirect, [int]$TimeoutSec = 10) {
    $req = [Net.HttpWebRequest]::Create($Url)
    $req.UserAgent = $UserAgent
    $req.Timeout = $TimeoutSec * 1000
    $req.ReadWriteTimeout = $TimeoutSec * 1000
    $req.AllowAutoRedirect = -not $NoRedirect
    $req.CookieContainer = $script:Cookies
    $req.Headers['Cache-Control'] = 'no-cache'
    # Like the Mac version, don't let an expired portal certificate block the login;
    # the campus check above is what keeps the password from going anywhere else.
    $req.ServerCertificateValidationCallback = { $true }
    if ($Referer) { $req.Referer = $Referer }
    if ($null -ne $Form) {
        $bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-FormBody $Form))
        $req.Method = 'POST'
        $req.ContentType = 'application/x-www-form-urlencoded'
        $req.ContentLength = $bytes.Length
        $stream = $req.GetRequestStream()
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Close()
    }
    try {
        $resp = $req.GetResponse()
    } catch {
        # 4xx/5xx still come with a page worth reading; anything else is a real failure.
        $ex = $_.Exception
        while ($ex -and -not ($ex -is [Net.WebException])) { $ex = $ex.InnerException }
        if (-not $ex -or -not $ex.Response) { throw }
        $resp = $ex.Response
    }
    try {
        $reader = New-Object IO.StreamReader($resp.GetResponseStream())
        [pscustomobject]@{
            Url      = $resp.ResponseUri.AbsoluteUri
            Status   = [int]$resp.StatusCode
            Location = $resp.Headers['Location']
            Body     = $reader.ReadToEnd()
        }
    } finally {
        $resp.Close()
    }
}

function Get-NetStatus {
    # Asks Microsoft's connectivity check whether the internet works.
    # Returns @("online" | "portal" | "offline", detail-for-the-log).
    $script:Cookies = New-Object Net.CookieContainer
    try {
        $r = Invoke-Http $CheckUrl -NoRedirect -TimeoutSec 5
    } catch {
        return @('offline', (Get-ErrorText $_))
    }
    if ($r.Status -eq 200 -and $r.Body.Trim() -eq 'Microsoft Connect Test') { return @('online', '') }
    if ($r.Location) { return @('portal', "redirected to $($r.Location)") }
    @('portal', 'the check page was replaced')
}


# --------------------------------------------------------------- page parsing

function Get-Attributes([string]$Text) {
    $attrs = @{}
    $pattern = '([\w:-]+)(?:\s*=\s*(?:"([^"]*)"|''([^'']*)''|([^\s"''>]+)))?'
    foreach ($m in [regex]::Matches($Text, $pattern)) {
        $name = $m.Groups[1].Value.ToLower()
        if ($attrs.ContainsKey($name)) { continue }
        $value = ''
        foreach ($g in 2, 3, 4) { if ($m.Groups[$g].Success) { $value = $m.Groups[$g].Value } }
        $attrs[$name] = [Net.WebUtility]::HtmlDecode($value)
    }
    $attrs
}

function Get-Forms([string]$Html) {
    # Each form with its action, method and fields (input/button tags as attribute tables).
    foreach ($fm in [regex]::Matches($Html, '(?is)<form\b([^>]*)>(.*?)(?:</form>|$)')) {
        $attrs = Get-Attributes $fm.Groups[1].Value
        $fields = @(foreach ($im in [regex]::Matches($fm.Groups[2].Value, '(?is)<(input|button)\b([^>]*)>')) {
            $field = Get-Attributes $im.Groups[2].Value
            $field['tag'] = $im.Groups[1].Value.ToLower()
            $field
        })
        $method = if ($attrs['method']) { $attrs['method'].ToLower() } else { 'get' }
        [pscustomobject]@{ Action = [string]$attrs['action']; Method = $method; Fields = $fields }
    }
}

function Get-NextLink([string]$Html) {
    # Where a page without a login form points to next (frame or meta refresh).
    $patterns = '(?is)<i?frame\b[^>]*?\bsrc\s*=\s*["'']?([^"''\s>]+)',
                '(?is)<meta\b[^>]*?http-equiv\s*=\s*["'']?refresh[^>]*?url\s*=\s*([^"''\s>]+)'
    foreach ($p in $patterns) {
        $m = [regex]::Match($Html, $p)
        if ($m.Success) { return [Net.WebUtility]::HtmlDecode($m.Groups[1].Value) }
    }
    $null
}

function Get-FieldType($Field) {
    if ($Field['type']) { $Field['type'].ToLower() } elseif ($Field['tag'] -eq 'button') { 'submit' } else { 'text' }
}

function Get-FormData($Fields, [string]$User, [string]$Pass) {
    # Builds the POST data a browser would send after typing in the credentials.
    $texts = @($Fields | Where-Object { $_['name'] -and ((Get-FieldType $_) -in 'text', 'email', 'tel', 'number') })
    $named = @($texts | Where-Object { $_['name'] -match 'user|login|uname|mail|account|uid|name|id$' })
    $userField = if ($named.Count) { $named[0] } elseif ($texts.Count) { $texts[0] } else { $null }

    $data = New-Object Collections.Generic.List[object]
    $clicked = $false
    foreach ($f in $Fields) {
        $name = [string]$f['name']
        $kind = Get-FieldType $f
        if (-not $name) { continue }
        if ($kind -eq 'password') { $value = $Pass }
        elseif ([object]::ReferenceEquals($f, $userField)) { $value = $User }
        elseif ($kind -in 'submit', 'image') {
            if ($clicked) { continue }  # a browser sends only the button that was pressed
            $clicked = $true
            $value = [string]$f['value']
        }
        elseif ($kind -eq 'checkbox' -or ($kind -eq 'radio' -and $f.ContainsKey('checked'))) {
            $value = if ($f['value']) { $f['value'] } else { 'on' }  # e.g. "I accept the terms"
        }
        elseif ($kind -in 'radio', 'button', 'reset', 'file') { continue }
        else { $value = [string]$f['value'] }
        # The Cisco login page's Submit button runs JavaScript that sets buttonClicked=4.
        if ($name -eq 'buttonClicked') { $value = '4' }
        $data.Add([pscustomobject]@{ Name = $name; Value = $value })
    }
    , $data
}


# ---------------------------------------------------------------------- login

function Submit-Form([string]$PageUrl, $Form, [string]$User, [string]$Pass) {
    $action = if ($Form.Action) { ([Uri]::new([Uri]$PageUrl, $Form.Action)).AbsoluteUri } else { $PageUrl }
    if (-not (Test-TrustedPortal $action)) {
        Write-Log "The login form sends to $action, which isn't the UoM portal; not sending the password."
        return 'no-form'
    }
    $data = Get-FormData $Form.Fields $User $Pass
    Write-Log ("Submitting the login form to {0} (fields: {1})" -f $action, (($data | ForEach-Object { $_.Name }) -join ', '))
    if ($Form.Method -eq 'post') {
        $r = Invoke-Http $action -Form $data -Referer $PageUrl
    } else {
        $sep = if ($action.Contains('?')) { '&' } else { '?' }
        $r = Invoke-Http ($action.Split('#')[0] + $sep + (ConvertTo-FormBody $data)) -Referer $PageUrl
    }
    Save-Snapshot 'portal-response.html' $r.Body
    if ($r.Body -match '(?i)name=["'']?err_flag["'']?[^>]*value=["'']?1\b') {
        # The Cisco page comes back with err_flag=1 on a bad password.
        Write-Log 'The portal says the username or password is wrong.'
        return 'rejected'
    }
    Write-Log "Portal answered HTTP $($r.Status)"
    'sent'
}

function Invoke-Login([string]$StartUrl, [string]$User, [string]$Pass) {
    # Finds the login form (following frames/redirects) and submits it.
    # Returns "sent", "rejected" (wrong username/password), "unreachable" or "no-form".
    $script:Cookies = New-Object Net.CookieContainer
    $url = $StartUrl
    for ($hop = 0; $hop -lt 4; $hop++) {
        if (-not (Test-TrustedPortal $url)) {
            Write-Log "Ended up at $url, which isn't the UoM portal; stopping."
            return 'no-form'
        }
        try {
            $page = Invoke-Http $url
        } catch {
            Write-Log "Can't reach the login page yet ($(Get-ErrorText $_)); will try again shortly."
            return 'unreachable'
        }
        $url = $page.Url
        Save-Snapshot 'portal-page.html' $page.Body

        $form = Get-Forms $page.Body |
            Where-Object { @($_.Fields | Where-Object { (Get-FieldType $_) -eq 'password' }).Count } |
            Select-Object -First 1
        if ($form -and (Test-TrustedPortal $url)) {
            try {
                return Submit-Form $url $form $User $Pass
            } catch {
                Write-Log "Sending the login failed ($(Get-ErrorText $_)); will try again shortly."
                return 'unreachable'
            }
        }
        $next = Get-NextLink $page.Body
        if (-not $next) { break }
        $url = ([Uri]::new([Uri]$url, $next)).AbsoluteUri
    }
    Write-Log "No login form found on $url. The page is saved as $(Join-Path $LogDir 'portal-page.html') for a closer look."
    'no-form'
}


# ----------------------------------------------------------------------- main

function Invoke-Main {
    New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
    $mutex = New-Object Threading.Mutex($false, 'Local\UoMAutoLogin')
    if (-not $mutex.WaitOne(0)) {
        Write-Log 'Another check is already running.' -Quiet
        return 0
    }

    # Right after waking, Wi-Fi may still be joining: keep checking for up to ~20 s on campus.
    for ($attempt = 0; $attempt -lt 10; $attempt++) {
        $status, $detail = Get-NetStatus
        if ($status -ne 'offline' -or -not (Test-OnCampus)) { break }
        if ($attempt -lt 9) { Start-Sleep -Seconds 2 }
    }

    if ($status -eq 'online') {
        Write-Log 'Internet is working; nothing to do.' -Quiet
        return 0
    }
    if (-not (Test-OnCampus) -and -not $TestHosts) {
        Write-Log "No internet ($detail), but this isn't the UoM network; leaving it alone." -Quiet
        return 0
    }

    $lastFailure = 0
    if (Test-Path $FailFile) { $lastFailure = [double](Get-Content $FailFile -TotalCount 1) }
    if (-not $Now -and (Get-UnixTime) - $lastFailure -lt $FailBackoff) {
        Write-Log 'The last login was rejected less than 10 minutes ago; waiting before trying again.' -Quiet
        return 0
    }

    $login = Get-SavedLogin
    if (-not $login) {
        Write-Log 'No UoM username/password saved. Double-click "Set Up.bat" to add them.'
        return 1
    }

    Write-Log "No internet on the UoM network ($detail); logging in as $($login[0])"
    $result = Invoke-Login $PortalUrl $login[0] $login[1]
    if ($result -eq 'unreachable') { return 0 }  # the network isn't ready yet; the next run tries again
    if ($result -eq 'sent') {
        for ($i = 0; $i -lt 8; $i++) {
            Start-Sleep -Seconds 2
            if ((Get-NetStatus)[0] -eq 'online') {
                Write-Log 'Logged in. Internet is working.'
                Show-Notification 'Logged in to UoM Wi-Fi automatically.'
                Remove-Item -Force $FailFile -ErrorAction SilentlyContinue
                return 0
            }
        }
    }

    $firstFailure = -not (Test-Path $FailFile)
    Set-Content -Path $FailFile -Value (Get-UnixTime)
    Write-Log "Automatic login didn't get the internet working."
    if ($firstFailure -and -not $Now) {  # don't nag again every 10 minutes
        if ($result -eq 'rejected') {
            Show-Notification 'UoM Wi-Fi did not accept your username/password. Run "Set Up" again to fix it.'
        } else {
            Show-Notification 'Automatic login did not work. Please log in on the page that just opened.'
        }
        Start-Process $PortalUrl
    }
    1
}

exit (Invoke-Main)
