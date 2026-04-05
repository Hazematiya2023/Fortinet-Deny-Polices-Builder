<#
    FortiGate Automation Tool v10 - IP Reputation Edition
    Developed by: Hazem Mohamed

    New in V10:
    - IP Reputation Check BEFORE any block
    - Uses DNS-based blacklists (FREE, no login, no API key needed)
    - Sources: Spamhaus ZEN, Barracuda, SORBS, Blocklist.de, SpamCop, UCEPROTECT
    - Shows reputation result before executing policy
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$global:SSHSession = $null

# ============================================================
# IP REPUTATION ENGINE - DNS Based (No API Key Required)
# ============================================================
function Reverse-IP {
    param([string]$ip)
    $parts = $ip.Split(".")
    [array]::Reverse($parts)
    return $parts -join "."
}

function Check-SingleIP-DNS {
    param([string]$ip)

    $reversedIP = Reverse-IP -ip $ip

    $blacklists = @{
        "Spamhaus_ZEN"  = "zen.spamhaus.org"
        "Barracuda"     = "b.barracudacentral.org"
        "SORBS_SPAM"    = "spam.dnsbl.sorbs.net"
        "Blocklist_DE"  = "bl.blocklist.de"
        "SpamCop"       = "bl.spamcop.net"
        "UCEPROTECT_L1" = "dnsbl-1.uceprotect.net"
    }

    $listedCount = 0
    $details = @()

    foreach ($bl in $blacklists.GetEnumerator()) {
        $query = "$reversedIP.$($bl.Value)"
        try {
            $resolve = [System.Net.Dns]::GetHostAddresses($query)
            if ($resolve.Count -gt 0) {
                $listedCount++
                $details += "  [LISTED]  $($bl.Key)"
            }
        } catch {
            $details += "  [CLEAN]   $($bl.Key)"
        }
    }

    $totalLists = $blacklists.Count
    $score = [math]::Round((($totalLists - $listedCount) / $totalLists) * 100)

    return @{
        IP           = $ip
        Listed       = $listedCount
        Total        = $totalLists
        Score        = $score
        Details      = $details
        IsMalicious  = ($listedCount -ge 2)
        IsSuspicious = ($listedCount -eq 1)
    }
}

function Check-IPReputation {
    param(
        [string[]]$addresses,
        [System.Windows.Forms.TextBox]$logBox
    )

    $ts = { "[$((Get-Date).ToString('HH:mm:ss'))]" }

    $logBox.AppendText("$(& $ts) ========================================`r`n")
    $logBox.AppendText("$(& $ts) [*] IP REPUTATION CHECK (DNS-Based, Free)`r`n")
    $logBox.AppendText("$(& $ts) ========================================`r`n")

    $maliciousIPs  = @()
    $suspiciousIPs = @()
    $cleanIPs      = @()

    foreach ($addr in $addresses) {
        $addr = $addr.Trim()

        if ($addr -match "^(\d+\.\d+\.\d+\.\d+)(/\d+)?$") {
            $ip = $matches[1]
        } else {
            $logBox.AppendText("$(& $ts) [SKIP] FQDN '$addr' - skipping DNS check`r`n")
            continue
        }

        $logBox.AppendText("$(& $ts) Checking: $ip ...`r`n")
        $logBox.ScrollToCaret()
        [System.Windows.Forms.Application]::DoEvents()

        $result = Check-SingleIP-DNS -ip $ip

        foreach ($d in $result.Details) {
            $logBox.AppendText("$(& $ts)$d`r`n")
        }

        if ($result.IsMalicious) {
            $logBox.AppendText("$(& $ts) [MALICIOUS]  $ip - Listed: $($result.Listed)/$($result.Total) - Score: $($result.Score)%`r`n")
            $maliciousIPs += $ip
        } elseif ($result.IsSuspicious) {
            $logBox.AppendText("$(& $ts) [SUSPICIOUS] $ip - Listed: $($result.Listed)/$($result.Total) - Score: $($result.Score)%`r`n")
            $suspiciousIPs += $ip
        } else {
            $logBox.AppendText("$(& $ts) [CLEAN]      $ip - Score: $($result.Score)%`r`n")
            $cleanIPs += $ip
        }
    }

    $logBox.AppendText("$(& $ts) ========================================`r`n")
    $logBox.AppendText("$(& $ts) SUMMARY: Malicious=$($maliciousIPs.Count)  Suspicious=$($suspiciousIPs.Count)  Clean=$($cleanIPs.Count)`r`n")
    $logBox.AppendText("$(& $ts) ========================================`r`n")
    $logBox.ScrollToCaret()

    return @{
        Malicious  = $maliciousIPs
        Suspicious = $suspiciousIPs
        Clean      = $cleanIPs
        HasThreats = ($maliciousIPs.Count -gt 0 -or $suspiciousIPs.Count -gt 0)
    }
}

# ============================================================
# FORM
# ============================================================
$form = New-Object System.Windows.Forms.Form
$form.Text = "FortiGate Builder V10 - IP Reputation Edition"
$form.Size = New-Object System.Drawing.Size(720, 980)
$form.StartPosition = "CenterScreen"
$form.BackColor = "#f0f0f0"

$lblCredit = New-Object System.Windows.Forms.Label
$lblCredit.Text = "Developed by Hazem Mohamed | V10 - IP Reputation Edition"
$lblCredit.AutoSize = $true
$lblCredit.ForeColor = "DimGray"
$lblCredit.Font = New-Object System.Drawing.Font("Arial", 9, [System.Drawing.FontStyle]::Bold)
$lblCredit.Location = New-Object System.Drawing.Point(15, 910)
$form.Controls.Add($lblCredit)

# --- Group 1: Connection ---
$grpConn = New-Object System.Windows.Forms.GroupBox
$grpConn.Location = New-Object System.Drawing.Point(10, 10)
$grpConn.Size = New-Object System.Drawing.Size(680, 100)
$grpConn.Text = "1. Connection"
$form.Controls.Add($grpConn)

$lblIP2 = New-Object System.Windows.Forms.Label
$lblIP2.Location = New-Object System.Drawing.Point(10, 25)
$lblIP2.Text = "IP:"; $lblIP2.AutoSize = $true
$grpConn.Controls.Add($lblIP2)

$txtIP = New-Object System.Windows.Forms.TextBox
$txtIP.Location = New-Object System.Drawing.Point(40, 22)
$txtIP.Size = New-Object System.Drawing.Size(100, 20)
$grpConn.Controls.Add($txtIP)

$lblU = New-Object System.Windows.Forms.Label
$lblU.Location = New-Object System.Drawing.Point(150, 25)
$lblU.Text = "User:"; $lblU.AutoSize = $true
$grpConn.Controls.Add($lblU)

$txtUser = New-Object System.Windows.Forms.TextBox
$txtUser.Location = New-Object System.Drawing.Point(190, 22)
$txtUser.Size = New-Object System.Drawing.Size(100, 20)
$grpConn.Controls.Add($txtUser)

$lblP = New-Object System.Windows.Forms.Label
$lblP.Location = New-Object System.Drawing.Point(300, 25)
$lblP.Text = "Pass:"; $lblP.AutoSize = $true
$grpConn.Controls.Add($lblP)

$txtPass = New-Object System.Windows.Forms.TextBox
$txtPass.Location = New-Object System.Drawing.Point(340, 22)
$txtPass.Size = New-Object System.Drawing.Size(100, 20)
$txtPass.PasswordChar = "*"
$grpConn.Controls.Add($txtPass)

$btnConnect = New-Object System.Windows.Forms.Button
$btnConnect.Location = New-Object System.Drawing.Point(450, 20)
$btnConnect.Size = New-Object System.Drawing.Size(100, 25)
$btnConnect.Text = "Connect"
$grpConn.Controls.Add($btnConnect)

$lblSDWAN = New-Object System.Windows.Forms.Label
$lblSDWAN.Location = New-Object System.Drawing.Point(10, 55)
$lblSDWAN.Size = New-Object System.Drawing.Size(660, 40)
$lblSDWAN.Text = "SD-WAN Status: Not Connected"
$lblSDWAN.Font = New-Object System.Drawing.Font("Arial", 9, [System.Drawing.FontStyle]::Bold)
$lblSDWAN.ForeColor = "Gray"
$grpConn.Controls.Add($lblSDWAN)

# --- Group 2: Addresses ---
$grpAddr = New-Object System.Windows.Forms.GroupBox
$grpAddr.Location = New-Object System.Drawing.Point(10, 120)
$grpAddr.Size = New-Object System.Drawing.Size(680, 120)
$grpAddr.Text = "2. Addresses (No mask = /32 host)"
$form.Controls.Add($grpAddr)

$lblAddrName = New-Object System.Windows.Forms.Label
$lblAddrName.Location = New-Object System.Drawing.Point(10, 25)
$lblAddrName.Text = "Name:"; $lblAddrName.AutoSize = $true
$grpAddr.Controls.Add($lblAddrName)

$txtName = New-Object System.Windows.Forms.TextBox
$txtName.Location = New-Object System.Drawing.Point(60, 22)
$txtName.Size = New-Object System.Drawing.Size(150, 20)
$grpAddr.Controls.Add($txtName)

$lblType = New-Object System.Windows.Forms.Label
$lblType.Location = New-Object System.Drawing.Point(220, 25)
$lblType.Text = "Type:"; $lblType.AutoSize = $true
$grpAddr.Controls.Add($lblType)

$cmbType = New-Object System.Windows.Forms.ComboBox
$cmbType.Location = New-Object System.Drawing.Point(260, 22)
$cmbType.Size = New-Object System.Drawing.Size(80, 20)
$cmbType.Items.AddRange(@("subnet", "fqdn"))
$cmbType.SelectedIndex = 0
$cmbType.DropDownStyle = "DropDownList"
$grpAddr.Controls.Add($cmbType)

$lblVal = New-Object System.Windows.Forms.Label
$lblVal.Location = New-Object System.Drawing.Point(350, 25)
$lblVal.Text = "Value:"; $lblVal.AutoSize = $true
$grpAddr.Controls.Add($lblVal)

$txtVal = New-Object System.Windows.Forms.TextBox
$txtVal.Location = New-Object System.Drawing.Point(400, 22)
$txtVal.Size = New-Object System.Drawing.Size(150, 20)
$grpAddr.Controls.Add($txtVal)

$btnAddAddr = New-Object System.Windows.Forms.Button
$btnAddAddr.Location = New-Object System.Drawing.Point(560, 20)
$btnAddAddr.Size = New-Object System.Drawing.Size(100, 25)
$btnAddAddr.Text = "Add"
$grpAddr.Controls.Add($btnAddAddr)

$lstAddresses = New-Object System.Windows.Forms.ListBox
$lstAddresses.Location = New-Object System.Drawing.Point(10, 50)
$lstAddresses.Size = New-Object System.Drawing.Size(660, 60)
$grpAddr.Controls.Add($lstAddresses)

# --- Group 3: IP Reputation ---
$grpRep = New-Object System.Windows.Forms.GroupBox
$grpRep.Location = New-Object System.Drawing.Point(10, 250)
$grpRep.Size = New-Object System.Drawing.Size(680, 100)
$grpRep.Text = "3. IP Reputation Check (FREE - No API Key - DNS Based)"
$grpRep.ForeColor = "DarkGreen"
$form.Controls.Add($grpRep)

# Row 1: Button (left) + Sources info (right)
$btnCheckRep = New-Object System.Windows.Forms.Button
$btnCheckRep.Location = New-Object System.Drawing.Point(10, 18)
$btnCheckRep.Size = New-Object System.Drawing.Size(200, 32)
$btnCheckRep.Text = ">> Check IP Reputation"
$btnCheckRep.BackColor = "SteelBlue"
$btnCheckRep.ForeColor = "White"
$btnCheckRep.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Bold)
$grpRep.Controls.Add($btnCheckRep)

$lblSources = New-Object System.Windows.Forms.Label
$lblSources.Location = New-Object System.Drawing.Point(220, 22)
$lblSources.Size = New-Object System.Drawing.Size(450, 18)
$lblSources.Text = "Sources: Spamhaus ZEN, Barracuda, SORBS, Blocklist.de, SpamCop, UCEPROTECT"
$lblSources.Font = New-Object System.Drawing.Font("Arial", 8)
$lblSources.ForeColor = "DarkGray"
$grpRep.Controls.Add($lblSources)

# Row 2: Status label (full width)
$lblRepStatus = New-Object System.Windows.Forms.Label
$lblRepStatus.Location = New-Object System.Drawing.Point(10, 55)
$lblRepStatus.Size = New-Object System.Drawing.Size(480, 18)
$lblRepStatus.Text = "Status: Add addresses first, then click Check Reputation."
$lblRepStatus.Font = New-Object System.Drawing.Font("Arial", 8, [System.Drawing.FontStyle]::Bold)
$lblRepStatus.ForeColor = "DarkGray"
$grpRep.Controls.Add($lblRepStatus)

$chkSkipClean = New-Object System.Windows.Forms.CheckBox
$chkSkipClean.Location = New-Object System.Drawing.Point(500, 52)
$chkSkipClean.Size = New-Object System.Drawing.Size(170, 20)
$chkSkipClean.Text = "Ignore reputation result"
$chkSkipClean.AutoSize = $false
$chkSkipClean.ForeColor = "DarkRed"
$chkSkipClean.Font = New-Object System.Drawing.Font("Arial", 8)
$grpRep.Controls.Add($chkSkipClean)

# --- Group 4: Zones & Execution ---
$grpPol = New-Object System.Windows.Forms.GroupBox
$grpPol.Location = New-Object System.Drawing.Point(10, 355)
$grpPol.Size = New-Object System.Drawing.Size(680, 320)
$grpPol.Text = "4. Zones/Interfaces & Execution"
$form.Controls.Add($grpPol)

$btnFetch = New-Object System.Windows.Forms.Button
$btnFetch.Location = New-Object System.Drawing.Point(10, 20)
$btnFetch.Size = New-Object System.Drawing.Size(480, 35)
$btnFetch.Text = "Click Here to Fetch Zones/Interfaces"
$btnFetch.BackColor = "LightBlue"
$btnFetch.Font = New-Object System.Drawing.Font("Arial", 10, [System.Drawing.FontStyle]::Bold)
$grpPol.Controls.Add($btnFetch)

$lblManual = New-Object System.Windows.Forms.Label
$lblManual.Location = New-Object System.Drawing.Point(500, 25)
$lblManual.Text = "Manual:"; $lblManual.AutoSize = $true
$grpPol.Controls.Add($lblManual)

$txtManualZone = New-Object System.Windows.Forms.TextBox
$txtManualZone.Location = New-Object System.Drawing.Point(555, 22)
$txtManualZone.Size = New-Object System.Drawing.Size(100, 20)
$txtManualZone.Text = "WAN_ZONE"
$grpPol.Controls.Add($txtManualZone)

$btnAddManual = New-Object System.Windows.Forms.Button
$btnAddManual.Location = New-Object System.Drawing.Point(500, 45)
$btnAddManual.Size = New-Object System.Drawing.Size(160, 25)
$btnAddManual.Text = "Add Manual Zone"
$btnAddManual.BackColor = "LightGreen"
$grpPol.Controls.Add($btnAddManual)

$lblMode = New-Object System.Windows.Forms.Label
$lblMode.Location = New-Object System.Drawing.Point(10, 60)
$lblMode.Size = New-Object System.Drawing.Size(660, 20)
$lblMode.Text = "Mode: Not Loaded"
$lblMode.Font = New-Object System.Drawing.Font("Arial", 9, [System.Drawing.FontStyle]::Bold)
$grpPol.Controls.Add($lblMode)

$lblIn = New-Object System.Windows.Forms.Label
$lblIn.Location = New-Object System.Drawing.Point(10, 85)
$lblIn.Text = "Incoming (Source):"
$lblIn.AutoSize = $true
$lblIn.Font = New-Object System.Drawing.Font("Arial", 9, [System.Drawing.FontStyle]::Bold)
$grpPol.Controls.Add($lblIn)

$chkLstIn = New-Object System.Windows.Forms.CheckedListBox
$chkLstIn.Location = New-Object System.Drawing.Point(10, 105)
$chkLstIn.Size = New-Object System.Drawing.Size(240, 150)
$grpPol.Controls.Add($chkLstIn)

$lblOut = New-Object System.Windows.Forms.Label
$lblOut.Location = New-Object System.Drawing.Point(260, 85)
$lblOut.Text = "Outgoing (Destination):"
$lblOut.AutoSize = $true
$lblOut.Font = New-Object System.Drawing.Font("Arial", 9, [System.Drawing.FontStyle]::Bold)
$grpPol.Controls.Add($lblOut)

$chkLstOut = New-Object System.Windows.Forms.CheckedListBox
$chkLstOut.Location = New-Object System.Drawing.Point(260, 105)
$chkLstOut.Size = New-Object System.Drawing.Size(240, 150)
$grpPol.Controls.Add($chkLstOut)

$lblPol = New-Object System.Windows.Forms.Label
$lblPol.Location = New-Object System.Drawing.Point(510, 105)
$lblPol.Text = "Policy Prefix:"; $lblPol.AutoSize = $true
$grpPol.Controls.Add($lblPol)

$txtPolName = New-Object System.Windows.Forms.TextBox
$txtPolName.Location = New-Object System.Drawing.Point(510, 125)
$txtPolName.Size = New-Object System.Drawing.Size(150, 20)
$txtPolName.Text = "Auto_Deny"
$grpPol.Controls.Add($txtPolName)

$chkTop = New-Object System.Windows.Forms.CheckBox
$chkTop.Location = New-Object System.Drawing.Point(510, 155)
$chkTop.Text = "Move to Top"
$chkTop.Checked = $true
$chkTop.AutoSize = $true
$grpPol.Controls.Add($chkTop)

$btnExecute = New-Object System.Windows.Forms.Button
$btnExecute.Location = New-Object System.Drawing.Point(510, 185)
$btnExecute.Size = New-Object System.Drawing.Size(150, 70)
$btnExecute.Text = "EXECUTE"
$btnExecute.BackColor = "DarkRed"
$btnExecute.ForeColor = "White"
$btnExecute.Font = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Bold)
$grpPol.Controls.Add($btnExecute)

$lblInstr = New-Object System.Windows.Forms.Label
$lblInstr.Location = New-Object System.Drawing.Point(10, 265)
$lblInstr.Size = New-Object System.Drawing.Size(660, 45)
$lblInstr.Text = "Steps: 1)Connect  2)Add Addresses  3)Check Reputation  4)Fetch Zones  5)Select  6)EXECUTE`r`nSD-WAN: Use zones like 'virtual-wan-link' instead of individual ports!"
$lblInstr.ForeColor = "DarkBlue"
$lblInstr.Font = New-Object System.Drawing.Font("Arial", 8)
$grpPol.Controls.Add($lblInstr)

# --- Log ---
$txtLog = New-Object System.Windows.Forms.TextBox
$txtLog.Location = New-Object System.Drawing.Point(10, 685)
$txtLog.Size = New-Object System.Drawing.Size(680, 215)
$txtLog.Multiline = $true
$txtLog.ScrollBars = "Vertical"
$txtLog.ReadOnly = $true
$txtLog.Font = New-Object System.Drawing.Font("Consolas", 8)
$form.Controls.Add($txtLog)

function Log-Message {
    param($msg)
    $txtLog.AppendText("[$((Get-Date).ToString('HH:mm:ss'))] $msg`r`n")
    $txtLog.ScrollToCaret()
}

# ============================================================
# BUTTON EVENTS
# ============================================================

$btnConnect.Add_Click({
    try {
        $creds = New-Object System.Management.Automation.PSCredential(
            $txtUser.Text,
            ($txtPass.Text | ConvertTo-SecureString -AsPlainText -Force)
        )
        Get-SSHSession | Remove-SSHSession -ErrorAction SilentlyContinue
        $global:SSHSession = New-SSHSession -ComputerName $txtIP.Text -Credential $creds -AcceptKey -ErrorAction Stop
        Log-Message "Connected to $($txtIP.Text)"
        $btnConnect.BackColor = "LightGreen"

        Log-Message "Checking SD-WAN..."
        $sdwanCheck = Invoke-SSHCommand -SSHSession $global:SSHSession -Command "config system sdwan`nshow`nend" -TimeOut 10

        if ($sdwanCheck.Output -match "status enable") {
            $lblSDWAN.Text = "SD-WAN ENABLED - You MUST use zones (not individual interfaces)!"
            $lblSDWAN.ForeColor = "Green"
            Log-Message "SD-WAN is ENABLED"
        } else {
            $lblSDWAN.Text = "SD-WAN Disabled - Using regular interfaces"
            $lblSDWAN.ForeColor = "Orange"
            Log-Message "SD-WAN is DISABLED"
        }
    } catch {
        Log-Message "Connection Error: $($_.Exception.Message)"
        $btnConnect.BackColor = "Red"
        $lblSDWAN.Text = "Connection Failed"
        $lblSDWAN.ForeColor = "Red"
    }
})

$btnCheckRep.Add_Click({
    if ($lstAddresses.Items.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Please add addresses first!", "No Addresses", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $btnCheckRep.Enabled = $false
    $btnCheckRep.Text = "Checking..."
    $lblRepStatus.Text = "Running DNS reputation checks... Please wait."
    $lblRepStatus.ForeColor = "Blue"
    [System.Windows.Forms.Application]::DoEvents()

    $ipsToCheck = @()
    foreach ($item in $lstAddresses.Items) {
        $p = $item.Split("|")
        if ($p[1] -eq "subnet") {
            $ipsToCheck += $p[2].Split(" ")[0]
        }
    }

    if ($ipsToCheck.Count -eq 0) {
        Log-Message "No IP/subnet addresses to check (FQDNs skipped)"
        $lblRepStatus.Text = "No IPs to check - only FQDNs found"
        $btnCheckRep.Enabled = $true
        $btnCheckRep.Text = ">> Check IP Reputation"
        return
    }

    $repResults = Check-IPReputation -addresses $ipsToCheck -logBox $txtLog

    if ($repResults.HasThreats) {
        $msg = "REPUTATION ALERT`r`n`r`n"
        if ($repResults.Malicious.Count -gt 0) {
            $msg += "MALICIOUS IPs ($($repResults.Malicious.Count)):`r`n"
            foreach ($mip in $repResults.Malicious) { $msg += "  * $mip`r`n" }
        }
        if ($repResults.Suspicious.Count -gt 0) {
            $msg += "`r`nSUSPICIOUS IPs ($($repResults.Suspicious.Count)):`r`n"
            foreach ($sip in $repResults.Suspicious) { $msg += "  * $sip`r`n" }
        }
        $msg += "`r`nThese IPs appear on DNS blacklists.`r`nProceed with blocking? (Recommended: YES)"

        $lblRepStatus.Text = "THREAT DETECTED - Check log. You may proceed with blocking."
        $lblRepStatus.ForeColor = "Red"
        [System.Windows.Forms.MessageBox]::Show($msg, "Reputation Alert", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    } else {
        $lblRepStatus.Text = "All IPs CLEAN ($($ipsToCheck.Count) checked). Safe to proceed."
        $lblRepStatus.ForeColor = "DarkGreen"
        Log-Message "All IPs passed reputation check"
    }

    $btnCheckRep.Enabled = $true
    $btnCheckRep.Text = ">> Check IP Reputation"
})

$btnFetch.Add_Click({
    if ($global:SSHSession -eq $null -or -not $global:SSHSession.Connected) {
        [System.Windows.Forms.MessageBox]::Show("Please connect first!", "Error"); return
    }

    $chkLstIn.Items.Clear()
    $chkLstOut.Items.Clear()

    $sdwanCheck = Invoke-SSHCommand -SSHSession $global:SSHSession -Command "config system sdwan`nshow`nend" -TimeOut 10

    if ($sdwanCheck.Output -match "status enable") {
        Log-Message "=== SD-WAN: Fetching Zones + Interfaces ==="
        $lblMode.Text = "Mode: SD-WAN Zones + LAN Interfaces"
        $lblMode.ForeColor = "Green"

        try {
            $cmd = Invoke-SSHCommand -SSHSession $global:SSHSession -Command "show system sdwan" -TimeOut 20
            $lines = $cmd.Output -split "`n"
            $chkLstIn.Items.Add("any") | Out-Null
            $chkLstOut.Items.Add("any") | Out-Null
            $zonesFound = 0
            $inZoneSection = $false

            foreach ($line in $lines) {
                if ($line -match "^\s*config zone\s*$") { $inZoneSection = $true; continue }
                if ($inZoneSection -and $line -match "^\s*end\s*$") { $inZoneSection = $false; continue }
                if ($inZoneSection) {
                    if ($line -match '^\s*edit\s+"([^"]+)"') {
                        $zoneName = $matches[1]
                        if ($chkLstIn.Items -notcontains $zoneName) {
                            $chkLstIn.Items.Add($zoneName) | Out-Null
                            $chkLstOut.Items.Add($zoneName) | Out-Null
                            Log-Message "  Zone: $zoneName"
                            $zonesFound++
                        }
                    } elseif ($line -match '^\s*edit\s+([^\s]+)') {
                        $zoneName = $matches[1].Trim()
                        if ($zoneName -ne "" -and $chkLstIn.Items -notcontains $zoneName) {
                            $chkLstIn.Items.Add($zoneName) | Out-Null
                            $chkLstOut.Items.Add($zoneName) | Out-Null
                            Log-Message "  Zone: $zoneName"
                            $zonesFound++
                        }
                    }
                }
            }

            Log-Message "Fetching LAN interfaces..."
            $cmd2 = Invoke-SSHCommand -SSHSession $global:SSHSession -Command "show system interface" -TimeOut 15
            $lines2 = $cmd2.Output -split "`n"
            $currentInt = $null; $currentAlias = $null; $interfacesFound = 0

            foreach ($line in $lines2) {
                if ($line -match 'edit\s+"?([^"\s]+)"?') {
                    if ($currentInt) {
                        $dName = if ($currentAlias) { "$currentInt ($currentAlias)" } else { $currentInt }
                        if ($chkLstIn.Items -notcontains $dName) { $chkLstIn.Items.Add($dName) | Out-Null }
                        if ($chkLstOut.Items -notcontains $dName) { $chkLstOut.Items.Add($dName) | Out-Null }
                        $interfacesFound++
                    }
                    $currentInt = $matches[1]; $currentAlias = $null
                } elseif ($line -match 'set\s+(?:alias|description)\s+"?([^"\r\n]+)"?') {
                    $currentAlias = $matches[1]
                }
            }
            if ($currentInt) {
                $dName = if ($currentAlias) { "$currentInt ($currentAlias)" } else { $currentInt }
                if ($chkLstIn.Items -notcontains $dName) { $chkLstIn.Items.Add($dName) | Out-Null }
                if ($chkLstOut.Items -notcontains $dName) { $chkLstOut.Items.Add($dName) | Out-Null }
                $interfacesFound++
            }

            Log-Message "Total: $zonesFound zones + $interfacesFound interfaces"
            if ($zonesFound -eq 0) { Log-Message "No zones found. Use Manual field." }
        } catch { Log-Message "Fetch Error: $($_.Exception.Message)" }

    } else {
        Log-Message "=== Fetching Regular Interfaces ==="
        $lblMode.Text = "Mode: Regular Interfaces"
        $lblMode.ForeColor = "Blue"

        try {
            $cmd = Invoke-SSHCommand -SSHSession $global:SSHSession -Command "show system interface" -TimeOut 15
            $lines = $cmd.Output -split "`n"
            $chkLstIn.Items.Add("any") | Out-Null
            $chkLstOut.Items.Add("any") | Out-Null
            $currentInt = $null; $currentAlias = $null

            foreach ($line in $lines) {
                if ($line -match 'edit\s+"?([^"\s]+)"?') {
                    if ($currentInt) {
                        $dName = if ($currentAlias) { "$currentInt ($currentAlias)" } else { $currentInt }
                        $chkLstIn.Items.Add($dName) | Out-Null
                        $chkLstOut.Items.Add($dName) | Out-Null
                    }
                    $currentInt = $matches[1]; $currentAlias = $null
                } elseif ($line -match 'set\s+(?:alias|description)\s+"?([^"\r\n]+)"?') {
                    $currentAlias = $matches[1]
                }
            }
            if ($currentInt) {
                $dName = if ($currentAlias) { "$currentInt ($currentAlias)" } else { $currentInt }
                $chkLstIn.Items.Add($dName) | Out-Null
                $chkLstOut.Items.Add($dName) | Out-Null
            }
            Log-Message "Interfaces loaded: $($chkLstIn.Items.Count - 1)"
        } catch { Log-Message "Fetch Error: $($_.Exception.Message)" }
    }
})

$btnAddAddr.Add_Click({
    if ($txtName.Text -and $txtVal.Text) {
        $lstAddresses.Items.Add("$($txtName.Text)|$($cmbType.SelectedItem)|$($txtVal.Text)")
        Log-Message "Added: $($txtName.Text) = $($txtVal.Text)"
        $txtName.Text = ""; $txtVal.Text = ""
    } else {
        [System.Windows.Forms.MessageBox]::Show("Please fill Name and Value!", "Error")
    }
})

$btnAddManual.Add_Click({
    if ($txtManualZone.Text) {
        $zoneName = $txtManualZone.Text.Trim()
        if ($chkLstIn.Items -notcontains $zoneName) {
            $chkLstIn.Items.Add($zoneName) | Out-Null
            $chkLstOut.Items.Add($zoneName) | Out-Null
            Log-Message "Manually added zone: $zoneName"
        } else {
            Log-Message "Zone '$zoneName' already exists"
        }
    }
})

$btnExecute.Add_Click({
    if (!$global:SSHSession.Connected) {
        [System.Windows.Forms.MessageBox]::Show("Not Connected!", "Error"); return
    }
    if ($chkLstIn.CheckedItems.Count -eq 0 -or $chkLstOut.CheckedItems.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("Select at least one source and one destination!", "Error"); return
    }

    if (-not $chkSkipClean.Checked) {
        $hasSubnets = $false
        foreach ($item in $lstAddresses.Items) {
            if ($item -match "\|subnet\|") { $hasSubnets = $true; break }
        }
        if ($hasSubnets) {
            $answer = [System.Windows.Forms.MessageBox]::Show(
                "Did you run IP Reputation check?`r`n`r`nYES = Proceed anyway`r`nNO = Go back and check",
                "Reputation Reminder",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Question
            )
            if ($answer -eq [System.Windows.Forms.DialogResult]::No) { return }
        }
    }

    Log-Message "========================================"
    Log-Message "STARTING EXECUTION"
    Log-Message "========================================"

    $cmds = @()

    if ($lstAddresses.Items.Count -gt 0) {
        $cmds += "config firewall address"
        foreach ($item in $lstAddresses.Items) {
            $p = $item.Split("|")
            $name = $p[0]; $type = $p[1]; $val = $p[2]
            $cmds += "edit `"$name`""
            if ($type -eq "subnet") {
                if ($val -notmatch "/" -and $val -notmatch " ") {
                    Log-Message "Auto-fix: Adding /32 to $val"
                    $val = "$val 255.255.255.255"
                }
                $cmds += "set subnet $val"
            } else {
                $cmds += "set type fqdn"
                $cmds += "set fqdn `"$val`""
            }
            $cmds += "next"
        }
        $cmds += "end"
    }

    $addrStr = if ($lstAddresses.Items.Count) {
        ($lstAddresses.Items | ForEach-Object { "`"" + $_.Split("|")[0] + "`"" }) -join " "
    } else { "all" }

    $myPolicyNames = @()
    $cmds += "config firewall policy"

    foreach ($srcRaw in $chkLstIn.CheckedItems) {
        foreach ($dstRaw in $chkLstOut.CheckedItems) {
            $src = if ($srcRaw.ToString() -match "^(\S+)") { $matches[1] } else { $srcRaw.ToString() }
            $dst = if ($dstRaw.ToString() -match "^(\S+)") { $matches[1] } else { $dstRaw.ToString() }
            $rnd = Get-Random -Minimum 1000 -Maximum 9999
            $pName = "$($txtPolName.Text)_$($src)_to_$($dst)_$rnd"
            $myPolicyNames += $pName
            Log-Message "Creating policy: $pName"
            $cmds += "edit 0"
            $cmds += "set name `"$pName`""
            $cmds += "set srcintf `"$src`""
            $cmds += "set dstintf `"$dst`""
            $cmds += "set srcaddr $addrStr"
            $cmds += "set dstaddr all"
            $cmds += "set action deny"
            $cmds += "set schedule always"
            $cmds += "set service ALL"
            $cmds += "set logtraffic all"
            $cmds += "next"
        }
    }
    $cmds += "end"

    Log-Message "Sending commands to FortiGate..."
    $stream = $global:SSHSession.Session.CreateShellStream("dumb", 0, 0, 0, 0, 1000)
    $writer = New-Object System.IO.StreamWriter($stream)
    $writer.AutoFlush = $true
    Start-Sleep -Milliseconds 500
    while ($stream.DataAvailable) { $null = $stream.Read() }

    foreach ($c in $cmds) {
        $writer.WriteLine($c)
        Start-Sleep -Milliseconds 300
        while ($stream.DataAvailable) {
            $out = $stream.Read()
            if ($out -match "error|fail") { Log-Message "ERROR: $out" }
        }
    }

    if ($chkTop.Checked) {
        Log-Message "Moving policies to top..."
        Start-Sleep -Seconds 2
        try {
            $dumpCmd = Invoke-SSHCommand -SSHSession $global:SSHSession -Command "show firewall policy" -TimeOut 30
            $rawConfig = $dumpCmd.Output -split "`n"
            $nameToIdMap = @{}
            $currentID = $null
            foreach ($line in $rawConfig) {
                if ($line -match 'edit\s+(\d+)') { $currentID = $matches[1] }
                elseif ($line -match 'set\s+name\s+"?([^"\r\n]+)"?' -and $currentID) {
                    $nameToIdMap[$matches[1]] = $currentID
                }
            }
            $topID = $null
            if ($dumpCmd.Output -match 'edit\s+(\d+)') { $topID = $matches[1] }
            $cmds2 = @("config firewall policy")
            $movedCount = 0
            foreach ($name in $myPolicyNames) {
                if ($nameToIdMap.ContainsKey($name)) {
                    $myID = $nameToIdMap[$name]
                    if ($myID -ne $topID) { $cmds2 += "move $myID before $topID"; $movedCount++ }
                }
            }
            $cmds2 += "end"
            if ($movedCount -gt 0) {
                foreach ($c in $cmds2) { $writer.WriteLine($c); Start-Sleep -Milliseconds 100 }
                Log-Message "Moved $movedCount policies to top"
            }
        } catch { Log-Message "Move Error: $($_.Exception.Message)" }
    }

    $writer.Close()
    Log-Message "========================================"
    Log-Message "EXECUTION COMPLETE!"
    Log-Message "========================================"

    [System.Windows.Forms.MessageBox]::Show(
        "Process Complete!`r`n`r`nPolicies created: $($myPolicyNames.Count)",
        "Success",
        [System.Windows.Forms.MessageBoxButtons]::OK,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
})

$form.ShowDialog()
