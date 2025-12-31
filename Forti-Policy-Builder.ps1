<#
    FortiGate Automation Tool V1 
    Developed by: Hazem Mohamed | Free Mind Teach 
    
    Fixes:
    1. Auto-appends subnet mask if missing (Fixes 'incomplete command').
    2. Appends Random ID to policy names to avoid 'already used' error.
    3. Handles interface aliases gracefully.
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$global:SSHSession = $null

# --- Form Setup ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "FortiGate Deny Polices Builder-V1)"
$form.Size = New-Object System.Drawing.Size(700, 850)
$form.StartPosition = "CenterScreen"
$form.BackColor = "#f0f0f0"

# --- Credits ---
$lblCredit = New-Object System.Windows.Forms.Label
$lblCredit.Text = "Developed by Hazem Mohamed | FreeMind Tech"
$lblCredit.AutoSize = $true; $lblCredit.ForeColor = "DimGray"
$lblCredit.Font = New-Object System.Drawing.Font("Arial", 9, [System.Drawing.FontStyle]::Bold)
$lblCredit.Location = New-Object System.Drawing.Point(15, 780); $form.Controls.Add($lblCredit)

# --- UI Elements ---
$grpConn = New-Object System.Windows.Forms.GroupBox; $grpConn.Location = New-Object System.Drawing.Point(10, 10); $grpConn.Size = New-Object System.Drawing.Size(660, 80); $grpConn.Text = "1. Connection"
$form.Controls.Add($grpConn)
$lblIP = New-Object System.Windows.Forms.Label; $lblIP.Location = New-Object System.Drawing.Point(10, 25); $lblIP.Text = "IP:"; $lblIP.AutoSize = $true; $grpConn.Controls.Add($lblIP)
$txtIP = New-Object System.Windows.Forms.TextBox; $txtIP.Location = New-Object System.Drawing.Point(40, 22); $txtIP.Size = New-Object System.Drawing.Size(100, 20); $grpConn.Controls.Add($txtIP)
$lblU = New-Object System.Windows.Forms.Label; $lblU.Location = New-Object System.Drawing.Point(150, 25); $lblU.Text = "User:"; $lblU.AutoSize = $true; $grpConn.Controls.Add($lblU)
$txtUser = New-Object System.Windows.Forms.TextBox; $txtUser.Location = New-Object System.Drawing.Point(190, 22); $txtUser.Size = New-Object System.Drawing.Size(100, 20); $grpConn.Controls.Add($txtUser)
$lblP = New-Object System.Windows.Forms.Label; $lblP.Location = New-Object System.Drawing.Point(300, 25); $lblP.Text = "Pass:"; $lblP.AutoSize = $true; $grpConn.Controls.Add($lblP)
$txtPass = New-Object System.Windows.Forms.TextBox; $txtPass.Location = New-Object System.Drawing.Point(340, 22); $txtPass.Size = New-Object System.Drawing.Size(100, 20); $txtPass.PasswordChar = "*"; $grpConn.Controls.Add($txtPass)
$btnConnect = New-Object System.Windows.Forms.Button; $btnConnect.Location = New-Object System.Drawing.Point(450, 20); $btnConnect.Size = New-Object System.Drawing.Size(100, 25); $btnConnect.Text = "Connect"; $grpConn.Controls.Add($btnConnect)

$grpAddr = New-Object System.Windows.Forms.GroupBox; $grpAddr.Location = New-Object System.Drawing.Point(10, 100); $grpAddr.Size = New-Object System.Drawing.Size(660, 120); $grpAddr.Text = "2. Addresses (Values without mask will act as /32)"
$form.Controls.Add($grpAddr)
$txtName = New-Object System.Windows.Forms.TextBox; $txtName.Location = New-Object System.Drawing.Point(60, 22); $txtName.Size = New-Object System.Drawing.Size(150, 20); $grpAddr.Controls.Add($txtName)
$cmbType = New-Object System.Windows.Forms.ComboBox; $cmbType.Location = New-Object System.Drawing.Point(260, 22); $cmbType.Size = New-Object System.Drawing.Size(80, 20); $cmbType.Items.AddRange(@("subnet", "fqdn")); $cmbType.SelectedIndex = 0; $grpAddr.Controls.Add($cmbType)
$txtVal = New-Object System.Windows.Forms.TextBox; $txtVal.Location = New-Object System.Drawing.Point(360, 22); $txtVal.Size = New-Object System.Drawing.Size(130, 20); $grpAddr.Controls.Add($txtVal)
$btnAddAddr = New-Object System.Windows.Forms.Button; $btnAddAddr.Location = New-Object System.Drawing.Point(500, 20); $btnAddAddr.Text = "Add"; $grpAddr.Controls.Add($btnAddAddr)
$lstAddresses = New-Object System.Windows.Forms.ListBox; $lstAddresses.Location = New-Object System.Drawing.Point(10, 50); $lstAddresses.Size = New-Object System.Drawing.Size(640, 60); $grpAddr.Controls.Add($lstAddresses)

$grpPol = New-Object System.Windows.Forms.GroupBox; $grpPol.Location = New-Object System.Drawing.Point(10, 230); $grpPol.Size = New-Object System.Drawing.Size(660, 300); $grpPol.Text = "3. Matrix & Execution"
$form.Controls.Add($grpPol)
$btnFetch = New-Object System.Windows.Forms.Button; $btnFetch.Location = New-Object System.Drawing.Point(10, 20); $btnFetch.Size = New-Object System.Drawing.Size(640, 30); $btnFetch.Text = "Fetch Interfaces"; $btnFetch.BackColor = "LightBlue"; $grpPol.Controls.Add($btnFetch)
$chkLstIn = New-Object System.Windows.Forms.CheckedListBox; $chkLstIn.Location = New-Object System.Drawing.Point(10, 80); $chkLstIn.Size = New-Object System.Drawing.Size(220, 150); $grpPol.Controls.Add($chkLstIn)
$chkLstOut = New-Object System.Windows.Forms.CheckedListBox; $chkLstOut.Location = New-Object System.Drawing.Point(240, 80); $chkLstOut.Size = New-Object System.Drawing.Size(220, 150); $grpPol.Controls.Add($chkLstOut)
$lblPol = New-Object System.Windows.Forms.Label; $lblPol.Location = New-Object System.Drawing.Point(470, 80); $lblPol.Text = "Prefix:"; $lblPol.AutoSize = $true; $grpPol.Controls.Add($lblPol)
$txtPolName = New-Object System.Windows.Forms.TextBox; $txtPolName.Location = New-Object System.Drawing.Point(520, 77); $txtPolName.Size = New-Object System.Drawing.Size(100, 20); $txtPolName.Text = "Auto_Deny"; $grpPol.Controls.Add($txtPolName)
$chkTop = New-Object System.Windows.Forms.CheckBox; $chkTop.Location = New-Object System.Drawing.Point(470, 110); $chkTop.Text = "Move to Top"; $chkTop.Checked = $true; $chkTop.AutoSize = $true; $grpPol.Controls.Add($chkTop)
$btnExecute = New-Object System.Windows.Forms.Button; $btnExecute.Location = New-Object System.Drawing.Point(470, 150); $btnExecute.Size = New-Object System.Drawing.Size(170, 80); $btnExecute.Text = "EXECUTE (SAFE)"; $btnExecute.BackColor = "DarkRed"; $btnExecute.ForeColor = "White"; $grpPol.Controls.Add($btnExecute)

$txtLog = New-Object System.Windows.Forms.TextBox; $txtLog.Location = New-Object System.Drawing.Point(10, 540); $txtLog.Size = New-Object System.Drawing.Size(660, 230); $txtLog.Multiline = $true; $txtLog.ScrollBars = "Vertical"; $txtLog.ReadOnly = $true; $form.Controls.Add($txtLog)

function Log-Message { param($msg) $txtLog.AppendText("[$((Get-Date).ToString('HH:mm:ss'))] $msg`r`n"); $txtLog.ScrollToCaret() }

$btnConnect.Add_Click({
    try {
        $creds = New-Object System.Management.Automation.PSCredential($txtUser.Text, ($txtPass.Text | ConvertTo-SecureString -AsPlainText -Force))
        Get-SSHSession | Remove-SSHSession -ErrorAction SilentlyContinue
        $global:SSHSession = New-SSHSession -ComputerName $txtIP.Text -Credential $creds -AcceptKey -ErrorAction Stop
        Log-Message "Connected to $($txtIP.Text)"
        $btnConnect.BackColor = "LightGreen"
    } catch { Log-Message "Connect Error: $($_.Exception.Message)" }
})

$btnFetch.Add_Click({
    if ($global:SSHSession -eq $null -or -not $global:SSHSession.Connected) { Log-Message "Connect first!"; return }
    Log-Message "Fetching Interfaces..."
    $chkLstIn.Items.Clear(); $chkLstOut.Items.Clear()
    try {
        $cmd = Invoke-SSHCommand -SSHSession $global:SSHSession -Command "show system interface"
        $lines = $cmd.Output -split "`n"
        $currentInt = $null; $currentAlias = $null
        foreach ($line in $lines) {
            if ($line -match 'edit\s+"?([^"\s]+)"?') {
                if ($currentInt) {
                     $dName = if ($currentAlias) { "$currentInt ($currentAlias)" } else { $currentInt }
                     $chkLstIn.Items.Add($dName)|Out-Null; $chkLstOut.Items.Add($dName)|Out-Null
                }
                $currentInt = $matches[1]; $currentAlias = $null
            } elseif ($line -match 'set\s+(?:alias|description)\s+"?([^"\r\n]+)"?') { $currentAlias = $matches[1] }
        }
        if ($currentInt) { 
            $dName = if ($currentAlias) { "$currentInt ($currentAlias)" } else { $currentInt }
            $chkLstIn.Items.Add($dName)|Out-Null; $chkLstOut.Items.Add($dName)|Out-Null 
        }
        Log-Message "Interfaces Fetched."
    } catch { Log-Message "Fetch Error: $($_.Exception.Message)" }
})

$btnAddAddr.Add_Click({ if ($txtName.Text) { $lstAddresses.Items.Add("$($txtName.Text)|$($cmbType.SelectedItem)|$($txtVal.Text)"); $txtName.Text="" } })

# --- CORE EXECUTION (FIXED) ---
$btnExecute.Add_Click({
    if (!$global:SSHSession.Connected) { [System.Windows.Forms.MessageBox]::Show("Not Connected"); return }
    
    # 1. Prepare Commands
    $cmds = @()
    
    # Address Block with AUTO-FIX
    if ($lstAddresses.Items.Count -gt 0) {
        $cmds += "config firewall address"
        foreach ($item in $lstAddresses.Items) {
            $p=$item.Split("|")
            $name = $p[0]
            $type = $p[1]
            $val = $p[2]
            
            $cmds += "edit `"$name`""
            
            if ($type -eq "subnet") {
                # --- AUTO-FIX: Check if mask is missing ---
                if ($val -notmatch "/" -and $val -notmatch " ") {
                     Log-Message "Info: Value '$val' has no mask. Appending '255.255.255.255'"
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

    # Policy Block with UNIQUE NAMES
    $addrStr = if ($lstAddresses.Items.Count) { ($lstAddresses.Items | % { "`"" + $_.Split("|")[0] + "`"" }) -join " " } else { "all" }
    $myPolicyNames = @()
    
    $cmds += "config firewall policy"
    foreach ($srcRaw in $chkLstIn.CheckedItems) {
        foreach ($dstRaw in $chkLstOut.CheckedItems) {
            # Clean Interfaces
            $srcRawString = $srcRaw.ToString()
            $dstRawString = $dstRaw.ToString()
            if ($srcRawString -match "^(\S+)") { $src = $matches[1] } else { $src = $srcRawString }
            if ($dstRawString -match "^(\S+)") { $dst = $matches[1] } else { $dst = $dstRawString }

            # --- UNIQUE NAME GENERATOR ---
            # Appends a random number (1000-9999) to ensure name is unique each run
            $rnd = Get-Random -Minimum 1000 -Maximum 9999
            $pName = "$($txtPolName.Text)_$($src)_to_$($dst)_$rnd"
            $myPolicyNames += $pName
            
            Log-Message "Queued: $pName"
            
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
    
    # 2. EXECUTE
    Log-Message "--- Sending Config ---"
    $stream = $global:SSHSession.Session.CreateShellStream("dumb", 0, 0, 0, 0, 1000)
    $writer = New-Object System.IO.StreamWriter($stream); $writer.AutoFlush = $true
    
    Start-Sleep -Milliseconds 500
    while($stream.DataAvailable) { $null = $stream.Read() } 

    foreach ($c in $cmds) {
        $writer.WriteLine($c)
        Start-Sleep -Milliseconds 250 
        # Check for errors
        while($stream.DataAvailable) { 
            $out = $stream.Read()
            if ($out -match "error" -or $out -match "fail") { Log-Message "ERROR: $out" }
        }
    }
    
    # 3. MOVE LOGIC
    if ($chkTop.Checked) {
        Log-Message "--- Moving Policies ---"
        Start-Sleep -Seconds 2
        try {
            $dumpCmd = Invoke-SSHCommand -SSHSession $global:SSHSession -Command "show firewall policy"
            $rawConfig = $dumpCmd.Output -split "`n"
            $nameToIdMap = @{}; $currentID = $null
            
            foreach ($line in $rawConfig) {
                if ($line -match 'edit\s+(\d+)') { $currentID = $matches[1] }
                elseif ($line -match 'set\s+name\s+"?([^"\r\n]+)"?' -and $currentID) { $nameToIdMap[$matches[1]] = $currentID }
            }
            
            # Find the very first ID in the list
            $topID = $null
            if ($dumpCmd.Output -match 'edit\s+(\d+)') { $topID = $matches[1] }
            
            $cmds2 = @("config firewall policy"); $movedCount = 0
            foreach ($name in $myPolicyNames) {
                if ($nameToIdMap.ContainsKey($name)) {
                    $myID = $nameToIdMap[$name]
                    if ($myID -ne $topID) { $cmds2 += "move $myID before $topID"; $movedCount++ }
                }
            }
            $cmds2 += "end"
            
            if ($movedCount -gt 0) { 
                foreach ($c in $cmds2) { $writer.WriteLine($c); Start-Sleep -Milliseconds 100 }
                Log-Message "Success: Moved $movedCount policies."
            }
        } catch { Log-Message "Move Error: $($_.Exception.Message)" }
    }
    
    $writer.Close()
    Log-Message "DONE."
    [System.Windows.Forms.MessageBox]::Show("Process Complete!", "Success")
})

$form.ShowDialog()