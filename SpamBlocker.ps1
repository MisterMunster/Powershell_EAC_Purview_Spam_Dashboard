# SpamBlocker.ps1
# Exchange Online Spam IP Blocker with WHOIS HUD and Abuse Reporting
# Requires: ExchangeOnlineManagement module
# Run: powershell -ExecutionPolicy Bypass -File SpamBlocker.ps1

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# --- THEME ---
$bgDark    = [System.Drawing.Color]::FromArgb(18, 18, 24)
$bgPanel   = [System.Drawing.Color]::FromArgb(28, 28, 38)
$bgCard    = [System.Drawing.Color]::FromArgb(38, 38, 52)
$accent    = [System.Drawing.Color]::FromArgb(99, 102, 241)
$accentRed = [System.Drawing.Color]::FromArgb(239, 68, 68)
$accentGrn = [System.Drawing.Color]::FromArgb(34, 197, 94)
$accentAmb = [System.Drawing.Color]::FromArgb(251, 191, 36)
$textPri   = [System.Drawing.Color]::FromArgb(240, 240, 255)
$textSec   = [System.Drawing.Color]::FromArgb(148, 148, 180)
$fontMono  = New-Object System.Drawing.Font("Consolas", 9)
$fontUI    = New-Object System.Drawing.Font("Segoe UI", 9)
$fontUIB   = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$fontH     = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$fontSm    = New-Object System.Drawing.Font("Segoe UI", 8)

# --- STATE ---
$script:connected   = $false
$script:detectedIP  = $null
$script:blockRange  = $null
$script:abuseEmail  = $null
$script:whoisData   = $null
$script:lastTraces  = @()
$script:senderDomain = $null

# --- HELPERS ---
function Make-Label($text, $x, $y, $w, $h, $font=$fontUI, $color=$textPri) {
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $text
    $l.Location = [System.Drawing.Point]::new($x, $y)
    $l.Size = [System.Drawing.Size]::new($w, $h)
    $l.Font = $font
    $l.ForeColor = $color
    $l.BackColor = [System.Drawing.Color]::Transparent
    return $l
}

function Make-Button($text, $x, $y, $w, $h, $bg=$accent, $fg=$textPri) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $text
    $b.Location = [System.Drawing.Point]::new($x, $y)
    $b.Size = [System.Drawing.Size]::new($w, $h)
    $b.Font = $fontUIB
    $b.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
    $b.FlatAppearance.BorderSize = 0
    $b.BackColor = $bg
    $b.ForeColor = $fg
    $b.Cursor = [System.Windows.Forms.Cursors]::Hand
    return $b
}

function Make-TextBox($x, $y, $w, $h, $mono=$false) {
    $t = New-Object System.Windows.Forms.TextBox
    $t.Location = [System.Drawing.Point]::new($x, $y)
    $t.Size = [System.Drawing.Size]::new($w, $h)
    $t.BackColor = $bgCard
    $t.ForeColor = $textPri
    $t.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
    $t.Font = if ($mono) { $fontMono } else { $fontUI }
    return $t
}

function Make-Panel($x, $y, $w, $h, $color=$bgPanel) {
    $p = New-Object System.Windows.Forms.Panel
    $p.Location = [System.Drawing.Point]::new($x, $y)
    $p.Size = [System.Drawing.Size]::new($w, $h)
    $p.BackColor = $color
    return $p
}

function StatusMsg($msg, $color=$textSec) {
    $script:lblStatus.Text = $msg
    $script:lblStatus.ForeColor = $color
    $form.Refresh()
}

function Get-IPRange($ip) {
    $parts = $ip -split '\.'
    if ($parts.Count -ne 4) { return $null }
    return "$($parts[0]).$($parts[1]).$($parts[2]).1-$($parts[0]).$($parts[1]).$($parts[2]).255"
}

function Lookup-WHOIS($ip) {
    try {
        $r = Invoke-RestMethod "https://ipapi.co/$ip/json/" -TimeoutSec 8 -ErrorAction Stop
        return $r
    } catch {
        try {
            $r2 = Invoke-RestMethod "http://ip-api.com/json/$ip" -TimeoutSec 8 -ErrorAction Stop
            return [PSCustomObject]@{
                org          = $r2.org
                country_name = $r2.country
                city         = $r2.city
                asn          = $r2.as
                abuse_email  = $null
            }
        } catch { return $null }
    }
}

function Get-AbuseEmail($ip) {
    try {
        $r = Invoke-RestMethod "https://rdap.arin.net/registry/ip/$ip" -TimeoutSec 8 -ErrorAction Stop
        foreach ($entity in $r.entities) {
            if ($entity.roles -contains 'abuse') {
                foreach ($card in $entity.vcardArray[1]) {
                    if ($card[0] -eq 'email') { return $card[3] }
                }
            }
        }
    } catch {}
    return $null
}

# --- MAIN FORM ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "SpamBlocker - Exchange Online"
$form.Size = [System.Drawing.Size]::new(780, 872)
$form.StartPosition = "CenterScreen"
$form.BackColor = $bgDark
$form.ForeColor = $textPri
$form.Font = $fontUI
$form.FormBorderStyle = "FixedSingle"
$form.MaximizeBox = $false

# --- HEADER ---
$pHeader = Make-Panel 0 0 780 60 $bgPanel
$form.Controls.Add($pHeader)
$pHeader.Controls.Add((Make-Label "SpamBlocker" 18 8 300 30 $fontH $textPri))
$pHeader.Controls.Add((Make-Label "Exchange Online IP Block Tool" 22 36 400 16 $fontSm $textSec))

$script:lblConnect = Make-Label "* Not Connected" 560 18 200 20 $fontUIB $accentRed
$pHeader.Controls.Add($script:lblConnect)

$btnConnect = Make-Button "Connect EXO" 580 36 160 20 $bgCard $accent
$btnConnect.Font = $fontSm
$pHeader.Controls.Add($btnConnect)

# --- STEP 1 - TRACE ---
$p1 = Make-Panel 14 70 752 148 $bgPanel
$form.Controls.Add($p1)
$p1.Controls.Add((Make-Label "STEP 1 - Message Trace" 12 10 400 20 $fontUIB $accent))
$p1.Controls.Add((Make-Label "Subject contains:" 12 38 120 20))

$script:txtSubject = Make-TextBox 140 35 460 22
$p1.Controls.Add($script:txtSubject)

$p1.Controls.Add((Make-Label "Recipient email:" 12 65 115 20))
$script:txtRecipient = Make-TextBox 140 62 460 22
$p1.Controls.Add($script:txtRecipient)

$p1.Controls.Add((Make-Label "Days back:" 12 95 80 20))
$script:numDays = New-Object System.Windows.Forms.NumericUpDown
$script:numDays.Location = [System.Drawing.Point]::new(140, 92)
$script:numDays.Size = [System.Drawing.Size]::new(60, 22)
$script:numDays.Minimum = 1
$script:numDays.Maximum = 10
$script:numDays.Value = 2
$script:numDays.BackColor = $bgCard
$script:numDays.ForeColor = $textPri
$p1.Controls.Add($script:numDays)

$btnTrace = Make-Button "Run Trace" 615 42 120 52 $accent $textPri
$p1.Controls.Add($btnTrace)

$p1.Controls.Add((Make-Label "Results:" 12 122 60 18 $fontSm $textSec))
$script:lblTraceCount = Make-Label "-" 75 122 500 18 $fontSm $textSec
$p1.Controls.Add($script:lblTraceCount)

# --- STEP 2 - IP HUD ---
$p2 = Make-Panel 14 228 752 240 $bgPanel
$form.Controls.Add($p2)
$p2.Controls.Add((Make-Label "STEP 2 - Sender IP Intelligence" 12 10 400 20 $fontUIB $accent))

$pIP = Make-Panel 12 34 728 80 $bgCard
$p2.Controls.Add($pIP)

$pIP.Controls.Add((Make-Label "Detected IP:" 10 8 90 18 $fontSm $textSec))
$script:lblIP = Make-Label "-" 105 6 200 22 $fontH $accentAmb
$pIP.Controls.Add($script:lblIP)

$pIP.Controls.Add((Make-Label "Block Range:" 10 34 90 18 $fontSm $textSec))
$script:lblRange = Make-Label "-" 105 32 300 18 $fontMono $textPri
$pIP.Controls.Add($script:lblRange)

$pIP.Controls.Add((Make-Label "Country:" 420 8 60 18 $fontSm $textSec))
$script:lblCountry = Make-Label "-" 485 6 220 18 $fontUIB $textPri
$pIP.Controls.Add($script:lblCountry)

$pIP.Controls.Add((Make-Label "Org/ASN:" 420 34 60 18 $fontSm $textSec))
$script:lblOrg = Make-Label "-" 485 32 230 18 $fontUI $textSec
$pIP.Controls.Add($script:lblOrg)

$p2.Controls.Add((Make-Label "Abuse Contact:" 12 122 100 18 $fontSm $textSec))
$script:lblAbuse = Make-Label "-" 115 120 380 18 $fontMono $accentGrn
$p2.Controls.Add($script:lblAbuse)

$btnCopyAbuse = Make-Button "Copy Email" 510 116 110 22 $bgCard $textSec
$btnCopyAbuse.Font = $fontSm
$p2.Controls.Add($btnCopyAbuse)

$btnReportAbuse = Make-Button "Report Abuse" 12 150 150 34 $bgCard $accentAmb
$p2.Controls.Add($btnReportAbuse)

$btnIPHistory = Make-Button "Check AbuseIPDB" 172 150 150 34 $bgCard $textSec
$p2.Controls.Add($btnIPHistory)

$btnCopyIP = Make-Button "Copy IP" 332 150 90 34 $bgCard $textSec
$p2.Controls.Add($btnCopyIP)

$p2.Controls.Add((Make-Label "All IPs found:" 12 196 100 18 $fontSm $textSec))
$script:cmbIPs = New-Object System.Windows.Forms.ComboBox
$script:cmbIPs.Location = [System.Drawing.Point]::new(115, 193)
$script:cmbIPs.Size = [System.Drawing.Size]::new(250, 22)
$script:cmbIPs.BackColor = $bgCard
$script:cmbIPs.ForeColor = $textPri
$script:cmbIPs.FlatStyle = [System.Windows.Forms.FlatStyle]::Flat
$script:cmbIPs.Font = $fontMono
$p2.Controls.Add($script:cmbIPs)

$btnSelectIP = Make-Button "Use This IP" 375 191 100 22 $bgCard $accent
$btnSelectIP.Font = $fontSm
$p2.Controls.Add($btnSelectIP)

$btnParseHeaders = Make-Button "Parse Headers" 490 191 150 22 $bgCard $accentAmb
$btnParseHeaders.Font = $fontSm
$p2.Controls.Add($btnParseHeaders)

$p2.Controls.Add((Make-Label "Manual IP:" 12 220 72 18 $fontSm $textSec))
$script:txtManualIP = Make-TextBox 87 217 200 22 $true
$script:txtManualIP.Font = $fontMono
$p2.Controls.Add($script:txtManualIP)
$btnLookupIP = Make-Button "Look Up" 295 217 90 22 $bgCard $accent
$btnLookupIP.Font = $fontSm
$p2.Controls.Add($btnLookupIP)

# --- STEP 3 - BLOCK ---
$p3 = Make-Panel 14 478 752 202 $bgPanel
$form.Controls.Add($p3)
$p3.Controls.Add((Make-Label "STEP 3 - Block IP Range" 12 10 500 20 $fontUIB $accent))

# Row 1: Range field
$p3.Controls.Add((Make-Label "Range to block:" 12 40 110 20))
$script:txtBlockRange = Make-TextBox 125 37 450 22 $true
$p3.Controls.Add($script:txtBlockRange)

# Row 2: EXO Connection Filter
$p3.Controls.Add((Make-Label "EXO Filter Policy:" 12 70 120 20))
$script:txtPolicy = Make-TextBox 135 67 150 22
$script:txtPolicy.Text = "Default"
$p3.Controls.Add($script:txtPolicy)
$btnBlockEXO = Make-Button "Block in EXO" 295 63 140 26 $accentRed $textPri
$p3.Controls.Add($btnBlockEXO)
$btnUnblockEXO = Make-Button "Revert from EXO" 445 63 150 26 $bgCard $accentAmb
$p3.Controls.Add($btnUnblockEXO)

# Row 3: Purview DLP
$p3.Controls.Add((Make-Label "Purview DLP Policy:" 12 100 130 20))
$script:txtDLPPolicy = Make-TextBox 145 97 100 22
$script:txtDLPPolicy.Text = "IP based"
$p3.Controls.Add($script:txtDLPPolicy)
$p3.Controls.Add((Make-Label "Rule:" 252 100 35 20))
$script:txtDLPRule = Make-TextBox 290 97 100 22
$script:txtDLPRule.Text = "Sender IP Block"
$p3.Controls.Add($script:txtDLPRule)
$btnBlockDLP = Make-Button "Block in Purview" 400 93 150 26 $accentRed $textPri
$p3.Controls.Add($btnBlockDLP)
$btnUnblockDLP = Make-Button "Revert from Purview" 558 93 175 26 $bgCard $accentAmb
$p3.Controls.Add($btnUnblockDLP)

# Row 4: Block both + Manage
$btnBlockBoth = Make-Button "BLOCK IN BOTH" 12 130 200 30 $accentRed $textPri
$btnBlockBoth.Font = $fontUIB
$p3.Controls.Add($btnBlockBoth)
$p3.Controls.Add((Make-Label "Blocks EXO + Purview simultaneously." 220 136 230 18 $fontSm $textSec))
$btnManageBlockList = Make-Button "Manage Block List" 460 130 200 30 $bgCard $accentAmb
$btnManageBlockList.Font = $fontUIB
$p3.Controls.Add($btnManageBlockList)

# Row 5: Domain block
$p3.Controls.Add((Make-Label "Sender domain:" 12 170 110 20))
$script:txtBlockDomain = Make-TextBox 125 167 255 22 $true
$p3.Controls.Add($script:txtBlockDomain)
$btnBlockDomain  = Make-Button "Block Domain"  390 163 140 26 $accentRed $textPri
$btnUnblockDomain = Make-Button "Revert Domain" 540 163 148 26 $bgCard $accentAmb
$p3.Controls.Add($btnBlockDomain)
$p3.Controls.Add($btnUnblockDomain)

# --- STATUS BAR ---
$pStatus = Make-Panel 0 688 780 30 $bgCard
$form.Controls.Add($pStatus)
$script:lblStatus = Make-Label "Ready. Connect to Exchange Online to begin." 10 6 750 18 $fontSm $textSec
$pStatus.Controls.Add($script:lblStatus)

# --- LOG ---
$pLog = Make-Panel 14 724 752 100 $bgPanel
$form.Controls.Add($pLog)
$script:txtLog = New-Object System.Windows.Forms.RichTextBox
$script:txtLog.Location = [System.Drawing.Point]::new(0, 0)
$script:txtLog.Size = [System.Drawing.Size]::new(752, 62)
$script:txtLog.BackColor = $bgDark
$script:txtLog.ForeColor = $textSec
$script:txtLog.Font = $fontSm
$script:txtLog.ReadOnly = $true
$script:txtLog.BorderStyle = [System.Windows.Forms.BorderStyle]::None
$script:txtLog.ScrollBars = "Vertical"
$pLog.Controls.Add($script:txtLog)

function Log($msg, $color=$textSec) {
    $ts = Get-Date -Format "HH:mm:ss"
    $script:txtLog.SelectionColor = $color
    $script:txtLog.AppendText("[$ts] $msg`n")
    $script:txtLog.ScrollToCaret()
}

# --- SET IP INFO ---
function Set-IPInfo($ip) {
    $script:detectedIP = $ip
    $range = Get-IPRange $ip
    $script:blockRange = $range
    $script:lblIP.Text = $ip
    $script:lblRange.Text = $range
    $script:txtBlockRange.Text = $range
    Log "IP detected: $ip  ->  Range: $range" $accentAmb

    StatusMsg "Looking up IP intelligence for $ip..." $accentAmb
    $w = Lookup-WHOIS $ip
    if ($w) {
        $script:whoisData = $w
        $country = if ($w.country_name) { $w.country_name } elseif ($w.country) { $w.country } else { "Unknown" }
        $org     = if ($w.org) { $w.org } elseif ($w.asn) { $w.asn } else { "Unknown" }
        $city    = if ($w.city) { "$($w.city), " } else { "" }
        $script:lblCountry.Text = "$city$country"
        $script:lblOrg.Text = $org
        Log "Org: $org | Location: $city$country" $textSec

        $abuse = if ($w.abuse_email) { $w.abuse_email } else { Get-AbuseEmail $ip }
        if ($abuse) {
            $script:abuseEmail = $abuse
            $script:lblAbuse.Text = $abuse
            Log "Abuse contact: $abuse" $accentGrn
        } else {
            $script:lblAbuse.Text = "Not found - check AbuseIPDB"
            $script:abuseEmail = $null
        }
    }
    StatusMsg "IP intelligence loaded for $ip" $accentGrn
}

# --- EVENTS ---

$btnConnect.Add_Click({
    StatusMsg "Connecting to Exchange Online + Purview..." $accentAmb
    try {
        Import-Module ExchangeOnlineManagement -ErrorAction Stop
        # Connect Exchange Online (for message trace + connection filter)
        Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
        Log "Connected to Exchange Online." $accentGrn
        # Connect Security & Compliance (for Purview DLP cmdlets)
        try {
            Connect-IPPSSession -ShowBanner:$false -ErrorAction Stop
            Log "Connected to Security and Compliance (Purview)." $accentGrn
        } catch {
            Log "Purview (IPPS) connection failed: $_" $accentAmb
            Log "Purview DLP blocking will not work - EXO functions still available." $accentAmb
        }
        $script:connected = $true
        $script:lblConnect.Text = "* Connected"
        $script:lblConnect.ForeColor = $accentGrn
        StatusMsg "Connected to Exchange Online and Purview." $accentGrn
    } catch {
        StatusMsg "Connection failed: $_" $accentRed
        Log "Connection failed: $_" $accentRed
    }
})

$btnTrace.Add_Click({
    if (-not $script:connected) { StatusMsg "Connect to Exchange Online first." $accentRed; return }
    $subj = $script:txtSubject.Text.Trim()
    if ([string]::IsNullOrEmpty($subj)) { StatusMsg "Enter a subject to search." $accentRed; return }
    $recip = $script:txtRecipient.Text.Trim()

    StatusMsg "Running message trace - please wait..." $accentAmb
    Log "Tracing subject: '$subj' $(if($recip){"recipient: $recip"} else {"(all recipients)"})" $textSec
    try {
        $daysBack = [int]$script:numDays.Value
        $end    = Get-Date
        $start  = $end.AddDays(-$daysBack)
        Log "Date range: $($start.ToString('MM/dd HH:mm')) to $($end.ToString('MM/dd HH:mm'))" $textSec
        # Get-MessageTraceV2 - no PageSize param, handles pagination internally
        $params = @{
            StartDate   = $start
            EndDate     = $end
            ErrorAction = "SilentlyContinue"
        }
        if (-not [string]::IsNullOrEmpty($recip)) {
            $params.RecipientAddress = $recip
        }
        Log "Querying Exchange (V2 API)..." $textSec
        $allTraces = @(Get-MessageTraceV2 @params)
        Log "Total messages pulled: $($allTraces.Count) - filtering by subject..." $textSec
        $traces = @($allTraces | Where-Object { $_.Subject -like "*$subj*" })

        if (-not $traces -or $traces.Count -eq 0) {
            StatusMsg "No messages found matching that subject." $accentAmb
            Log "No results found." $accentAmb
            return
        }

        $script:lastTraces = @($traces)
        $script:lblTraceCount.Text = "$($traces.Count) message(s) found"
        Log "$($traces.Count) messages found. Fetching sender IPs..." $textSec

        $allIPs = @()
        $msgIndex = 0
        foreach ($t in ($traces | Select-Object -First 20)) {
            try {
                # Try V2 detail first, fall back to original
                $details = $null
                try {
                    $details = Get-MessageTraceDetailV2 -MessageTraceId $t.MessageTraceId `
                               -RecipientAddress $t.RecipientAddress -ErrorAction Stop
                } catch {
                    try {
                        $details = Get-MessageTraceDetail -MessageTraceId $t.MessageTraceId `
                                   -RecipientAddress $t.RecipientAddress -ErrorAction Stop
                    } catch {}
                }

                # Also check SenderAddress field directly on the trace record
                if ($t.SenderAddress -and $t.SenderAddress -notmatch '@mbaks') {
                    Log "Sender address from trace: $($t.SenderAddress)" $textSec
                    if ($msgIndex -eq 0 -and $t.SenderAddress -match '@(.+)$') {
                        $script:senderDomain = $Matches[1]
                        $script:txtBlockDomain.Text = $script:senderDomain
                    }
                }

                # Known relay/infrastructure ranges to skip (keep scanning for the real source)
                # RFC1918 private | Proofpoint Essentials | Amazon SES sending ranges
                $excludedRanges = '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|67\.231\.|148\.163\.|54\.240\.|54\.241\.|23\.249\.|23\.251\.)'

                foreach ($d in $details) {
                    # Check Data field for IPs
                    $searchText = "$($d.Data) $($d.Detail)"
                    if ($searchText -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
                        $ip = $Matches[1]
                        if ($ip -eq '127.0.0.1') { continue }
                        if ($ip -match $excludedRanges) {
                            if ($ip -match '^67\.231\.') {
                                Log "Skipped Proofpoint relay hop: $ip - continuing scan..." $textSec
                            } elseif ($ip -match '^(148\.163\.|54\.240\.|54\.241\.|23\.249\.|23\.251\.)') {
                                Log "Skipped Amazon SES relay hop: $ip - continuing scan..." $textSec
                            }
                            continue
                        }
                        if ($ip -notin $allIPs) {
                            $allIPs += $ip
                            Log "Found IP in details: $ip" $accentAmb
                        }
                    }
                }

                # Log raw detail for first message so we can see the structure
                if ($msgIndex -eq 0 -and $details) {
                    $first = $details | Select-Object -First 3
                    foreach ($d in $first) {
                        Log "Detail sample: Event=$($d.Event) Data=$($d.Data)" $textSec
                    }
                }
                $msgIndex++
            } catch {
                Log "Detail error: $_" $accentRed
            }
        }

        $script:cmbIPs.Items.Clear()
        foreach ($ip in $allIPs) { $script:cmbIPs.Items.Add($ip) | Out-Null }

        if ($allIPs.Count -gt 0) {
            $script:cmbIPs.SelectedIndex = 0
            Set-IPInfo $allIPs[0]
            StatusMsg "Trace complete. $($allIPs.Count) unique sender IP(s) found." $accentGrn
        } else {
            StatusMsg "Messages found but could not extract external sender IP." $accentAmb
            Log "Could not extract IPs from trace details." $accentAmb
        }
    } catch {
        StatusMsg "Trace error: $_" $accentRed
        Log "Error: $_" $accentRed
    }
})

$btnSelectIP.Add_Click({
    if ($script:cmbIPs.SelectedItem) { Set-IPInfo $script:cmbIPs.SelectedItem }
})

$btnParseHeaders.Add_Click({
    if (-not $script:connected) { StatusMsg "Connect to Exchange Online first." $accentRed; return }
    if (-not $script:lastTraces -or $script:lastTraces.Count -eq 0) {
        StatusMsg "Run a message trace first." $accentRed; return
    }
    StatusMsg "Fetching message headers..." $accentAmb
    Log "Parsing headers for source IP (checking X-Originating-IP, X-Forwarded-For, Received chain)..." $textSec

    $t = $script:lastTraces[0]
    try {
        $details = $null
        try {
            $details = @(Get-MessageTraceDetailV2 -MessageTraceId $t.MessageTraceId `
                         -RecipientAddress $t.RecipientAddress -ErrorAction Stop)
        } catch {
            try {
                $details = @(Get-MessageTraceDetail -MessageTraceId $t.MessageTraceId `
                             -RecipientAddress $t.RecipientAddress -ErrorAction Stop)
            } catch {}
        }

        if (-not $details -or $details.Count -eq 0) {
            StatusMsg "No detail events returned for that message." $accentAmb
            Log "No events found - cannot parse headers." $accentAmb
            return
        }

        $blob = ($details | ForEach-Object { "$($_.Data) $($_.Detail)" }) -join " "
        Log "Scanned $($details.Count) events ($($blob.Length) chars) for header IPs." $textSec

        $found = [System.Collections.Generic.List[string]]::new()

        # X-Originating-IP
        if ($blob -match 'X-Originating-IP[:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
            $found.Add("X-Originating-IP  : $($Matches[1])")
            Log "X-Originating-IP: $($Matches[1])" $accentAmb
        }

        # X-Forwarded-For
        $xffHits = [regex]::Matches($blob, 'X-Forwarded-For[:\s]+([\d\.,\s]+)')
        foreach ($m in $xffHits) {
            $innerIPs = [regex]::Matches($m.Groups[1].Value, '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
            foreach ($ipM in $innerIPs) {
                $found.Add("X-Forwarded-For   : $($ipM.Value)")
                Log "X-Forwarded-For: $($ipM.Value)" $accentAmb
            }
        }

        # Received: chain
        $rcvHits = [regex]::Matches($blob, 'Received[:\s]+[^\d]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        foreach ($m in $rcvHits) {
            $ip = $m.Groups[1].Value
            if ($ip -ne '127.0.0.1') {
                $found.Add("Received header   : $ip")
                Log "Received header IP: $ip" $accentAmb
            }
        }

        if ($found.Count -eq 0) {
            StatusMsg "No IPs found in headers - Proofpoint may have stripped them." $accentAmb
            Log "No header IPs found. Source IP likely stripped by Proofpoint before Exchange handoff." $accentAmb
            [System.Windows.Forms.MessageBox]::Show(
                "No source IPs were found in the message header events.`n`n" +
                "Proofpoint may have stripped the originating IP before handoff to Exchange.`n`n" +
                "To find the real source, examine the raw email's Received: headers directly`n" +
                "by downloading the .eml from Quarantine or asking the recipient to forward`n" +
                "the message as an attachment.",
                "Header Parse - No IPs Found",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information)
            return
        }

        # Build selection dialog
        $dlg = New-Object System.Windows.Forms.Form
        $dlg.Text = "Header IPs - $($t.Subject)"
        $dlg.Size = [System.Drawing.Size]::new(500, 310)
        $dlg.StartPosition = "CenterScreen"
        $dlg.BackColor = $bgDark
        $dlg.ForeColor = $textPri
        $dlg.FormBorderStyle = "FixedDialog"
        $dlg.MaximizeBox = $false

        $dlg.Controls.Add((Make-Label "IPs extracted from message headers:" 12 10 470 20 $fontUIB $accent))
        $dlg.Controls.Add((Make-Label "Select an entry and click Use Selected IP to load it into the HUD." 12 32 470 16 $fontSm $textSec))

        $lb = New-Object System.Windows.Forms.ListBox
        $lb.Location = [System.Drawing.Point]::new(12, 56)
        $lb.Size = [System.Drawing.Size]::new(462, 170)
        $lb.BackColor = $bgCard
        $lb.ForeColor = $textPri
        $lb.Font = $fontMono
        $lb.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
        foreach ($item in $found) { $lb.Items.Add($item) | Out-Null }
        $lb.SelectedIndex = 0
        $dlg.Controls.Add($lb)

        $btnUse   = Make-Button "Use Selected IP" 12 238 160 32 $accent $textPri
        $btnClose = Make-Button "Close" 184 238 80 32 $bgCard $textSec
        $dlg.Controls.Add($btnUse)
        $dlg.Controls.Add($btnClose)

        $btnUse.Add_Click({
            if ($lb.SelectedItem) {
                $raw = $lb.SelectedItem.ToString()
                if ($raw -match '(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') {
                    Set-IPInfo $Matches[1]
                    $dlg.Close()
                }
            }
        })
        $btnClose.Add_Click({ $dlg.Close() })

        StatusMsg "Header parse complete - $($found.Count) IP(s) found." $accentGrn
        $dlg.ShowDialog() | Out-Null

    } catch {
        StatusMsg "Header parse error: $_" $accentRed
        Log "Header parse error: $_" $accentRed
    }
})

# Shared lookup logic so both the button and Enter key call the same path
function Invoke-ManualIPLookup {
    $ip = $script:txtManualIP.Text.Trim()
    if ($ip -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
        Log "Manual IP entry: $ip" $textSec
        Set-IPInfo $ip
    } else {
        StatusMsg "Enter a valid IPv4 address (e.g. 203.0.113.45)." $accentRed
    }
}

$btnLookupIP.Add_Click({ Invoke-ManualIPLookup })

$script:txtManualIP.Add_KeyDown({
    if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Return) { Invoke-ManualIPLookup }
})

$btnCopyAbuse.Add_Click({
    if ($script:abuseEmail) {
        [System.Windows.Forms.Clipboard]::SetText($script:abuseEmail)
        StatusMsg "Abuse email copied to clipboard." $accentGrn
    }
})

$btnCopyIP.Add_Click({
    if ($script:detectedIP) {
        [System.Windows.Forms.Clipboard]::SetText($script:detectedIP)
        StatusMsg "IP copied to clipboard." $accentGrn
    }
})

$btnReportAbuse.Add_Click({
    $ip    = $script:detectedIP
    $email = $script:abuseEmail
    $org   = if ($script:whoisData -and $script:whoisData.org) { $script:whoisData.org } else { "your network" }
    if (-not $ip) { StatusMsg "No IP selected." $accentRed; return }

    # Build header block from trace detail events
    $headerBlock = ""
    if ($script:connected -and $script:lastTraces -and $script:lastTraces.Count -gt 0) {
        try {
            $t = $script:lastTraces[0]
            $details = $null
            try {
                $details = @(Get-MessageTraceDetailV2 -MessageTraceId $t.MessageTraceId `
                             -RecipientAddress $t.RecipientAddress -ErrorAction Stop)
            } catch {
                try {
                    $details = @(Get-MessageTraceDetail -MessageTraceId $t.MessageTraceId `
                                 -RecipientAddress $t.RecipientAddress -ErrorAction Stop)
                } catch {}
            }

            if ($details) {
                $wantedFields = @('ClientIP','ServerHostName','ProxiedClientIPAddress',
                                  'ProxiedClientHostname','OriginalFromAddress','ReturnPath',
                                  'ConnectorId','InboundConnectorData')
                $lines = @(
                    "--- Message Trace Headers ---",
                    "Message-ID : $($t.MessageId)",
                    "From       : $($t.SenderAddress)",
                    "To         : $($t.RecipientAddress)",
                    "Received   : $($t.Received)",
                    "Subject    : $($t.Subject)",
                    ""
                )
                foreach ($d in ($details | Where-Object { $_.Event -in @('Receive','Transfer','Submit') })) {
                    $lines += "Event: $($d.Event)"
                    try {
                        [xml]$xml = $d.Data
                        foreach ($mep in $xml.root.MEP) {
                            if ($mep.Name -in $wantedFields) {
                                $val = if ($mep.String) { $mep.String } `
                                       elseif ($mep.Blob) { $mep.Blob } `
                                       else { $null }
                                if ($val) { $lines += "  $($mep.Name): $val" }
                            }
                        }
                    } catch {
                        $lines += "  (raw) $($d.Data)"
                    }
                    $lines += ""
                }
                $headerBlock = $lines -join "`n"
                Log "Header block built: $($headerBlock.Length) chars" $textSec
            }
        } catch {
            Log "Could not fetch headers for abuse report: $_" $accentAmb
        }
    }

    $to      = if ($email) { $email } else { "" }
    $subject = [uri]::EscapeDataString("Abuse Report: Spam from $ip")

    $baseBody = "Dear Abuse Team,

I am writing to report spam email originating from IP address $ip ($org).

IP Address   : $ip
Block Range  : $($script:blockRange)
Sender Domain: $($script:senderDomain)
Date Reported: $(Get-Date -Format 'yyyy-MM-dd HH:mm') UTC
Subject      : $($script:txtSubject.Text)

"
    $closing = "Please investigate and take appropriate action.

Regards"

    # Fit headers inline if URL stays under 1900 chars; otherwise copy to clipboard
    $fullBody  = $baseBody + $headerBlock + "`n" + $closing
    $encodedFull = [uri]::EscapeDataString($fullBody)

    if ($encodedFull.Length -le 1900) {
        $body = $encodedFull
        if ($headerBlock) { Log "Headers included inline in abuse report." $textSec }
    } else {
        if ($headerBlock) {
            [System.Windows.Forms.Clipboard]::SetText($headerBlock)
            Log "Header block copied to clipboard (too long for mailto)." $accentAmb
            StatusMsg "Headers copied to clipboard - paste into email body after it opens." $accentAmb
        }
        $clipNote = if ($headerBlock) { "[Message headers copied to clipboard - paste here]`n`n" } else { "" }
        $body = [uri]::EscapeDataString($baseBody + $clipNote + $closing)
    }

    Start-Process "mailto:${to}?subject=$subject&body=$body"
    Log "Opened abuse report email to: $to" $accentAmb
})

$btnIPHistory.Add_Click({
    if ($script:detectedIP) {
        Start-Process "https://www.abuseipdb.com/check/$($script:detectedIP)"
        Log "Opened AbuseIPDB for $($script:detectedIP)" $textSec
    }
})

# Helper: Block in EXO Connection Filter
function Do-BlockEXO($range, $policy) {
    try {
        StatusMsg "Adding $range to EXO connection filter..." $accentAmb
        Set-HostedConnectionFilterPolicy -Identity $policy -IPBlockList @{Add=$range} -ErrorAction Stop
        Log "BLOCKED in EXO [$policy]: $range" $accentRed
        return $true
    } catch {
        Log "EXO block error: $_" $accentRed
        return $false
    }
}

# Helper: Revert from EXO Connection Filter
function Do-UnblockEXO($range, $policy) {
    try {
        StatusMsg "Removing $range from EXO connection filter..." $accentAmb
        Set-HostedConnectionFilterPolicy -Identity $policy -IPBlockList @{Remove=$range} -ErrorAction Stop
        Log "REVERTED from EXO [$policy]: $range" $accentGrn
        return $true
    } catch {
        Log "EXO revert error: $_" $accentRed
        return $false
    }
}

# Helper: Block in Purview DLP
function Do-BlockDLP($range, $dlpPolicy, $dlpRule) {
    try {
        StatusMsg "Adding $range to Purview DLP rule..." $accentAmb
        $rule = Get-DlpComplianceRule -Identity $dlpRule -ErrorAction Stop
        $existing = $rule.SenderIPRanges
        if ($existing -notcontains $range) {
            $newList = @($existing) + $range
            Set-DlpComplianceRule -Identity $dlpRule -SenderIPRanges $newList -Confirm:$false -ErrorAction Stop
            Log "BLOCKED in Purview [$dlpPolicy > $dlpRule]: $range" $accentRed
        } else {
            Log "Already in Purview DLP: $range" $accentAmb
        }
        return $true
    } catch {
        Log "Purview block error: $_" $accentRed
        return $false
    }
}

# Helper: Revert from Purview DLP
function Do-UnblockDLP($range, $dlpPolicy, $dlpRule) {
    try {
        StatusMsg "Removing $range from Purview DLP rule..." $accentAmb
        $rule = Get-DlpComplianceRule -Identity $dlpRule -ErrorAction Stop
        $newList = $rule.SenderIPRanges | Where-Object { $_ -ne $range }
        Set-DlpComplianceRule -Identity $dlpRule -SenderIPRanges $newList -Confirm:$false -ErrorAction Stop
        Log "REVERTED from Purview [$dlpRule]: $range" $accentGrn
        return $true
    } catch {
        Log "Purview revert error: $_" $accentRed
        return $false
    }
}

# Block in EXO only
$btnBlockEXO.Add_Click({
    if (-not $script:connected) { StatusMsg "Connect to Exchange Online first." $accentRed; return }
    $range = $script:txtBlockRange.Text.Trim()
    $policy = $script:txtPolicy.Text.Trim()
    if ([string]::IsNullOrEmpty($range)) { StatusMsg "No IP range specified." $accentRed; return }
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Block in EXO Connection Filter:`n$range`n`nPolicy: $policy`n`nContinue?",
        "Confirm EXO Block", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -ne "Yes") { return }
    if (Do-BlockEXO $range $policy) { StatusMsg "Blocked in EXO: $range" $accentGrn }
})

# Revert from EXO only
$btnUnblockEXO.Add_Click({
    if (-not $script:connected) { StatusMsg "Connect to Exchange Online first." $accentRed; return }
    $range = $script:txtBlockRange.Text.Trim()
    $policy = $script:txtPolicy.Text.Trim()
    if ([string]::IsNullOrEmpty($range)) { StatusMsg "No IP range specified." $accentRed; return }
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "REVERT from EXO Connection Filter:`n$range`n`nPolicy: $policy`n`nContinue?",
        "Confirm EXO Revert", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -ne "Yes") { return }
    if (Do-UnblockEXO $range $policy) { StatusMsg "Reverted from EXO: $range" $accentGrn }
})

# Block in Purview DLP only
$btnBlockDLP.Add_Click({
    if (-not $script:connected) { StatusMsg "Connect to Exchange Online first." $accentRed; return }
    $range = $script:txtBlockRange.Text.Trim()
    $dlpPolicy = $script:txtDLPPolicy.Text.Trim()
    $dlpRule = $script:txtDLPRule.Text.Trim()
    if ([string]::IsNullOrEmpty($range)) { StatusMsg "No IP range specified." $accentRed; return }
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Block in Purview DLP:`n$range`n`nPolicy: $dlpPolicy`nRule: $dlpRule`n`nContinue?",
        "Confirm Purview Block", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -ne "Yes") { return }
    if (Do-BlockDLP $range $dlpPolicy $dlpRule) { StatusMsg "Blocked in Purview: $range" $accentGrn }
})

# Revert from Purview DLP only
$btnUnblockDLP.Add_Click({
    if (-not $script:connected) { StatusMsg "Connect to Exchange Online first." $accentRed; return }
    $range = $script:txtBlockRange.Text.Trim()
    $dlpPolicy = $script:txtDLPPolicy.Text.Trim()
    $dlpRule = $script:txtDLPRule.Text.Trim()
    if ([string]::IsNullOrEmpty($range)) { StatusMsg "No IP range specified." $accentRed; return }
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "REVERT from Purview DLP:`n$range`n`nPolicy: $dlpPolicy`nRule: $dlpRule`n`nContinue?",
        "Confirm Purview Revert", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -ne "Yes") { return }
    if (Do-UnblockDLP $range $dlpPolicy $dlpRule) { StatusMsg "Reverted from Purview: $range" $accentGrn }
})

# Block in BOTH
$btnBlockBoth.Add_Click({
    if (-not $script:connected) { StatusMsg "Connect to Exchange Online first." $accentRed; return }
    $range = $script:txtBlockRange.Text.Trim()
    $policy = $script:txtPolicy.Text.Trim()
    $dlpPolicy = $script:txtDLPPolicy.Text.Trim()
    $dlpRule = $script:txtDLPRule.Text.Trim()
    if ([string]::IsNullOrEmpty($range)) { StatusMsg "No IP range specified." $accentRed; return }
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Block in BOTH locations:`n$range`n`nEXO Filter Policy: $policy`nPurview Policy: $dlpPolicy`nPurview Rule: $dlpRule`n`nContinue?",
        "Confirm Block Both", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -ne "Yes") { return }
    $exoOK = Do-BlockEXO $range $policy
    $dlpOK = Do-BlockDLP $range $dlpPolicy $dlpRule
    if ($exoOK -and $dlpOK) {
        StatusMsg "Blocked in both EXO and Purview: $range" $accentGrn
        [System.Windows.Forms.MessageBox]::Show("Blocked in both locations:`n$range", "Success",
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    } elseif ($exoOK) {
        StatusMsg "Blocked in EXO only - Purview failed. Check log." $accentAmb
    } elseif ($dlpOK) {
        StatusMsg "Blocked in Purview only - EXO failed. Check log." $accentAmb
    } else {
        StatusMsg "Both blocks failed. Check log." $accentRed
    }
})

$btnBlockDomain.Add_Click({
    if (-not $script:connected) { StatusMsg "Connect to Exchange Online first." $accentRed; return }
    $domain = $script:txtBlockDomain.Text.Trim()
    if ([string]::IsNullOrEmpty($domain)) { StatusMsg "No sender domain specified." $accentRed; return }
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Block all mail from sender domain:`n$domain`n`nCreates an EXO transport rule to reject messages from this domain.`n`nContinue?",
        "Confirm Domain Block", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -ne "Yes") { return }
    try {
        StatusMsg "Creating transport rule to block $domain..." $accentAmb
        $ruleName = "SpamBlocker: Block $domain"
        New-TransportRule -Name $ruleName `
            -SenderDomainIs $domain `
            -RejectMessageReasonText "Your message was rejected by the recipient organization." `
            -RejectMessageEnhancedStatusCode "5.7.1" `
            -Enabled $true `
            -ErrorAction Stop
        Log "BLOCKED sender domain via transport rule: $domain" $accentRed
        StatusMsg "Domain blocked: $domain" $accentGrn
    } catch {
        Log "Domain block error: $_" $accentRed
        StatusMsg "Domain block failed. Check log." $accentRed
    }
})

$btnUnblockDomain.Add_Click({
    if (-not $script:connected) { StatusMsg "Connect to Exchange Online first." $accentRed; return }
    $domain = $script:txtBlockDomain.Text.Trim()
    if ([string]::IsNullOrEmpty($domain)) { StatusMsg "No sender domain specified." $accentRed; return }
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "Remove domain block for:`n$domain`n`nContinue?",
        "Confirm Domain Revert", [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($confirm -ne "Yes") { return }
    try {
        StatusMsg "Removing domain block for $domain..." $accentAmb
        $ruleName = "SpamBlocker: Block $domain"
        $rule = Get-TransportRule -Identity $ruleName -ErrorAction SilentlyContinue
        if (-not $rule) {
            $rule = Get-TransportRule | Where-Object { $_.SenderDomainIs -contains $domain } | Select-Object -First 1
        }
        if ($rule) {
            Remove-TransportRule -Identity $rule.Identity -Confirm:$false -ErrorAction Stop
            Log "REVERTED domain block: $domain" $accentGrn
            StatusMsg "Domain block removed: $domain" $accentGrn
        } else {
            StatusMsg "No block rule found for domain: $domain" $accentAmb
            Log "No transport rule found for domain: $domain" $accentAmb
        }
    } catch {
        Log "Domain revert error: $_" $accentRed
        StatusMsg "Domain revert failed. Check log." $accentRed
    }
})

$btnManageBlockList.Add_Click({
    if (-not $script:connected) { StatusMsg "Connect to Exchange Online first." $accentRed; return }
    StatusMsg "Loading block lists..." $accentAmb

    try {
        $policy     = $script:txtPolicy.Text.Trim()
        $dlpRule    = $script:txtDLPRule.Text.Trim()
        $exoRanges  = @()
        $dlpRanges  = @()

        try {
            $cf = Get-HostedConnectionFilterPolicy -Identity $policy -ErrorAction Stop
            $exoRanges = @($cf.IPBlockList)
        } catch { Log "Could not read EXO block list: $_" $accentAmb }

        try {
            $rule = Get-DlpComplianceRule -Identity $dlpRule -ErrorAction Stop
            $dlpRanges = @($rule.SenderIPRanges)
        } catch { Log "Could not read Purview block list: $_" $accentAmb }

        Log "EXO blocked ranges: $($exoRanges.Count)  |  Purview blocked ranges: $($dlpRanges.Count)" $textSec

        # Build dialog
        $dlg = New-Object System.Windows.Forms.Form
        $dlg.Text = "Manage Block List"
        $dlg.Size = [System.Drawing.Size]::new(580, 460)
        $dlg.StartPosition = "CenterScreen"
        $dlg.BackColor = $bgDark
        $dlg.ForeColor = $textPri
        $dlg.FormBorderStyle = "FixedDialog"
        $dlg.MaximizeBox = $false

        $dlg.Controls.Add((Make-Label "EXO Connection Filter Block List  ($($exoRanges.Count) entries)" 12 10 540 20 $fontUIB $accent))
        $lbEXO = New-Object System.Windows.Forms.ListBox
        $lbEXO.Location  = [System.Drawing.Point]::new(12, 34)
        $lbEXO.Size      = [System.Drawing.Size]::new(540, 130)
        $lbEXO.BackColor = $bgCard
        $lbEXO.ForeColor = $textPri
        $lbEXO.Font      = $fontMono
        $lbEXO.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
        foreach ($r in $exoRanges) { $lbEXO.Items.Add($r) | Out-Null }
        $dlg.Controls.Add($lbEXO)

        $btnRemoveEXO = Make-Button "Remove Selected from EXO" 12 172 220 26 $accentRed $textPri
        $btnRemoveEXO.Font = $fontSm
        $dlg.Controls.Add($btnRemoveEXO)

        $dlg.Controls.Add((Make-Label "Purview DLP Blocked Ranges  ($($dlpRanges.Count) entries)" 12 212 540 20 $fontUIB $accent))
        $lbDLP = New-Object System.Windows.Forms.ListBox
        $lbDLP.Location  = [System.Drawing.Point]::new(12, 234)
        $lbDLP.Size      = [System.Drawing.Size]::new(540, 130)
        $lbDLP.BackColor = $bgCard
        $lbDLP.ForeColor = $textPri
        $lbDLP.Font      = $fontMono
        $lbDLP.BorderStyle = [System.Windows.Forms.BorderStyle]::FixedSingle
        foreach ($r in $dlpRanges) { $lbDLP.Items.Add($r) | Out-Null }
        $dlg.Controls.Add($lbDLP)

        $btnRemoveDLP = Make-Button "Remove Selected from Purview" 12 372 230 26 $accentRed $textPri
        $btnRemoveDLP.Font = $fontSm
        $dlg.Controls.Add($btnRemoveDLP)

        $btnClose = Make-Button "Close" 480 406 80 26 $bgCard $textSec
        $btnClose.Font = $fontSm
        $dlg.Controls.Add($btnClose)

        $btnRemoveEXO.Add_Click({
            $sel = $lbEXO.SelectedItem
            if (-not $sel) { return }
            $confirm = [System.Windows.Forms.MessageBox]::Show(
                "Remove from EXO block list:`n$sel`n`nContinue?", "Confirm Remove",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Warning)
            if ($confirm -ne "Yes") { return }
            try {
                Set-HostedConnectionFilterPolicy -Identity $policy -IPBlockList @{Remove=$sel} -ErrorAction Stop
                $lbEXO.Items.Remove($sel)
                Log "REMOVED from EXO block list: $sel" $accentGrn
                StatusMsg "Removed from EXO: $sel" $accentGrn
            } catch {
                Log "EXO remove error: $_" $accentRed
                StatusMsg "Remove failed. Check log." $accentRed
            }
        })

        $btnRemoveDLP.Add_Click({
            $sel = $lbDLP.SelectedItem
            if (-not $sel) { return }
            $confirm = [System.Windows.Forms.MessageBox]::Show(
                "Remove from Purview DLP:`n$sel`n`nContinue?", "Confirm Remove",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Warning)
            if ($confirm -ne "Yes") { return }
            try {
                $currentRule = Get-DlpComplianceRule -Identity $dlpRule -ErrorAction Stop
                $newList = $currentRule.SenderIPRanges | Where-Object { $_ -ne $sel }
                Set-DlpComplianceRule -Identity $dlpRule -SenderIPRanges $newList -Confirm:$false -ErrorAction Stop
                $lbDLP.Items.Remove($sel)
                Log "REMOVED from Purview DLP: $sel" $accentGrn
                StatusMsg "Removed from Purview: $sel" $accentGrn
            } catch {
                Log "Purview remove error: $_" $accentRed
                StatusMsg "Remove failed. Check log." $accentRed
            }
        })

        $btnClose.Add_Click({ $dlg.Close() })

        StatusMsg "Block list loaded. EXO: $($exoRanges.Count) | Purview: $($dlpRanges.Count)" $accentGrn
        $dlg.ShowDialog() | Out-Null

    } catch {
        StatusMsg "Block list load error: $_" $accentRed
        Log "Block list error: $_" $accentRed
    }
})

# --- RUN ---
Log "SpamBlocker ready. Connect to Exchange Online to start." $textSec
[System.Windows.Forms.Application]::Run($form)
