# SpamBlocker - Exchange Online Spam IP Block Dashboard

A PowerShell GUI tool for Microsoft 365 administrators to quickly trace, investigate, and block spam sender IPs across both Exchange Online connection filters and Microsoft Purview DLP policies — all from a single desktop application.

---

## The Problem

Spam campaigns frequently bypass DKIM, SPF, and DMARC filters by rotating sending IPs. The traditional remediation workflow requires navigating multiple admin portals:

1. Exchange Admin Center → Message Trace → find the email → drill into events → extract the sender IP
2. Look up the IP on a WHOIS/abuse tool to identify the sending organization
3. Microsoft Purview → DLP Policies → IP based → edit the rule → add the IP range
4. Exchange Online → Anti-spam → Connection filter policy → add the IP range

This process takes several minutes per incident and must often be repeated multiple times per day during active spam campaigns.

**SpamBlocker compresses this entire workflow into under 60 seconds.**

---

## Features

- **Message Trace** — Search Exchange Online message logs by subject + recipient using the `Get-MessageTraceV2` API
- **IP Intelligence HUD** — Automatically looks up detected sender IP for country, org, ASN, and abuse contact via ipapi.co / ip-api.com
- **AbuseIPDB Integration** — One-click to check the IP reputation on AbuseIPDB
- **Abuse Report Email** — Pre-fills a professional abuse report email to the hosting provider's abuse contact
- **Dual Block** — Blocks the IP /24 range in both:
  - Exchange Online Connection Filter Policy (Default)
  - Microsoft Purview DLP Policy (Sender IP Block rule)
- **Revert Buttons** — Instantly remove a block from either location if a legitimate sender is accidentally blocked
- **Activity Log** — Timestamped log panel showing all actions taken during the session
- **Dark UI** — Clean, readable interface built with Windows Forms

---

## Screenshots

> _Add screenshots here after first run_

---

## Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or later
- [ExchangeOnlineManagement module v3.x](https://www.powershellgallery.com/packages/ExchangeOnlineManagement)
- Microsoft 365 admin account with the following roles:
  - **Exchange Administrator** (for message trace and connection filter)
  - **Compliance Administrator** or **DLP Compliance Management** (for Purview DLP rules)

### Install the Exchange Online module (first time only)

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

---

## Installation

### Option 1: Installer (Recommended)

1. Download both `SpamBlocker.ps1` and `Install-SpamBlocker.ps1` to the same folder
2. Optionally place a file named `SPAM-Can.jpg` in your Downloads folder to use as the desktop icon
3. Right-click `Install-SpamBlocker.ps1` and select **Run with PowerShell**, or run:

```powershell
powershell -ExecutionPolicy Bypass -File Install-SpamBlocker.ps1
```

The installer will:
- Create `C:\Users\<you>\SpamBlocker\` and copy the script there
- Convert your `SPAM-Can.jpg` to a `.ico` file automatically (no extra tools needed)
- Create a **SpamCan** shortcut on your desktop

### Option 2: Manual

Copy `SpamBlocker.ps1` anywhere and run:

```powershell
powershell -ExecutionPolicy Bypass -File SpamBlocker.ps1
```

---

## Usage

### Step 1 — Connect

Click **Connect EXO**. This establishes two sessions:
- `Connect-ExchangeOnline` for message tracing and connection filter management
- `Connect-IPPSSession` for Purview DLP rule management

You may be prompted to authenticate twice via browser. The status indicator in the top right will turn green when connected.

### Step 2 — Trace

Fill in:
- **Subject contains** — a keyword or phrase from the spam subject line (e.g. `Voice Message`, `Missed Call`)
- **Recipient email** — the mailbox that received the spam (e.g. `user@yourdomain.com`)
- **Days back** — how far back to search (1–10 days)

Click **Run Trace**. The tool will pull matching messages and extract all unique external sender IPs found in the message trace details. Results are shown in the **All IPs found** dropdown.

### Step 3 — Investigate

The **Sender IP Intelligence** panel auto-populates with:
- Detected IP address
- Auto-generated block range (x.x.x.1 – x.x.x.255)
- Country and city
- Organization / ASN
- Abuse contact email

Use the action buttons to:
- **Check AbuseIPDB** — opens the IP reputation page in your browser
- **Report Abuse** — opens a pre-filled abuse report email in your mail client
- **Copy IP / Copy Email** — copies to clipboard for manual use
- **Use This IP** — if multiple IPs were found, select from the dropdown and switch

### Step 4 — Block

The block range is auto-filled in Step 3. Configure:
- **EXO Filter Policy** — defaults to `Default` (the Exchange Online connection filter)
- **Purview DLP Policy** — defaults to `IP based`
- **Purview Rule** — defaults to `Sender IP Block`

Then choose:
- **Block in EXO** — adds to Exchange Online connection filter only
- **Block in Purview** — adds to Purview DLP rule only
- **BLOCK IN BOTH** — adds to both locations simultaneously (recommended)

Each action requires confirmation before executing.

### Reverting a Block

If you accidentally block a legitimate sender, enter the same IP range in the block range field and click:
- **Revert from EXO** — removes from Exchange Online connection filter
- **Revert from Purview** — removes from Purview DLP rule

---

## Where Blocks Are Stored

| Location | Portal | Path |
|---|---|---|
| EXO Connection Filter | Microsoft Defender | Email & Collaboration → Policies & Rules → Threat Policies → Anti-spam policies → Connection filter policy (Default) → IP Block List |
| Purview DLP | Microsoft Purview | Data Loss Prevention → Policies → IP based → Edit → Advanced DLP rules → Sender IP Block |

---

## Architecture Notes

- Uses `Get-MessageTraceV2` (the current supported API — `Get-MessageTrace` is deprecated as of September 2025)
- Uses `Get-DlpComplianceRule` / `Set-DlpComplianceRule` via the Security & Compliance PowerShell endpoint (`Connect-IPPSSession`)
- Uses `Set-HostedConnectionFilterPolicy` for Exchange Online connection filter management
- IP intelligence lookups use `https://ipapi.co` with fallback to `http://ip-api.com`
- Abuse contact lookup uses the ARIN RDAP API (`https://rdap.arin.net`)
- All blocking actions require explicit user confirmation via dialog
- No data is stored or transmitted outside of Microsoft 365 APIs and public IP lookup services

---

## Files

| File | Description |
|---|---|
| `SpamBlocker.ps1` | Main application |
| `Install-SpamBlocker.ps1` | One-time installer that creates the desktop shortcut and converts the icon |

---

## Troubleshooting

**"Get-MessageTraceV2 is not recognized"**
Your ExchangeOnlineManagement module is outdated. Run:
```powershell
Update-Module ExchangeOnlineManagement
```

**"Get-DlpComplianceRule is not recognized"**
The Purview session did not connect. Click Connect EXO again — you should see a second browser authentication prompt for the Security & Compliance endpoint.

**"No messages found matching that subject"**
- Try increasing Days back to 3–5
- Check the exact subject text — Exchange stores subjects with `<External>` prefixes
- Confirm the recipient email address is correct

**Icon not showing on shortcut**
Make sure `SPAM-Can.jpg` is in your Downloads folder before running the installer. You can re-run the installer at any time to update the icon.

---

## Contributing

Pull requests welcome. Common enhancements to consider:
- CSV log of all blocked IP ranges with timestamps
- "View current block list" panel showing all entries in both EXO and Purview
- Sender domain blocking in addition to IP range blocking
- Integration with AbuseIPDB API for automated reputation scoring

---

## License

MIT License — free to use, modify, and distribute.

---

## Author

Built for [Master Builders Association of King and Snohomish Counties (MBAKS)](https://www.mbaks.com) IT administration.
