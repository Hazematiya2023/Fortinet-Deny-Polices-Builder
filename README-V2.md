# FortiGate Builder — Automated Policy & Address Tool

> **Developed by Hazem Mohamed**
> PowerShell GUI tool for automating FortiGate firewall policy creation over SSH, with built-in IP Reputation checking.

---

## ✨ Features

- 🔌 **SSH Connection** to FortiGate with credential support
- 🌐 **SD-WAN Aware** — auto-detects SD-WAN and fetches zones instead of interfaces
- 📋 **Address Management** — add subnet or FQDN objects in one click
- 🔍 **IP Reputation Check** — free DNS-based blacklist lookup (no API key needed)
- 🚫 **Deny Policy Creation** — auto-builds firewall deny policies across selected zones
- ⬆️ **Move to Top** — automatically moves new policies to the top of the policy list

---

## 🛡️ IP Reputation Engine

The tool checks every IP address against **6 free DNS blacklists** before blocking:

| Blacklist | Description |
|-----------|-------------|
| Spamhaus ZEN | Combined spam/exploit/botnet list |
| Barracuda | Email and network reputation |
| SORBS SPAM | Spam sources database |
| Blocklist.de | Attack/brute-force sources |
| SpamCop | Community spam reporting |
| UCEPROTECT L1 | Unsolicited commercial email sources |

**No account. No API key. No login. Completely free.**

Results are classified as:
- `[MALICIOUS]` — Listed in 2 or more blacklists
- `[SUSPICIOUS]` — Listed in 1 blacklist
- `[CLEAN]` — Not found in any blacklist

---

## 🖥️ Requirements

- Windows OS (Windows 10 / 11 / Server 2016+)
- PowerShell 5.1 or later
- [Posh-SSH module](https://github.com/darkoperator/Posh-SSH) installed:

```powershell
Install-Module -Name Posh-SSH -Scope CurrentUser
```

---

## 🚀 How to Use

1. **Connect** — Enter FortiGate IP, username, and password → click `Connect`
2. **Add Addresses** — Enter a name, select type (`subnet` or `fqdn`), enter value → click `Add`
3. **Check Reputation** — Click `>> Check IP Reputation` before blocking
4. **Fetch Zones** — Click `Fetch Zones/Interfaces` to load available interfaces
5. **Select** — Check the source (Incoming) and destination (Outgoing) zones
6. **Execute** — Click `EXECUTE` to push addresses and policies to FortiGate

---

## 📁 Project Structure

```
FortiGate-Builder/
│
├── FortiGate_Builder.ps1     # V1 
├── FortiGate_Builder_V2.ps1  # V2 — IP Reputation edition
└── README.md
```

---

## 📦 Releases

### 🔖 v2.0 — IP Reputation Edition *(Latest)*
- Added DNS-based IP reputation check (6 blacklists, free, no API key)
- New reputation status bar with color-coded results
- Warning prompt before EXECUTE if reputation check was skipped
- Fixed all PowerShell encoding issues (removed emoji characters)
- Improved Group 3 layout — button no longer overlaps status label



---

## 📸 Screenshot

> *FortiGate Builder V10 — IP Reputation Edition in action*

<img width="702" height="969" alt="Screenshot 2026-03-01 011913" src="https://github.com/user-attachments/assets/c2724076-cafe-4964-a857-33dee94d90f7" />
<img width="705" height="966" alt="Screenshot 2026-03-01 012007" src="https://github.com/user-attachments/assets/8864ab72-f4bb-4b2d-871f-648f3dad9c7f" />


---

## ⚠️ Disclaimer

This tool is intended for **authorized network administrators** managing their own FortiGate devices.
Do not use against systems you do not own or have explicit permission to manage.

---

## 📬 Contact

**Hazem Mohamed**
Feel free to open an [Issue](../../issues) or submit a [Pull Request](../../pulls) for suggestions or improvements.
