##
<img width="687" height="842" alt="Screenshot 2025-12-31 201048" src="https://github.com/user-attachments/assets/d5408b91-4b8b-4c04-9e67-c59bf032e4ab" />

##

# Fortinet-Deny-Polices-Builder
If you need to add mailous IP Addresses and create polices to deny them, this tool will help you to provide SOC T1 the custom tool with specifc user on your Fortinet Firewall to only add addresses and create deny polices on all incoming interfaces and outgoing interfaces if you not enable add multiuple interfaces polices feature..


A powerful PowerShell automation wrapper for SSH connections and designed to simplify remote management, 
> **Ideal for:** SOC Team T1 operations, or Help Desk team... 
## 🌟 Features

- **Native PowerShell Integration:** No need for external binaries (uses Posh-SSH).
- **Secure Sessions:** Supports credential objects and key-based authentication.
- **Bulk Execution:** Run commands on multiple targets seamlessly.
- **Legacy Support:** Optimized instructions for Windows Server 2016 through 2022.

---

## 📋 Prerequisites & Compatibility Matrix

Before running the tool, ensure your environment meets the following requirements. **This is critical for Windows Server 2016 users.**

| OS Version | PowerShell Version | Required .NET Framework | Notes |
| :--- | :--- | :--- | :--- |
| **Windows Server 2016** | 5.1 | **4.7.2 or 4.8** (Required) | Default is 4.6 (Incompatible). Must update manually. |
| **Windows Server 2019** | 5.1 | Default (4.7+) | Works out of the box. |
| **Windows Server 2022** | 5.1 | Default (4.8) | Works out of the box. |
| **Windows 10 / 11** | 5.1 / 7.x | Default (4.8) | Works out of the box. |

### ⚠️ Critical Note for Windows Server 2016
If you encounter the error: `Could not load file or assembly 'netstandard'`, you **must** install **.NET Framework 4.8 Runtime**.
* [Download .NET Framework 4.8](https://dotnet.microsoft.com/download/dotnet-framework/net48)
* **Reboot is required** after installation.

---

## 🛠️ Installation


1. **Open PowerShell as Administrator.**
3. **Install the Posh-SSH module:**

```powershell
Install-Module Posh-SSH -Force -AllowClobber
```

3.Import the module:

```powershell

Import-Module Posh-SSH

```

## 🔧 Troubleshooting

Issue: Import-Module : Could not load file or assembly 'netstandard' ...

Fix: Your .NET Framework is outdated (common on Server 2016). Please install .NET 4.8.

Issue: Posh-SSH is not recognized.

Fix: Ensure your Execution Policy allows scripts:
PowerShell

Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
## 📜 License

MIT
