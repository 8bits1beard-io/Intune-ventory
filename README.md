# Intune-ventory

Documentation repository for Walmart's Microsoft Intune configuration profiles. Contains point-in-time exports of device management policies, settings, and assignments.

## Overview

This repository serves as a centralized archive for Intune configuration profile documentation. Each dated folder contains individual Markdown files documenting configuration profiles including Settings Catalog policies, Administrative Templates (ADMX), Device Configurations, and Endpoint Security policies with full settings and group assignments.

## Repository Structure

```
Intune-Configuration-Profiles/
├── docs/                           # Tool documentation
│   └── Intune-ition.md             # Technical documentation
├── Intune-ition.ps1                # Configuration profile export tool
├── App-rehension.ps1               # Application export tool
├── Base-ics.ps1                    # Security baseline export tool (in development)
├── Com-pliance.ps1                 # Compliance policy export tool
├── 17FEB2026/                      # Export snapshot
│   ├── README.md                   # Collection metadata & index
│   ├── Profile1.md                 # Individual profile docs
│   └── ...
└── README.md                       # This file
```

## Export Tools

| Tool | Description |
|------|-------------|
| [Intune-ition.ps1](Intune-ition.ps1) | Export Intune **configuration profiles** to Markdown files |
| [App-rehension.ps1](App-rehension.ps1) | Export Intune **applications** to Markdown files |
| [Com-pliance.ps1](Com-pliance.ps1) | Export Intune **compliance policies** to Markdown files |
| [Base-ics.ps1](Base-ics.ps1) | Export Intune **security baselines** to Markdown files *(in development)* |

### Prerequisites

- PowerShell 5.1 or higher
- Microsoft.Graph.Authentication module
- Azure AD account with `DeviceManagementConfiguration.Read.All` permission

### Installation

```powershell
# Install required module
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

### Export All Profiles (Full Tenant Snapshot)

```powershell
.\Intune-ition.ps1 -All -OutputPath ".\$(Get-Date -Format 'ddMMMyyyy')"
```

### Export Specific Profiles

```powershell
# By name pattern (wildcards supported)
.\Intune-ition.ps1 -ProfileNames "WinD_*,GLOBAL_*" -OutputPath ".\Exports"

# From CSV list
.\Intune-ition.ps1 -CsvFile "profiles.csv" -OutputPath ".\Exports"

# Interactive (prompts for names)
.\Intune-ition.ps1 -OutputPath ".\Exports"
```

### Export All Applications

```powershell
.\App-rehension.ps1 -All -OutputPath ".\Apps-$(Get-Date -Format 'ddMMMyyyy')"
```

### Export Specific Applications

```powershell
# By name pattern (wildcards supported)
.\App-rehension.ps1 -AppNames "7-Zip*,Chrome*,*Office*" -OutputPath ".\Apps"

# All platforms (default is Windows only)
.\App-rehension.ps1 -All -Platform All -OutputPath ".\AllApps"

# Interactive (prompts for names)
.\App-rehension.ps1 -OutputPath ".\Apps"
```

### Export All Security Baselines

```powershell
.\Base-ics.ps1 -All -OutputPath ".\Baselines-$(Get-Date -Format 'ddMMMyyyy')"
```

### Export Specific Security Baselines

```powershell
# By name pattern (wildcards supported)
.\Base-ics.ps1 -BaselineNames "Windows*,Defender*" -OutputPath ".\Baselines"

# Interactive (prompts for names)
.\Base-ics.ps1 -OutputPath ".\Baselines"
```

### Export All Compliance Policies

```powershell
.\Com-pliance.ps1 -All -OutputPath ".\Compliance-$(Get-Date -Format 'ddMMMyyyy')"
```

### Export Specific Compliance Policies

```powershell
# By name pattern (wildcards supported)
.\Com-pliance.ps1 -PolicyNames "Windows*,*BYOD*" -OutputPath ".\Compliance"

# Filter by platform
.\Com-pliance.ps1 -All -Platform Windows -OutputPath ".\WindowsCompliance"

# From CSV list
.\Com-pliance.ps1 -CsvFile "policies.csv" -OutputPath ".\Compliance"

# Interactive (prompts for names)
.\Com-pliance.ps1 -OutputPath ".\Compliance"
```

## Profile Documentation Format

Each profile Markdown file includes:
- Profile information (name, type, ID, dates)
- Group assignments with resolved group names
- Settings in human-readable table format
- Raw JSON data for technical reference

## Application Documentation Format

Each application Markdown file includes:
- Application information (name, type, publisher, version)
- Group assignments with install intent (required/available)
- Installation details (for Win32/LOB apps: commands, detection rules, requirements)
- Raw JSON data for technical reference

## Security Baseline Documentation Format

Each security baseline Markdown file includes:
- Baseline information (name, type, template, version)
- Group assignments with resolved group names
- Settings organized by category (where available)
- Template information for versioning
- Raw JSON data for technical reference

## Compliance Policy Documentation Format

Each compliance policy Markdown file includes:
- Policy information (name, platform, ID, dates)
- Scope tag assignments
- Group assignments with resolved group names
- Actions for non-compliance (grace periods, notifications)
- Compliance settings (password, encryption, device health, etc.)

## Supported Profile Types

| Type | API Endpoint |
|------|--------------|
| Settings Catalog | `configurationPolicies` |
| Administrative Templates (ADMX) | `groupPolicyConfigurations` |
| Device Configurations (Legacy) | `deviceConfigurations` |
| Endpoint Security | `intents` |

## Supported Application Types

| Platform | Types |
|----------|-------|
| Windows | Win32 LOB, Win32 Catalog, WinGet, MSI, MSIX/APPX, Microsoft 365 Apps, Edge, Web Apps |
| iOS | Store Apps, VPP Apps, LOB Apps |
| Android | Store Apps, Managed Google Play, LOB Apps |
| macOS | LOB Apps, DMG, PKG, Microsoft 365, Edge |

## Supported Security Baseline Types

| Type | Description |
|------|-------------|
| Windows Security Baseline | Microsoft's recommended security settings for Windows |
| Microsoft Edge Security Baseline | Security settings for Microsoft Edge browser |
| Microsoft Defender Antivirus | Antivirus protection policies |
| Windows Defender Firewall | Firewall rules and settings |
| Microsoft Defender for Endpoint | Advanced threat protection settings |
| BitLocker Encryption | Disk encryption policies |
| Attack Surface Reduction | ASR rules and exploit protection |
| Account Protection | Credential guard and account policies |

## Supported Compliance Policy Platforms

| Platform | Description |
|----------|-------------|
| Windows 10/11 | Windows device compliance policies |
| Windows 8.1 | Legacy Windows compliance |
| iOS/iPadOS | Apple mobile device compliance |
| macOS | Mac computer compliance |
| Android Device Administrator | Legacy Android compliance |
| Android Enterprise (Work Profile) | BYOD Android compliance |
| Android Enterprise (Fully Managed) | Corporate-owned Android compliance |
| Linux | Linux device compliance (Settings Catalog) |

## Documentation

| Tool | Documentation |
|------|---------------|
| Intune-ition.ps1 | [Technical Documentation](docs/Intune-ition.md) |
| App-rehension.ps1 | [Technical Documentation](docs/App-rehension.md) |
| Com-pliance.ps1 | [Technical Documentation](docs/Com-pliance.md) |
| Base-ics.ps1 | [Technical Documentation](docs/Base-ics.md) *(in development)* |

## Contributing

Contact the Windows Engineering team for questions or to contribute.

## Author

**Joshua Walderbach** (j0w03ow)  
Windows Engineering Team

---

### Found this helpful?

If these tools saved you time or made your work easier, consider giving a **Badge** to recognize the effort!

[Badgify](https://internal.walmart.com/content/badgify/home/badgify.html)

---

## License

Internal Walmart use only.
