# Base-ics - Technical Documentation

> ⚠️ **IN DEVELOPMENT** - This script is not ready for production use.

## Overview

`Base-ics.ps1` is a PowerShell script that exports Microsoft Intune security baselines to individual Markdown files. It queries security baseline templates, deployed instances, and Settings Catalog-based security policies via the Microsoft Graph API.

**Version:** 1.0.0 (Development)  
**Author:** Joshua Walderbach (j0w03ow)  
**Last Updated:** 2025-02-17  
**Status:** 🚧 In Development

---

## Current Status

This script is currently under development. The following challenges are being addressed:

### Known Issues
1. **Template vs Instance matching** - Security baseline templates have different names than deployed instances (e.g., "Microsoft Defender for Endpoint Security Baseline" vs "Microsoft Defender for Endpoint baseline")
2. **Multiple API sources** - Security baselines span multiple Graph API endpoints with different data structures
3. **Settings retrieval** - Intent-based policies require complex settings aggregation

### Development Roadmap
- [ ] Fix template-to-instance name matching
- [ ] Support Settings Catalog security policies
- [ ] Handle multiple baseline versions
- [ ] Add Settings Catalog settings expansion
- [ ] Complete settings formatting for all baseline types

---

## Table of Contents

1. [Requirements](#requirements)
2. [Parameters](#parameters)
3. [Authentication](#authentication)
4. [Baseline Types](#baseline-types)
5. [Output Format](#output-format)
6. [API Endpoints](#api-endpoints)
7. [Examples](#examples)

---

## Requirements

### PowerShell Version
- PowerShell 5.1 or higher
- PowerShell 7.x recommended for best performance

### Required Modules
```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

### Entra ID Permissions
The authenticating user must have the following Microsoft Graph permission:
- `DeviceManagementConfiguration.Read.All`

This permission is typically granted through one of these roles:
- Intune Administrator
- Global Reader
- Custom role with device configuration read access

---

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-BaselineNames` | String | No | Comma-separated baseline names with wildcard support |
| `-CsvFile` | String | No | Path to CSV file containing baseline names |
| `-CsvColumn` | String | No | CSV column name (default: "BaselineName") |
| `-OutputPath` | String | **Yes** | Output directory for Markdown files |
| `-All` | Switch | No | Export all security baselines in tenant |

### Parameter Sets

The script supports three mutually exclusive input methods:

1. **Names** - Specify baseline names directly via `-BaselineNames`
2. **Csv** - Import baseline names from a CSV file
3. **All** - Export all security baselines (no filtering)
4. **Default** - Interactive prompt for baseline names

---

## Authentication

The script uses interactive browser-based authentication via `Connect-MgGraph`. Upon execution:

1. A browser window opens for Azure AD sign-in
2. User authenticates with their Walmart credentials
3. Consent is requested for `DeviceManagementConfiguration.Read.All` scope
4. Token is cached for the session

```powershell
Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All" -NoWelcome
```

The script automatically disconnects from Microsoft Graph upon completion.

---

## Baseline Types

The script is designed to support multiple security baseline sources:

### 1. Legacy Security Baseline Templates
- **Endpoint:** `/deviceManagement/templates` (filtered for `securityBaselineTemplate`)
- **Examples:** Windows Security Baseline, Edge Security Baseline
- **Deployed via:** Intent-based policies

### 2. Configuration Policy Templates (Baseline Family)
- **Endpoint:** `/deviceManagement/configurationPolicyTemplates`
- **Filter:** `templateFamily eq 'Baseline'`
- **Examples:** HoloLens Security Baseline, Defender for Endpoint

### 3. Security Baseline Instances (Intents)
- **Endpoint:** `/deviceManagement/intents`
- **Contains:** Deployed baseline policies based on templates
- **Settings:** Retrieved via `/intents/{id}/settings`

### 4. Settings Catalog Security Policies
- **Endpoint:** `/deviceManagement/configurationPolicies`
- **Contains:** Security policies using template references
- **Settings:** Retrieved via `/configurationPolicies/{id}/settings`

### Supported Baseline Types

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
| HoloLens Security Baseline | Security settings for HoloLens 2 devices |

---

## Output Format

### Directory Structure (Planned)
```
OutputPath/
├── README.md                    # Collection index and metadata
├── Baseline_Name_1.md           # Individual baseline files
├── Baseline_Name_2.md
└── ...
```

### Individual Baseline Files (Planned)

Each Markdown file will contain:

#### Baseline Information Table
| Field | Description |
|-------|-------------|
| Name | Display name |
| Template | Source template name |
| Baseline ID | Unique GUID |
| Template Version | Baseline template version |
| Created | Creation timestamp |
| Last Modified | Last modification timestamp |

#### Assignments Table
| Field | Description |
|-------|-------------|
| Target Type | group, allDevices, allUsers, exclusionGroup |
| Group Name | Resolved Azure AD group display name |
| Filter | Assignment filter (if configured) |

#### Settings by Category
Settings organized by baseline category with configured values.

---

## API Endpoints

### Template Discovery
```
# Legacy security baseline templates
GET https://graph.microsoft.com/beta/deviceManagement/templates?$filter=(isof('microsoft.graph.securityBaselineTemplate'))

# Configuration policy templates (Baseline family)
GET https://graph.microsoft.com/beta/deviceManagement/configurationPolicyTemplates?$top=500&$filter=(lifecycleState eq 'draft' or lifecycleState eq 'superseded' or lifecycleState eq 'active')
```

### Deployed Instances
```
# Security baseline intents
GET https://graph.microsoft.com/beta/deviceManagement/intents?$top=999

# Settings Catalog policies
GET https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$top=999&$expand=settings
```

### Settings
```
# Intent settings
GET https://graph.microsoft.com/beta/deviceManagement/intents('{id}')/settings

# Settings Catalog settings
GET https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('{id}')/settings?$expand=settingDefinitions&$top=1000
```

### Assignments
```
GET https://graph.microsoft.com/beta/deviceManagement/intents('{id}')/assignments
```

---

## Examples

> ⚠️ These examples will work once development is complete.

### Export All Security Baselines
```powershell
.\Base-ics.ps1 -All -OutputPath "C:\Exports\Baselines-FY2026"
```

### Export Baselines by Name Pattern
```powershell
# All Windows baselines
.\Base-ics.ps1 -BaselineNames "Windows*" -OutputPath ".\WindowsBaselines"

# Defender baselines
.\Base-ics.ps1 -BaselineNames "*Defender*" -OutputPath ".\Defender"

# Multiple patterns
.\Base-ics.ps1 -BaselineNames "Windows*,Edge*,Defender*" -OutputPath ".\Baselines"
```

### Export from CSV
```powershell
.\Base-ics.ps1 -CsvFile "baselines.csv" -OutputPath ".\Baselines"
```

### Interactive Mode
```powershell
.\Base-ics.ps1 -OutputPath ".\Exports"
# Prompts: Enter baseline names (comma-separated, wildcards supported):
```

---

## Technical Notes

### Template ID Resolution

Security baselines use versioned template IDs:
- Base ID: `49b8320f-e179-472e-8e2c-2fde00289ca2`
- Version 1: `49b8320f-e179-472e-8e2c-2fde00289ca2_1`
- Version 2: `49b8320f-e179-472e-8e2c-2fde00289ca2_1_2`

The script attempts to match deployed policies to templates using both base and versioned IDs.

### Name Matching Complexity

Template names often differ from deployed policy names:
- **Template:** "Microsoft Defender for Endpoint Security Baseline"
- **Policy:** "WinD_BL_Dev_EndpointProtection_v4.0.1"

The script supports searching by both template name and policy name, including flexible matching that ignores "Security" keyword differences.

---

## Changelog

### Version 1.0.0 (2025-02-17) - In Development
- Initial development release
- Query multiple baseline sources (templates, intents, configuration policies)
- Template-to-instance matching logic
- Flexible name matching for templates
- Currently blocked by development notice

---

## Author

**Joshua Walderbach** (j0w03ow)  
Windows Engineering Team

---

### Questions or Contributions?

Contact the Windows Engineering team if you'd like to help complete this tool.

[Badgify](https://internal.walmart.com/content/badgify/home/badgify.html)
