# Intune-ition - Technical Documentation

## Overview

`Intune-ition.ps1` is a PowerShell script that exports Microsoft Intune configuration profiles to individual Markdown files. It queries all four Intune profile types via the Microsoft Graph API and generates human-readable documentation.

**Version:** 1.0.0  
**Author:** Joshua Walderbach (j0w03ow)  
**Last Updated:** 2025-02-17

---

## Table of Contents

1. [Requirements](#requirements)
2. [Parameters](#parameters)
3. [Authentication](#authentication)
4. [Profile Types](#profile-types)
5. [Output Format](#output-format)
6. [API Endpoints](#api-endpoints)
7. [Examples](#examples)
8. [Troubleshooting](#troubleshooting)
9. [Technical Details](#technical-details)

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
| `-ProfileNames` | String | No | Comma-separated profile names with wildcard support |
| `-CsvFile` | String | No | Path to CSV file containing profile names |
| `-CsvColumn` | String | No | CSV column name (default: "ProfileName") |
| `-OutputPath` | String | **Yes** | Output directory for Markdown files |
| `-All` | Switch | No | Export all profiles in tenant |

### Parameter Sets

The script supports three mutually exclusive input methods:

1. **Names** - Specify profile names directly via `-ProfileNames`
2. **Csv** - Import profile names from a CSV file
3. **All** - Export all profiles (no filtering)
4. **Default** - Interactive prompt for profile names

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

## Profile Types

The script queries four distinct Intune profile endpoints:

### 1. Device Configurations (Legacy)
- **Endpoint:** `/deviceManagement/deviceConfigurations`
- **Types:** Certificates, Custom OMA-URI, Device Restrictions, VPN, Wi-Fi, etc.
- **Identifier:** `@odata.type` contains configuration type

### 2. Settings Catalog
- **Endpoint:** `/deviceManagement/configurationPolicies`
- **Types:** Modern unified settings interface
- **Settings API:** `/configurationPolicies/{id}/settings?$expand=settingDefinitions`

### 3. Administrative Templates (ADMX)
- **Endpoint:** `/deviceManagement/groupPolicyConfigurations`
- **Types:** ADMX-backed Group Policy settings
- **Settings API:** `/groupPolicyConfigurations/{id}/definitionValues?$expand=definition`

### 4. Endpoint Security
- **Endpoint:** `/deviceManagement/intents`
- **Types:** Antivirus, Disk Encryption, Firewall, Attack Surface Reduction
- **Settings API:** `/intents/{id}/settings`

---

## Output Format

### Directory Structure
```
OutputPath/
├── README.md                    # Collection index and metadata
├── Profile_Name_1.md            # Individual profile files
├── Profile_Name_2.md
└── ...
```

### README.md Contents
- Collection metadata (who, when, how)
- Search patterns used
- Table of all exported profiles with links
- API endpoints queried
- Permission requirements

### Individual Profile Files

Each Markdown file contains:

#### Profile Information Table
| Field | Description |
|-------|-------------|
| Name | Display name |
| Type | Friendly type name |
| Profile ID | Unique GUID |
| Created | Creation timestamp |
| Last Modified | Last modification timestamp |
| Source | API endpoint source |

#### Assignments Table
| Field | Description |
|-------|-------------|
| Target Type | group, allDevices, allUsers, exclusionGroup |
| Group Name | Resolved Azure AD group display name |
| Filter | Assignment filter (if configured) |

#### Settings Section
Format varies by profile type:

**Settings Catalog:**
| Setting | Configured Value | Description |
|---------|------------------|-------------|

**ADMX:**
| Policy Setting | State | Category |
|----------------|-------|----------|

**OMA-URI:**
| Display Name | OMA-URI | Value | Description |
|--------------|---------|-------|-------------|

**Certificate:**
| Property | Value |
|----------|-------|

#### Raw JSON
- Collapsible `<details>` section with full settings JSON
- Complete profile object for technical reference

---

## API Endpoints

### Profile Discovery
```
GET https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?$top=999
GET https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$top=999
GET https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations?$top=999
GET https://graph.microsoft.com/beta/deviceManagement/intents?$top=999
```

### Assignments
```
GET https://graph.microsoft.com/beta/deviceManagement/{type}('{id}')/assignments
```

### Settings
```
# Settings Catalog
GET https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('{id}')/settings?$expand=settingDefinitions&$top=1000

# ADMX
GET https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations('{id}')/definitionValues?$expand=definition

# Endpoint Security
GET https://graph.microsoft.com/beta/deviceManagement/intents('{id}')/settings
```

### Group Resolution
```
GET https://graph.microsoft.com/v1.0/groups/{groupId}
```

### Filter Resolution
```
GET https://graph.microsoft.com/beta/deviceManagement/assignmentFilters/{filterId}
```

---

## Examples

### Export All Profiles (Full Tenant Snapshot)
```powershell
.\Intune-ition.ps1 -All -OutputPath "C:\Exports\FY2026-Q1"
```

### Export Profiles by Naming Convention
```powershell
# All Windows Device profiles
.\Intune-ition.ps1 -ProfileNames "WinD_*" -OutputPath ".\WindowsDevice"

# Multiple patterns
.\Intune-ition.ps1 -ProfileNames "WinD_*,WinC_*,GLOBAL_*" -OutputPath ".\Exports"

# Specific profile
.\Intune-ition.ps1 -ProfileNames "WinD_EP_Antivirus_policy_v1.0" -OutputPath ".\AV"
```

### Export from CSV
```powershell
# CSV format: ProfileName column
.\Intune-ition.ps1 -CsvFile "profiles.csv" -OutputPath ".\Profiles"

# Custom column name
.\Intune-ition.ps1 -CsvFile "audit.csv" -CsvColumn "IntuneName" -OutputPath ".\Audit"
```

### Interactive Mode
```powershell
.\Intune-ition.ps1 -OutputPath ".\Exports"
# Prompts: Enter profile names (comma-separated, wildcards supported):
# Input: WinD_EP_*,*Firewall*
```

---

## Troubleshooting

### Common Issues

#### "Cannot perform operation because the wildcard path did not resolve"
**Cause:** Profile name contains brackets `[]` which PowerShell interprets as wildcards.  
**Solution:** Script sanitizes filenames, but if issue persists, the `-LiteralPath` parameter is used internally.

#### "No profiles matched the provided names"
**Cause:** Profile names don't match or wildcards are incorrect.  
**Solution:** Use `*` wildcards, e.g., `*OneDrive*` instead of `OneDrive`.

#### "Failed to get assignments"
**Cause:** Permission issues or API throttling.  
**Solution:** Ensure user has `DeviceManagementConfiguration.Read.All` permission. Wait and retry if throttled.

#### Module Not Found
**Error:** `The term 'Connect-MgGraph' is not recognized`  
**Solution:**
```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
```

### Performance Considerations

- **Large tenants:** Exporting all profiles may take 10-30+ minutes due to per-profile API calls
- **API throttling:** Script handles pagination but may slow down with many profiles
- **Group resolution:** Each unique group ID requires an API call (results are cached)

---

## Technical Details

### Pagination Handling

The script implements custom pagination for Graph API responses:
```powershell
function Invoke-GraphRequestWithPaging {
    # Handles @odata.nextLink for paginated results
    # Aggregates all pages into single collection
}
```

### Group Name Caching

Group IDs are resolved to display names and cached to minimize API calls:
```powershell
$script:groupNameCache = @{}  # Persists across profile processing
$script:filterNameCache = @{} # Same for assignment filters
```

### Filename Sanitization

Profile names are sanitized for filesystem compatibility:
- Invalid characters replaced with `_`
- Whitespace replaced with `_`
- Brackets `[]` replaced with `_` (PowerShell wildcard characters)

### Error Handling

- `$ErrorActionPreference = 'Stop'` for fail-fast behavior
- Try/catch blocks around API calls with warnings for non-fatal errors
- Continues processing remaining profiles if one fails

---

## Changelog

### Version 1.0.0 (2025-02-17)
- Initial release as **Intune-ition**
- Export all four Intune profile types (Settings Catalog, ADMX, Legacy, Endpoint Security)
- `-All` parameter to export entire tenant
- Human-readable settings tables for all profile types
- Group name and filter name resolution
- Individual Markdown files per profile with README index
- Collapsible raw JSON sections
- Interactive mode with profile name prompting
- CSV import support

---

## Author

**Joshua Walderbach** (j0w03ow)  
Windows Engineering Team

---

### Found this helpful?

If this tool saved you time or made your work easier, consider giving a **Badge** to recognize the effort!

[Badgify](https://internal.walmart.com/content/badgify/home/badgify.html)
