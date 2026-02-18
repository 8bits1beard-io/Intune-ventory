# Com-pliance - Technical Documentation

## Overview

`Com-pliance.ps1` is a PowerShell script that exports Microsoft Intune compliance policies to individual Markdown files. It queries both legacy device compliance policies and Settings Catalog-based compliance policies via the Microsoft Graph API, generating human-readable documentation including settings, non-compliance actions, and assignments.

**Version:** 1.0.0  
**Author:** Joshua Walderbach (j0w03ow)  
**Last Updated:** 2026-02-17

---

## Table of Contents

1. [Requirements](#requirements)
2. [Parameters](#parameters)
3. [Authentication](#authentication)
4. [Policy Types](#policy-types)
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

Optional permission for scope tag resolution:
- `DeviceManagementRBAC.Read.All`

These permissions are typically granted through one of these roles:
- Intune Administrator
- Global Reader
- Custom role with device configuration read access

---

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-PolicyNames` | String | No | Comma-separated policy names with wildcard support |
| `-CsvFile` | String | No | Path to CSV file containing policy names |
| `-CsvColumn` | String | No | CSV column name (default: "PolicyName") |
| `-OutputPath` | String | **Yes** | Output directory for Markdown files |
| `-All` | Switch | No | Export all compliance policies in tenant |
| `-Platform` | String | No | Filter by platform (default: All) |

### Platform Values
- `Windows` - Windows compliance policies only
- `iOS` - iOS/iPadOS compliance policies
- `Android` - Android compliance policies
- `macOS` - macOS compliance policies
- `All` - All platforms (default)

### Parameter Sets

The script supports three mutually exclusive input methods:

1. **Names** - Specify policy names directly via `-PolicyNames`
2. **Csv** - Import policy names from a CSV file
3. **All** - Export all compliance policies (no filtering)
4. **Default** - Interactive prompt for policy names

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

## Policy Types

The script queries two distinct compliance policy APIs:

### 1. Settings Catalog Compliance Policies (Modern)
- **Endpoint:** `/deviceManagement/compliancePolicies`
- **Platforms:** Windows, Linux, iOS, Android, macOS
- **Settings:** Retrieved via `/compliancePolicies/{id}/settings`
- **Format:** Structured setting instances with definition IDs

### 2. Legacy Device Compliance Policies
- **Endpoint:** `/deviceManagement/deviceCompliancePolicies`
- **Types:** Platform-specific policies with embedded settings
- **Actions:** Scheduled actions for non-compliance expanded inline

### Supported Platform Types

| Platform | @odata.type | Description |
|----------|-------------|-------------|
| Windows 10/11 | `windows10CompliancePolicy` | Windows device compliance |
| Windows 8.1 | `windows81CompliancePolicy` | Legacy Windows compliance |
| iOS/iPadOS | `iosCompliancePolicy` | Apple mobile device compliance |
| macOS | `macOSCompliancePolicy` | Mac computer compliance |
| Android DA | `androidCompliancePolicy` | Android Device Administrator |
| Android Work Profile | `androidWorkProfileCompliancePolicy` | BYOD Android compliance |
| Android Fully Managed | `androidDeviceOwnerCompliancePolicy` | COPE/COBO Android compliance |
| Linux | Settings Catalog | Linux device compliance |

---

## Output Format

### Directory Structure
```
OutputPath/
├── README.md                    # Collection index and metadata
├── Policy_Name_1.md             # Individual policy files
├── Policy_Name_2.md
└── ...
```

### README.md Contents
- Collection metadata (who, when, how)
- Search patterns used
- Platform filter applied
- Table of all exported policies with links
- API endpoints queried
- Permission requirements

### Individual Policy Files

Each Markdown file contains:

#### Policy Information Table
| Field | Description |
|-------|-------------|
| Name | Display name |
| Type | Policy type (Windows 10/11, iOS, etc.) |
| Policy ID | Unique GUID |
| Created | Creation timestamp |
| Last Modified | Last modification timestamp |
| Platforms | Target platforms (Settings Catalog) |
| Technologies | MDM technologies used |
| Scope Tags | Role scope tag assignments |

#### Assignments Table
| Field | Description |
|-------|-------------|
| Target Type | group, allDevices, allUsers, exclusionGroup |
| Group Name | Resolved Azure AD group display name |
| Filter | Assignment filter (if configured) |

#### Actions for Non-Compliance
| Field | Description |
|-------|-------------|
| Action | Mark non-compliant, Send notification, Retire, Wipe |
| Grace Period | Days before action is taken |
| Additional Recipients | Notification template or recipients |

#### Compliance Settings
Format varies by policy type:

**Legacy Policies:**
| Setting | Value |
|---------|-------|

**Settings Catalog:**
| Setting | Value | Definition |
|---------|-------|------------|

#### Raw JSON (optional)
- Complete policy object for technical reference

---

## API Endpoints

### Policy Discovery
```
# Settings Catalog compliance policies
GET https://graph.microsoft.com/beta/deviceManagement/compliancePolicies?$select=id,name,description,platforms,technologies,lastModifiedDateTime,settingCount,roleScopeTagIds,scheduledActionsForRule&$top=100

# Legacy compliance policies (with expanded scheduled actions)
GET https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies?$expand=scheduledActionsForRule($expand=scheduledActionConfigurations)&$top=999
```

### Settings
```
# Settings Catalog
GET https://graph.microsoft.com/beta/deviceManagement/compliancePolicies('{id}')/settings
```

### Assignments
```
# Settings Catalog
GET https://graph.microsoft.com/beta/deviceManagement/compliancePolicies('{id}')/assignments

# Legacy
GET https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies('{id}')/assignments
```

### Scope Tags (Optional)
```
GET https://graph.microsoft.com/beta/deviceManagement/roleScopeTags
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

### Export All Compliance Policies
```powershell
.\Com-pliance.ps1 -All -OutputPath "C:\Exports\Compliance-FY2026"
```

### Export Windows Compliance Policies Only
```powershell
.\Com-pliance.ps1 -All -Platform Windows -OutputPath ".\WindowsCompliance"
```

### Export Policies by Name Pattern
```powershell
# All Windows policies
.\Com-pliance.ps1 -PolicyNames "Windows*" -OutputPath ".\Windows"

# Multiple patterns
.\Com-pliance.ps1 -PolicyNames "*BYOD*,*MDM*,*Compliance*" -OutputPath ".\Policies"

# Specific policy
.\Com-pliance.ps1 -PolicyNames "WindowsCompliance_v2.0" -OutputPath ".\WinCompliance"
```

### Export from CSV
```powershell
# CSV format: PolicyName column
.\Com-pliance.ps1 -CsvFile "policies.csv" -OutputPath ".\Policies"

# Custom column name
.\Com-pliance.ps1 -CsvFile "audit.csv" -CsvColumn "CompliancePolicyName" -OutputPath ".\Audit"
```

### Interactive Mode
```powershell
.\Com-pliance.ps1 -OutputPath ".\Exports"
# Prompts: Enter policy names (comma-separated, wildcards supported):
# Input: WinD_*,*iOS*
```

### Export Mobile Device Compliance
```powershell
# iOS policies
.\Com-pliance.ps1 -All -Platform iOS -OutputPath ".\iOS-Compliance"

# Android policies
.\Com-pliance.ps1 -All -Platform Android -OutputPath ".\Android-Compliance"
```

---

## Troubleshooting

### Common Issues

#### "No compliance policies matched the provided names"
**Cause:** Policy names don't match or wildcards are incorrect.  
**Solution:** Use `*` wildcards, e.g., `*Windows*` instead of `Windows`.

#### "Skipped (requires DeviceManagementRBAC.Read.All permission)"
**Cause:** User doesn't have permission to read scope tags.  
**Solution:** This is non-fatal. Scope tags will show IDs instead of names. Add `DeviceManagementRBAC.Read.All` permission for full resolution.

#### "Failed to get assignments"
**Cause:** Permission issues or API throttling.  
**Solution:** Ensure user has `DeviceManagementConfiguration.Read.All` permission. Wait and retry if throttled.

#### Platform filter not working as expected
**Cause:** Settings Catalog policies use different platform identifiers.  
**Solution:** Check the `platforms` field in the policy. Use `-Platform All` to capture all policies.

#### Module Not Found
**Error:** `The term 'Connect-MgGraph' is not recognized`  
**Solution:**
```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
```

### Performance Considerations

- **Large tenants:** Exporting all policies may take several minutes
- **API throttling:** Script handles pagination but may slow down with many policies
- **Group resolution:** Each unique group ID requires an API call (results are cached)

---

## Technical Details

### Platform Filtering

Policies are filtered by platform using:

**Settings Catalog:** `platforms` property matches keywords  
**Legacy:** `@odata.type` patterns

| Platform | Filter Patterns |
|----------|-----------------|
| Windows | `windows10`, `windows81`, `windowsPhone81` |
| iOS | `iOS`, `iosDevice` |
| Android | `android`, `androidEnterprise`, `androidWorkProfile`, `androidDeviceOwner` |
| macOS | `macOS` |

### Scheduled Actions Expansion

Legacy policies use `$expand` to retrieve scheduled actions in the initial query:
```
$expand=scheduledActionsForRule($expand=scheduledActionConfigurations)
```

This avoids separate API calls for each policy's non-compliance actions.

### Settings Extraction

**Settings Catalog policies:** Settings retrieved via dedicated endpoint with structured format.

**Legacy policies:** Settings extracted from the policy object directly, filtering out metadata properties:
- Excludes: `id`, `displayName`, `description`, `createdDateTime`, `@odata.type`, etc.
- Includes boolean `false` and numeric `0` as valid setting values

### Value Formatting

The script formats setting values for display:
- **Boolean:** `✓ Enabled` / `✗ Disabled`
- **Arrays:** Comma-separated values
- **Objects:** JSON representation (truncated if > 100 chars)
- **Strings/Numbers:** Direct display

### Group Name Caching

Group IDs are resolved to display names and cached to minimize API calls:
```powershell
$script:groupNameCache = @{}  # Persists across policy processing
$script:filterNameCache = @{} # Same for assignment filters
$script:scopeTagCache = @{}   # Scope tag ID to name mapping
```

### Filename Sanitization

Policy names are sanitized for filesystem compatibility:
- Invalid characters replaced with `_`
- Whitespace replaced with `_`
- Brackets `[]` replaced with `_` (PowerShell wildcard characters)

---

## Changelog

### Version 1.0.0 (2026-02-17)
- Initial release
- Export both Settings Catalog and legacy compliance policies
- Platform filtering (Windows, iOS, Android, macOS, All)
- `-All` parameter to export entire tenant
- Non-compliance actions (scheduled actions) documentation
- Scope tag resolution (optional permission)
- Group name and filter name resolution
- Human-readable settings tables
- Individual Markdown files per policy with README index
- Interactive mode with policy name prompting
- CSV import support

---

## Author

**Joshua Walderbach** (j0w03ow)  
Windows Engineering Team

---

### Found this helpful?

If this tool saved you time or made your work easier, consider giving a **Badge** to recognize the effort!

[Badgify](https://internal.walmart.com/content/badgify/home/badgify.html)
