<#
.SYNOPSIS
    Export Intune Compliance Policies to individual Markdown files.

.DESCRIPTION
    Authenticates to Microsoft Graph, retrieves all Compliance Policies
    (both legacy and Settings Catalog-based), collects full policy details 
    including settings, scheduled actions, and assignments, and exports 
    each policy to its own Markdown file.
    Creates a README.md index with links to all exported policies.

.PARAMETER PolicyNames
    Comma-separated list of policy display names to search for (supports wildcards).
    Example: "Windows*,iOS*,Android*"

.PARAMETER CsvFile
    Path to CSV file containing policy names.

.PARAMETER CsvColumn
    Column name in CSV containing policy names (default: "PolicyName").

.PARAMETER OutputPath
    Required. Output directory for Markdown files. Will be created if it doesn't exist.

.PARAMETER All
    Export all compliance policies in the tenant (ignores policy name filtering).

.PARAMETER Platform
    Filter by platform. Default is All platforms.
    Options: Windows, iOS, Android, macOS, All

.EXAMPLE
    .\Com-pliance.ps1 -All -OutputPath "C:\Exports\CompliancePolicies"
    Exports every compliance policy in the Intune tenant.

.EXAMPLE
    .\Com-pliance.ps1 -OutputPath "C:\Exports\2026-02"
    Prompts for policy names, then exports to the specified folder.

.EXAMPLE
    .\Com-pliance.ps1 -PolicyNames "Windows*,*BitLocker*" -OutputPath ".\Exports"
    Exports compliance policies matching the specified name patterns.

.EXAMPLE
    .\Com-pliance.ps1 -All -Platform Windows -OutputPath ".\WindowsCompliance"
    Exports all Windows compliance policies.

.NOTES
    File Name      : Com-pliance.ps1
    Author         : Joshua Walderbach (j0w03ow)
    Prerequisite   : Microsoft.Graph.Authentication PowerShell module
    Requires       : PowerShell 5.1 or higher
                     DeviceManagementConfiguration.Read.All permission
    Version        : 1.0.0
    Date           : 2026-02-17

.LINK
    https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-devicecompliancepolicy

.OUTPUTS
    Individual Markdown files for each compliance policy and a README.md index file.
#>
[CmdletBinding(DefaultParameterSetName='Default')]
param(
    [Parameter(ParameterSetName='Names')]
    [string]$PolicyNames,

    [Parameter(ParameterSetName='Csv', Mandatory=$true)]
    [string]$CsvFile,

    [Parameter(ParameterSetName='Csv')]
    [string]$CsvColumn = "PolicyName",

    [Parameter(ParameterSetName='All')]
    [switch]$All,

    [Parameter(Mandatory=$true)]
    [string]$OutputPath,

    [Parameter()]
    [ValidateSet('Windows', 'iOS', 'Android', 'macOS', 'All')]
    [string]$Platform = 'All'
)

$ErrorActionPreference = 'Stop'

# Handle -All parameter
if ($All) {
    $PolicyNamesArray = @('*')
    Write-Host "" 
    Write-Host "Exporting ALL compliance policies in the tenant..." -ForegroundColor Yellow
}
# Parse policy names based on input method
elseif ($PSCmdlet.ParameterSetName -eq 'Csv') {
    # Import from CSV
    if (-not (Test-Path $CsvFile)) {
        Write-Error "CSV file not found: $CsvFile"
        exit 1
    }

    try {
        $csvData = Import-Csv -Path $CsvFile

        # Check if column exists
        if (-not ($csvData[0].PSObject.Properties.Name -contains $CsvColumn)) {
            Write-Error "Column '$CsvColumn' not found in CSV. Available columns: $($csvData[0].PSObject.Properties.Name -join ', ')"
            exit 1
        }

        $PolicyNamesArray = $csvData | ForEach-Object { $_.$CsvColumn } | Where-Object { $_ -and $_.Trim() -ne '' }
    } catch {
        Write-Error "Failed to import CSV: $_"
        exit 1
    }
} elseif ($PolicyNames) {
    # Parse comma-separated string
    $PolicyNamesArray = $PolicyNames -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
} else {
    # Prompt for policy names
    Write-Host ""
    Write-Host "No policy names provided." -ForegroundColor Yellow
    Write-Host "Enter policy names (comma-separated, wildcards supported):" -ForegroundColor Cyan
    Write-Host "Example: WinD_*,*Compliance*,iOS_*" -ForegroundColor Gray
    Write-Host ""
    $inputNames = Read-Host "Policy names"
    
    if (-not $inputNames -or $inputNames.Trim() -eq '') {
        Write-Error "No policy names entered. Exiting."
        exit 1
    }
    
    $PolicyNamesArray = $inputNames -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
}

if (-not $PolicyNamesArray -or $PolicyNamesArray.Count -eq 0) {
    Write-Error "No policy names provided. Use -PolicyNames, -CsvFile, or -All"
    exit 1
}

# Validate and create output path if needed
if (-not (Test-Path $OutputPath)) {
    Write-Host "Creating output folder: $OutputPath" -ForegroundColor Yellow
    try {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        Write-Host "  ✓ Output folder created" -ForegroundColor Green
    } catch {
        Write-Error "Failed to create output folder: $_"
        exit 1
    }
}

Write-Host "=== Intune Compliance Policy Export (Com-pliance) ===" -ForegroundColor Cyan
Write-Host ""

# Check for Microsoft.Graph.Authentication module
Write-Host "[1/5] Checking for Microsoft.Graph.Authentication module..." -ForegroundColor Yellow
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Error "Microsoft.Graph.Authentication module not found. Install with: Install-Module Microsoft.Graph.Authentication"
    exit 1
}
Write-Host "  ✓ Module found" -ForegroundColor Green

# Import module
Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

# Connect to Graph
Write-Host ""
Write-Host "[2/5] Connecting to Microsoft Graph..." -ForegroundColor Yellow
try {
    Connect-MgGraph -Scopes "DeviceManagementConfiguration.Read.All" -NoWelcome -ErrorAction Stop
    Write-Host "  ✓ Connected" -ForegroundColor Green
} catch {
    Write-Error "Failed to connect to Microsoft Graph: $_"
    exit 1
}

# Helper function for Graph API calls with pagination
function Invoke-GraphRequestWithPaging {
    param(
        [string]$Uri
    )

    try {
        $results = @()
        $response = Invoke-MgGraphRequest -Uri $Uri -Method GET

        if ($response.value) {
            $results = @($response.value)

            while ($response.'@odata.nextLink') {
                $response = Invoke-MgGraphRequest -Uri $response.'@odata.nextLink' -Method GET
                $results += $response.value
            }
        }

        return $results | Where-Object { $_ -ne $null }
    } catch {
        Write-Warning "Graph API call failed: $_"
        return @()
    }
}

# Group name cache for resolving group IDs
$script:groupNameCache = @{}
$script:filterNameCache = @{}
$script:scopeTagCache = @{}

function Get-GroupDisplayName {
    param([string]$GroupId)
    
    if (-not $GroupId) { return $null }
    
    if ($script:groupNameCache.ContainsKey($GroupId)) {
        return $script:groupNameCache[$GroupId]
    }
    
    try {
        $group = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId" -Method GET
        $displayName = $group.displayName
        $script:groupNameCache[$GroupId] = $displayName
        return $displayName
    } catch {
        $script:groupNameCache[$GroupId] = $GroupId
        return $GroupId
    }
}

function Get-FilterDisplayName {
    param([string]$FilterId)
    
    if (-not $FilterId) { return $null }
    
    if ($script:filterNameCache.ContainsKey($FilterId)) {
        return $script:filterNameCache[$FilterId]
    }
    
    try {
        $filter = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/assignmentFilters/$FilterId" -Method GET
        $displayName = $filter.displayName
        $script:filterNameCache[$FilterId] = $displayName
        return $displayName
    } catch {
        $script:filterNameCache[$FilterId] = $FilterId
        return $FilterId
    }
}

function Get-ScopeTagName {
    param([string]$TagId)
    
    if (-not $TagId) { return $null }
    
    if ($script:scopeTagCache.ContainsKey($TagId)) {
        return $script:scopeTagCache[$TagId]
    }
    
    # Tag ID 0 is always "Default"
    if ($TagId -eq '0') {
        $script:scopeTagCache[$TagId] = 'Default'
        return 'Default'
    }
    
    return $TagId
}

# Load scope tags cache (requires DeviceManagementRBAC.Read.All - optional)
Write-Host ""
Write-Host "  Loading scope tags..." -ForegroundColor Gray
try {
    $scopeTagsResponse = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags" -Method GET -ErrorAction Stop
    if ($scopeTagsResponse.value) {
        foreach ($tag in $scopeTagsResponse.value) {
            $script:scopeTagCache[$tag.id] = $tag.displayName
        }
        Write-Host "    Loaded $($scopeTagsResponse.value.Count) scope tags" -ForegroundColor Gray
    }
} catch {
    # Scope tags require DeviceManagementRBAC.Read.All permission - continue without them
    Write-Host "    Skipped (requires DeviceManagementRBAC.Read.All permission)" -ForegroundColor DarkGray
}

# Search for compliance policies
Write-Host ""
Write-Host "[3/5] Searching for compliance policies..." -ForegroundColor Yellow
if (-not $All) {
    Write-Host "  Policy name patterns:" -ForegroundColor Gray
    $PolicyNamesArray | ForEach-Object { Write-Host "    - $_" -ForegroundColor Gray }
}

$foundPolicies = @()

# Platform filter mapping
$platformFilters = @{
    'Windows' = @('windows10', 'windows81', 'windowsPhone81')
    'iOS' = @('iOS', 'iosDevice')
    'Android' = @('android', 'androidEnterprise', 'androidForWork', 'androidWorkProfile', 'androidDeviceOwner')
    'macOS' = @('macOS')
    'All' = @()
}

# Query Settings Catalog compliance policies (newer API)
Write-Host ""
Write-Host "  Querying Settings Catalog compliance policies..." -ForegroundColor Gray
$settingsCatalogUri = 'https://graph.microsoft.com/beta/deviceManagement/compliancePolicies?$select=id,name,description,platforms,technologies,lastModifiedDateTime,settingCount,roleScopeTagIds,scheduledActionsForRule&$top=100'
$settingsCatalogPolicies = Invoke-GraphRequestWithPaging -Uri $settingsCatalogUri

if ($settingsCatalogPolicies -and $settingsCatalogPolicies.Count -gt 0) {
    Write-Host "    Found $($settingsCatalogPolicies.Count) Settings Catalog compliance policies" -ForegroundColor Gray
    foreach ($pattern in $PolicyNamesArray) {
        $policyMatches = $settingsCatalogPolicies | Where-Object { $_.name -like $pattern }
        
        # Apply platform filter if not 'All'
        if ($Platform -ne 'All' -and $policyMatches) {
            $platformKeywords = $platformFilters[$Platform]
            $policyMatches = $policyMatches | Where-Object {
                $policyPlatforms = $_.platforms
                $platformKeywords | Where-Object { $policyPlatforms -match $_ }
            }
        }
        
        if ($policyMatches) {
            $policyMatches | ForEach-Object {
                if ($foundPolicies.id -notcontains $_.id) {
                    $_ | Add-Member -NotePropertyName 'policySource' -NotePropertyValue 'compliancePolicy' -Force
                    $foundPolicies += $_
                }
            }
        }
    }
}

# Query legacy device compliance policies (with scheduled actions expanded)
Write-Host "  Querying legacy compliance policies..." -ForegroundColor Gray
$legacyUri = 'https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies?$expand=scheduledActionsForRule($expand=scheduledActionConfigurations)&$top=999'
$legacyPolicies = Invoke-GraphRequestWithPaging -Uri $legacyUri

if ($legacyPolicies -and $legacyPolicies.Count -gt 0) {
    Write-Host "    Found $($legacyPolicies.Count) legacy compliance policies" -ForegroundColor Gray
    foreach ($pattern in $PolicyNamesArray) {
        $policyMatches = $legacyPolicies | Where-Object { $_.displayName -like $pattern }
        
        # Apply platform filter if not 'All'
        if ($Platform -ne 'All' -and $policyMatches) {
            $platformKeywords = $platformFilters[$Platform]
            $policyMatches = $policyMatches | Where-Object {
                $odataType = $_.'@odata.type'
                $platformKeywords | Where-Object { $odataType -match $_ }
            }
        }
        
        if ($policyMatches) {
            $policyMatches | ForEach-Object {
                if ($foundPolicies.id -notcontains $_.id) {
                    $_ | Add-Member -NotePropertyName 'policySource' -NotePropertyValue 'deviceCompliancePolicy' -Force
                    $foundPolicies += $_
                }
            }
        }
    }
}

Write-Host ""
Write-Host "  ✓ Found $($foundPolicies.Count) matching compliance policies" -ForegroundColor Green
if ($foundPolicies.Count -eq 0) {
    Write-Warning "No compliance policies matched the provided names"
    
    # Show available policies for help
    Write-Host ""
    Write-Host "  Available Settings Catalog compliance policies:" -ForegroundColor Yellow
    $settingsCatalogPolicies | Select-Object -First 10 | ForEach-Object {
        Write-Host "    - $($_.name) [Platform: $($_.platforms)]" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "  Available legacy compliance policies:" -ForegroundColor Yellow
    $legacyPolicies | Select-Object -First 10 | ForEach-Object {
        $type = $_.'@odata.type' -replace '#microsoft.graph.', '' -replace 'CompliancePolicy$', ''
        Write-Host "    - $($_.displayName) [$type]" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "  Tip: Use wildcards like '*Windows*' for partial matching" -ForegroundColor Cyan
    
    Disconnect-MgGraph | Out-Null
    exit 0
}

# Display found policies
$foundPolicies | ForEach-Object {
    $name = if ($_.displayName) { $_.displayName } else { $_.name }
    $type = if ($_.'@odata.type') { $_.'@odata.type' -replace '#microsoft.graph.', '' -replace 'CompliancePolicy$', '' } else { $_.platforms }
    Write-Host "    - $name ($type)" -ForegroundColor Cyan
}

# Fetch assignments and settings for each policy
Write-Host ""
Write-Host "[4/5] Collecting assignments and settings for each policy..." -ForegroundColor Yellow

$totalPolicies = $foundPolicies.Count
$current = 0

foreach ($policy in $foundPolicies) {
    $current++
    $name = if ($policy.displayName) { $policy.displayName } else { $policy.name }
    Write-Host "  [$current/$totalPolicies] $name..." -ForegroundColor Gray

    # Fetch assignments based on policy source
    $assignments = @()
    $assignmentsUri = switch ($policy.policySource) {
        'compliancePolicy' { "https://graph.microsoft.com/beta/deviceManagement/compliancePolicies('$($policy.id)')/assignments" }
        'deviceCompliancePolicy' { "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies('$($policy.id)')/assignments" }
    }
    
    if ($assignmentsUri) {
        try {
            $assignmentsResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method GET
            if ($assignmentsResponse.value) {
                $assignments = $assignmentsResponse.value
                # Resolve group IDs to names
                foreach ($assignment in $assignments) {
                    if ($assignment.target.groupId) {
                        $groupName = Get-GroupDisplayName -GroupId $assignment.target.groupId
                        $assignment.target | Add-Member -NotePropertyName 'groupName' -NotePropertyValue $groupName -Force
                    }
                    # Resolve filter IDs if present
                    if ($assignment.target.deviceAndAppManagementAssignmentFilterId) {
                        $filterName = Get-FilterDisplayName -FilterId $assignment.target.deviceAndAppManagementAssignmentFilterId
                        $assignment.target | Add-Member -NotePropertyName 'filterName' -NotePropertyValue $filterName -Force
                    }
                }
            }
        } catch {
            Write-Warning "    Failed to get assignments: $_"
        }
    }
    $policy | Add-Member -NotePropertyName 'assignments' -NotePropertyValue $assignments -Force

    # Get scheduled actions (non-compliance actions)
    # For legacy policies, these are already expanded in the initial query
    # For Settings Catalog policies, they're included in the response
    $scheduledActions = @()
    if ($policy.scheduledActionsForRule) {
        $scheduledActions = $policy.scheduledActionsForRule
    }
    $policy | Add-Member -NotePropertyName 'scheduledActionsDetails' -NotePropertyValue $scheduledActions -Force

    # Fetch settings based on policy source
    $settings = @()
    try {
        if ($policy.policySource -eq 'compliancePolicy') {
            # Settings Catalog compliance policy - use settings endpoint
            $uri = "https://graph.microsoft.com/beta/deviceManagement/compliancePolicies('$($policy.id)')/settings"
            $settingsResponse = Invoke-MgGraphRequest -Uri $uri -Method GET
            if ($settingsResponse.value) {
                $settings = $settingsResponse.value
            }
        } elseif ($policy.policySource -eq 'deviceCompliancePolicy') {
            # Legacy compliance policy - extract settings from the policy object
            # Graph API returns hashtables, need to handle the underlying data
            $settingsData = @{}
            $excludeProps = @('id', 'displayName', 'description', 'createdDateTime', 'lastModifiedDateTime', 
                              '@odata.type', '@odata.context', 'version', 'roleScopeTagIds', 'assignments', 
                              'policySource', 'scheduledActionsForRule', 'scheduledActionsForRule@odata.context',
                              'scheduledActionsDetails', 'detailedSettings', 'deviceStatuses', 'userStatuses',
                              'deviceStatusOverview', 'userStatusOverview', 'deviceSettingStateSummaries')
            
            # Get the underlying keys - policy may be hashtable or have underlying hashtable
            $keys = @()
            if ($policy -is [hashtable]) {
                $keys = $policy.Keys
            } elseif ($policy.PSObject.BaseObject -is [hashtable]) {
                $keys = $policy.PSObject.BaseObject.Keys
            } else {
                $keys = $policy.PSObject.Properties | ForEach-Object { $_.Name }
            }
            
            foreach ($key in $keys) {
                if ($key -notin $excludeProps -and -not $key.StartsWith('@')) {
                    # Get value from either hashtable or PSObject property
                    $val = $null
                    if ($policy -is [hashtable] -or $policy.PSObject.BaseObject -is [hashtable]) {
                        $val = $policy[$key]
                    } else {
                        $val = $policy.$key
                    }
                    
                    # Only include properties with actual values (not null, empty string, or empty array)
                    # But DO include boolean false and numeric 0 as those are valid settings
                    $hasValue = $false
                    if ($val -is [bool]) {
                        $hasValue = $true  # Boolean false is a valid value
                    } elseif ($val -is [int] -or $val -is [long] -or $val -is [double]) {
                        $hasValue = $true  # Numeric 0 is a valid value
                    } elseif ($val -is [array]) {
                        $hasValue = $val.Count -gt 0
                    } elseif ($val -is [string]) {
                        $hasValue = -not [string]::IsNullOrWhiteSpace($val)
                    } elseif ($null -ne $val) {
                        $hasValue = $true
                    }
                    
                    if ($hasValue) {
                        $settingsData[$key] = $val
                    }
                }
            }
            
            if ($settingsData.Count -gt 0) {
                $settings = @(@{type = 'properties'; data = $settingsData})
            }
        }
    } catch {
        Write-Warning "    Failed to get settings: $_"
    }
    $policy | Add-Member -NotePropertyName 'detailedSettings' -NotePropertyValue $settings -Force
}

Write-Host "  ✓ Data collected" -ForegroundColor Green

# Export to individual Markdown files
Write-Host ""
Write-Host "[5/5] Exporting to Markdown files..." -ForegroundColor Yellow

$exportFolder = $OutputPath

# Get current user info
$context = Get-MgContext
$collectedBy = if ($context.Account) { $context.Account } else { $env:USERNAME }
$collectionDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Track exported files for README
$exportedFiles = @()

# Helper function to sanitize filename
function Get-SafeFileName {
    param([string]$Name)
    $invalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
    $sanitized = $Name -replace "[$([regex]::Escape($invalidChars))]", '_'
    $sanitized = $sanitized -replace '\s+', '_'
    # Remove brackets which PowerShell treats as wildcards
    $sanitized = $sanitized -replace '[\[\]]', '_'
    return $sanitized
}

# Helper function to format policy type
function Get-PolicyTypeName {
    param(
        [string]$ODataType,
        [string]$PolicySource,
        [string]$Platforms
    )
    
    if ($PolicySource -eq 'compliancePolicy') {
        if ($Platforms) {
            return "Settings Catalog ($Platforms)"
        }
        return "Settings Catalog"
    }
    
    switch -Wildcard ($ODataType) {
        "*windows10CompliancePolicy*" { "Windows 10/11" }
        "*windows81CompliancePolicy*" { "Windows 8.1" }
        "*windowsPhone81CompliancePolicy*" { "Windows Phone 8.1" }
        "*iosCompliancePolicy*" { "iOS/iPadOS" }
        "*macOSCompliancePolicy*" { "macOS" }
        "*androidCompliancePolicy*" { "Android Device Administrator" }
        "*androidWorkProfileCompliancePolicy*" { "Android Enterprise (Work Profile)" }
        "*androidDeviceOwnerCompliancePolicy*" { "Android Enterprise (Fully Managed)" }
        "*androidForWorkCompliancePolicy*" { "Android for Work" }
        "*aospDeviceOwnerCompliancePolicy*" { "Android (AOSP)" }
        default { 
            if ($ODataType) {
                $ODataType -replace '#microsoft.graph.', '' -replace 'CompliancePolicy$', ''
            } else {
                "Compliance Policy"
            }
        }
    }
}

# Helper function to format action type
function Get-ActionTypeName {
    param([string]$ActionType)
    
    switch ($ActionType) {
        "block" { "Mark device non-compliant" }
        "retire" { "Retire device" }
        "wipe" { "Wipe device" }
        "notification" { "Send email notification" }
        "pushNotification" { "Send push notification" }
        "remoteLock" { "Remotely lock device" }
        default { $ActionType }
    }
}

# Export each policy to its own MD file
$totalPolicies = $foundPolicies.Count
$current = 0

foreach ($policy in $foundPolicies) {
    $current++
    $name = if ($policy.displayName) { $policy.displayName } else { $policy.name }
    $safeFileName = Get-SafeFileName -Name $name
    $mdFileName = "$safeFileName.md"
    $mdFilePath = Join-Path $exportFolder $mdFileName
    
    Write-Host "  [$current/$totalPolicies] $name..." -ForegroundColor Gray
    
    $policyType = Get-PolicyTypeName -ODataType $policy.'@odata.type' -PolicySource $policy.policySource -Platforms $policy.platforms
    $policyId = $policy.id
    $createdDate = if ($policy.createdDateTime) { $policy.createdDateTime } else { "N/A" }
    $modifiedDate = if ($policy.lastModifiedDateTime) { $policy.lastModifiedDateTime } else { "N/A" }
    
    # Build Markdown content
    $md = @()
    $md += "# $name"
    $md += ""
    $md += "## Policy Information"
    $md += ""
    $md += "| Property | Value |"
    $md += "|----------|-------|"
    $md += "| **Name** | $name |"
    $md += "| **Type** | $policyType |"
    $md += "| **Policy ID** | ``$policyId`` |"
    $md += "| **Created** | $createdDate |"
    $md += "| **Last Modified** | $modifiedDate |"
    $md += "| **Source** | $($policy.policySource) |"
    
    # Add platforms for Settings Catalog policies
    if ($policy.platforms) {
        $md += "| **Platforms** | $($policy.platforms) |"
    }
    if ($policy.technologies) {
        $md += "| **Technologies** | $($policy.technologies) |"
    }
    
    # Scope tags
    $scopeTagIds = if ($policy.roleScopeTagIds) { $policy.roleScopeTagIds } else { @('0') }
    $scopeTagNames = $scopeTagIds | ForEach-Object { Get-ScopeTagName -TagId $_ }
    $md += "| **Scope Tags** | $($scopeTagNames -join ', ') |"
    $md += ""
    
    # Description if available
    if ($policy.description) {
        $md += "## Description"
        $md += ""
        $md += $policy.description
        $md += ""
    }
    
    # Assignments
    if ($policy.assignments -and $policy.assignments.Count -gt 0) {
        $md += "## Assignments"
        $md += ""
        $md += "| Target Type | Group Name | Filter |"
        $md += "|-------------|------------|--------|"
        foreach ($assignment in $policy.assignments) {
            $targetType = $assignment.target.'@odata.type' -replace '#microsoft.graph.', '' -replace 'AssignmentTarget', ''
            $groupName = if ($assignment.target.groupName) { $assignment.target.groupName } elseif ($assignment.target.groupId) { $assignment.target.groupId } else { "All Devices/Users" }
            $filter = if ($assignment.target.filterName) { 
                "$($assignment.target.deviceAndAppManagementAssignmentFilterType): $($assignment.target.filterName)" 
            } elseif ($assignment.target.deviceAndAppManagementAssignmentFilterId) {
                "$($assignment.target.deviceAndAppManagementAssignmentFilterType): $($assignment.target.deviceAndAppManagementAssignmentFilterId)"
            } else { "None" }
            $md += "| $targetType | $groupName | $filter |"
        }
        $md += ""
    } else {
        $md += "## Assignments"
        $md += ""
        $md += "*No assignments configured*"
        $md += ""
    }
    
    # Scheduled Actions (Non-compliance actions)
    $md += "## Actions for Non-Compliance"
    $md += ""
    
    if ($policy.scheduledActionsDetails -and $policy.scheduledActionsDetails.Count -gt 0) {
        $md += "| Action | Grace Period (Days) | Additional Recipients |"
        $md += "|--------|---------------------|----------------------|"
        
        foreach ($action in $policy.scheduledActionsDetails) {
            if ($action.actionConfigurations) {
                foreach ($config in $action.actionConfigurations) {
                    $actionType = Get-ActionTypeName -ActionType $config.actionType
                    $gracePeriod = if ($null -ne $config.gracePeriodHours) { [math]::Round($config.gracePeriodHours / 24, 1) } else { "0" }
                    $recipients = if ($config.notificationTemplateId) { "Template: $($config.notificationTemplateId)" } else { "N/A" }
                    $md += "| $actionType | $gracePeriod | $recipients |"
                }
            } elseif ($action.scheduledActionConfigurations) {
                # Settings Catalog format
                foreach ($config in $action.scheduledActionConfigurations) {
                    $actionType = Get-ActionTypeName -ActionType $config.actionType
                    $gracePeriod = if ($null -ne $config.gracePeriodHours) { [math]::Round($config.gracePeriodHours / 24, 1) } else { "0" }
                    $recipients = if ($config.notificationTemplateId) { "Template: $($config.notificationTemplateId)" } else { "N/A" }
                    $md += "| $actionType | $gracePeriod | $recipients |"
                }
            }
        }
        $md += ""
    } else {
        $md += "*Default action: Mark device non-compliant immediately*"
        $md += ""
    }
    
    # Settings
    $md += "## Compliance Settings"
    $md += ""
    
    if ($policy.detailedSettings -and $policy.detailedSettings.Count -gt 0) {
        $settingsType = if ($policy.detailedSettings[0].type) { $policy.detailedSettings[0].type } else { 'settingsCatalog' }
        
        if ($settingsType -eq 'properties') {
            # Legacy compliance policy - show as property table
            $md += "| Setting | Value |"
            $md += "|---------|-------|"
            
            $data = $policy.detailedSettings[0].data
            foreach ($key in ($data.Keys | Sort-Object)) {
                $value = $data[$key]
                # Format value for display
                if ($value -is [array]) {
                    $displayValue = $value -join ', '
                } elseif ($value -is [bool]) {
                    $displayValue = if ($value) { "✓ Enabled" } else { "✗ Disabled" }
                } elseif ($value -is [hashtable] -or $value -is [PSCustomObject]) {
                    $displayValue = ($value | ConvertTo-Json -Compress -Depth 2)
                    if ($displayValue.Length -gt 100) { $displayValue = $displayValue.Substring(0, 97) + "..." }
                } else {
                    $displayValue = "$value"
                }
                
                # Format setting name from camelCase to readable
                $settingName = $key -creplace '([A-Z])', ' $1' -replace '^\s', ''
                $settingName = (Get-Culture).TextInfo.ToTitleCase($settingName.ToLower())
                
                $md += "| $settingName | $displayValue |"
            }
            $md += ""
            
        } else {
            # Settings Catalog compliance policy
            $md += "| Setting | Value | Definition |"
            $md += "|---------|-------|------------|"
            
            foreach ($setting in $policy.detailedSettings) {
                $settingInstance = $setting.settingInstance
                if ($settingInstance) {
                    $definitionId = $settingInstance.settingDefinitionId
                    $settingName = $definitionId -replace '.*_', '' -replace 'device_vendor_msft_', ''
                    
                    # Get value based on setting type
                    $value = "N/A"
                    $odataType = $settingInstance.'@odata.type'
                    
                    switch -Wildcard ($odataType) {
                        "*choiceSettingInstance*" {
                            if ($settingInstance.choiceSettingValue) {
                                $value = $settingInstance.choiceSettingValue.value -replace '.*_', ''
                            }
                        }
                        "*simpleSetting*" {
                            if ($settingInstance.simpleSettingValue) {
                                $value = $settingInstance.simpleSettingValue.value
                            }
                        }
                        "*groupSettingCollection*" {
                            $value = "(Collection of $($settingInstance.groupSettingCollectionValue.Count) items)"
                        }
                        default {
                            $value = "(Complex setting)"
                        }
                    }
                    
                    $md += "| $settingName | $value | ``$definitionId`` |"
                }
            }
            $md += ""
        }
    } else {
        $md += "*No detailed settings available*"
        $md += ""
    }
    
    # Metadata
    $md += "---"
    $md += ""
    $md += "## Collection Metadata"
    $md += ""
    $md += "| Property | Value |"
    $md += "|----------|-------|"
    $md += "| **Collected By** | $collectedBy |"
    $md += "| **Collection Date** | $collectionDate |"
    $md += "| **Collection Method** | Microsoft Graph API |"
    $md += "| **Script** | Com-pliance.ps1 |"
    $md += ""
    
    # Write file
    $md -join "`n" | Out-File -LiteralPath $mdFilePath -Encoding UTF8
    
    # Track for README
    $exportedFiles += @{
        Name = $name
        Type = $policyType
        Created = $createdDate
        Modified = $modifiedDate
        FileName = $mdFileName
    }
}

# Generate README.md
Write-Host "  Generating README.md..." -ForegroundColor Gray

$readme = @()
$readme += "# Intune Compliance Policies Export"
$readme += ""
$readme += "## Collection Information"
$readme += ""
$readme += "| Property | Value |"
$readme += "|----------|-------|"
$readme += "| **Collected By** | $collectedBy |"
$readme += "| **Collection Date** | $collectionDate |"
$readme += "| **Collection Method** | Microsoft Graph API (PowerShell) |"
$readme += "| **Script** | Com-pliance.ps1 |"
$readme += "| **Policies Collected** | $($exportedFiles.Count) |"
$readme += ""
$readme += "## Search Patterns Used"
$readme += ""
$readme += "``````"
$PolicyNamesArray | ForEach-Object { $readme += $_ }
$readme += "``````"
$readme += ""

if ($Platform -ne 'All') {
    $readme += "**Platform Filter:** $Platform"
    $readme += ""
}

$readme += "## Policies Collected"
$readme += ""
$readme += "| Policy Name | Type | Created | Modified | Link |"
$readme += "|-------------|------|---------|----------|------|"

foreach ($file in ($exportedFiles | Sort-Object Name)) {
    $linkName = $file.Name -replace '\|', '\|'
    $readme += "| $linkName | $($file.Type) | $($file.Created) | $($file.Modified) | [$($file.FileName)]($($file.FileName)) |"
}

$readme += ""
$readme += "## API Endpoints Queried"
$readme += ""
$readme += "- ``https://graph.microsoft.com/beta/deviceManagement/compliancePolicies`` - Settings Catalog compliance policies"
$readme += "- ``https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies`` - Legacy compliance policies"
$readme += "- ``https://graph.microsoft.com/beta/deviceManagement/compliancePolicies/{id}/settings`` - Policy settings"
$readme += "- ``https://graph.microsoft.com/beta/deviceManagement/compliancePolicies/{id}/assignments`` - Policy assignments"
$readme += "- ``https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/{id}/scheduledActionsForRule`` - Non-compliance actions"
$readme += "- ``https://graph.microsoft.com/beta/deviceManagement/roleScopeTags`` - Scope tags"
$readme += ""
$readme += "## Permissions Required"
$readme += ""
$readme += "- ``DeviceManagementConfiguration.Read.All``"
$readme += ""
$readme += "---"
$readme += ""
$readme += "*Generated automatically by Com-pliance.ps1*"

$readmePath = Join-Path $exportFolder "README.md"
$readme -join "`n" | Out-File -LiteralPath $readmePath -Encoding UTF8

Write-Host "  ✓ Created README.md" -ForegroundColor Green

# Disconnect
Write-Host ""
Write-Host "Disconnecting from Microsoft Graph..." -ForegroundColor Gray
Disconnect-MgGraph | Out-Null

Write-Host ""
Write-Host "=== Export Complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "Output folder: $exportFolder" -ForegroundColor Yellow
Write-Host "  - $($exportedFiles.Count) compliance policy Markdown files" -ForegroundColor Gray
Write-Host "  - README.md index file" -ForegroundColor Gray
Write-Host ""

# Show appreciation call-to-action
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   Found Com-pliance helpful?" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "If this tool saved you time or made your work easier," -ForegroundColor White
Write-Host "consider giving a " -NoNewline -ForegroundColor White
Write-Host "Badge " -NoNewline -ForegroundColor Green
Write-Host "to recognize the effort!" -ForegroundColor White
Write-Host ""
Write-Host "Author: " -NoNewline -ForegroundColor Gray
Write-Host "Joshua Walderbach (j0w03ow)" -ForegroundColor White
Write-Host "Badgify: " -NoNewline -ForegroundColor Gray
Write-Host "https://internal.walmart.com/content/badgify/home/badgify.html" -ForegroundColor Cyan
Write-Host ""
Write-Host "Thank you for using Com-pliance! " -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
