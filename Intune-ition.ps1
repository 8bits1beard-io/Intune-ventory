<#
.SYNOPSIS
    Export specific Intune configuration profiles by name to individual Markdown files.

.DESCRIPTION
    Authenticates to Microsoft Graph, searches for configuration profiles
    matching provided names, collects full profile details including settings
    and assignments, and exports each profile to its own Markdown file.
    Creates a README.md index with links to all exported profiles.

.PARAMETER ProfileNames
    Comma-separated list of profile display names to search for (supports wildcards).
    Example: "OneDrive*,Firewall*,NetworkProxy"

.PARAMETER CsvFile
    Path to CSV file containing profile names.

.PARAMETER CsvColumn
    Column name in CSV containing profile names (default: "ProfileName").

.PARAMETER OutputPath
    Required. Output directory for Markdown files. Will be created if it doesn't exist.

.PARAMETER All
    Export all configuration profiles in the tenant (ignores profile name filtering).

.EXAMPLE
    .\Intune-ition.ps1 -All -OutputPath "C:\Exports\FullTenant"
    Exports every configuration profile in the Intune tenant.

.EXAMPLE
    .\Intune-ition.ps1 -OutputPath "C:\Exports\2026-02"
    Prompts for profile names, then exports to the specified folder.

.EXAMPLE
    .\Intune-ition.ps1 -ProfileNames "OneDrive*,Firewall*,GLOBAL*" -OutputPath ".\Exports"
    Exports profiles matching the specified name patterns.

.EXAMPLE
    .\Intune-ition.ps1 -CsvFile "profiles.csv" -CsvColumn "Name" -OutputPath "C:\Exports"
    Exports profiles listed in CSV.

.NOTES
    File Name      : Intune-ition.ps1
    Author         : Joshua Walderbach (j0w03ow)
    Prerequisite   : Microsoft.Graph.Authentication PowerShell module
    Requires       : PowerShell 5.1 or higher
                     DeviceManagementConfiguration.Read.All permission
    Version        : 1.0.0
    Date           : 2025-02-17

.LINK
    https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceconfig-deviceconfiguration

.OUTPUTS
    Individual Markdown files for each profile and a README.md index file.
#>
[CmdletBinding(DefaultParameterSetName='Default')]
param(
    [Parameter(ParameterSetName='Names')]
    [string]$ProfileNames,

    [Parameter(ParameterSetName='Csv', Mandatory=$true)]
    [string]$CsvFile,

    [Parameter(ParameterSetName='Csv')]
    [string]$CsvColumn = "ProfileName",

    [Parameter(ParameterSetName='All')]
    [switch]$All,

    [Parameter(Mandatory=$true)]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

# Handle -All parameter
if ($All) {
    $ProfileNamesArray = @('*')
    Write-Host "" 
    Write-Host "Exporting ALL configuration profiles in the tenant..." -ForegroundColor Yellow
}
# Parse profile names based on input method
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

        $ProfileNamesArray = $csvData | ForEach-Object { $_.$CsvColumn } | Where-Object { $_ -and $_.Trim() -ne '' }
    } catch {
        Write-Error "Failed to import CSV: $_"
        exit 1
    }
} elseif ($ProfileNames) {
    # Parse comma-separated string
    $ProfileNamesArray = $ProfileNames -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
} else {
    # Prompt for profile names
    Write-Host ""
    Write-Host "No profile names provided." -ForegroundColor Yellow
    Write-Host "Enter profile names (comma-separated, wildcards supported):" -ForegroundColor Cyan
    Write-Host "Example: WinD_*,Collab_*,*EdgeChromium*" -ForegroundColor Gray
    Write-Host ""
    $inputNames = Read-Host "Profile names"
    
    if (-not $inputNames -or $inputNames.Trim() -eq '') {
        Write-Error "No profile names entered. Exiting."
        exit 1
    }
    
    $ProfileNamesArray = $inputNames -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
}

if (-not $ProfileNamesArray -or $ProfileNamesArray.Count -eq 0) {
    Write-Error "No profile names provided. Use -ProfileNames, -CsvFile, or -All"
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

Write-Host "=== Intune Configuration Profile Export ===" -ForegroundColor Cyan
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

# Search for profiles
Write-Host ""
Write-Host "[3/5] Searching for configuration profiles..." -ForegroundColor Yellow
if (-not $All) {
    Write-Host "  Profile name patterns:" -ForegroundColor Gray
    $ProfileNamesArray | ForEach-Object { Write-Host "    - $_" -ForegroundColor Gray }
}

$allProfiles = @()
$foundProfiles = @()

# Query deviceConfigurations (legacy profiles)
Write-Host ""
Write-Host "  Querying deviceConfigurations..." -ForegroundColor Gray
$uri = 'https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?$top=999'
$legacyProfiles = Invoke-GraphRequestWithPaging -Uri $uri

if ($legacyProfiles -and $legacyProfiles.Count -gt 0) {
    Write-Host "    Found $($legacyProfiles.Count) total legacy profiles" -ForegroundColor Gray
    foreach ($pattern in $ProfileNamesArray) {
        $matches = $legacyProfiles | Where-Object { $_.displayName -like $pattern }
        if ($matches) {
            $matches | ForEach-Object {
                $_ | Add-Member -NotePropertyName 'profileSource' -NotePropertyValue 'deviceConfiguration' -Force
                $foundProfiles += $_
            }
        }
    }
}

# Query configurationPolicies (Settings Catalog)
Write-Host "  Querying configurationPolicies..." -ForegroundColor Gray
$uri = 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$top=999'
$catalogProfiles = Invoke-GraphRequestWithPaging -Uri $uri

if ($catalogProfiles -and $catalogProfiles.Count -gt 0) {
    Write-Host "    Found $($catalogProfiles.Count) total Settings Catalog profiles" -ForegroundColor Gray
    foreach ($pattern in $ProfileNamesArray) {
        $matches = $catalogProfiles | Where-Object { $_.name -like $pattern -or $_.displayName -like $pattern }
        if ($matches) {
            $matches | ForEach-Object {
                $_ | Add-Member -NotePropertyName 'profileSource' -NotePropertyValue 'configurationPolicy' -Force
                $foundProfiles += $_
            }
        }
    }
}

# Query groupPolicyConfigurations (Administrative Templates / ADMX)
Write-Host "  Querying groupPolicyConfigurations (ADMX)..." -ForegroundColor Gray
$uri = 'https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations?$top=999'
$admxProfiles = Invoke-GraphRequestWithPaging -Uri $uri

if ($admxProfiles -and $admxProfiles.Count -gt 0) {
    Write-Host "    Found $($admxProfiles.Count) total ADMX profiles" -ForegroundColor Gray
    foreach ($pattern in $ProfileNamesArray) {
        $matches = $admxProfiles | Where-Object { $_.displayName -like $pattern }
        if ($matches) {
            $matches | ForEach-Object {
                $_ | Add-Member -NotePropertyName 'profileSource' -NotePropertyValue 'groupPolicyConfiguration' -Force
                $foundProfiles += $_
            }
        }
    }
}

# Query intents (Endpoint Security policies)
Write-Host "  Querying intents (Endpoint Security)..." -ForegroundColor Gray
$uri = 'https://graph.microsoft.com/beta/deviceManagement/intents?$top=999'
$intentProfiles = Invoke-GraphRequestWithPaging -Uri $uri

if ($intentProfiles -and $intentProfiles.Count -gt 0) {
    Write-Host "    Found $($intentProfiles.Count) total Endpoint Security profiles" -ForegroundColor Gray
    foreach ($pattern in $ProfileNamesArray) {
        $matches = $intentProfiles | Where-Object { $_.displayName -like $pattern }
        if ($matches) {
            $matches | ForEach-Object {
                $_ | Add-Member -NotePropertyName 'profileSource' -NotePropertyValue 'intent' -Force
                $foundProfiles += $_
            }
        }
    }
}

Write-Host ""
Write-Host "  ✓ Found $($foundProfiles.Count) matching profiles" -ForegroundColor Green
if ($foundProfiles.Count -eq 0) {
    Write-Warning "No profiles matched the provided names"
    Disconnect-MgGraph | Out-Null
    exit 0
}

# Display found profiles
$foundProfiles | ForEach-Object {
    $name = if ($_.displayName) { $_.displayName } else { $_.name }
    $type = $_.'@odata.type' -replace '#microsoft.graph.', ''
    Write-Host "    - $name ($type)" -ForegroundColor Cyan
}

# Fetch assignments and settings for each profile
Write-Host ""
Write-Host "[4/5] Collecting assignments and settings for each profile..." -ForegroundColor Yellow

$totalProfiles = $foundProfiles.Count
$current = 0

foreach ($profile in $foundProfiles) {
    $current++
    $name = if ($profile.displayName) { $profile.displayName } else { $profile.name }
    Write-Host "  [$current/$totalProfiles] $name..." -ForegroundColor Gray

    # Fetch assignments based on profile source
    $assignments = @()
    $assignmentsUri = switch ($profile.profileSource) {
        'configurationPolicy' { "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$($profile.id)')/assignments" }
        'deviceConfiguration' { "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations('$($profile.id)')/assignments" }
        'groupPolicyConfiguration' { "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations('$($profile.id)')/assignments" }
        'intent' { "https://graph.microsoft.com/beta/deviceManagement/intents('$($profile.id)')/assignments" }
    }
    
    if ($assignmentsUri) {
        try {
            $assignmentsResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method GET
            if ($assignmentsResponse.value) {
                $assignments = $assignmentsResponse.value
                # Resolve group IDs to names
                foreach ($assignment in $assignments) {
                    if ($assignment.target.groupId) {
                        $groupId = $assignment.target.groupId
                        if (-not $script:groupNameCache) { $script:groupNameCache = @{} }
                        if (-not $script:groupNameCache.ContainsKey($groupId)) {
                            try {
                                $groupResponse = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/groups/$groupId" -Method GET
                                $script:groupNameCache[$groupId] = $groupResponse.displayName
                            } catch {
                                $script:groupNameCache[$groupId] = $groupId
                            }
                        }
                        $assignment.target | Add-Member -NotePropertyName 'groupName' -NotePropertyValue $script:groupNameCache[$groupId] -Force
                    }
                    # Also resolve filter IDs if present
                    if ($assignment.target.deviceAndAppManagementAssignmentFilterId) {
                        $filterId = $assignment.target.deviceAndAppManagementAssignmentFilterId
                        if (-not $script:filterNameCache) { $script:filterNameCache = @{} }
                        if (-not $script:filterNameCache.ContainsKey($filterId)) {
                            try {
                                $filterResponse = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/assignmentFilters/$filterId" -Method GET
                                $script:filterNameCache[$filterId] = $filterResponse.displayName
                            } catch {
                                $script:filterNameCache[$filterId] = $filterId
                            }
                        }
                        $assignment.target | Add-Member -NotePropertyName 'filterName' -NotePropertyValue $script:filterNameCache[$filterId] -Force
                    }
                }
            }
        } catch {
            Write-Warning "    Failed to get assignments: $_"
        }
    }
    $profile | Add-Member -NotePropertyName 'assignments' -NotePropertyValue $assignments -Force

    # Fetch settings based on profile source
    $settings = @()
    try {
        if ($profile.profileSource -eq 'configurationPolicy') {
            # Settings Catalog - use settings endpoint
            $uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$($profile.id)')/settings?`$expand=settingDefinitions&`$top=1000"
            $settingsResponse = Invoke-MgGraphRequest -Uri $uri -Method GET
            if ($settingsResponse.value) {
                $settings = $settingsResponse.value
            }
        } elseif ($profile.profileSource -eq 'deviceConfiguration') {
            # Legacy profile - extract settings from the profile object based on type
            $odataType = $profile.'@odata.type'
            if ($odataType -like '*CustomConfiguration*' -and $profile.omaSettings) {
                # Custom OMA-URI profile
                $settings = @(@{type = 'omaSettings'; data = $profile.omaSettings})
            } elseif ($odataType -like '*TrustedRootCertificate*' -or $odataType -like '*PKCS*' -or $odataType -like '*SCEP*') {
                # Certificate profile
                $settings = @(@{type = 'certificate'; data = $profile})
            } else {
                # Other legacy profiles - extract non-system properties as settings
                $settingsData = @{}
                $excludeProps = @('id', 'displayName', 'description', 'createdDateTime', 'lastModifiedDateTime', 
                                  '@odata.type', 'version', 'supportsScopeTags', 'roleScopeTagIds', 'assignments',
                                  'deviceManagementApplicabilityRuleDeviceMode', 'deviceManagementApplicabilityRuleOsEdition',
                                  'deviceManagementApplicabilityRuleOsVersion', 'profileSource', 'detailedSettings')
                $profile.PSObject.Properties | Where-Object { $_.Name -notin $excludeProps -and $null -ne $_.Value } | ForEach-Object {
                    $settingsData[$_.Name] = $_.Value
                }
                if ($settingsData.Count -gt 0) {
                    $settings = @(@{type = 'properties'; data = $settingsData})
                } else {
                    $settings = @(@{type = 'embedded'})
                }
            }
        } elseif ($profile.profileSource -eq 'groupPolicyConfiguration') {
            # ADMX profile - get definition values with definitions expanded
            $uri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations('$($profile.id)')/definitionValues?`$expand=definition"
            $defResponse = Invoke-MgGraphRequest -Uri $uri -Method GET
            if ($defResponse.value) {
                $definitionValues = $defResponse.value
                # For each definition value, get presentation values
                foreach ($defVal in $definitionValues) {
                    $presUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations('$($profile.id)')/definitionValues('$($defVal.id)')/presentationValues?`$expand=presentation"
                    try {
                        $presResponse = Invoke-MgGraphRequest -Uri $presUri -Method GET
                        if ($presResponse.value) {
                            $defVal | Add-Member -NotePropertyName 'presentationValues' -NotePropertyValue $presResponse.value -Force
                        }
                    } catch { }
                }
                $settings = $definitionValues
            }
        } elseif ($profile.profileSource -eq 'intent') {
            # Endpoint Security intent - get settings directly
            $uri = "https://graph.microsoft.com/beta/deviceManagement/intents('$($profile.id)')/settings"
            $intentResponse = Invoke-MgGraphRequest -Uri $uri -Method GET
            if ($intentResponse.value) {
                $settings = $intentResponse.value
            }
        }
    } catch {
        Write-Warning "    Failed to get settings: $_"
    }
    $profile | Add-Member -NotePropertyName 'detailedSettings' -NotePropertyValue $settings -Force
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
$collectionDateISO = Get-Date -Format "o"

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

# Helper function to format profile type
function Get-ProfileTypeName {
    param(
        [string]$ODataType,
        [string]$ProfileSource
    )
    
    # Check profile source first for types without @odata.type
    if ($ProfileSource -eq 'groupPolicyConfiguration') {
        return "Administrative Template (ADMX)"
    }
    if ($ProfileSource -eq 'intent') {
        return "Endpoint Security"
    }
    if ($ProfileSource -eq 'configurationPolicy') {
        return "Settings Catalog"
    }
    if ($ProfileSource -eq 'deviceConfiguration') {
        # For legacy profiles, fall through to switch statement to get specific type
    }
    
    switch -Wildcard ($ODataType) {
        "*windowsDeliveryOptimizationConfiguration*" { "Delivery Optimization" }
        "*windows10CustomConfiguration*" { "Custom (OMA-URI)" }
        "*windows10GeneralConfiguration*" { "Device Restrictions" }
        "*windowsHealthMonitoringConfiguration*" { "Health Monitoring" }
        "*windowsIdentityProtectionConfiguration*" { "Identity Protection" }
        "*windows10EndpointProtectionConfiguration*" { "Endpoint Protection" }
        "*deviceManagementConfigurationPolicy*" { "Settings Catalog" }
        "*windows10SecureAssessmentConfiguration*" { "Secure Assessment" }
        "*editionUpgradeConfiguration*" { "Edition Upgrade" }
        "*windowsUpdateForBusiness*" { "Windows Update for Business" }
        "*groupPolicyConfiguration*" { "Administrative Template (ADMX)" }
        "*deviceManagementIntent*" { "Endpoint Security" }
        default { 
            if ($ODataType) {
                $ODataType -replace '#microsoft.graph.', '' -replace 'Configuration$', ''
            } else {
                "Device Configuration"
            }
        }
    }
}

# Export each profile to its own MD file
$totalProfiles = $foundProfiles.Count
$current = 0

foreach ($profile in $foundProfiles) {
    $current++
    $name = if ($profile.displayName) { $profile.displayName } else { $profile.name }
    $safeFileName = Get-SafeFileName -Name $name
    $mdFileName = "$safeFileName.md"
    $mdFilePath = Join-Path $exportFolder $mdFileName
    
    Write-Host "  [$current/$totalProfiles] $name..." -ForegroundColor Gray
    
    $profileType = Get-ProfileTypeName -ODataType $profile.'@odata.type' -ProfileSource $profile.profileSource
    $profileId = $profile.id
    $createdDate = if ($profile.createdDateTime) { $profile.createdDateTime } else { "N/A" }
    $modifiedDate = if ($profile.lastModifiedDateTime) { $profile.lastModifiedDateTime } else { "N/A" }
    
    # Build Markdown content
    $md = @()
    $md += "# $name"
    $md += ""
    $md += "## Profile Information"
    $md += ""
    $md += "| Property | Value |"
    $md += "|----------|-------|"
    $md += "| **Name** | $name |"
    $md += "| **Type** | $profileType |"
    $md += "| **Profile ID** | ``$profileId`` |"
    $md += "| **Created** | $createdDate |"
    $md += "| **Last Modified** | $modifiedDate |"
    $md += "| **Source** | $($profile.profileSource) |"
    $md += ""
    
    # Description if available
    if ($profile.description) {
        $md += "## Description"
        $md += ""
        $md += $profile.description
        $md += ""
    }
    
    # Assignments
    if ($profile.assignments -and $profile.assignments.Count -gt 0) {
        $md += "## Assignments"
        $md += ""
        $md += "| Target Type | Group Name | Filter |"
        $md += "|-------------|------------|--------|"
        foreach ($assignment in $profile.assignments) {
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
    
    # Settings
    $md += "## Settings"
    $md += ""
    
    if ($profile.detailedSettings -and $profile.detailedSettings.Count -gt 0) {
        # Check the type of settings we have
        $settingsType = $profile.detailedSettings[0].type
        
        if ($settingsType -eq 'omaSettings') {
            # Custom OMA-URI profile
            $md += "| Display Name | OMA-URI | Value | Description |"
            $md += "|--------------|---------|-------|-------------|"
            foreach ($oma in $profile.detailedSettings[0].data) {
                $omaName = if ($oma.displayName) { $oma.displayName } else { "N/A" }
                $omaUri = if ($oma.omaUri) { "``$($oma.omaUri)``" } else { "N/A" }
                $omaValue = if ($oma.isEncrypted) { "(Encrypted)" } elseif ($oma.value) { 
                    $v = "$($oma.value)"
                    if ($v.Length -gt 50) { $v.Substring(0, 47) + "..." } else { $v }
                } else { "N/A" }
                $omaDesc = if ($oma.description) { $oma.description -replace '\|', '-' -replace "`n", ' ' } else { "" }
                if ($omaDesc.Length -gt 80) { $omaDesc = $omaDesc.Substring(0, 77) + "..." }
                $md += "| $omaName | $omaUri | $omaValue | $omaDesc |"
            }
            $md += ""
            
        } elseif ($settingsType -eq 'certificate') {
            # Certificate profile
            $cert = $profile.detailedSettings[0].data
            $md += "| Property | Value |"
            $md += "|----------|-------|"
            if ($cert.certFileName) { $md += "| **Certificate File** | $($cert.certFileName) |" }
            if ($cert.destinationStore) { $md += "| **Destination Store** | $($cert.destinationStore) |" }
            if ($cert.subjectName) { $md += "| **Subject Name** | $($cert.subjectName) |" }
            if ($cert.subjectAlternativeNameType) { $md += "| **SAN Type** | $($cert.subjectAlternativeNameType) |" }
            if ($cert.certificateValidityPeriodValue) { $md += "| **Validity Period** | $($cert.certificateValidityPeriodValue) $($cert.certificateValidityPeriodScale) |" }
            if ($cert.renewalThresholdPercentage) { $md += "| **Renewal Threshold** | $($cert.renewalThresholdPercentage)% |" }
            if ($cert.scepServerUrls) { $md += "| **SCEP Server URLs** | $($cert.scepServerUrls -join ', ') |" }
            if ($cert.keyUsage) { $md += "| **Key Usage** | $($cert.keyUsage) |" }
            if ($cert.keySize) { $md += "| **Key Size** | $($cert.keySize) |" }
            if ($cert.hashAlgorithm) { $md += "| **Hash Algorithm** | $($cert.hashAlgorithm) |" }
            $md += ""
            
        } elseif ($settingsType -eq 'properties') {
            # Other legacy profile with extracted properties
            $md += "| Setting | Value |"
            $md += "|---------|-------|"
            foreach ($prop in $profile.detailedSettings[0].data.GetEnumerator()) {
                $propName = $prop.Key
                $propValue = if ($null -eq $prop.Value) { "null" } 
                             elseif ($prop.Value -is [array]) { $prop.Value -join ", " }
                             elseif ($prop.Value -is [hashtable] -or $prop.Value -is [PSCustomObject]) { "(Complex value - see JSON)" }
                             else { "$($prop.Value)" }
                if ($propValue.Length -gt 100) { $propValue = $propValue.Substring(0, 97) + "..." }
                $md += "| $propName | $propValue |"
            }
            $md += ""
            
        } elseif ($settingsType -eq 'embedded') {
            $md += "Settings are embedded in the profile configuration below."
            $md += ""
            
        } else {
            # Format settings based on profile type
            if ($profile.profileSource -eq 'configurationPolicy') {
                # Settings Catalog - extract readable settings
                $md += "| Setting | Configured Value | Description |"
                $md += "|---------|------------------|-------------|"
                
                foreach ($setting in $profile.detailedSettings) {
                    $settingDef = $setting.settingDefinitions | Select-Object -First 1
                    $settingName = if ($settingDef.displayName) { $settingDef.displayName } else { $settingDef.id }
                    $description = if ($settingDef.description) { 
                        ($settingDef.description -split "`n")[0] -replace '\|', '-' 
                        if ($_.Length -gt 100) { $_.Substring(0, 100) + "..." } else { $_ }
                    } else { "" }
                    
                    # Get configured value
                    $configuredValue = "N/A"
                    $inst = $setting.settingInstance
                    if ($inst.choiceSettingValue) {
                        # Find the option that matches
                        $selectedOption = $settingDef.options | Where-Object { $_.itemId -eq $inst.choiceSettingValue.value } | Select-Object -First 1
                        $configuredValue = if ($selectedOption.displayName) { $selectedOption.displayName } else { $inst.choiceSettingValue.value -replace '.*_', '' }
                    } elseif ($inst.simpleSettingValue) {
                        $configuredValue = $inst.simpleSettingValue.value
                    } elseif ($inst.simpleSettingCollectionValue) {
                        $configuredValue = ($inst.simpleSettingCollectionValue.value -join ", ")
                    } elseif ($inst.groupSettingCollectionValue) {
                        $configuredValue = "(Group settings - see JSON)"
                    }
                    
                    $md += "| $settingName | $configuredValue | $description |"
                }
                $md += ""
                
            } elseif ($profile.profileSource -eq 'groupPolicyConfiguration') {
                # ADMX settings
                $md += "| Policy Setting | State | Category |"
                $md += "|----------------|-------|----------|"
                
                foreach ($defVal in $profile.detailedSettings) {
                    $policyName = if ($defVal.definition.displayName) { $defVal.definition.displayName } else { $defVal.definition.id }
                    $state = if ($defVal.enabled) { "Enabled" } else { "Disabled" }
                    $category = if ($defVal.definition.categoryPath) { $defVal.definition.categoryPath } else { "" }
                    $md += "| $policyName | $state | $category |"
                    
                    # Add presentation values if any
                    if ($defVal.presentationValues -and $defVal.presentationValues.Count -gt 0) {
                        foreach ($pres in $defVal.presentationValues) {
                            $presLabel = if ($pres.presentation.label) { $pres.presentation.label -replace ':$', '' } else { "Value" }
                            $presValue = if ($pres.value -ne $null) { $pres.value } elseif ($pres.values) { $pres.values -join ", " } else { "" }
                            $md += "| ↳ *$presLabel* | $presValue | |"
                        }
                    }
                }
                $md += ""
                
            } elseif ($profile.profileSource -eq 'intent') {
                # Endpoint Security settings
                $md += "| Setting ID | Value |"
                $md += "|------------|-------|"
                
                foreach ($setting in $profile.detailedSettings) {
                    $settingId = $setting.definitionId -replace '.*/', ''
                    $value = if ($setting.value -ne $null) { 
                        if ($setting.value -is [array]) { $setting.value -join ", " } else { $setting.value }
                    } elseif ($setting.valueJson) {
                        $setting.valueJson
                    } else { "N/A" }
                    $md += "| $settingId | $value |"
                }
                $md += ""
            }
            
            # Add collapsible raw JSON
            $md += "<details>"
            $md += "<summary>View Raw Settings JSON</summary>"
            $md += ""
            $md += "``````json"
            $md += ($profile.detailedSettings | ConvertTo-Json -Depth 15)
            $md += "``````"
            $md += "</details>"
            $md += ""
        }
    } else {
        $md += "*No settings found for this profile.*"
        $md += ""
    }
    
    # Raw Profile Data
    $md += "## Raw Profile Data"
    $md += ""
    $md += "``````json"
    $profileCopy = $profile | Select-Object -Property * -ExcludeProperty detailedSettings
    $md += ($profileCopy | ConvertTo-Json -Depth 20)
    $md += "``````"
    $md += ""
    
    # Collection metadata
    $md += "---"
    $md += ""
    $md += "*Collected: $collectionDate by $collectedBy*"
    
    # Write MD file
    $md -join "`n" | Out-File -LiteralPath $mdFilePath -Encoding UTF8
    
    # Track for README
    $exportedFiles += [PSCustomObject]@{
        Name = $name
        FileName = $mdFileName
        Type = $profileType
        Id = $profileId
        Created = $createdDate
        Modified = $modifiedDate
    }
}

Write-Host "  ✓ Exported $($exportedFiles.Count) profile files" -ForegroundColor Green

# Create README.md index
Write-Host ""
Write-Host "  Creating README.md index..." -ForegroundColor Gray

$readme = @()
$readme += "# Intune Configuration Profiles Export"
$readme += ""
$readme += "## Collection Information"
$readme += ""
$readme += "| Property | Value |"
$readme += "|----------|-------|"
$readme += "| **Collected By** | $collectedBy |"
$readme += "| **Collection Date** | $collectionDate |"
$readme += "| **Collection Method** | Microsoft Graph API (PowerShell) |"
$readme += "| **Script** | Get-IntuneProfilesByName.ps1 |"
$readme += "| **Profiles Collected** | $($exportedFiles.Count) |"
$readme += ""
$readme += "## Search Patterns Used"
$readme += ""
$readme += "``````"
$ProfileNamesArray | ForEach-Object { $readme += $_ }
$readme += "``````"
$readme += ""
$readme += "## Profiles Collected"
$readme += ""
$readme += "| Profile Name | Type | Created | Modified | Link |"
$readme += "|--------------|------|---------|----------|------|"

foreach ($file in ($exportedFiles | Sort-Object Name)) {
    $linkName = $file.Name -replace '\|', '\|'
    $readme += "| $linkName | $($file.Type) | $($file.Created) | $($file.Modified) | [$($file.FileName)]($($file.FileName)) |"
}

$readme += ""
$readme += "## API Endpoints Queried"
$readme += ""
$readme += "- ``https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations`` - Legacy device configurations"
$readme += "- ``https://graph.microsoft.com/beta/deviceManagement/configurationPolicies`` - Settings Catalog policies"
$readme += "- ``https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations`` - Administrative Templates (ADMX)"
$readme += "- ``https://graph.microsoft.com/beta/deviceManagement/intents`` - Endpoint Security policies"
$readme += "- ``https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/{id}/settings`` - Settings Catalog settings"
$readme += "- ``https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/{id}/definitionValues`` - ADMX definition values"
$readme += "- ``https://graph.microsoft.com/beta/deviceManagement/intents/{id}/settings`` - Endpoint Security settings"
$readme += ""
$readme += "## Permissions Required"
$readme += ""
$readme += "- ``DeviceManagementConfiguration.Read.All``"
$readme += ""
$readme += "---"
$readme += ""
$readme += "*Generated automatically by Intune-ition.ps1*"

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
Write-Host "  - $($exportedFiles.Count) profile Markdown files" -ForegroundColor Gray
Write-Host "  - README.md index file" -ForegroundColor Gray
Write-Host ""

# Show appreciation call-to-action
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   Found Intune-ition helpful?" -ForegroundColor Yellow
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
Write-Host "Thank you for using Intune-ition! " -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
