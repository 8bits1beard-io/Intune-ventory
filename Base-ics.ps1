<#
.SYNOPSIS
    [IN DEVELOPMENT - NOT READY FOR USE]
    Export Intune Endpoint Security Security Baselines to individual Markdown files.

.DESCRIPTION
    ** THIS SCRIPT IS CURRENTLY IN DEVELOPMENT AND NOT READY FOR PRODUCTION USE **
    
    Authenticates to Microsoft Graph, retrieves all Security Baseline templates,
    finds deployed baseline instances, collects full details including settings
    and assignments, and exports each baseline to its own Markdown file.
    Creates a README.md index with links to all exported baselines.

.PARAMETER BaselineNames
    Comma-separated list of baseline display names to search for (supports wildcards).
    Example: "Windows*,Edge*,Defender*"

.PARAMETER CsvFile
    Path to CSV file containing baseline names.

.PARAMETER CsvColumn
    Column name in CSV containing baseline names (default: "BaselineName").

.PARAMETER OutputPath
    Required. Output directory for Markdown files. Will be created if it doesn't exist.

.PARAMETER All
    Export all security baselines in the tenant (ignores baseline name filtering).

.EXAMPLE
    .\Base-ics.ps1 -All -OutputPath "C:\Exports\SecurityBaselines"
    Exports every security baseline in the Intune tenant.

.EXAMPLE
    .\Base-ics.ps1 -OutputPath "C:\Exports\2026-02"
    Prompts for baseline names, then exports to the specified folder.

.EXAMPLE
    .\Base-ics.ps1 -BaselineNames "Windows*,Defender*" -OutputPath ".\Exports"
    Exports baselines matching the specified name patterns.

.EXAMPLE
    .\Base-ics.ps1 -CsvFile "baselines.csv" -CsvColumn "Name" -OutputPath "C:\Exports"
    Exports baselines listed in CSV.

.NOTES
    File Name      : Base-ics.ps1
    Author         : Joshua Walderbach (j0w03ow)
    Prerequisite   : Microsoft.Graph.Authentication PowerShell module
    Requires       : PowerShell 5.1 or higher
                     DeviceManagementConfiguration.Read.All permission
    Version        : 1.0.0
    Date           : 2025-02-17

.LINK
    https://learn.microsoft.com/en-us/graph/api/resources/intune-deviceintent-securitybaselinetemplate

.OUTPUTS
    Individual Markdown files for each security baseline and a README.md index file.
#>
[CmdletBinding(DefaultParameterSetName='Default')]
param(
    [Parameter(ParameterSetName='Names')]
    [string]$BaselineNames,

    [Parameter(ParameterSetName='Csv', Mandatory=$true)]
    [string]$CsvFile,

    [Parameter(ParameterSetName='Csv')]
    [string]$CsvColumn = "BaselineName",

    [Parameter(ParameterSetName='All')]
    [switch]$All,

    [Parameter(Mandatory=$true)]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

# ============================================================================
# DEVELOPMENT NOTICE - Script is not ready for production use
# ============================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Red
Write-Host "  BASE-ICS.PS1 IS CURRENTLY IN DEVELOPMENT" -ForegroundColor Red
Write-Host "  This script is not ready for production use." -ForegroundColor Yellow
Write-Host "  Please check back later for updates." -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Red
Write-Host ""
exit 0
# ============================================================================

# Handle -All parameter
if ($All) {
    $BaselineNamesArray = @('*')
    Write-Host "" 
    Write-Host "Exporting ALL security baselines in the tenant..." -ForegroundColor Yellow
}
# Parse baseline names based on input method
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

        $BaselineNamesArray = $csvData | ForEach-Object { $_.$CsvColumn } | Where-Object { $_ -and $_.Trim() -ne '' }
    } catch {
        Write-Error "Failed to import CSV: $_"
        exit 1
    }
} elseif ($BaselineNames) {
    # Parse comma-separated string
    $BaselineNamesArray = $BaselineNames -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
} else {
    # Prompt for baseline names
    Write-Host ""
    Write-Host "No baseline names provided." -ForegroundColor Yellow
    Write-Host "Enter baseline names (comma-separated, wildcards supported):" -ForegroundColor Cyan
    Write-Host "Example: Windows*,Defender*,Edge*" -ForegroundColor Gray
    Write-Host ""
    $inputNames = Read-Host "Baseline names"
    
    if (-not $inputNames -or $inputNames.Trim() -eq '') {
        Write-Error "No baseline names entered. Exiting."
        exit 1
    }
    
    $BaselineNamesArray = $inputNames -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
}

if (-not $BaselineNamesArray -or $BaselineNamesArray.Count -eq 0) {
    Write-Error "No baseline names provided. Use -BaselineNames, -CsvFile, or -All"
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

Write-Host "=== Intune Security Baseline Export (Base-ics) ===" -ForegroundColor Cyan
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
$script:templateCache = @{}

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

# Helper function to do flexible template name matching
# Handles cases like "Microsoft Defender for Endpoint Security Baseline" matching "Microsoft Defender for Endpoint baseline"
function Test-TemplateNameMatch {
    param(
        [string]$TemplateName,
        [string]$Pattern
    )
    
    if (-not $TemplateName -or -not $Pattern) { return $false }
    
    # First try standard -like matching (handles wildcards)
    if ($TemplateName -like $Pattern) { return $true }
    
    # Normalize both strings for comparison:
    # - Remove "Security " prefix/infix 
    # - Make case-insensitive comparison
    $normalizedTemplate = $TemplateName -replace '\s*Security\s*', ' ' -replace '\s+', ' '
    $normalizedPattern = $Pattern -replace '\s*Security\s*', ' ' -replace '\s+', ' '
    
    # Try matching with normalized names
    if ($normalizedTemplate -like $normalizedPattern) { return $true }
    
    # Also try if pattern (without wildcards) is contained in template name
    $cleanPattern = $Pattern.Trim('*')
    if ($cleanPattern -and $TemplateName -like "*$cleanPattern*") { return $true }
    
    return $false
}

# Search for security baselines
Write-Host ""
Write-Host "[3/5] Searching for security baselines..." -ForegroundColor Yellow
if (-not $All) {
    Write-Host "  Baseline name patterns:" -ForegroundColor Gray
    $BaselineNamesArray | ForEach-Object { Write-Host "    - $_" -ForegroundColor Gray }
}

$allBaselines = @()
$foundBaselines = @()

# First, get all available Security Baseline templates (legacy intents)
Write-Host ""
Write-Host "  Querying Security Baseline templates (legacy)..." -ForegroundColor Gray
$templatesUri = "https://graph.microsoft.com/beta/deviceManagement/templates?`$filter=(isof(%27microsoft.graph.securityBaselineTemplate%27))"
$templates = Invoke-GraphRequestWithPaging -Uri $templatesUri

if ($templates -and $templates.Count -gt 0) {
    Write-Host "    Found $($templates.Count) legacy security baseline templates" -ForegroundColor Gray
    foreach ($template in $templates) {
        $script:templateCache[$template.id] = $template
    }
} else {
    Write-Host "    No legacy security baseline templates found" -ForegroundColor Gray
}

# Get ALL Configuration Policy Templates (including Baselines like HoloLens, Defender for Endpoint, etc.)
Write-Host "  Querying Configuration Policy Templates (all baselines)..." -ForegroundColor Gray
$configTemplatesUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicyTemplates?`$top=500&`$filter=(lifecycleState%20eq%20%27draft%27%20or%20lifecycleState%20eq%20%27superseded%27%20or%20lifecycleState%20eq%20%27active%27)"
$allConfigTemplates = @()
try {
    $allConfigTemplates = Invoke-GraphRequestWithPaging -Uri $configTemplatesUri
    if ($allConfigTemplates -and $allConfigTemplates.Count -gt 0) {
        # Filter for baseline templates specifically
        $baselineTemplates = $allConfigTemplates | Where-Object { $_.templateFamily -eq 'Baseline' }
        Write-Host "    Found $($allConfigTemplates.Count) total templates ($($baselineTemplates.Count) are Baseline family)" -ForegroundColor Gray
        foreach ($template in $allConfigTemplates) {
            $script:templateCache["config_$($template.id)"] = $template
        }
    }
} catch {
    Write-Host "    Note: Could not query configuration policy templates: $_" -ForegroundColor Gray
}

# Check if user is searching by TEMPLATE NAME (e.g., "Advanced Security Baseline for HoloLens 2")
# If so, we need to find policies deployed from that template
$matchingTemplateIds = @()
foreach ($pattern in $BaselineNamesArray) {
    # Search in legacy templates
    $matchedLegacy = $templates | Where-Object { $_.displayName -like $pattern }
    if ($matchedLegacy) {
        $matchingTemplateIds += $matchedLegacy | ForEach-Object { $_.id }
        Write-Host "    Matched legacy template: $($matchedLegacy.displayName -join ', ')" -ForegroundColor Cyan
    }
    
    # Search in configuration policy templates
    $matchedConfig = $allConfigTemplates | Where-Object { $_.displayName -like $pattern }
    if ($matchedConfig) {
        foreach ($t in $matchedConfig) {
            $matchingTemplateIds += $t.id
            # Also add versioned IDs (templateId_version format)
            $matchingTemplateIds += "$($t.id)_1"
            $matchingTemplateIds += "$($t.id)_2"
            $matchingTemplateIds += "$($t.id)_3"
            if ($t.baseId) {
                $matchingTemplateIds += $t.baseId
                $matchingTemplateIds += "$($t.baseId)_1"
                $matchingTemplateIds += "$($t.baseId)_2"
            }
        }
        Write-Host "    Matched config template: $($matchedConfig.displayName -join ', ')" -ForegroundColor Cyan
    }
}

# Get deployed Security Baseline instances (intents based on security baseline templates)
Write-Host "  Querying deployed Security Baseline instances..." -ForegroundColor Gray
$intentsUri = 'https://graph.microsoft.com/beta/deviceManagement/intents?$top=999'
$allIntents = Invoke-GraphRequestWithPaging -Uri $intentsUri

if ($allIntents -and $allIntents.Count -gt 0) {
    Write-Host "    Found $($allIntents.Count) total intents" -ForegroundColor Gray
    
    # Search by name pattern OR by matching template ID OR by template display name
    foreach ($pattern in $BaselineNamesArray) {
        # Match by display name OR by template display name
        $matches = $allIntents | Where-Object { 
            $_.displayName -like $pattern -or
            ($_.templateId -and $script:templateCache.ContainsKey($_.templateId) -and 
             $script:templateCache[$_.templateId].displayName -like $pattern)
        }
        if ($matches) {
            foreach ($match in $matches) {
                if ($foundBaselines.id -notcontains $match.id) {
                    if ($match.templateId -and $script:templateCache.ContainsKey($match.templateId)) {
                        $match | Add-Member -NotePropertyName 'baselineSource' -NotePropertyValue 'intent' -Force
                        $templateInfo = $script:templateCache[$match.templateId]
                        $match | Add-Member -NotePropertyName 'templateInfo' -NotePropertyValue $templateInfo -Force
                    } else {
                        $match | Add-Member -NotePropertyName 'baselineSource' -NotePropertyValue 'endpointSecurityIntent' -Force
                        if ($match.templateId) {
                            try {
                                $templateUri = "https://graph.microsoft.com/beta/deviceManagement/templates('$($match.templateId)')"
                                $templateInfo = Invoke-MgGraphRequest -Uri $templateUri -Method GET
                                $match | Add-Member -NotePropertyName 'templateInfo' -NotePropertyValue $templateInfo -Force
                            } catch { }
                        }
                    }
                    $foundBaselines += $match
                }
            }
        }
    }
    
    # Also match by template ID (if user searched by template name)
    if ($matchingTemplateIds.Count -gt 0) {
        $templateMatches = $allIntents | Where-Object { $matchingTemplateIds -contains $_.templateId }
        foreach ($match in $templateMatches) {
            if ($foundBaselines.id -notcontains $match.id) {
                $match | Add-Member -NotePropertyName 'baselineSource' -NotePropertyValue 'intent' -Force
                if ($match.templateId -and $script:templateCache.ContainsKey($match.templateId)) {
                    $templateInfo = $script:templateCache[$match.templateId]
                    $match | Add-Member -NotePropertyName 'templateInfo' -NotePropertyValue $templateInfo -Force
                }
                $foundBaselines += $match
            }
        }
    }
    
    $securityBaselineCount = ($allIntents | Where-Object { 
        $_.templateId -and $script:templateCache.ContainsKey($_.templateId)
    }).Count
    Write-Host "    ($securityBaselineCount are security baseline template instances)" -ForegroundColor Gray
}

# Also check Settings Catalog policies that are based on security templates
Write-Host "  Querying Settings Catalog security policies..." -ForegroundColor Gray
$catalogUri = 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$top=999&$expand=settings'
$catalogPolicies = Invoke-GraphRequestWithPaging -Uri $catalogUri

if ($catalogPolicies -and $catalogPolicies.Count -gt 0) {
    Write-Host "    Found $($catalogPolicies.Count) total Settings Catalog policies" -ForegroundColor Gray
    
    # When searching by name, search ALL policies (not just security-filtered ones)
    foreach ($pattern in $BaselineNamesArray) {
        $nameMatches = $catalogPolicies | Where-Object { 
            $_.name -like $pattern -or $_.displayName -like $pattern 
        }
        if ($nameMatches) {
            foreach ($match in $nameMatches) {
                if ($foundBaselines.id -notcontains $match.id) {
                    $match | Add-Member -NotePropertyName 'baselineSource' -NotePropertyValue 'configurationPolicy' -Force
                    $foundBaselines += $match
                }
            }
        }
    }
    
    # Also search by template ID (if user searched by template name like "Microsoft Defender for Endpoint Security Baseline")
    if ($matchingTemplateIds.Count -gt 0) {
        Write-Host "    Searching for policies using template IDs: $($matchingTemplateIds.Count) templates" -ForegroundColor Gray
        $templateMatches = $catalogPolicies | Where-Object { 
            $_.templateReference -and (
                $matchingTemplateIds -contains $_.templateReference.templateId -or
                $matchingTemplateIds -contains ($_.templateReference.templateId -replace '_\d+$', '')
            )
        }
        if ($templateMatches) {
            Write-Host "    Found $(@($templateMatches).Count) policies matching template IDs" -ForegroundColor Cyan
            foreach ($match in $templateMatches) {
                if ($foundBaselines.id -notcontains $match.id) {
                    $match | Add-Member -NotePropertyName 'baselineSource' -NotePropertyValue 'configurationPolicy' -Force
                    # Add template info from the matched template
                    foreach ($tid in $matchingTemplateIds) {
                        if ($script:templateCache.ContainsKey("config_$tid")) {
                            $match | Add-Member -NotePropertyName 'templateInfo' -NotePropertyValue $script:templateCache["config_$tid"] -Force
                            break
                        }
                    }
                    $foundBaselines += $match
                }
            }
        }
    }
    
    # Count security-related policies for logging
    $securityCatalogCount = ($catalogPolicies | Where-Object { 
        ($_.templateReference -and $_.templateReference.templateId) -or
        $_.technologies -match 'endpointSecurityConfiguration|mdm' -and (
            $_.name -match 'Security|Baseline|Defender|Firewall|Antivirus|BitLocker|Attack Surface|AppLocker|Credential|Exploit|SmartScreen|Windows Hello|Encryption' -or
            $_.templateReference.templateDisplayName -match 'Security|Baseline|Defender|Firewall|Antivirus|BitLocker|Attack Surface'
        )
    }).Count
    Write-Host "    ($securityCatalogCount are security-related)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "  ✓ Found $($foundBaselines.Count) matching security baselines" -ForegroundColor Green
if ($foundBaselines.Count -eq 0) {
    Write-Warning "No security baselines matched the provided names"
    Write-Host ""
    Write-Host "  Available intents ($($allIntents.Count) total):" -ForegroundColor Yellow
    $allIntents | ForEach-Object {
        $templateName = "unknown"
        if ($_.templateId -and $script:templateCache.ContainsKey($_.templateId)) {
            $templateName = $script:templateCache[$_.templateId].displayName
        }
        Write-Host "    - $($_.displayName) [Template: $templateName]" -ForegroundColor Gray
    }
    Write-Host ""
    
    # Show if we matched any templates
    if ($matchingTemplateIds.Count -gt 0) {
        Write-Host "  Matched template IDs (but no deployed policies found using these):" -ForegroundColor Yellow
        $matchingTemplateIds | Select-Object -Unique | Select-Object -First 5 | ForEach-Object {
            Write-Host "    - $_" -ForegroundColor Gray
        }
        Write-Host ""
        Write-Host "  NOTE: The template exists but no policies are deployed from it." -ForegroundColor Cyan
        Write-Host "  Try searching by the actual policy NAME instead, e.g.:" -ForegroundColor Cyan
        Write-Host "    -BaselineNames '*Endpoint*' or -BaselineNames 'WinD_*'" -ForegroundColor White
        Write-Host ""
        Write-Host "  Policies with templateReference (first 10):" -ForegroundColor Yellow
        $catalogPolicies | Where-Object { $_.templateReference -and $_.templateReference.templateId } | Select-Object -First 10 | ForEach-Object {
            Write-Host "    - $($_.name) [TemplateId: $($_.templateReference.templateId)]" -ForegroundColor Gray
        }
    } else {
        Write-Host "  Available Settings Catalog policies matching pattern (first 20):" -ForegroundColor Yellow
        $catalogPolicies | Where-Object { 
            $_.name -match 'Security|Baseline|HoloLens|Defender|Firewall' 
        } | Select-Object -First 20 | ForEach-Object {
            Write-Host "    - $($_.name)" -ForegroundColor Gray
        }
    }
    Write-Host ""
    Write-Host "  Tip: Use wildcards like '*HoloLens*' for partial matching" -ForegroundColor Cyan
    Disconnect-MgGraph | Out-Null
    exit 0
}

# Display found baselines
$foundBaselines | ForEach-Object {
    $name = if ($_.displayName) { $_.displayName } else { $_.name }
    $source = $_.baselineSource
    $templateName = if ($_.templateInfo) { $_.templateInfo.displayName } elseif ($_.templateReference) { $_.templateReference.templateDisplayName } else { "N/A" }
    Write-Host "    - $name [Template: $templateName] ($source)" -ForegroundColor Cyan
}

# Fetch assignments and settings for each baseline
Write-Host ""
Write-Host "[4/5] Collecting assignments and settings for each baseline..." -ForegroundColor Yellow

$totalBaselines = $foundBaselines.Count
$current = 0

foreach ($baseline in $foundBaselines) {
    $current++
    $name = if ($baseline.displayName) { $baseline.displayName } else { $baseline.name }
    Write-Host "  [$current/$totalBaselines] $name..." -ForegroundColor Gray

    # Fetch assignments based on baseline source
    $assignments = @()
    $assignmentsUri = switch ($baseline.baselineSource) {
        'intent' { "https://graph.microsoft.com/beta/deviceManagement/intents('$($baseline.id)')/assignments" }
        'endpointSecurityIntent' { "https://graph.microsoft.com/beta/deviceManagement/intents('$($baseline.id)')/assignments" }
        'configurationPolicy' { "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$($baseline.id)')/assignments" }
    }
    
    if ($assignmentsUri) {
        try {
            $assignmentsResponse = Invoke-MgGraphRequest -Uri $assignmentsUri -Method GET
            if ($assignmentsResponse.value) {
                $assignments = $assignmentsResponse.value
                
                # Resolve group names and filter names
                foreach ($assignment in $assignments) {
                    if ($assignment.target.groupId) {
                        $groupName = Get-GroupDisplayName -GroupId $assignment.target.groupId
                        $assignment.target | Add-Member -NotePropertyName 'groupName' -NotePropertyValue $groupName -Force
                    }
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
    $baseline | Add-Member -NotePropertyName 'assignments' -NotePropertyValue $assignments -Force

    # Fetch settings based on baseline source
    $settings = @()
    try {
        if ($baseline.baselineSource -eq 'intent' -or $baseline.baselineSource -eq 'endpointSecurityIntent') {
            # Intent-based - get settings with categories
            $settingsUri = "https://graph.microsoft.com/beta/deviceManagement/intents('$($baseline.id)')/settings"
            $settingsResponse = Invoke-MgGraphRequest -Uri $settingsUri -Method GET
            if ($settingsResponse.value) {
                $settings = $settingsResponse.value
            }
            
            # Also try to get categories for better organization
            try {
                $categoriesUri = "https://graph.microsoft.com/beta/deviceManagement/intents('$($baseline.id)')/categories"
                $categoriesResponse = Invoke-MgGraphRequest -Uri $categoriesUri -Method GET
                if ($categoriesResponse.value) {
                    $baseline | Add-Member -NotePropertyName 'categories' -NotePropertyValue $categoriesResponse.value -Force
                    
                    # Get settings per category
                    foreach ($category in $categoriesResponse.value) {
                        $catSettingsUri = "https://graph.microsoft.com/beta/deviceManagement/intents('$($baseline.id)')/categories('$($category.id)')/settings"
                        try {
                            $catSettingsResponse = Invoke-MgGraphRequest -Uri $catSettingsUri -Method GET
                            if ($catSettingsResponse.value) {
                                $category | Add-Member -NotePropertyName 'settings' -NotePropertyValue $catSettingsResponse.value -Force
                            }
                        } catch { }
                    }
                }
            } catch { }
            
            # Get device and user state summaries for deployment status
            try {
                $deviceSummaryUri = "https://graph.microsoft.com/beta/deviceManagement/intents('$($baseline.id)')/deviceStateSummary"
                $deviceSummary = Invoke-MgGraphRequest -Uri $deviceSummaryUri -Method GET
                $baseline | Add-Member -NotePropertyName 'deviceStateSummary' -NotePropertyValue $deviceSummary -Force
            } catch { }
            
            try {
                $userSummaryUri = "https://graph.microsoft.com/beta/deviceManagement/intents('$($baseline.id)')/userStateSummary"
                $userSummary = Invoke-MgGraphRequest -Uri $userSummaryUri -Method GET
                $baseline | Add-Member -NotePropertyName 'userStateSummary' -NotePropertyValue $userSummary -Force
            } catch { }
            
        } elseif ($baseline.baselineSource -eq 'configurationPolicy') {
            # Settings Catalog based
            $settingsUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$($baseline.id)')/settings?`$expand=settingDefinitions&`$top=1000"
            $settingsResponse = Invoke-MgGraphRequest -Uri $settingsUri -Method GET
            if ($settingsResponse.value) {
                $settings = $settingsResponse.value
            }
        }
    } catch {
        Write-Warning "    Failed to get settings: $_"
    }
    $baseline | Add-Member -NotePropertyName 'detailedSettings' -NotePropertyValue $settings -Force
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

# Helper function to format baseline type
function Get-BaselineTypeName {
    param(
        [object]$Baseline
    )
    
    # Check if we have template info
    if ($Baseline.templateInfo) {
        $templateName = $Baseline.templateInfo.displayName
        switch -Wildcard ($templateName) {
            "*Windows*Security*" { return "Windows Security Baseline" }
            "*Edge*" { return "Microsoft Edge Security Baseline" }
            "*Defender*Antivirus*" { return "Microsoft Defender Antivirus" }
            "*Defender*Firewall*" { return "Windows Defender Firewall" }
            "*Defender*ATP*" { return "Microsoft Defender for Endpoint" }
            "*BitLocker*" { return "BitLocker Encryption" }
            "*Attack Surface*" { return "Attack Surface Reduction" }
            "*Account Protection*" { return "Account Protection" }
            "*Device Control*" { return "Device Control" }
            "*Windows*LAPS*" { return "Windows LAPS" }
            default { return $templateName }
        }
    }
    
    # Check template reference for Settings Catalog policies
    if ($Baseline.templateReference -and $Baseline.templateReference.templateDisplayName) {
        return $Baseline.templateReference.templateDisplayName
    }
    
    # Fall back to source type
    switch ($Baseline.baselineSource) {
        'intent' { return "Security Baseline (Intent)" }
        'endpointSecurityIntent' { return "Endpoint Security Policy" }
        'configurationPolicy' { return "Security Policy (Settings Catalog)" }
        default { return "Security Baseline" }
    }
}

# Export each baseline to its own MD file
$totalBaselines = $foundBaselines.Count
$current = 0

foreach ($baseline in $foundBaselines) {
    $current++
    $name = if ($baseline.displayName) { $baseline.displayName } else { $baseline.name }
    $safeFileName = Get-SafeFileName -Name $name
    $mdFileName = "$safeFileName.md"
    $mdFilePath = Join-Path $exportFolder $mdFileName
    
    Write-Host "  [$current/$totalBaselines] $name..." -ForegroundColor Gray
    
    $baselineType = Get-BaselineTypeName -Baseline $baseline
    $baselineId = $baseline.id
    $createdDate = if ($baseline.createdDateTime) { $baseline.createdDateTime } else { "N/A" }
    $modifiedDate = if ($baseline.lastModifiedDateTime) { $baseline.lastModifiedDateTime } else { "N/A" }
    
    # Build Markdown content
    $md = @()
    $md += "# $name"
    $md += ""
    $md += "## Baseline Information"
    $md += ""
    $md += "| Property | Value |"
    $md += "|----------|-------|"
    $md += "| **Name** | $name |"
    $md += "| **Type** | $baselineType |"
    $md += "| **Baseline ID** | ``$baselineId`` |"
    if ($baseline.templateId) { $md += "| **Template ID** | ``$($baseline.templateId)`` |" }
    if ($baseline.templateInfo) { 
        $md += "| **Template Name** | $($baseline.templateInfo.displayName) |" 
        if ($baseline.templateInfo.versionInfo) {
            $md += "| **Template Version** | $($baseline.templateInfo.versionInfo) |"
        }
    }
    if ($baseline.templateReference -and $baseline.templateReference.templateDisplayName) {
        $md += "| **Template Name** | $($baseline.templateReference.templateDisplayName) |"
        if ($baseline.templateReference.templateDisplayVersion) {
            $md += "| **Template Version** | $($baseline.templateReference.templateDisplayVersion) |"
        }
    }
    $md += "| **Created** | $createdDate |"
    $md += "| **Last Modified** | $modifiedDate |"
    $md += "| **Source** | $($baseline.baselineSource) |"
    if ($baseline.isAssigned -ne $null) { $md += "| **Is Assigned** | $($baseline.isAssigned) |" }
    $md += ""
    
    # Description if available
    if ($baseline.description) {
        $md += "## Description"
        $md += ""
        $md += $baseline.description
        $md += ""
    }
    
    # Scope Tags if available
    if ($baseline.roleScopeTagIds -and $baseline.roleScopeTagIds.Count -gt 0) {
        $md += "## Scope Tags"
        $md += ""
        $md += "- " + ($baseline.roleScopeTagIds -join "`n- ")
        $md += ""
    }
    
    # Assignments
    if ($baseline.assignments -and $baseline.assignments.Count -gt 0) {
        $md += "## Assignments"
        $md += ""
        $md += "| Target Type | Group Name | Filter |"
        $md += "|-------------|------------|--------|"
        foreach ($assignment in $baseline.assignments) {
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
    
    # Deployment Status (for intent-based baselines)
    if ($baseline.deviceStateSummary -or $baseline.userStateSummary) {
        $md += "## Deployment Status"
        $md += ""
        
        if ($baseline.deviceStateSummary) {
            $ds = $baseline.deviceStateSummary
            $md += "### Device State Summary"
            $md += ""
            $md += "| Status | Count |"
            $md += "|--------|-------|"
            if ($ds.successCount -ne $null) { $md += "| ✅ Success | $($ds.successCount) |" }
            if ($ds.errorCount -ne $null) { $md += "| ❌ Error | $($ds.errorCount) |" }
            if ($ds.conflictCount -ne $null) { $md += "| ⚠️ Conflict | $($ds.conflictCount) |" }
            if ($ds.notApplicableCount -ne $null) { $md += "| ➖ Not Applicable | $($ds.notApplicableCount) |" }
            if ($ds.notApplicablePlatformCount -ne $null) { $md += "| ➖ Not Applicable (Platform) | $($ds.notApplicablePlatformCount) |" }
            if ($ds.inGracePeriodCount -ne $null) { $md += "| ⏳ In Grace Period | $($ds.inGracePeriodCount) |" }
            $md += ""
        }
        
        if ($baseline.userStateSummary) {
            $us = $baseline.userStateSummary
            $md += "### User State Summary"
            $md += ""
            $md += "| Status | Count |"
            $md += "|--------|-------|"
            if ($us.successCount -ne $null) { $md += "| ✅ Success | $($us.successCount) |" }
            if ($us.errorCount -ne $null) { $md += "| ❌ Error | $($us.errorCount) |" }
            if ($us.conflictCount -ne $null) { $md += "| ⚠️ Conflict | $($us.conflictCount) |" }
            if ($us.notApplicableCount -ne $null) { $md += "| ➖ Not Applicable | $($us.notApplicableCount) |" }
            $md += ""
        }
    }
    
    # Settings
    $md += "## Settings"
    $md += ""
    
    # Check if we have category-organized settings (intent-based)
    if ($baseline.categories -and $baseline.categories.Count -gt 0) {
        foreach ($category in $baseline.categories) {
            $md += "### $($category.displayName)"
            $md += ""
            
            if ($category.settings -and $category.settings.Count -gt 0) {
                $md += "| Setting | Value |"
                $md += "|---------|-------|"
                
                foreach ($setting in $category.settings) {
                    $settingId = $setting.definitionId -replace '.*/deviceManagement/', '' -replace '.*/deviceConfiguration/', ''
                    $settingId = $settingId -replace '.*/', ''
                    $value = if ($setting.value -ne $null) { 
                        if ($setting.value -is [array]) { $setting.value -join ", " } 
                        elseif ($setting.value -is [bool]) { if ($setting.value) { "Enabled" } else { "Disabled" } }
                        else { "$($setting.value)" }
                    } elseif ($setting.valueJson) {
                        $setting.valueJson
                    } else { "N/A" }
                    
                    # Truncate long values
                    if ($value.Length -gt 100) { $value = $value.Substring(0, 97) + "..." }
                    
                    $md += "| $settingId | $value |"
                }
                $md += ""
            } else {
                $md += "*No settings in this category*"
                $md += ""
            }
        }
    }
    # Display settings without categories
    elseif ($baseline.detailedSettings -and $baseline.detailedSettings.Count -gt 0) {
        
        if ($baseline.baselineSource -eq 'configurationPolicy') {
            # Settings Catalog format
            $md += "| Setting | Configured Value | Description |"
            $md += "|---------|------------------|-------------|"
            
            foreach ($setting in $baseline.detailedSettings) {
                $settingDef = $setting.settingDefinitions | Select-Object -First 1
                $settingName = if ($settingDef.displayName) { $settingDef.displayName } else { $settingDef.id -replace '.*/', '' }
                $description = if ($settingDef.description) { 
                    $desc = ($settingDef.description -split "`n")[0] -replace '\|', '-'
                    if ($desc.Length -gt 80) { $desc.Substring(0, 77) + "..." } else { $desc }
                } else { "" }
                
                # Get configured value
                $configuredValue = "N/A"
                $inst = $setting.settingInstance
                if ($inst.choiceSettingValue) {
                    $selectedOption = $settingDef.options | Where-Object { $_.itemId -eq $inst.choiceSettingValue.value } | Select-Object -First 1
                    $configuredValue = if ($selectedOption.displayName) { $selectedOption.displayName } else { $inst.choiceSettingValue.value -replace '.*_', '' }
                } elseif ($inst.simpleSettingValue) {
                    $configuredValue = "$($inst.simpleSettingValue.value)"
                } elseif ($inst.simpleSettingCollectionValue) {
                    $configuredValue = ($inst.simpleSettingCollectionValue.value -join ", ")
                } elseif ($inst.groupSettingCollectionValue) {
                    $configuredValue = "(Group settings - see JSON)"
                }
                
                if ($configuredValue.Length -gt 60) { $configuredValue = $configuredValue.Substring(0, 57) + "..." }
                
                $md += "| $settingName | $configuredValue | $description |"
            }
            $md += ""
            
        } else {
            # Intent-based format (flat list)
            $md += "| Setting ID | Value |"
            $md += "|------------|-------|"
            
            foreach ($setting in $baseline.detailedSettings) {
                $settingId = $setting.definitionId -replace '.*/', ''
                $value = if ($setting.value -ne $null) { 
                    if ($setting.value -is [array]) { $setting.value -join ", " } 
                    elseif ($setting.value -is [bool]) { if ($setting.value) { "Enabled" } else { "Disabled" } }
                    else { "$($setting.value)" }
                } elseif ($setting.valueJson) {
                    $setting.valueJson
                } else { "N/A" }
                
                if ($value.Length -gt 100) { $value = $value.Substring(0, 97) + "..." }
                
                $md += "| $settingId | $value |"
            }
            $md += ""
        }
        
        # Add collapsible raw JSON
        $md += "<details>"
        $md += "<summary>View Raw Settings JSON</summary>"
        $md += ""
        $md += "``````json"
        $md += ($baseline.detailedSettings | ConvertTo-Json -Depth 15)
        $md += "``````"
        $md += "</details>"
        $md += ""
    } else {
        $md += "*No settings found for this baseline.*"
        $md += ""
    }
    
    # Template Information (if available)
    if ($baseline.templateInfo) {
        $md += "## Template Information"
        $md += ""
        $md += "| Property | Value |"
        $md += "|----------|-------|"
        $md += "| **Template Name** | $($baseline.templateInfo.displayName) |"
        $md += "| **Template ID** | ``$($baseline.templateInfo.id)`` |"
        if ($baseline.templateInfo.description) { $md += "| **Description** | $($baseline.templateInfo.description) |" }
        if ($baseline.templateInfo.platformType) { $md += "| **Platform** | $($baseline.templateInfo.platformType) |" }
        if ($baseline.templateInfo.templateType) { $md += "| **Template Type** | $($baseline.templateInfo.templateType) |" }
        if ($baseline.templateInfo.versionInfo) { $md += "| **Version** | $($baseline.templateInfo.versionInfo) |" }
        if ($baseline.templateInfo.publishedDateTime) { $md += "| **Published** | $($baseline.templateInfo.publishedDateTime) |" }
        $md += ""
    }
    
    # Raw Baseline Data
    $md += "## Raw Baseline Data"
    $md += ""
    $md += "<details>"
    $md += "<summary>Click to expand JSON</summary>"
    $md += ""
    $md += "``````json"
    $baselineCopy = $baseline | Select-Object -Property * -ExcludeProperty detailedSettings, categories, templateInfo
    $md += ($baselineCopy | ConvertTo-Json -Depth 20)
    $md += "``````"
    $md += ""
    $md += "</details>"
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
        Type = $baselineType
        TemplateName = if ($baseline.templateInfo) { $baseline.templateInfo.displayName } elseif ($baseline.templateReference) { $baseline.templateReference.templateDisplayName } else { "N/A" }
        FileName = $mdFileName
        Created = $createdDate
        Modified = $modifiedDate
    }
}

Write-Host "  ✓ Exported $($exportedFiles.Count) baseline files" -ForegroundColor Green

# Create README.md index
Write-Host ""
Write-Host "  Creating README.md index..." -ForegroundColor Gray

$readme = @()
$readme += "# Intune Security Baselines Export"
$readme += ""
$readme += "## Collection Information"
$readme += ""
$readme += "| Property | Value |"
$readme += "|----------|-------|"
$readme += "| **Collected By** | $collectedBy |"
$readme += "| **Collection Date** | $collectionDate |"
$readme += "| **Collection Method** | Microsoft Graph API (PowerShell) |"
$readme += "| **Script** | Base-ics.ps1 |"
$readme += "| **Baselines Collected** | $($exportedFiles.Count) |"
$readme += ""
$readme += "## Search Patterns Used"
$readme += ""
$readme += "``````"
$BaselineNamesArray | ForEach-Object { $readme += $_ }
$readme += "``````"
$readme += ""
$readme += "## Security Baselines Collected"
$readme += ""
$readme += "| Baseline Name | Type | Template | Created | Modified | Link |"
$readme += "|---------------|------|----------|---------|----------|------|"

foreach ($file in ($exportedFiles | Sort-Object Name)) {
    $linkName = $file.Name -replace '\|', '\|'
    $readme += "| $linkName | $($file.Type) | $($file.TemplateName) | $($file.Created) | $($file.Modified) | [$($file.FileName)]($($file.FileName)) |"
}

$readme += ""
$readme += "## API Endpoints Queried"
$readme += ""
$readme += "- ``https://graph.microsoft.com/beta/deviceManagement/templates?`$filter=(isof('microsoft.graph.securityBaselineTemplate'))`` - Security baseline templates"
$readme += "- ``https://graph.microsoft.com/beta/deviceManagement/configurationPolicyTemplates`` - Configuration policy templates (Settings Catalog)"
$readme += "- ``https://graph.microsoft.com/beta/deviceManagement/intents`` - Deployed baseline instances"
$readme += "- ``https://graph.microsoft.com/beta/deviceManagement/configurationPolicies`` - Settings Catalog security policies"
$readme += "- ``https://graph.microsoft.com/beta/deviceManagement/intents/{id}/settings`` - Baseline settings"
$readme += "- ``https://graph.microsoft.com/beta/deviceManagement/intents/{id}/categories`` - Baseline setting categories"
$readme += "- ``https://graph.microsoft.com/beta/deviceManagement/intents/{id}/assignments`` - Baseline assignments"
$readme += ""
$readme += "## Permissions Required"
$readme += ""
$readme += "- ``DeviceManagementConfiguration.Read.All``"
$readme += ""
$readme += "## Security Baseline Types"
$readme += ""
$readme += "This script collects the following types of security baselines:"
$readme += ""
$readme += "- **Windows Security Baseline** - Microsoft's recommended security settings for Windows"
$readme += "- **Microsoft Edge Security Baseline** - Security settings for Microsoft Edge browser"
$readme += "- **Microsoft Defender Antivirus** - Antivirus protection policies"
$readme += "- **Windows Defender Firewall** - Firewall rules and settings"
$readme += "- **Microsoft Defender for Endpoint** - Advanced threat protection settings"
$readme += "- **BitLocker Encryption** - Disk encryption policies"
$readme += "- **Attack Surface Reduction** - ASR rules and exploit protection"
$readme += "- **Account Protection** - Credential guard and account policies"
$readme += ""
$readme += "---"
$readme += ""
$readme += "*Generated automatically by Base-ics.ps1*"

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
Write-Host "  - $($exportedFiles.Count) baseline Markdown files" -ForegroundColor Gray
Write-Host "  - README.md index file" -ForegroundColor Gray
Write-Host ""

# Show appreciation call-to-action
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   Found Base-ics helpful?" -ForegroundColor Yellow
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
Write-Host "Thank you for using Base-ics! " -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
