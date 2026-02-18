<#
.SYNOPSIS
    Export Intune applications by name to individual Markdown files.

.DESCRIPTION
    Authenticates to Microsoft Graph, searches for Intune applications
    matching provided names, collects full app details including assignments
    and deployment settings, and exports each app to its own Markdown file.
    Creates a README.md index with links to all exported applications.

.PARAMETER AppNames
    Comma-separated list of application display names to search for (supports wildcards).
    Example: "7-Zip*,Chrome*,Microsoft 365*"

.PARAMETER CsvFile
    Path to CSV file containing application names.

.PARAMETER CsvColumn
    Column name in CSV containing application names (default: "AppName").

.PARAMETER OutputPath
    Required. Output directory for Markdown files. Will be created if it doesn't exist.

.PARAMETER All
    Export all applications in the tenant (ignores app name filtering).

.PARAMETER Platform
    Filter by platform. Default is Windows only.
    Options: Windows, iOS, Android, macOS, All

.EXAMPLE
    .\App-rehension.ps1 -All -OutputPath "C:\Exports\AllApps"
    Exports every Windows application in the Intune tenant.

.EXAMPLE
    .\App-rehension.ps1 -OutputPath "C:\Exports\2026-02"
    Prompts for application names, then exports to the specified folder.

.EXAMPLE
    .\App-rehension.ps1 -AppNames "7-Zip*,Chrome*,*Office*" -OutputPath ".\Exports"
    Exports applications matching the specified name patterns.

.EXAMPLE
    .\App-rehension.ps1 -All -Platform All -OutputPath ".\AllPlatforms"
    Exports all applications across all platforms.

.NOTES
    File Name      : App-rehension.ps1
    Author         : Joshua Walderbach (j0w03ow)
    Prerequisite   : Microsoft.Graph.Authentication PowerShell module
    Requires       : PowerShell 5.1 or higher
                     DeviceManagementApps.Read.All permission
    Version        : 1.0.0
    Date           : 2025-02-17

.LINK
    https://learn.microsoft.com/en-us/graph/api/resources/intune-apps-mobileapp

.OUTPUTS
    Individual Markdown files for each application and a README.md index file.
#>
[CmdletBinding(DefaultParameterSetName='Default')]
param(
    [Parameter(ParameterSetName='Names')]
    [string]$AppNames,

    [Parameter(ParameterSetName='Csv', Mandatory=$true)]
    [string]$CsvFile,

    [Parameter(ParameterSetName='Csv')]
    [string]$CsvColumn = "AppName",

    [Parameter(ParameterSetName='All')]
    [switch]$All,

    [Parameter(Mandatory=$true)]
    [string]$OutputPath,

    [Parameter()]
    [ValidateSet('Windows', 'iOS', 'Android', 'macOS', 'All')]
    [string]$Platform = 'Windows'
)

$ErrorActionPreference = 'Stop'

# Handle -All parameter
if ($All) {
    $AppNamesArray = @('*')
    Write-Host "" 
    Write-Host "Exporting ALL applications in the tenant..." -ForegroundColor Yellow
}
# Parse app names based on input method
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

        $AppNamesArray = $csvData | ForEach-Object { $_.$CsvColumn } | Where-Object { $_ -and $_.Trim() -ne '' }
    } catch {
        Write-Error "Failed to import CSV: $_"
        exit 1
    }
} elseif ($AppNames) {
    # Parse comma-separated string
    $AppNamesArray = $AppNames -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
} else {
    # Prompt for app names
    Write-Host ""
    Write-Host "No application names provided." -ForegroundColor Yellow
    Write-Host "Enter application names (comma-separated, wildcards supported):" -ForegroundColor Cyan
    Write-Host "Example: 7-Zip*,Chrome*,*Office*" -ForegroundColor Gray
    Write-Host ""
    $inputNames = Read-Host "Application names"
    
    if (-not $inputNames -or $inputNames.Trim() -eq '') {
        Write-Error "No application names entered. Exiting."
        exit 1
    }
    
    $AppNamesArray = $inputNames -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
}

if (-not $AppNamesArray -or $AppNamesArray.Count -eq 0) {
    Write-Error "No application names provided. Use -AppNames, -CsvFile, or -All"
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

Write-Host "=== Intune Application Export (App-rehension) ===" -ForegroundColor Cyan
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
    Connect-MgGraph -Scopes "DeviceManagementApps.Read.All" -NoWelcome -ErrorAction Stop
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

# Build platform filter for mobileApps query
function Get-PlatformFilter {
    param([string]$Platform)
    
    $windowsTypes = @(
        "#microsoft.graph.win32CatalogApp",
        "#microsoft.graph.windowsStoreApp",
        "#microsoft.graph.officeSuiteApp",
        "#microsoft.graph.windowsAutoUpdateCatalogApp",
        "#microsoft.graph.win32LobApp",
        "#microsoft.graph.windowsMicrosoftEdgeApp",
        "#microsoft.graph.windowsPhone81AppX",
        "#microsoft.graph.windowsPhone81StoreApp",
        "#microsoft.graph.windowsPhoneXAP",
        "#microsoft.graph.windowsAppX",
        "#microsoft.graph.windowsMobileMSI",
        "#microsoft.graph.windowsUniversalAppX",
        "#microsoft.graph.webApp",
        "#microsoft.graph.windowsWebApp",
        "#microsoft.graph.winGetApp"
    )
    
    $iosTypes = @(
        "#microsoft.graph.iosStoreApp",
        "#microsoft.graph.iosVppApp",
        "#microsoft.graph.iosLobApp",
        "#microsoft.graph.managedIOSStoreApp",
        "#microsoft.graph.managedIOSLobApp"
    )
    
    $androidTypes = @(
        "#microsoft.graph.androidStoreApp",
        "#microsoft.graph.androidLobApp",
        "#microsoft.graph.androidManagedStoreApp",
        "#microsoft.graph.managedAndroidStoreApp",
        "#microsoft.graph.managedAndroidLobApp",
        "#microsoft.graph.androidForWorkApp"
    )
    
    $macosTypes = @(
        "#microsoft.graph.macOSLobApp",
        "#microsoft.graph.macOSMicrosoftEdgeApp",
        "#microsoft.graph.macOSOfficeSuiteApp",
        "#microsoft.graph.macOSMicrosoftDefenderApp",
        "#microsoft.graph.macOSDmgApp",
        "#microsoft.graph.macOSPkgApp"
    )
    
    switch ($Platform) {
        'Windows' { return $windowsTypes }
        'iOS' { return $iosTypes }
        'Android' { return $androidTypes }
        'macOS' { return $macosTypes }
        'All' { return $windowsTypes + $iosTypes + $androidTypes + $macosTypes }
    }
}

# Search for applications
Write-Host ""
Write-Host "[3/5] Searching for applications..." -ForegroundColor Yellow
Write-Host "  Platform: $Platform" -ForegroundColor Gray
if (-not $All) {
    Write-Host "  Application name patterns:" -ForegroundColor Gray
    $AppNamesArray | ForEach-Object { Write-Host "    - $_" -ForegroundColor Gray }
}

$allApps = @()
$foundApps = @()

# Build the filter for platform types
$platformTypes = Get-PlatformFilter -Platform $Platform

# Query apps - using simpler query without complex filter since pagination handles it
Write-Host ""
Write-Host "  Querying mobileApps..." -ForegroundColor Gray
$uri = 'https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?$top=999'
$apps = Invoke-GraphRequestWithPaging -Uri $uri

if ($apps -and $apps.Count -gt 0) {
    Write-Host "    Found $($apps.Count) total applications" -ForegroundColor Gray
    
    # Filter by platform type
    $platformFiltered = $apps | Where-Object { 
        $appType = $_.'@odata.type'
        $platformTypes -contains $appType
    }
    
    Write-Host "    $($platformFiltered.Count) applications match platform filter ($Platform)" -ForegroundColor Gray
    
    # Filter by name patterns
    foreach ($pattern in $AppNamesArray) {
        $matches = $platformFiltered | Where-Object { $_.displayName -like $pattern }
        if ($matches) {
            foreach ($match in $matches) {
                if ($foundApps.id -notcontains $match.id) {
                    $match | Add-Member -NotePropertyName 'appSource' -NotePropertyValue 'mobileApp' -Force
                    $foundApps += $match
                }
            }
        }
    }
}

Write-Host ""
Write-Host "  ✓ Found $($foundApps.Count) matching applications" -ForegroundColor Green
if ($foundApps.Count -eq 0) {
    Write-Warning "No applications matched the provided names"
    Disconnect-MgGraph | Out-Null
    exit 0
}

# Display found apps
$foundApps | ForEach-Object {
    $type = $_.'@odata.type' -replace '#microsoft.graph.', ''
    Write-Host "    - $($_.displayName) ($type)" -ForegroundColor Cyan
}

# Fetch assignments for each app
Write-Host ""
Write-Host "[4/5] Collecting assignments for each application..." -ForegroundColor Yellow

$totalApps = $foundApps.Count
$current = 0

foreach ($app in $foundApps) {
    $current++
    Write-Host "  [$current/$totalApps] $($app.displayName)..." -ForegroundColor Gray

    # Fetch assignments
    $assignments = @()
    $assignmentsUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$($app.id)')/assignments"
    
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
    $app | Add-Member -NotePropertyName 'assignments' -NotePropertyValue $assignments -Force
    
    # Fetch additional details for Win32 apps (detection rules, requirements, etc.)
    if ($app.'@odata.type' -match 'win32LobApp|win32CatalogApp') {
        try {
            $detailUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$($app.id)')"
            $appDetails = Invoke-MgGraphRequest -Uri $detailUri -Method GET
            
            # Add detection rules if available
            if ($appDetails.detectionRules) {
                $app | Add-Member -NotePropertyName 'detectionRules' -NotePropertyValue $appDetails.detectionRules -Force
            }
            if ($appDetails.requirementRules) {
                $app | Add-Member -NotePropertyName 'requirementRules' -NotePropertyValue $appDetails.requirementRules -Force
            }
            if ($appDetails.installCommandLine) {
                $app | Add-Member -NotePropertyName 'installCommandLine' -NotePropertyValue $appDetails.installCommandLine -Force
            }
            if ($appDetails.uninstallCommandLine) {
                $app | Add-Member -NotePropertyName 'uninstallCommandLine' -NotePropertyValue $appDetails.uninstallCommandLine -Force
            }
            if ($appDetails.installExperience) {
                $app | Add-Member -NotePropertyName 'installExperience' -NotePropertyValue $appDetails.installExperience -Force
            }
            if ($appDetails.returnCodes) {
                $app | Add-Member -NotePropertyName 'returnCodes' -NotePropertyValue $appDetails.returnCodes -Force
            }
            if ($appDetails.rules) {
                $app | Add-Member -NotePropertyName 'rules' -NotePropertyValue $appDetails.rules -Force
            }
        } catch {
            # Some details may not be available
        }
    }
    
    # Fetch content versions for LOB apps
    if ($app.'@odata.type' -match 'LobApp') {
        try {
            $contentUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps('$($app.id)')?`$select=committedContentVersion"
            $contentResponse = Invoke-MgGraphRequest -Uri $contentUri -Method GET
            if ($contentResponse.committedContentVersion) {
                $app | Add-Member -NotePropertyName 'committedContentVersion' -NotePropertyValue $contentResponse.committedContentVersion -Force
            }
        } catch {
            # Content version may not be available
        }
    }
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

# Helper function to format app type
function Get-AppTypeName {
    param([string]$ODataType)
    
    switch -Wildcard ($ODataType) {
        "*win32LobApp*" { "Win32 App (LOB)" }
        "*win32CatalogApp*" { "Win32 Catalog App" }
        "*winGetApp*" { "WinGet App (Store)" }
        "*windowsStoreApp*" { "Windows Store App" }
        "*windowsMicrosoftEdgeApp*" { "Microsoft Edge" }
        "*officeSuiteApp*" { "Microsoft 365 Apps" }
        "*windowsUniversalAppX*" { "Universal App (APPX/MSIX)" }
        "*windowsAppX*" { "AppX Package" }
        "*windowsMobileMSI*" { "MSI Package" }
        "*webApp*" { "Web App (Link)" }
        "*windowsWebApp*" { "Windows Web App" }
        "*iosStoreApp*" { "iOS Store App" }
        "*iosVppApp*" { "iOS VPP App" }
        "*iosLobApp*" { "iOS LOB App" }
        "*androidStoreApp*" { "Android Store App" }
        "*androidLobApp*" { "Android LOB App" }
        "*androidManagedStoreApp*" { "Android Managed Google Play" }
        "*macOSLobApp*" { "macOS LOB App" }
        "*macOSDmgApp*" { "macOS DMG App" }
        "*macOSPkgApp*" { "macOS PKG App" }
        "*macOSMicrosoftEdgeApp*" { "macOS Microsoft Edge" }
        "*macOSOfficeSuiteApp*" { "macOS Microsoft 365" }
        default { 
            if ($ODataType) {
                $ODataType -replace '#microsoft.graph.', '' -replace 'App$', ' App'
            } else {
                "Mobile App"
            }
        }
    }
}

# Export each app to its own MD file
$totalApps = $foundApps.Count
$current = 0

foreach ($app in $foundApps) {
    $current++
    $name = $app.displayName
    $safeFileName = Get-SafeFileName -Name $name
    $mdFileName = "$safeFileName.md"
    $mdFilePath = Join-Path $exportFolder $mdFileName
    
    Write-Host "  [$current/$totalApps] $name..." -ForegroundColor Gray
    
    $appType = Get-AppTypeName -ODataType $app.'@odata.type'
    $appId = $app.id
    $createdDate = if ($app.createdDateTime) { $app.createdDateTime } else { "N/A" }
    $modifiedDate = if ($app.lastModifiedDateTime) { $app.lastModifiedDateTime } else { "N/A" }
    
    # Build Markdown content
    $md = @()
    $md += "# $name"
    $md += ""
    $md += "## Application Information"
    $md += ""
    $md += "| Property | Value |"
    $md += "|----------|-------|"
    $md += "| **Name** | $name |"
    $md += "| **Type** | $appType |"
    $md += "| **App ID** | ``$appId`` |"
    if ($app.publisher) { $md += "| **Publisher** | $($app.publisher) |" }
    if ($app.version -or $app.displayVersion) { 
        $version = if ($app.displayVersion) { $app.displayVersion } else { $app.version }
        $md += "| **Version** | $version |" 
    }
    $md += "| **Created** | $createdDate |"
    $md += "| **Last Modified** | $modifiedDate |"
    if ($app.isFeatured) { $md += "| **Featured** | Yes |" }
    if ($app.isAssigned) { $md += "| **Assigned** | Yes |" }
    $md += ""
    
    # Description if available
    if ($app.description) {
        $md += "## Description"
        $md += ""
        $md += $app.description
        $md += ""
    }
    
    # Notes/Information URL
    if ($app.notes -or $app.informationUrl -or $app.privacyInformationUrl) {
        $md += "## Additional Information"
        $md += ""
        if ($app.notes) { 
            $md += "**Notes:** $($app.notes)"
            $md += ""
        }
        if ($app.informationUrl) { $md += "- **Information URL:** $($app.informationUrl)" }
        if ($app.privacyInformationUrl) { $md += "- **Privacy URL:** $($app.privacyInformationUrl)" }
        $md += ""
    }
    
    # Assignments
    if ($app.assignments -and $app.assignments.Count -gt 0) {
        $md += "## Assignments"
        $md += ""
        $md += "| Intent | Target Type | Group Name | Filter |"
        $md += "|--------|-------------|------------|--------|"
        foreach ($assignment in $app.assignments) {
            $intent = if ($assignment.intent) { $assignment.intent } else { "N/A" }
            $targetType = $assignment.target.'@odata.type' -replace '#microsoft.graph.', '' -replace 'AssignmentTarget', ''
            $groupName = if ($assignment.target.groupName) { $assignment.target.groupName } elseif ($assignment.target.groupId) { $assignment.target.groupId } else { "All Devices/Users" }
            $filter = if ($assignment.target.filterName) { 
                "$($assignment.target.deviceAndAppManagementAssignmentFilterType): $($assignment.target.filterName)" 
            } elseif ($assignment.target.deviceAndAppManagementAssignmentFilterId) {
                "$($assignment.target.deviceAndAppManagementAssignmentFilterType): $($assignment.target.deviceAndAppManagementAssignmentFilterId)"
            } else { "None" }
            $md += "| $intent | $targetType | $groupName | $filter |"
        }
        $md += ""
    } else {
        $md += "## Assignments"
        $md += ""
        $md += "*No assignments configured*"
        $md += ""
    }
    
    # Win32 App specific details
    if ($app.'@odata.type' -match 'win32LobApp|win32CatalogApp') {
        $md += "## Installation Details"
        $md += ""
        $md += "| Property | Value |"
        $md += "|----------|-------|"
        
        if ($app.fileName) { $md += "| **File Name** | $($app.fileName) |" }
        if ($app.setupFilePath) { $md += "| **Setup File** | $($app.setupFilePath) |" }
        if ($app.installCommandLine) { $md += "| **Install Command** | ``$($app.installCommandLine)`` |" }
        if ($app.uninstallCommandLine) { $md += "| **Uninstall Command** | ``$($app.uninstallCommandLine)`` |" }
        if ($app.installExperience) {
            if ($app.installExperience.runAsAccount) { $md += "| **Run As** | $($app.installExperience.runAsAccount) |" }
            if ($app.installExperience.deviceRestartBehavior) { $md += "| **Restart Behavior** | $($app.installExperience.deviceRestartBehavior) |" }
            if ($app.installExperience.maxRunTimeInMinutes) { $md += "| **Max Runtime** | $($app.installExperience.maxRunTimeInMinutes) minutes |" }
        }
        if ($app.minimumSupportedOperatingSystem) {
            $osReq = $app.minimumSupportedOperatingSystem
            $minOs = ($osReq.PSObject.Properties | Where-Object { $_.Value -eq $true } | Select-Object -First 1).Name
            if ($minOs) { $md += "| **Min OS** | $minOs |" }
        }
        $md += ""
        
        # Detection Rules
        if ($app.detectionRules -or $app.rules) {
            $rules = if ($app.detectionRules) { $app.detectionRules } else { $app.rules | Where-Object { $_.'@odata.type' -match 'Detection' } }
            if ($rules -and $rules.Count -gt 0) {
                $md += "### Detection Rules"
                $md += ""
                $md += "| Type | Details |"
                $md += "|------|---------|"
                foreach ($rule in $rules) {
                    $ruleType = $rule.'@odata.type' -replace '#microsoft.graph.', '' -replace 'win32Lob', '' -replace 'DetectionRule', ''
                    $ruleDetails = switch -Wildcard ($rule.'@odata.type') {
                        "*Registry*" { 
                            $check = if ($rule.check32BitOn64System) { " (32-bit)" } else { "" }
                            "Key: ``$($rule.keyPath)``$check Value: $($rule.valueName) $($rule.detectionType)" 
                        }
                        "*File*" { 
                            $check = if ($rule.check32BitOn64System) { " (32-bit)" } else { "" }
                            "Path: ``$($rule.path)\$($rule.fileOrFolderName)``$check $($rule.detectionType)" 
                        }
                        "*Msi*" { "Product Code: ``$($rule.productCode)`` Version: $($rule.productVersionOperator) $($rule.productVersion)" }
                        "*Script*" { "Script detection (PowerShell)" }
                        default { $rule.'@odata.type' }
                    }
                    $md += "| $ruleType | $ruleDetails |"
                }
                $md += ""
            }
        }
        
        # Requirement Rules
        if ($app.requirementRules) {
            $md += "### Requirement Rules"
            $md += ""
            $md += "| Type | Details |"
            $md += "|------|---------|"
            foreach ($rule in $app.requirementRules) {
                $ruleType = $rule.'@odata.type' -replace '#microsoft.graph.', '' -replace 'win32Lob', '' -replace 'RequirementRule', ''
                $ruleDetails = switch -Wildcard ($rule.'@odata.type') {
                    "*Registry*" { "Key: ``$($rule.keyPath)`` Value: $($rule.valueName)" }
                    "*File*" { "Path: ``$($rule.path)\$($rule.fileOrFolderName)``" }
                    "*Script*" { "Script requirement (PowerShell)" }
                    default { $rule.'@odata.type' }
                }
                $md += "| $ruleType | $ruleDetails |"
            }
            $md += ""
        }
        
        # Return Codes
        if ($app.returnCodes -and $app.returnCodes.Count -gt 0) {
            $md += "### Return Codes"
            $md += ""
            $md += "| Code | Type |"
            $md += "|------|------|"
            foreach ($code in $app.returnCodes) {
                $md += "| $($code.returnCode) | $($code.type) |"
            }
            $md += ""
        }
    }
    
    # WinGet App specific details
    if ($app.'@odata.type' -match 'winGetApp') {
        $md += "## WinGet Details"
        $md += ""
        $md += "| Property | Value |"
        $md += "|----------|-------|"
        if ($app.packageIdentifier) { $md += "| **Package ID** | ``$($app.packageIdentifier)`` |" }
        if ($app.installExperience) {
            if ($app.installExperience.runAsAccount) { $md += "| **Run As** | $($app.installExperience.runAsAccount) |" }
        }
        $md += ""
    }
    
    # Microsoft 365 Apps specific details
    if ($app.'@odata.type' -match 'officeSuiteApp') {
        $md += "## Microsoft 365 Apps Configuration"
        $md += ""
        $md += "| Property | Value |"
        $md += "|----------|-------|"
        if ($app.officeConfigurationXml) { $md += "| **Custom XML** | Configured |" }
        if ($app.officePlatformArchitecture) { $md += "| **Architecture** | $($app.officePlatformArchitecture) |" }
        if ($app.updateChannel) { $md += "| **Update Channel** | $($app.updateChannel) |" }
        if ($app.localesToInstall) { $md += "| **Languages** | $($app.localesToInstall -join ', ') |" }
        if ($app.excludedApps) {
            $excluded = $app.excludedApps.PSObject.Properties | Where-Object { $_.Value -eq $true } | Select-Object -ExpandProperty Name
            if ($excluded) { $md += "| **Excluded Apps** | $($excluded -join ', ') |" }
        }
        if ($app.productIds) { $md += "| **Products** | $($app.productIds -join ', ') |" }
        $md += ""
    }
    
    # Categories
    if ($app.categories -and $app.categories.Count -gt 0) {
        $md += "## Categories"
        $md += ""
        $categoryNames = $app.categories | ForEach-Object { $_.displayName }
        $md += $categoryNames -join ", "
        $md += ""
    }
    
    # Raw App Data
    $md += "## Raw Application Data"
    $md += ""
    $md += "<details>"
    $md += "<summary>Click to expand JSON</summary>"
    $md += ""
    $md += "``````json"
    $appCopy = $app | Select-Object -Property * -ExcludeProperty assignments, detectionRules, requirementRules, returnCodes, rules
    $md += ($appCopy | ConvertTo-Json -Depth 20)
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
        Type = $appType
        Publisher = if ($app.publisher) { $app.publisher } else { "N/A" }
        FileName = $mdFileName
        Created = $createdDate
        Modified = $modifiedDate
    }
}

Write-Host "  ✓ Exported $($exportedFiles.Count) application files" -ForegroundColor Green

# Create README.md index
Write-Host ""
Write-Host "  Creating README.md index..." -ForegroundColor Gray

$readme = @()
$readme += "# Intune Applications Export"
$readme += ""
$readme += "## Collection Information"
$readme += ""
$readme += "| Property | Value |"
$readme += "|----------|-------|"
$readme += "| **Collected By** | $collectedBy |"
$readme += "| **Collection Date** | $collectionDate |"
$readme += "| **Collection Method** | Microsoft Graph API (PowerShell) |"
$readme += "| **Script** | App-rehension.ps1 |"
$readme += "| **Platform Filter** | $Platform |"
$readme += "| **Applications Collected** | $($exportedFiles.Count) |"
$readme += ""
$readme += "## Search Patterns Used"
$readme += ""
$readme += "``````"
$AppNamesArray | ForEach-Object { $readme += $_ }
$readme += "``````"
$readme += ""
$readme += "## Applications Collected"
$readme += ""
$readme += "| Application Name | Type | Publisher | Created | Modified | Link |"
$readme += "|------------------|------|-----------|---------|----------|------|"

foreach ($file in ($exportedFiles | Sort-Object Name)) {
    $linkName = $file.Name -replace '\|', '\|'
    $readme += "| $linkName | $($file.Type) | $($file.Publisher) | $($file.Created) | $($file.Modified) | [$($file.FileName)]($($file.FileName)) |"
}

$readme += ""
$readme += "## API Endpoints Queried"
$readme += ""
$readme += "- ``https://graph.microsoft.com/beta/deviceAppManagement/mobileApps`` - All mobile applications"
$readme += "- ``https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/{id}/assignments`` - App assignments"
$readme += ""
$readme += "## Permissions Required"
$readme += ""
$readme += "- ``DeviceManagementApps.Read.All``"
$readme += ""
$readme += "---"
$readme += ""
$readme += "*Generated automatically by App-rehension.ps1*"

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
Write-Host "  - $($exportedFiles.Count) application Markdown files" -ForegroundColor Gray
Write-Host "  - README.md index file" -ForegroundColor Gray
Write-Host ""

# Show appreciation call-to-action
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   Found App-rehension helpful?" -ForegroundColor Yellow
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
Write-Host "Thank you for using App-rehension! " -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
