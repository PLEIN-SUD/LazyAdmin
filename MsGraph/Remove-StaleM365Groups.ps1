<#
.SYNOPSIS
    Remove stale Microsoft 365 Groups from Entra ID

.DESCRIPTION
    This script identifies and removes stale Microsoft 365 Groups using activity data from the
    Microsoft 365 Groups Activity Report. A group is considered stale when it has had no activity
    across SharePoint/OneDrive, Exchange (email), and Teams within the defined threshold.

    Activity signals used (all sourced from Get-MgReportOffice365GroupActivityDetail):
      - SharePoint last activity date
      - Exchange last activity date
      - Teams channel messages count / last activity date

    The script uses the same two-stage approach as the device and guest cleanup scripts:
      Stage 1 - Flag group as stale (report only, no destructive action at this stage)
      Stage 2 - Delete groups that have been stale for more than -DeleteThresholdDays

    Note: Microsoft 365 Groups that are connected to a Team, have active SharePoint sites, or
    have active Exchange mailboxes are flagged individually so you can review before deletion.
    Deleted M365 Groups go to the recycle bin (soft-delete) and can be restored within 30 days.

    Authentication modes:
      - Azure Runbook  : Managed Identity (-RunbookMode)
      - Local dev      : Interactive login (-TenantId only)

.PARAMETER StaleThresholdDays
    Days since last activity before a group is considered stale and reported. Default: 90.

.PARAMETER DeleteThresholdDays
    Days since last activity before a stale group is DELETED. Default: 180.
    Intentionally higher default than devices/users - M365 Groups often contain valuable data.

.PARAMETER ReportOnly
    List which groups would be deleted without making any changes.

.PARAMETER ExcludeGroupNames
    Group display name patterns to exclude (wildcards supported, e.g. "Project-*").

.PARAMETER RunbookMode
    Use Managed Identity (Azure Automation Runbook).

.PARAMETER TenantId
    Entra tenant ID. Required for interactive and app-registration auth.

.PARAMETER ExportPath
    Folder for CSV exports. Defaults to the script directory.

.EXAMPLE
    # Report-only, interactive login
    .\Remove-StaleM365Groups.ps1 -TenantId "your-tenant-id" -ReportOnly

.EXAMPLE
    # Custom thresholds, exclude certain groups
    .\Remove-StaleM365Groups.ps1 -TenantId "your-tenant-id" `
        -StaleThresholdDays 90 -DeleteThresholdDays 180 `
        -ExcludeGroupNames @("Project-*","Board-*") -ReportOnly

.EXAMPLE
    # Azure Runbook live run via Managed Identity
    .\Remove-StaleM365Groups.ps1 -RunbookMode -StaleThresholdDays 90 -DeleteThresholdDays 180

.NOTES
    Author:  LazyAdmin.nl
    Version: 1.0
    Date:    2026-03-12

    Required Microsoft Graph permissions:
      Group.Read.All               - list groups
      Group.ReadWrite.All          - delete groups
      Reports.Read.All             - read M365 activity reports
      TeamSettings.Read.All        - read Teams connection status

    Note on report data freshness:
      The Microsoft 365 Groups activity report data has a 48-hour delay. This is a platform
      limitation and not a script issue. Very recently active groups may appear stale.
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter()][int]         $StaleThresholdDays   = 90,
    [Parameter()][int]         $DeleteThresholdDays  = 180,
    [Parameter()][switch]      $ReportOnly           = $true,
    [Parameter()][string[]]    $ExcludeGroupNames    = @(),
    [Parameter()][switch]      $RunbookMode,
    [Parameter()][string]      $TenantId,
    [Parameter()][string]      $ClientId,
    [Parameter()][SecureString]$ClientSecret,
    [Parameter()][string]      $ExportPath           = $PSScriptRoot
)

$ErrorActionPreference = "Stop"

# -------------------------------------------------------------
# Logging
# -------------------------------------------------------------
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARNING","ERROR","SUCCESS")][string]$Level = "INFO"
    )

    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"

    switch ($Level) {
        "WARNING" { Write-Warning $line }
        "ERROR"   { Write-Error   $line }
        default   { Write-Output  $line }
    }
}

# -------------------------------------------------------------
# Connect to Microsoft Graph
# -------------------------------------------------------------
function Connect-ToGraph {

    # Reuse existing session if available
    $context = Get-MgContext
    if ($context) {
        Write-Log "Already connected as $($context.Account) (tenant: $($context.TenantId))." -Level SUCCESS
        return
    }

    if ($RunbookMode) {
        Write-Log "Authenticating with Managed Identity..."
        Connect-MgGraph -Identity -NoWelcome
    }
    else {
        Write-Log "Authenticating interactively..."
        $p = @{
            Scopes                  = @("Group.Read.All","Group.ReadWrite.All","Reports.Read.All","TeamSettings.Read.All")
            NoWelcome               = $true
        }
        if ($TenantId) { $p.TenantId = $TenantId }
        Connect-MgGraph @p
    }
    Write-Log "Connected to Microsoft Graph." -Level SUCCESS
}

# -------------------------------------------------------------
# Exclusion by display name pattern
# -------------------------------------------------------------
function Test-IsExcluded {
    param([string]$DisplayName)

    foreach ($pattern in $ExcludeGroupNames) {
        if ($DisplayName -like $pattern) { return $true }
    }

    return $false
}

# -------------------------------------------------------------
# Storage formatting helper
# -------------------------------------------------------------
function Format-Bytes {
    param([long]$Bytes)

    if ($Bytes -ge 1GB) { return "{0:N2} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N2} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N2} KB" -f ($Bytes / 1KB) }

    return "$Bytes B"
}

# -------------------------------------------------------------
# Resolve the most recent activity date across all three signals
# -------------------------------------------------------------
function Get-LastActivityDate {
    param($ActivityRow)
    if ($ActivityRow.'Last Activity Date' -and $ActivityRow.'Last Activity Date' -ne '') {
        return [datetime]::Parse($ActivityRow.'Last Activity Date', [System.Globalization.CultureInfo]::InvariantCulture)
    }
    return $null
}

# -------------------------------------------------------------
# CSV export
# -------------------------------------------------------------
function Export-Report {
    param($Data, [string]$Suffix)

    $file = Join-Path $ExportPath "EntraID_M365Groups_${Suffix}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $Data | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8
    Write-Log "Report saved: $file" -Level SUCCESS
}


# =============================================================
# MAIN
# =============================================================

Write-Log "========================================================"
Write-Log " Entra ID Stale M365 Group Cleanup  -  LazyAdmin.nl"
Write-Log " Stale threshold  : $StaleThresholdDays days"
Write-Log " Delete threshold : $DeleteThresholdDays days"
Write-Log " Mode             : $(if ($ReportOnly) { 'REPORT ONLY - no changes will be made' } else { 'LIVE - groups WILL be deleted' })"
Write-Log "========================================================"

if ($DeleteThresholdDays -le $StaleThresholdDays) {
    throw "DeleteThresholdDays ($DeleteThresholdDays) must be greater than StaleThresholdDays ($StaleThresholdDays)."
}

# 1. Connect
Connect-ToGraph

# 2. Fetch M365 Groups activity report
# The report covers the last 180 days and includes SharePoint, Exchange and Teams signals.
# Note: report data has up to a 48-hour delay.
Write-Log "Retrieving Microsoft 365 Groups activity report (last 180 days)..."

$tempFile = Join-Path $env:TEMP "M365GroupActivityReport_$(Get-Date -Format 'yyyyMMddHHmmss').csv"

Get-MgReportOffice365GroupActivityDetail -Period "D180" -OutFile $tempFile

$reportRows = Import-Csv -Path $tempFile
Remove-Item $tempFile -Force

Write-Log "Activity report rows retrieved: $($reportRows.Count)"

# Build a hashtable for quick lookup by GroupId
$activityMap = @{}
foreach ($row in $reportRows) {
    if ($row.'Group Id') { $activityMap[$row.'Group Id'] = $row }
}

# 3. Fetch all M365 Groups
Write-Log "Retrieving all Microsoft 365 Groups from Entra ID..."

$allGroups = Get-MgGroup -All `
    -Filter "groupTypes/any(c:c eq 'Unified')" `
    -Property "Id,DisplayName,Description,
               Visibility,GroupTypes,ResourceProvisioningOptions,Mail" |
    Select-Object Id, DisplayName, Description, Visibility, GroupTypes, ResourceProvisioningOptions, Mail

Write-Log "Total M365 Groups found: $($allGroups.Count)"

$staleCutoff  = (Get-Date).AddDays(-$StaleThresholdDays)
$deleteCutoff = (Get-Date).AddDays(-$DeleteThresholdDays)

$toDelete  = [System.Collections.Generic.List[object]]::new()
$staleOnly = [System.Collections.Generic.List[object]]::new()
$skipped   = [System.Collections.Generic.List[object]]::new()

foreach ($group in $allGroups) {

    # --Exclusion by name
    if (Test-IsExcluded $group.DisplayName) {
        $skipped.Add([PSCustomObject]@{
            DisplayName          = $group.DisplayName
            ObjectId             = $group.Id
            Mail                 = $group.Mail
            HasTeam              = $false
            MemberCount          = $null
            CreatedDateTime      = $group.CreatedDateTime
            LastActivityDate     = $null
            SharePointLastActivity = $null
            ExchangeLastActivity = $null
            TeamsLastActivity    = $null
            DaysSinceLastActivity = $null
            PlannedAction        = "Skipped"
            SkipReason           = "ExcludedByFilter"
        }); continue
    }

    # --Match to activity report
    $activity    = $activityMap[$group.Id]
    $lastActivity = if ($activity) { Get-LastActivityDate $activity } else { $null }
    $hasTeam   = $activity ? [bool]$activity.HasTeam : ($group.ResourceProvisioningOptions -contains "Team")

    $entry = [PSCustomObject]@{
        DisplayName             = $group.DisplayName
        ObjectId                = $group.Id
        Mail                    = $group.Mail
        HasTeam                 = ($group.ResourceProvisioningOptions -contains "Team")
        Owners                  = $activity.'Owner Principal Name'
        MemberCount             = $activity.'Member Count'
        ExternalMemberCount     = $activity.'External Member Count'
        LastActivityDate        = $lastActivity
        SharePointActiveFiles   = $activity.'SharePoint Active File Count'
        SharePointTotalFiles    = $activity.'SharePoint Total File Count'
        SharePointStorageUsed   = if ($activity.'SharePoint Site Storage Used (Byte)') { Format-Bytes ([long]$activity.'SharePoint Site Storage Used (Byte)') } else { "N/A" }
        ExchangeItemCount       = $activity.'Exchange Mailbox Total Item Count'
        ExchangeStorageUsed     = if ($activity.'Exchange Mailbox Storage Used (Byte)') { Format-Bytes ([long]$activity.'Exchange Mailbox Storage Used (Byte)') } else { "N/A" }
        DaysSinceLastActivity   = $null
        PlannedAction           = $null
        SkipReason              = $null
    }

    # --No activity data - skip, we can't determine staleness
    if (-not $lastActivity) {
        $entry.SkipReason    = "NoActivityData"
        $entry.PlannedAction = "Skipped"
        $skipped.Add($entry); continue
    }

    # -- Calculate days since last activity for reporting
    $entry.DaysSinceLastActivity = [math]::Round(((Get-Date) - $lastActivity).TotalDays)

    # --Classify 
    if ($lastActivity  -le $deleteCutoff) {
        $entry.PlannedAction = "Delete"
        $toDelete.Add($entry)
    }
    elseif ($lastActivity  -le $staleCutoff) {
        $entry.PlannedAction = "StaleReviewNeeded"
        $staleOnly.Add($entry)
    }
}

Write-Log "Groups to delete        : $($toDelete.Count)"
Write-Log "Groups stale (review)   : $($staleOnly.Count)"
Write-Log "Groups skipped          : $($skipped.Count)"

# 4. Always export pre-run report
Export-Report -Data (@($toDelete) + @($staleOnly) + @($skipped)) -Suffix "PreCleanup"

if ($toDelete.Count -eq 0 -and $staleOnly.Count -eq 0) {
    Write-Log "No stale groups found. Exiting." -Level SUCCESS
    Disconnect-MgGraph | Out-Null
    exit 0
}

if ($ReportOnly) {
    Write-Log "`n--Groups that WOULD be deleted ($($toDelete.Count))"
    $toDelete | Format-Table DisplayName, Owners, HasTeam, MemberCount, SharePointActiveFiles, `
    SharePointStorageUsed, ExchangeStorageUsed, LastActivityDate, DaysSinceLastActivity -AutoSize | Out-String | Write-Output

    Write-Log "--Groups that are stale but below delete threshold ($($staleOnly.Count))"
    $staleOnly | Format-Table DisplayName, HasTeam, MemberCount, LastActivityDate, DaysSinceLastActivity -AutoSize | Out-String | Write-Output

    Write-Log "ReportOnly mode active - no changes were made." -Level WARNING
    Disconnect-MgGraph | Out-Null
    exit 0
}

# -------------------------------------------------------------
# Delete stale groups
# Note: deleted M365 Groups go to the recycle bin and can be
# restored within 30 days via the Entra ID portal or PowerShell.
# -------------------------------------------------------------
Write-Log "--- Deleting stale M365 Groups ---"
$deleteResults = [System.Collections.Generic.List[object]]::new()

foreach ($group in $toDelete) {
    try {

        # -------------------------------------------------------------
        #
        ## WARNING: The actual deletion command is commented out for safety. Uncomment to enable deletion.
        #
        # -------------------------------------------------------------

        # Remove-MgGroup -GroupId $group.ObjectId
        # Write-Log "Deleted: $($group.DisplayName) (inactive $($group.DaysSinceLastActivity) days)" -Level SUCCESS

        # Comment out or remove the line below when enabling actual deletion
        Write-Log "DRY RUN: Would delete $($group.DisplayName) (inactive $($group.DaysSinceLastActivity) days)" -Level WARNING

        $group.PlannedAction = "Deleted"
    }
    catch {
        Write-Log "Failed to delete $($group.DisplayName): $_" -Level WARNING
        $group.PlannedAction = "DeleteFailed - $($_.Exception.Message)"
    }
    $deleteResults.Add($group)
}

# 5. Export final results
Export-Report -Data (@($deleteResults) + @($staleOnly) + @($skipped)) -Suffix "CleanupResults"

Write-Log "All done." -Level SUCCESS
Disconnect-MgGraph | Out-Null