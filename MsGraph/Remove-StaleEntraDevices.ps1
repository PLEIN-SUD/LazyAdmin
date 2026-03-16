<#
.SYNOPSIS
    Remove stale devices from Microsoft Entra ID

.DESCRIPTION
    This script removes stale devices from Microsoft Entra ID based on the ApproximateLastSignInDateTime.
    It uses a two-stage approach:
      Stage 1 - Disable devices inactive for more than -StaleThresholdDays (default: 90)
      Stage 2 - Delete devices that are ALREADY disabled AND inactive for more than -DeleteThresholdDays (default: 120)

    Safety guards (per Microsoft recommendations):
      - System-managed devices (Autopilot etc.) are never touched.
      - Devices with BitLocker recovery keys in Entra ID are skipped unless -IncludeBitLockerDevices is set.
      - A pre-cleanup CSV report is always written before any changes are made.

    Authentication modes:
      - Azure Runbook  : Managed Identity (-RunbookMode)
      - Local dev      : Interactive login (-TenantId only)

.PARAMETER StaleThresholdDays
    Days since last sign-in before a device is DISABLED. Default: 90.

.PARAMETER DeleteThresholdDays
    Days since last sign-in before an already-DISABLED device is DELETED. Default: 120.
    Must be greater than StaleThresholdDays.

.PARAMETER ReportOnly
    List which devices would be disabled / deleted without making any changes.

.PARAMETER IncludeBitLockerDevices
    By default, devices with BitLocker recovery keys in Entra ID are skipped.
    Set this switch only after confirming keys are backed up or no longer needed.

.PARAMETER ExcludeDeviceNames
    Display-name patterns to skip (wildcards supported, e.g. "KIOSK-*").

.PARAMETER ExcludeOperatingSystems
    OS types to skip entirely, e.g. @("iOS","Android").

.PARAMETER RunbookMode
    Use Managed Identity (Azure Automation Runbook).

.PARAMETER TenantId
    Entra tenant ID. Required for interactive and app-registration auth.

.PARAMETER ExportPath
    Folder for CSV exports. Defaults to the script directory.

.EXAMPLE
    # Report-only, interactive login
    .\Remove-StaleEntraDevices.ps1 -TenantId "your-tenant-id" -ReportOnly

.EXAMPLE
    # Custom thresholds, exclude mobile, report-only
    .\Remove-StaleEntraDevices.ps1 -TenantId "your-tenant-id" `
        -StaleThresholdDays 60 -DeleteThresholdDays 90 `
        -ExcludeOperatingSystems @("iOS","Android") -ReportOnly

.EXAMPLE
    # Azure Runbook live run via Managed Identity
    .\Remove-StaleEntraDevices.ps1 -RunbookMode -StaleThresholdDays 90 -DeleteThresholdDays 120

.NOTES
    Author:  LazyAdmin.nl
    Version: 2.0
    Date:    2026-03-12

    Required Microsoft Graph permissions:
      Device.Read.All          - list devices
      Device.ReadWrite.All     - disable and delete devices
      BitLockerKey.Read.All    - check for stored recovery keys
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter()][int]         $StaleThresholdDays      = 90,
    [Parameter()][int]         $DeleteThresholdDays     = 120,
    [Parameter()][bool]        $ReportOnly              = $true,
    [Parameter()][bool]        $IncludeBitLockerDevices = $false,
    [Parameter()][string[]]    $ExcludeDeviceNames      = @(),
    [Parameter()][string[]]    $ExcludeOperatingSystems = @(),
    [Parameter()][bool]        $RunbookMode             = $false,
    [Parameter()][string]      $TenantId,
    [Parameter()][string]      $ExportPath              = $PSScriptRoot,
    [Parameter()][string]      $ReportEmailTo,
    [Parameter()][string]      $ReportEmailFrom
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

     # Check if already connected with a valid session
    $context = Get-MgContext
    if ($context) {
        Write-Log "Already connected to Microsoft Graph as $($context.Account) (tenant: $($context.TenantId))." -Level SUCCESS
        return
    }
    
    if ($RunbookMode) {
        Write-Log "Authenticating with Managed Identity..."
        Connect-MgGraph -Identity -NoWelcome
    }
    else {
        Write-Log "Authenticating interactively..."
        $p = @{
            Scopes    = @("Device.ReadWrite.All","BitLockerKey.Read.All","Mail.Send")
            NoWelcome = $true
        }
        if ($TenantId) { $p.TenantId = $TenantId }
        Connect-MgGraph @p
    }
    Write-Log "Connected to Microsoft Graph." -Level SUCCESS
}

# -------------------------------------------------------------
# BitLocker: does this device have keys stored in Entra ID?
# -------------------------------------------------------------
function Test-HasBitLockerKey {
    param([string]$DeviceId)
    try {
        $keys = Get-MgInformationProtectionBitlockerRecoveryKey `
                    -Filter "deviceId eq '$DeviceId'" -ErrorAction SilentlyContinue
        return ($keys -and $keys.Count -gt 0)
    }
    catch {
        # Fail safe: if we can't check, assume a key exists
        Write-Log "Cannot query BitLocker keys for $DeviceId - treating as protected." -Level WARNING
        return $true
    }
}

# -------------------------------------------------------------
# Autopilot / system-managed detection
# Microsoft: "Don't delete system-managed devices such as Autopilot.
#             Once deleted, they can't be reprovisioned."
# -------------------------------------------------------------
function Test-IsSystemManaged {
    param($Device)

    # Devices enrolled via Autopilot have a profile name set
    if ($Device.EnrollmentProfileName) { return $true }

    # Co-managed / Autopilot enrollment types
    if ($Device.EnrollmentType -in @("windowsCoManagement")) { return $true }

    # Hybrid Entra Joined devices are managed via on-premises AD - skip them
    if ($Device.TrustType -eq "ServerAd") { return $true }

    return $false
}

# -------------------------------------------------------------
# Exclusion by name pattern or OS
# -------------------------------------------------------------
function Test-IsExcluded {
    param($Device)
    foreach ($os in $ExcludeOperatingSystems) {
        if ($Device.OperatingSystem -like "*$os*") { return $true }
    }
    foreach ($pattern in $ExcludeDeviceNames) {
        if ($Device.DisplayName -like $pattern) { return $true }
    }
    return $false
}

# -------------------------------------------------------------
# CSV export
# -------------------------------------------------------------
function Export-Report {
    param(
        $Data,
        [string]$Suffix,
        [string]$Subject
    )

    # Always build the CSV content in memory
    $csvContent = $Data | ConvertTo-Csv -NoTypeInformation | Out-String

    if ($RunbookMode) {
        # Email via Microsoft Graph
        if (-not $ReportEmailTo -or -not $ReportEmailFrom) {
            Write-Log "ReportEmailTo and ReportEmailFrom are required in Runbook mode." -Level WARNING
            return
        }

        $fileName    = "EntraID_${Suffix}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $base64Csv   = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($csvContent))

        $message = @{
            subject = $Subject
            body    = @{
                contentType = "Text"
                content     = "Attached the Stale Devices Cleanup report.`n`nRun time: $(Get-Date)`nReport: $Suffix"
            }
            toRecipients = @(
                @{ emailAddress = @{ address = $ReportEmailTo } }
            )
            attachments = @(
                @{
                    "@odata.type"  = "#microsoft.graph.fileAttachment"
                    name           = $fileName
                    contentType    = "text/csv"
                    contentBytes   = $base64Csv
                }
            )
        }

        try {
            Send-MgUserMail -UserId $ReportEmailFrom -BodyParameter @{ message = $message }
            Write-Log "Report emailed to $ReportEmailTo" -Level SUCCESS
        }
        catch {
            Write-Log "Failed to send email: $_" -Level ERROR
        }
    }
    else {
        # Save to disk locally
        $file = Join-Path $ExportPath "EntraID_${Suffix}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $csvContent | Out-File -FilePath $file -Encoding UTF8
        Write-Log "Report saved: $file" -Level SUCCESS
    }
}


# =============================================================
# MAIN
# =============================================================

Write-Log "========================================================"
Write-Log " Entra ID Stale Device Cleanup  -  LazyAdmin.nl"
Write-Log " Disable threshold : $StaleThresholdDays days"
Write-Log " Delete threshold  : $DeleteThresholdDays days"
Write-Log " Mode              : $(if ($ReportOnly) { 'REPORT ONLY - no changes will be made' } else { 'LIVE - devices WILL be disabled / deleted' })"
Write-Log "========================================================"

if ($DeleteThresholdDays -le $StaleThresholdDays) {
    throw "DeleteThresholdDays ($DeleteThresholdDays) must be greater than StaleThresholdDays ($StaleThresholdDays)."
}

# 1. Connect
Connect-ToGraph

# 2. Fetch all devices with the properties we need
Write-Log "Retrieving all devices from Entra ID..."

$allDevices = Get-MgDevice -All | Select-Object `
    Id, DeviceId, DisplayName, AccountEnabled,
    OperatingSystem, OperatingSystemVersion,
    TrustType, ManagementType, DeviceOwnership,
    EnrollmentType, EnrollmentProfileName,
    ApproximateLastSignInDateTime, RegistrationDateTime,
    IsManaged, IsCompliant

Write-Log "Total devices retrieved: $($allDevices.Count)"

# 3. Calculate cutoff dates
$disableCutoff = (Get-Date).AddDays(-$StaleThresholdDays)
$deleteCutoff  = (Get-Date).AddDays(-$DeleteThresholdDays)

$toDisable = [System.Collections.Generic.List[object]]::new()
$toDelete  = [System.Collections.Generic.List[object]]::new()
$skipped   = [System.Collections.Generic.List[object]]::new()

foreach ($device in $allDevices) {

    # Resolve last activity date
    $lastSignIn = if ($device.ApproximateLastSignInDateTime) {
                      [datetime]$device.ApproximateLastSignInDateTime
                  } elseif ($device.RegistrationDateTime) {
                      [datetime]$device.RegistrationDateTime
                  } else {
                      $null
                  }

    # No date data at all - skip silently, not enough info to evaluate
    if (-not $lastSignIn) { continue }

    # Not stale - skip silently, nothing to report
    if ($lastSignIn -gt $disableCutoff) { continue }

    $daysSince = [math]::Round(((Get-Date) - $lastSignIn).TotalDays)

    # Build entry - only for stale devices
    $entry = [PSCustomObject]@{
        DisplayName               = $device.DisplayName
        DeviceId                  = $device.DeviceId
        ObjectId                  = $device.Id
        AccountEnabled            = $device.AccountEnabled
        OperatingSystem           = $device.OperatingSystem
        OperatingSystemVersion    = $device.OperatingSystemVersion
        TrustType                 = $device.TrustType
        IsManaged                 = $device.IsManaged
        IsCompliant               = $device.IsCompliant
        ManagementType            = $device.ManagementType
        DeviceOwnership           = $device.DeviceOwnership
        EnrollmentProfileName     = $device.EnrollmentProfileName
        RegistrationDateTime      = $device.RegistrationDateTime
        ApproximateLastSignInDate = $lastSignIn
        DaysSinceLastSignIn       = $daysSince
        HasBitLockerKey           = "N/A"
        PlannedAction             = $null
        SkipReason                = $null
    }

    # Check BitLocker for all stale devices
    $entry.HasBitLockerKey = Test-HasBitLockerKey -DeviceId $device.DeviceId

    # Stale but system managed - report only, no action
    if (Test-IsSystemManaged $device) {
        $entry.SkipReason    = "SystemManaged"
        $entry.PlannedAction = "SkippedManualReviewNeeded"
        $skipped.Add($entry); continue
    }

    # Stale but excluded by filter - report only, no action
    if (Test-IsExcluded $device) {
        $entry.SkipReason    = "ExcludedByFilter"
        $entry.PlannedAction = "Skipped"
        $skipped.Add($entry); continue
    }

    # Stage 2: delete candidate - already disabled AND past delete threshold
    if ($lastSignIn -le $deleteCutoff -and $device.AccountEnabled -eq $false) {
        if ($entry.HasBitLockerKey -eq $true -and -not $IncludeBitLockerDevices) {
            $entry.SkipReason    = "BitLockerKeyPresent"
            $entry.PlannedAction = "Skipped"
            $skipped.Add($entry); continue
        }
        $entry.PlannedAction = "Delete"
        $toDelete.Add($entry); continue
    }

    # Stage 1: disable candidate - active AND past disable threshold
    if ($lastSignIn -le $disableCutoff -and $device.AccountEnabled -eq $true) {
        $entry.PlannedAction = "Disable"
        $toDisable.Add($entry); continue
    }

    # Stale but doesn't fit Stage 1 or 2 yet - already disabled but not past delete threshold
    $entry.PlannedAction = "DisabledPendingDeletion"
    $skipped.Add($entry)
}

Write-Log "Devices to disable : $($toDisable.Count)"
Write-Log "Devices to delete  : $($toDelete.Count)"
Write-Log "Devices skipped    : $($skipped.Count)"

# 4. Always export a pre-run inventory
$foundCount  = $toDisable.Count + $toDelete.Count
$subject     = if ($foundCount -gt 0) {
                   "[$($foundCount) found] Entra ID Stale Device Report - $(Get-Date -Format 'yyyy-MM-dd')"
               } else {
                   "[Nothing found] Entra ID Stale Device Report - $(Get-Date -Format 'yyyy-MM-dd')"
               }

Export-Report -Data (@($toDisable) + @($toDelete) + @($skipped)) -Suffix "PreCleanup" -Subject $subject

if ($toDisable.Count -eq 0 -and $toDelete.Count -eq 0) {
    Write-Log "Nothing to process. Exiting." -Level SUCCESS
    Disconnect-MgGraph | Out-Null
    exit 0
}

if ($ReportOnly) {
    Write-Log "`n--Devices that WOULD be disabled"
    $toDisable | Format-Table DisplayName, OperatingSystem, ApproximateLastSignInDate, DaysSinceLastSignIn, TrustType -AutoSize | Out-String | Write-Output

    Write-Log "--Devices that WOULD be deleted"
    $toDelete  | Format-Table DisplayName, OperatingSystem, ApproximateLastSignInDate, DaysSinceLastSignIn, HasBitLockerKey -AutoSize | Out-String | Write-Output

    Write-Log "ReportOnly mode active - no changes were made." -Level WARNING
    Disconnect-MgGraph | Out-Null
    exit 0
}

# -------------------------------------------------------------
# Stage 1 - Disable stale active devices
# -------------------------------------------------------------
Write-Log "--- Stage 1: Disabling stale devices ---"
$disableResults = [System.Collections.Generic.List[object]]::new()

foreach ($device in $toDisable) {
    try {
        #Update-MgDevice -DeviceId $device.ObjectId -BodyParameter @{ accountEnabled = $false }
        Write-Log "Disabled: $($device.DisplayName) (inactive $($device.DaysSinceLastSignIn) days)" -Level SUCCESS
        $device.PlannedAction = "Disabled"
    }
    catch {
        Write-Log "Failed to disable $($device.DisplayName): $_" -Level WARNING
        $device.PlannedAction = "DisableFailed - $($_.Exception.Message)"
    }
    $disableResults.Add($device)
}

# -------------------------------------------------------------
# Stage 2 - Delete disabled stale devices
# -------------------------------------------------------------
Write-Log "--- Stage 2: Deleting disabled stale devices ---"
$deleteResults = [System.Collections.Generic.List[object]]::new()

foreach ($device in $toDelete) {
    try {
        #Remove-MgDevice -DeviceId $device.ObjectId
        Write-Log "Deleted: $($device.DisplayName) (inactive $($device.DaysSinceLastSignIn) days)" -Level SUCCESS
        $device.PlannedAction = "Deleted"
    }
    catch {
        Write-Log "Failed to delete $($device.DisplayName): $_" -Level WARNING
        $device.PlannedAction = "DeleteFailed - $($_.Exception.Message)"
    }
    $deleteResults.Add($device)
}

# 5. Export final results
Export-Report -Data (@($disableResults) + @($deleteResults) + @($skipped)) -Suffix "CleanupResults" -Subject $subject

Write-Log "All done." -Level SUCCESS
Disconnect-MgGraph | Out-Null