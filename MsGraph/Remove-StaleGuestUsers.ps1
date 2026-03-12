<#
.SYNOPSIS
    Remove stale Guest users from Microsoft Entra ID

.DESCRIPTION
    This script removes stale Guest users from Microsoft Entra ID based on their last successful
    sign-in date. It uses the same two-stage approach as the device cleanup script:
      Stage 1 – Disable guests inactive for more than -StaleThresholdDays (default: 90)
      Stage 2 – Delete guests that are ALREADY disabled AND inactive for more than -DeleteThresholdDays (default: 120)

    Never-signed-in guests (invite/creation date older than -NeverSignedInDays, default: 7) are
    reported separately and flagged for review. They are not automatically deleted but will be
    included in the pre-cleanup report.

    Authentication modes:
      - Azure Runbook  : Managed Identity (-RunbookMode)
      - Local dev      : Interactive login (-TenantId only)

.PARAMETER StaleThresholdDays
    Days since last sign-in before a guest is DISABLED. Default: 90.

.PARAMETER DeleteThresholdDays
    Days since last sign-in before an already-DISABLED guest is DELETED. Default: 120.
    Must be greater than StaleThresholdDays.

.PARAMETER NeverSignedInDays
    If a guest has never signed in and their invite/creation date is older than this many days,
    they are flagged in the report as NeverSignedIn. Default: 7.

.PARAMETER ReportOnly
    List which guests would be disabled / deleted without making any changes.

.PARAMETER ExcludeDomains
    Guest UPN domains to exclude entirely, e.g. @("partner.com", "vendor.org").

.PARAMETER RunbookMode
    Use Managed Identity (Azure Automation Runbook).

.PARAMETER TenantId
    Entra tenant ID. Required for interactive and app-registration auth.

.PARAMETER ExportPath
    Folder for CSV exports. Defaults to the script directory.

.EXAMPLE
    # Report-only, interactive login
    .\Remove-StaleGuestUsers.ps1 -TenantId "your-tenant-id" -ReportOnly

.EXAMPLE
    # Custom thresholds, exclude a partner domain
    .\Remove-StaleGuestUsers.ps1 -TenantId "your-tenant-id" `
        -StaleThresholdDays 60 -DeleteThresholdDays 90 `
        -ExcludeDomains @("partner.com") -ReportOnly

.EXAMPLE
    # Azure Runbook live run via Managed Identity
    .\Remove-StaleGuestUsers.ps1 -RunbookMode -StaleThresholdDays 90 -DeleteThresholdDays 120

.NOTES
    Author:  LazyAdmin.nl
    Version: 1.0
    Date:    2026-03-12

    Required Microsoft Graph permissions:
      User.Read.All          – list users and sign-in activity
      User.ReadWrite.All     – disable and delete users
      AuditLog.Read.All      – read sign-in activity via signInActivity property
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter()][int]         $StaleThresholdDays   = 90,
    [Parameter()][int]         $DeleteThresholdDays  = 120,
    [Parameter()][int]         $NeverSignedInDays    = 7,
    [Parameter()][switch]      $ReportOnly           = $true,
    [Parameter()][string[]]    $ExcludeDomains       = @(),
    [Parameter()][switch]      $RunbookMode,
    [Parameter()][string]      $TenantId,
    [Parameter()][string]      $ClientId,
    [Parameter()][SecureString]$ClientSecret,
    [Parameter()][string]      $ExportPath           = $PSScriptRoot
)

$ErrorActionPreference = "Stop"

# ─────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────
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

# ─────────────────────────────────────────────────────────────
# Module check / install
# ─────────────────────────────────────────────────────────────
function Assert-Module {
    param([string]$Name)
    if (-not (Get-Module -ListAvailable -Name $Name)) {
        Write-Log "Installing module $Name ..." -Level WARNING
        Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module $Name -Force -ErrorAction Stop
}

# ─────────────────────────────────────────────────────────────
# Connect to Microsoft Graph
# ─────────────────────────────────────────────────────────────
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
            Scopes             = @("User.Read.All","User.ReadWrite.All","AuditLog.Read.All")
            NoWelcome          = $true
        }
        if ($TenantId) { $p.TenantId = $TenantId }
        Connect-MgGraph @p
    }
    Write-Log "Connected to Microsoft Graph." -Level SUCCESS
}

# ─────────────────────────────────────────────────────────────
# Exclusion: guest UPN domain
# ─────────────────────────────────────────────────────────────
function Test-IsExcludedDomain {
    param([string]$UserPrincipalName)
    # Guest UPNs are formatted as name_domain.com#EXT#@tenant.onmicrosoft.com
    # Extract the original domain from the UPN
    if ($UserPrincipalName -match "([^_]+)_([^#]+)#EXT#") {
        $originalDomain = $Matches[2]
        foreach ($domain in $ExcludeDomains) {
            if ($originalDomain -like "*$domain*") { return $true }
        }
    }
    return $false
}

# ─────────────────────────────────────────────────────────────
# CSV export
# ─────────────────────────────────────────────────────────────
function Export-Report {
    param($Data, [string]$Suffix)
    $file = Join-Path $ExportPath "EntraID_GuestUsers_${Suffix}_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $Data | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8
    Write-Log "Report saved: $file" -Level SUCCESS
}


# ═════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════

Write-Log "========================================================"
Write-Log " Entra ID Stale Guest User Cleanup  –  LazyAdmin.nl"
Write-Log " Disable threshold      : $StaleThresholdDays days"
Write-Log " Delete threshold       : $DeleteThresholdDays days"
Write-Log " Never signed-in flag   : $NeverSignedInDays days since invite"
Write-Log " Mode                   : $(if ($ReportOnly) { 'REPORT ONLY – no changes will be made' } else { 'LIVE – guests WILL be disabled / deleted' })"
Write-Log "========================================================"

if ($DeleteThresholdDays -le $StaleThresholdDays) {
    throw "DeleteThresholdDays ($DeleteThresholdDays) must be greater than StaleThresholdDays ($StaleThresholdDays)."
}

# 1. Connect
Connect-ToGraph

# 2. Fetch all guest users with sign-in activity
# Note: signInActivity requires AuditLog.Read.All and the Beta endpoint
Write-Log "Retrieving all Guest users from Entra ID..."

$disableCutoff       = (Get-Date).AddDays(-$StaleThresholdDays)
$deleteCutoff        = (Get-Date).AddDays(-$DeleteThresholdDays)
$neverSignedInCutoff = (Get-Date).AddDays(-$NeverSignedInDays)

# Use the Beta endpoint for signInActivity support
$allGuests = Get-MgUser -All `
    -Filter "userType eq 'Guest'" `
    -Property "Id,DisplayName,UserPrincipalName,AccountEnabled,UserType,
               CreatedDateTime,ExternalUserState,ExternalUserStateChangeDateTime,
               SignInActivity,Mail" |
    Select-Object Id, DisplayName, UserPrincipalName, AccountEnabled, UserType,
                  CreatedDateTime, ExternalUserState, ExternalUserStateChangeDateTime,
                  SignInActivity, Mail

Write-Log "Total guest users found: $($allGuests.Count)"

$toDisable      = [System.Collections.Generic.List[object]]::new()
$toDelete       = [System.Collections.Generic.List[object]]::new()
$neverSignedIn  = [System.Collections.Generic.List[object]]::new()
$skipped        = [System.Collections.Generic.List[object]]::new()

foreach ($guest in $allGuests) {

    $lastSignIn = $null
    if ($guest.SignInActivity -and $guest.SignInActivity.LastSuccessfulSignInDateTime) {
        $lastSignIn = [datetime]$guest.SignInActivity.LastSuccessfulSignInDateTime
    }

    $createdDate = if ($guest.CreatedDateTime) { [datetime]$guest.CreatedDateTime } else { $null }
    $daysSince   = if ($lastSignIn) { [math]::Round(((Get-Date) - $lastSignIn).TotalDays) } else { $null }

    $entry = [PSCustomObject]@{
        DisplayName                     = $guest.DisplayName
        UserPrincipalName               = $guest.UserPrincipalName
        Mail                            = $guest.Mail
        ObjectId                        = $guest.Id
        AccountEnabled                  = $guest.AccountEnabled
        ExternalUserState               = $guest.ExternalUserState
        CreatedDateTime                 = $createdDate
        LastSuccessfulSignInDateTime    = $lastSignIn
        DaysSinceLastSignIn             = $daysSince
        PlannedAction                   = $null
        SkipReason                      = $null
    }

    # ── Exclude by domain ───────────────────────────────────
    if (Test-IsExcludedDomain $guest.UserPrincipalName) {
        $entry.SkipReason    = "ExcludedDomain"
        $entry.PlannedAction = "Skipped"
        $skipped.Add($entry); continue
    }

    # ── Never signed in ─────────────────────────────────────
    if (-not $lastSignIn) {
        if ($createdDate -and $createdDate -lt $neverSignedInCutoff) {
            $entry.PlannedAction = "NeverSignedIn"
            $neverSignedIn.Add($entry)
        }
        else {
            $entry.SkipReason    = "RecentlyInvited"
            $entry.PlannedAction = "Skipped"
            $skipped.Add($entry)
        }
        continue
    }

    # ── Stage 2: delete candidate ───────────────────────────
    if ($lastSignIn -le $deleteCutoff -and $guest.AccountEnabled -eq $false) {
        $entry.PlannedAction = "Delete"
        $toDelete.Add($entry); continue
    }

    # ── Stage 1: disable candidate ──────────────────────────
    if ($lastSignIn -le $disableCutoff -and $guest.AccountEnabled -eq $true) {
        $entry.PlannedAction = "Disable"
        $toDisable.Add($entry)
    }
}

Write-Log "Guests to disable     : $($toDisable.Count)"
Write-Log "Guests to delete      : $($toDelete.Count)"
Write-Log "Never signed in       : $($neverSignedIn.Count)"
Write-Log "Skipped               : $($skipped.Count)"

# 3. Always export a pre-run inventory
Export-Report -Data (@($toDisable) + @($toDelete) + @($neverSignedIn) + @($skipped)) -Suffix "PreCleanup"

if ($toDisable.Count -eq 0 -and $toDelete.Count -eq 0) {
    Write-Log "Nothing to process. Exiting." -Level SUCCESS
    Disconnect-MgGraph | Out-Null
    exit 0
}

if ($ReportOnly) {
    Write-Log "`n── Guests that WOULD be disabled ───────────────────────"
    $toDisable | Format-Table DisplayName, UserPrincipalName, LastSuccessfulSignInDateTime, DaysSinceLastSignIn -AutoSize | Out-String | Write-Output

    Write-Log "── Guests that WOULD be deleted ────────────────────────"
    $toDelete | Format-Table DisplayName, UserPrincipalName, LastSuccessfulSignInDateTime, DaysSinceLastSignIn -AutoSize | Out-String | Write-Output

    Write-Log "── Guests that have NEVER signed in ────────────────────"
    $neverSignedIn | Format-Table DisplayName, UserPrincipalName, CreatedDateTime, ExternalUserState -AutoSize | Out-String | Write-Output

    Write-Log "ReportOnly mode active – no changes were made." -Level WARNING
    Disconnect-MgGraph | Out-Null
    exit 0
}

# ─────────────────────────────────────────────────────────────
# Stage 1 – Disable stale active guests
# ─────────────────────────────────────────────────────────────
Write-Log "--- Stage 1: Disabling stale guests ---"
$disableResults = [System.Collections.Generic.List[object]]::new()

foreach ($guest in $toDisable) {
    try {
        Update-MgUser -UserId $guest.ObjectId -AccountEnabled $false
        Write-Log "Disabled: $($guest.DisplayName) ($($guest.UserPrincipalName))" -Level SUCCESS
        $guest.PlannedAction = "Disabled"
    }
    catch {
        Write-Log "Failed to disable $($guest.DisplayName): $_" -Level WARNING
        $guest.PlannedAction = "DisableFailed – $($_.Exception.Message)"
    }
    $disableResults.Add($guest)
}

# ─────────────────────────────────────────────────────────────
# Stage 2 – Delete disabled stale guests
# ─────────────────────────────────────────────────────────────
Write-Log "--- Stage 2: Deleting disabled stale guests ---"
$deleteResults = [System.Collections.Generic.List[object]]::new()

foreach ($guest in $toDelete) {
    try {
        Remove-MgUser -UserId $guest.ObjectId
        Write-Log "Deleted: $($guest.DisplayName) ($($guest.UserPrincipalName))" -Level SUCCESS
        $guest.PlannedAction = "Deleted"
    }
    catch {
        Write-Log "Failed to delete $($guest.DisplayName): $_" -Level WARNING
        $guest.PlannedAction = "DeleteFailed – $($_.Exception.Message)"
    }
    $deleteResults.Add($guest)
}

# 4. Export final results
Export-Report -Data (@($disableResults) + @($deleteResults) + @($neverSignedIn) + @($skipped)) -Suffix "CleanupResults"

Write-Log "All done." -Level SUCCESS
Disconnect-MgGraph | Out-Null