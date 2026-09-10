Connect-MgGraph -Scopes "Application.Read.All","Directory.Read.All","AuditLog.Read.All"

$exoAppId  = "00000002-0000-0ff1-ce00-000000000000"   # Office 365 Exchange Online
$ewsRoleId = "dc890d15-9560-4a4c-9b7f-a736ec74ec40"   # full_access_as_app

$exo = Get-MgServicePrincipal -Filter "appId eq '$exoAppId'"

# Every app granted an app role on Exchange Online, filtered to the EWS role
$ewsApps = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $exo.Id -All |
    Where-Object { $_.AppRoleId -eq $ewsRoleId }

$report = foreach ($assignment in $ewsApps) {

    $sp = Get-MgServicePrincipal -ServicePrincipalId $assignment.PrincipalId -ErrorAction SilentlyContinue

    # Sign-in activity lives on the beta endpoint
    $lastSignIn = $null
    try {
        $activity = Invoke-MgGraphRequest -Method GET `
            -Uri "https://graph.microsoft.com/beta/servicePrincipals/$($assignment.PrincipalId)?`$select=signInActivity"
        $lastSignIn = $activity.signInActivity.lastSignInDateTime
    } catch {}

    [pscustomobject]@{
        AppName     = $assignment.PrincipalDisplayName
        AppId       = $sp.AppId
        ObjectId    = $assignment.PrincipalId
        Permission  = "full_access_as_app (application)"
        LastSignIn  = $lastSignIn
    }
}

$report | Sort-Object LastSignIn -Descending | Format-Table -AutoSize
$report | Export-Csv -Path .\EWS-AppPermissions.csv -NoTypeInformation -Encoding UTF8
Write-Host "Found $($report.Count) app(s) with EWS application permission" -ForegroundColor Yellow