param(
    [Parameter(Mandatory)]
    [string]$CsvPath   # the EWSWeeklyUsage_*.csv you downloaded from the usage report
)

Connect-MgGraph -Scopes "Application.Read.All","Directory.Read.All"

# Known Microsoft first-party AppIDs that don't always resolve as a service principal.
# Starter set only - the authoritative list is Microsoft's apps-to-allow page.
$knownFirstParty = @{
    "00000002-0000-0ff1-ce00-000000000000" = "Office 365 Exchange Online"
    "d3590ed6-52b3-4102-aeff-aad2292ab01c" = "Microsoft Office / Outlook (classic)"
    "774a8455-3122-4fd5-90f1-c4d1a062ad91" = "Microsoft 365 admin center EWS health probe"
}

function Resolve-AppName {
    param([string]$AppId)

    # 1. Enterprise application (service principal) - resolves iOS Accounts, your own apps, most first-party
    $sp = Get-MgServicePrincipal -Filter "appId eq '$AppId'" -ErrorAction SilentlyContinue
    if ($sp)  { return [pscustomobject]@{ Name=$sp.DisplayName;  Source="Enterprise application" } }

    # 2. App registration you own
    $app = Get-MgApplication -Filter "appId eq '$AppId'" -ErrorAction SilentlyContinue
    if ($app) { return [pscustomobject]@{ Name=$app.DisplayName; Source="App registration" } }

    # 3. Known first-party fallback for the phantom IDs
    if ($knownFirstParty.ContainsKey($AppId)) {
        return [pscustomobject]@{ Name=$knownFirstParty[$AppId]; Source="Known first-party" }
    }

    # 4. Give up gracefully
    return [pscustomobject]@{ Name="Unknown - likely Microsoft first-party (check apps-to-allow)"; Source="Not found in tenant" }
}

# Import the usage report and roll it up per AppID
$usage = Import-Csv -Path $CsvPath

$report = $usage | Group-Object AppID | ForEach-Object {
    $resolved = Resolve-AppName $_.Name
    [pscustomobject]@{
        AppId      = $_.Name
        Name       = $resolved.Name
        Source     = $resolved.Source
        TotalCalls = ($_.Group | Measure-Object CallVolume -Sum).Sum
        Operations = ($_.Group.SoapAction | Sort-Object -Unique) -join ', '
        LastSeen   = ($_.Group.Date | Sort-Object | Select-Object -Last 1)
    }
}

$report | Sort-Object TotalCalls -Descending | Format-Table AppId, Name, Source, TotalCalls, LastSeen -AutoSize
$report | Export-Csv -Path .\EWS-ResolvedApps.csv -NoTypeInformation -Encoding UTF8
Write-Host "Resolved $($report.Count) app(s) from the usage report" -ForegroundColor Yellow