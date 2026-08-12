# Get-EntraLicenseGap.ps1
# Compares Conditional Access policy targeting against P1/P2 license entitlements
# The license usage blade shows evaluated users - this script shows targeted users

# Required modules
# Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
# Install-Module Microsoft.Graph.Identity.DirectoryManagement -Scope CurrentUser
# Install-Module Microsoft.Graph.Groups -Scope CurrentUser
# Install-Module Microsoft.Graph.Users -Scope CurrentUser

Connect-MgGraph -Scopes "Policy.Read.All","Directory.Read.All","Group.Read.All","GroupMember.Read.All","User.Read.All"

# ── Part 1: Get all enabled CA policies and their user scope ──

Write-Host "`n=== Conditional Access Policy Targeting ===" -ForegroundColor Cyan

$policies = Get-MgIdentityConditionalAccessPolicy -All | 
    Where-Object { $_.State -ne 'disabled' }

# Get total user count for "All users" policies
$allUsers = Get-MgUser -All -ConsistencyLevel eventual -CountVariable totalUsers -Filter "userType eq 'Member'" | 
    Select-Object Id, UserPrincipalName, DisplayName
$totalUserCount = $allUsers.Count

Write-Host "Total member users in tenant: $totalUserCount" -ForegroundColor Yellow

foreach ($policy in $policies) {
    $name = $policy.DisplayName
    $state = $policy.State
    $includeUsers = $policy.Conditions.Users.IncludeUsers
    $includeGroups = $policy.Conditions.Users.IncludeGroups
    $includeRoles = $policy.Conditions.Users.IncludeRoles
    $excludeUsers = $policy.Conditions.Users.ExcludeUsers
    $excludeGroups = $policy.Conditions.Users.ExcludeGroups

    Write-Host "`nPolicy: $name [$state]" -ForegroundColor Green
    
    # Determine targeting
    if ($includeUsers -contains 'All') {
        $excludedCount = 0
        
        # Count excluded users
        $excludedUserIds = @()
        if ($excludeUsers) {
            $excludedUserIds += $excludeUsers | Where-Object { $_ -ne 'GuestsOrExternalUsers' }
        }
        if ($excludeGroups) {
            foreach ($groupId in $excludeGroups) {
                $members = Get-MgGroupMember -GroupId $groupId -All
                $excludedUserIds += $members.Id
            }
        }
        $excludedUserIds = $excludedUserIds | Select-Object -Unique
        $excludedCount = $excludedUserIds.Count
        
        $inScope = $totalUserCount - $excludedCount
        Write-Host "  Target: All users" -ForegroundColor White
        Write-Host "  Excluded: $excludedCount users" -ForegroundColor White
        Write-Host "  Users in scope: $inScope" -ForegroundColor Yellow
    }
    else {
        $includedUserIds = @()
        
        # Specific users
        if ($includeUsers) {
            $includedUserIds += $includeUsers
        }
        
        # Groups
        if ($includeGroups) {
            foreach ($groupId in $includeGroups) {
                $members = Get-MgGroupMember -GroupId $groupId -All
                $includedUserIds += $members.Id
                $groupName = (Get-MgGroup -GroupId $groupId).DisplayName
                Write-Host "  Includes group: $groupName ($($members.Count) members)" -ForegroundColor White
            }
        }

        # Roles
        if ($includeRoles) {
            foreach ($roleId in $includeRoles) {
                Write-Host "  Includes directory role: $roleId" -ForegroundColor White
            }
        }
        
        $includedUserIds = $includedUserIds | Select-Object -Unique
        Write-Host "  Users in scope: $($includedUserIds.Count)" -ForegroundColor Yellow
    }
}

# ── Part 2: Get P1 and P2 license counts ──

Write-Host "`n=== License Entitlements ===" -ForegroundColor Cyan

# Service plan IDs for Entra ID P1 and P2
$p1PlanId = '41781fb2-bc02-4b7c-bd55-b576c07bb09d'  # AAD_PREMIUM
$p2PlanId = 'eec0eb4f-6444-4f95-aba0-50c24d67f998'  # AAD_PREMIUM_P2

$skus = Get-MgSubscribedSku -All

$p1Total = 0
$p2Total = 0
$p1Skus = @()
$p2Skus = @()

foreach ($sku in $skus) {
    $hasP1 = $sku.ServicePlans | Where-Object { $_.ServicePlanId -eq $p1PlanId }
    $hasP2 = $sku.ServicePlans | Where-Object { $_.ServicePlanId -eq $p2PlanId }
    
    if ($hasP2) {
        # P2 includes P1, so count towards both
        $available = $sku.PrepaidUnits.Enabled
        $p2Total += $available
        $p1Total += $available
        $p2Skus += "$($sku.SkuPartNumber) ($available)"
    }
    elseif ($hasP1) {
        $available = $sku.PrepaidUnits.Enabled
        $p1Total += $available
        $p1Skus += "$($sku.SkuPartNumber) ($available)"
    }
}

Write-Host "P1 licenses (total): $p1Total" -ForegroundColor White
if ($p1Skus) { Write-Host "  From: $($p1Skus -join ', ')" -ForegroundColor Gray }
Write-Host "P2 licenses (total): $p2Total" -ForegroundColor White
if ($p2Skus) { Write-Host "  From: $($p2Skus -join ', ')" -ForegroundColor Gray }

# ── Part 3: Compare and show the gap ──

Write-Host "`n=== License Gap Analysis ===" -ForegroundColor Cyan

# Find the broadest CA policy scope (the one that determines your P1 obligation)
$maxScope = 0
$broadestPolicy = ""

foreach ($policy in $policies) {
    if ($policy.Conditions.Users.IncludeUsers -contains 'All') {
        $excludedUserIds = @()
        if ($policy.Conditions.Users.ExcludeUsers) {
            $excludedUserIds += $policy.Conditions.Users.ExcludeUsers | Where-Object { $_ -ne 'GuestsOrExternalUsers' }
        }
        if ($policy.Conditions.Users.ExcludeGroups) {
            foreach ($groupId in $policy.Conditions.Users.ExcludeGroups) {
                $members = Get-MgGroupMember -GroupId $groupId -All
                $excludedUserIds += $members.Id
            }
        }
        $scope = $totalUserCount - ($excludedUserIds | Select-Object -Unique).Count
        if ($scope -gt $maxScope) {
            $maxScope = $scope
            $broadestPolicy = $policy.DisplayName
        }
    }
}

if ($maxScope -gt 0) {
    Write-Host "Broadest CA policy: $broadestPolicy" -ForegroundColor White
    Write-Host "Users targeted: $maxScope" -ForegroundColor White
    Write-Host "P1 licenses available: $p1Total" -ForegroundColor White
    
    $gap = $maxScope - $p1Total
    if ($gap -gt 0) {
        Write-Host "`nLICENSE GAP: $gap users targeted without a P1 license" -ForegroundColor Red
    }
    else {
        Write-Host "`nNo gap - you have enough P1 licenses for your CA targeting" -ForegroundColor Green
    }
}

# Also check for risk-based policies (P2 requirement)
$riskPolicies = $policies | Where-Object {
    $_.Conditions.UserRiskLevels -or $_.Conditions.SignInRiskLevels
}

if ($riskPolicies) {
    Write-Host "`nRisk-based CA policies found (require P2):" -ForegroundColor Yellow
    foreach ($rp in $riskPolicies) {
        Write-Host "  $($rp.DisplayName)" -ForegroundColor White
    }
}

Write-Host "`nDone. Review the gap above and compare with the license usage blade." -ForegroundColor Cyan
Write-Host "The blade shows evaluated users. This script shows targeted users." -ForegroundColor Cyan
Write-Host "Your licensing obligation is based on targeting, not evaluation.`n" -ForegroundColor Yellow