<#
.SYNOPSIS
    GCC High variant of GrantPermissions.ps1 for STATv2 (https://aka.ms/mstat).

.DESCRIPTION
    Configures API and RBAC permissions for the STAT identity in US Government cloud
    environments (GCC High, GCC, DoD).

    Differences from the commercial version:
    - Connect-MgGraph is called with -Environment USGov (GCC High / GCC) or
      -Environment USGovDoD (DoD). Set the -CloudEnvironment parameter to switch.
    - Connect-AzAccount / Login-AzAccount is called with -Environment AzureUSGovernment.
    - The two Entra permissions that Microsoft does NOT publish to GCC/GCCH/DoD
      (SecurityAnalyzedMessage.Read.All and ThreatIntelligence.Read.All) are commented
      out so the script does not fail trying to assign them.

    Usage (interactive):
      .\GrantPermissions.ps1

    Usage (fully parameterised):
      .\GrantPermissions.ps1 `
        -TenantId <TenantId> `
        -AzureSubscriptionId <AzureSubscriptionId> `
        -SentinelResourceGroupName <SentinelResourceGroupName> `
        -STATIdentityName <STATIdentityName> `
        -CloudEnvironment USGov

.PARAMETER CloudEnvironment
    Which US Government cloud to connect to.
    USGov  = GCC High and GCC (default)
    USGovDoD = DoD IL5

.PARAMETER TenantId
.PARAMETER AzureSubscriptionId
.PARAMETER SentinelResourceGroupName
.PARAMETER STATIdentityName
.PARAMETER SampleLogicAppName
.PARAMETER DeviceCodeFlow
    See the commercial version for descriptions.

.NOTES
    Required modules (install once):
      Install-Module Microsoft.Graph.Applications -Scope CurrentUser -Force
      Install-Module -Name Az.Resources -Scope CurrentUser -Repository PSGallery -Force
#>

param(
    [Parameter(Mandatory=$true)]
    [string] $TenantId,
    [Parameter(Mandatory=$true)]
    [string] $AzureSubscriptionId,
    [Parameter(Mandatory=$true)]
    [string] $SentinelResourceGroupName,
    [Parameter(Mandatory=$true)]
    [string] $STATIdentityName,
    [Parameter(Mandatory=$false)]
    [string] $SampleLogicAppName,
    [Parameter(Mandatory=$false)]
    [bool] $DeviceCodeFlow = $false,
    [Parameter(Mandatory=$false)]
    [ValidateSet('USGov','USGovDoD')]
    [string] $CloudEnvironment = 'USGov'
)

#Requires -Modules Microsoft.Graph.Applications, Az.Resources

# Map CloudEnvironment to the per-SDK environment names each cmdlet expects.
# MgGraph values: USGov (GCC High / GCC), USGovDoD (DoD)
# Az values:     AzureUSGovernment (covers both GCC High and DoD)
$MgEnvironment = $CloudEnvironment
$AzEnvironment = 'AzureUSGovernment'

if( $env:AZUREPS_HOST_ENVIRONMENT -like "cloud-shell*" ) {
    Write-Host "[+] Running in Azure Cloud Shell. Device Code flow will be used."
    Write-Host "[+] Note: the connection will appear to come from the Azure data center, not your client." -ForegroundColor Yellow
    $DeviceCodeFlow = $true
}

Write-Host "[+] Connecting to Microsoft Graph in environment '$MgEnvironment' for tenant: $TenantId"
if ( $DeviceCodeFlow -eq $true ) {
    Connect-MgGraph -TenantId $TenantId -Environment $MgEnvironment `
        -Scopes AppRoleAssignment.ReadWrite.All, Application.Read.All `
        -NoWelcome -ErrorAction Stop
} else {
    Connect-MgGraph -TenantId $TenantId -Environment $MgEnvironment `
        -Scopes AppRoleAssignment.ReadWrite.All, Application.Read.All `
        -NoWelcome -ErrorAction Stop | Out-Null
}

Write-Host "[+] Connecting to Azure subscription '$AzureSubscriptionId' in environment '$AzEnvironment'"
try
{
    if ( $DeviceCodeFlow -eq $true ) {
        Connect-AzAccount -Subscription $AzureSubscriptionId -Tenant $TenantId `
            -Environment $AzEnvironment -ErrorAction Stop -UseDeviceAuthentication
    } else {
        Login-AzAccount -Subscription $AzureSubscriptionId -Tenant $TenantId `
            -Environment $AzEnvironment -ErrorAction Stop | Out-Null
    }
}
catch
{
    Write-Host "[-] Login to Azure Management failed. $($error[0])" -ForegroundColor Red
    return
}

function Set-APIPermissions ($MSIName, $AppId, $PermissionName) {
    Write-Host "[+] Setting permission $PermissionName on $MSIName"
    $MSI = Get-AppIds -AppName $MSIName
    if ( $MSI.count -gt 1 )
    {
        Write-Host "[-] Found multiple principals with the same name." -ForegroundColor Red
        return
    } elseif ( $MSI.count -eq 0 ) {
        Write-Host "[-] Principal not found." -ForegroundColor Red
        return
    }
    Start-Sleep -Seconds 2
    $GraphServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$AppId'"
    if ( $null -eq $GraphServicePrincipal ) {
        Write-Host "[-] Service principal for AppId $AppId not found in this tenant. The resource provider may not be registered in this cloud." -ForegroundColor Red
        return
    }
    $AppRole = $GraphServicePrincipal.AppRoles | Where-Object {$_.Value -eq $PermissionName -and $_.AllowedMemberTypes -contains "Application"}
    if ( $null -eq $AppRole ) {
        Write-Host "[-] AppRole '$PermissionName' not published on AppId $AppId in this cloud. Skipping." -ForegroundColor Yellow
        return
    }
    try
    {
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $MSI.Id -PrincipalId $MSI.Id `
            -ResourceId $GraphServicePrincipal.Id -AppRoleId $AppRole.Id -ErrorAction Stop | Out-Null
    }
    catch
    {
        if ( $_.Exception.Message -eq "Permission being assigned already exists on the object" )
        {
            Write-Host "[-] $($_.Exception.Message)"
        } else {
            Write-Host "[-] $($_.Exception.Message)" -ForegroundColor Red
        }
        return
    }
    Write-Host "[+] Permission granted" -ForegroundColor Green
}

function Get-AppIds ($AppName) {
    Get-MgServicePrincipal -Filter "displayName eq '$AppName'"
}

function Set-RBACPermissions ($MSIName, $Role) {
    Write-Host "Adding $Role to $MSIName"
    $MSI = Get-AppIds -AppName $MSIName
    if ( $MSI.count -gt 1 )
    {
        Write-Host "[-] Found multiple principals with the same name." -ForegroundColor Red
        return
    } elseif ( $MSI.count -eq 0 ) {
        Write-Host "[-] Principal not found." -ForegroundColor Red
        return
    }
    $Assign = New-AzRoleAssignment -ApplicationId $MSI.AppId `
        -Scope "/subscriptions/$($AzureSubscriptionId)/resourceGroups/$($SentinelResourceGroupName)" `
        -RoleDefinitionName $Role -ErrorAction SilentlyContinue -ErrorVariable AzError
    if ( $null -ne $Assign )
    {
        Write-Host "[+] Role added" -ForegroundColor Green
    } elseif ( $AzError[0].Exception.Message -like "*Conflict*" ) {
        Write-Host "[-] Role already assigned"
    } else {
        Write-Host "[-] $($AzError[0].Exception.Message)" -ForegroundColor Red
    }
}

Set-RBACPermissions -MSIName $STATIdentityName -Role "Microsoft Sentinel Responder"
Set-APIPermissions -MSIName $STATIdentityName -AppId "ca7f3f0b-7d91-482c-8e09-c5d840d0eac5" -PermissionName "Data.Read"
Set-APIPermissions -MSIName $STATIdentityName -AppId "00000003-0000-0000-c000-000000000000" -PermissionName "MailboxSettings.Read"
Set-APIPermissions -MSIName $STATIdentityName -AppId "00000003-0000-0000-c000-000000000000" -PermissionName "Mail.ReadBasic.All"
Set-APIPermissions -MSIName $STATIdentityName -AppId "fc780465-2017-40d4-a0c5-307022471b92" -PermissionName "AdvancedQuery.Read.All"
Set-APIPermissions -MSIName $STATIdentityName -AppId "fc780465-2017-40d4-a0c5-307022471b92" -PermissionName "Machine.Read.All"
Set-APIPermissions -MSIName $STATIdentityName -AppId "fc780465-2017-40d4-a0c5-307022471b92" -PermissionName "File.Read.All"
#Set-APIPermissions -MSIName $STATIdentityName -AppId "05a65629-4c1b-48c1-a78b-804c4abdd4af" -PermissionName "investigation.read"
Set-APIPermissions -MSIName $STATIdentityName -AppId "00000003-0000-0000-c000-000000000000" -PermissionName "Directory.Read.All"
Set-APIPermissions -MSIName $STATIdentityName -AppId "00000003-0000-0000-c000-000000000000" -PermissionName "Reports.Read.All"
Set-APIPermissions -MSIName $STATIdentityName -AppId "00000003-0000-0000-c000-000000000000" -PermissionName "AuditLog.Read.All"
Set-APIPermissions -MSIName $STATIdentityName -AppId "00000003-0000-0000-c000-000000000000" -PermissionName "RoleManagement.Read.Directory"
Set-APIPermissions -MSIName $STATIdentityName -AppId "8ee8fdad-f234-4243-8f3b-15c294843740" -PermissionName "AdvancedHunting.Read.All"
Set-APIPermissions -MSIName $STATIdentityName -AppId "00000003-0000-0000-c000-000000000000" -PermissionName "IdentityRiskyUser.Read.All"
Set-APIPermissions -MSIName $STATIdentityName -AppId "00000003-0000-0000-c000-000000000000" -PermissionName "IdentityRiskEvent.Read.All"

# NOT SUPPORTED IN GCC / GCC HIGH / DOD — commented out for US Government deployments.
# The upstream commercial script notes these are unavailable in US Government clouds.
# Any STAT module that depends on them (e.g. Microsoft Defender for Office email analysis,
# Microsoft Defender Threat Intelligence lookups) will degrade or need to be disabled in your playbooks.
#Set-APIPermissions -MSIName $STATIdentityName -AppId "00000003-0000-0000-c000-000000000000" -PermissionName "SecurityAnalyzedMessage.Read.All"
#Set-APIPermissions -MSIName $STATIdentityName -AppId "00000003-0000-0000-c000-000000000000" -PermissionName "ThreatIntelligence.Read.All"

#Triage-Content Sample
if ( $PSBoundParameters.ContainsKey('SampleLogicAppName') ) {
    Set-RBACPermissions -MSIName $SampleLogicAppName -Role "Microsoft Sentinel Responder"
}

Write-Host "[+] End of the script. Please review the output and check for potential failures."
