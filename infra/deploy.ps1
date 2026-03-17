# ============================================================================
# Cloudflare Log Ingestion — Full Deployment Script
# Deploys all Azure infrastructure and the Function App in one step.
# ============================================================================
# Prerequisites:
#   - Azure CLI (az) installed and logged in
#   - Azure Functions Core Tools (func) installed
#   - PowerShell 7+
# Usage:
#   .\deploy.ps1
# ============================================================================

#Requires -Version 7.0

$ErrorActionPreference = "Stop"

# ============================================================================
# CONFIGURATION — Edit these values before running
# ============================================================================

$subscriptionId   = "<your-azure-subscription-id>"
$resourceGroup    = "rg-cf-log-ingestion"
$location         = "uksouth"                      # Change to your preferred region
$workspaceName    = "law-cf-security"
$dcrName          = "dcr-cf-firewall"
$storageName      = "<your-storage-account-name>"  # Must be globally unique, lowercase, 3-24 chars
$functionAppName  = "<your-function-app-name>"     # Must be globally unique
$keyVaultName     = "<your-keyvault-name>"         # Must be globally unique, 3-24 chars
$cfApiToken       = "<your-cloudflare-api-token>"  # Read-only token with Zone:Analytics:Read
$cfZones          = '[{"id":"<zone-id-1>","name":"example.com"},{"id":"<zone-id-2>","name":"other.com"}]'

# ============================================================================
# DEPLOYMENT
# ============================================================================

Write-Host "============================================" -ForegroundColor Cyan
Write-Host " Cloudflare Log Ingestion — Azure Setup" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# --- Set subscription ---
Write-Host "`n[1/7] Setting Azure subscription..." -ForegroundColor Yellow
az account set --subscription $subscriptionId

# --- Create Resource Group ---
Write-Host "`n[2/7] Creating resource group: $resourceGroup..." -ForegroundColor Yellow
az group create --name $resourceGroup --location $location --output none

# --- Deploy Bicep template ---
Write-Host "`n[3/7] Deploying infrastructure (Bicep)..." -ForegroundColor Yellow
$deployment = az deployment group create `
    --resource-group $resourceGroup `
    --template-file "$PSScriptRoot\main.bicep" `
    --parameters `
        cfApiToken=$cfApiToken `
        cfZones=$cfZones `
        storageName=$storageName `
        functionAppName=$functionAppName `
        keyVaultName=$keyVaultName `
        workspaceName=$workspaceName `
        dcrName=$dcrName `
        location=$location `
    --query "properties.outputs" `
    --output json | ConvertFrom-Json

$dcrImmutableId    = $deployment.dcrImmutableId.value
$dcrEndpoint       = $deployment.dcrEndpoint.value
$dcrResourceId     = $deployment.dcrResourceId.value
$kvId              = $deployment.keyVaultId.value
$aiKey             = $deployment.appInsightsKey.value
$aiConnectionStr   = $deployment.appInsightsConnectionString.value
$workspaceId       = $deployment.workspaceId.value

Write-Host "  DCR Immutable ID: $dcrImmutableId"
Write-Host "  Ingestion Endpoint: $dcrEndpoint"

# --- Create Flex Consumption Function App ---
Write-Host "`n[4/7] Creating Flex Consumption Function App..." -ForegroundColor Yellow
az functionapp create `
    --name $functionAppName `
    --resource-group $resourceGroup `
    --storage-account $storageName `
    --flexconsumption-location $location `
    --runtime python `
    --runtime-version 3.11 `
    --app-insights $functionAppName `
    --app-insights-key $aiKey `
    --instance-memory 512 `
    --output none

# Set max instances to 2 (timer trigger only needs 1, second is for resilience)
az functionapp scale config set `
    --name $functionAppName `
    --resource-group $resourceGroup `
    --maximum-instance-count 2 `
    --output none

# Enable System-Assigned Managed Identity
Write-Host "  Enabling Managed Identity..."
$identityResult = az functionapp identity assign `
    --name $functionAppName `
    --resource-group $resourceGroup `
    --output json | ConvertFrom-Json
$principalId = $identityResult.principalId
Write-Host "  Principal ID: $principalId"

# --- Assign RBAC roles ---
Write-Host "`n[5/7] Assigning RBAC roles to Managed Identity..." -ForegroundColor Yellow
Write-Host "  Waiting 20s for identity propagation..."
Start-Sleep -Seconds 20

# Monitoring Metrics Publisher on DCR (required for log ingestion)
az role assignment create `
    --assignee-object-id $principalId `
    --assignee-principal-type ServicePrincipal `
    --role "Monitoring Metrics Publisher" `
    --scope $dcrResourceId `
    --output none
Write-Host "  Monitoring Metrics Publisher on DCR"

# Key Vault Secrets User (to read the CF API token)
az role assignment create `
    --assignee-object-id $principalId `
    --assignee-principal-type ServicePrincipal `
    --role "Key Vault Secrets User" `
    --scope $kvId `
    --output none
Write-Host "  Key Vault Secrets User on Key Vault"

# --- Configure Function App settings ---
Write-Host "`n[6/7] Configuring app settings..." -ForegroundColor Yellow

$kvRef = "@Microsoft.KeyVault(SecretUri=https://${keyVaultName}.vault.azure.net/secrets/cf-api-token/)"

# Write settings to a temp JSON file to avoid shell escaping issues
$settingsFile = Join-Path $env:TEMP "cf-func-settings.json"
@(
    @{ name = "CF_API_TOKEN";    value = $kvRef }
    @{ name = "CF_ZONES";        value = $cfZones }
    @{ name = "DCR_IMMUTABLE_ID"; value = $dcrImmutableId }
    @{ name = "DCR_STREAM_NAME"; value = "Custom-CloudflareFirewall_CL" }
    @{ name = "DCR_ENDPOINT";    value = $dcrEndpoint }
) | ConvertTo-Json | Set-Content -Path $settingsFile

az functionapp config appsettings set `
    --name $functionAppName `
    --resource-group $resourceGroup `
    --settings "@$settingsFile" `
    --output none

Remove-Item $settingsFile -ErrorAction SilentlyContinue
Write-Host "  App settings configured (CF token via Key Vault reference)"

# --- Set App Insights daily cap ---
az monitor app-insights component billing update `
    --app $functionAppName `
    --resource-group $resourceGroup `
    --cap 0.5 `
    --output none
Write-Host "  App Insights daily cap set to 0.5 GB"

# --- Deploy Function code ---
Write-Host "`n[7/7] Deploying function code..." -ForegroundColor Yellow
$repoRoot = Split-Path $PSScriptRoot -Parent
Push-Location $repoRoot
func azure functionapp publish $functionAppName
Pop-Location

# --- Summary ---
Write-Host "`n============================================" -ForegroundColor Green
Write-Host " Deployment Complete" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Resource Group:      $resourceGroup"
Write-Host "Log Analytics:       $workspaceName"
Write-Host "Custom Table:        CloudflareFirewall_CL"
Write-Host "DCR:                 $dcrName ($dcrImmutableId)"
Write-Host "Ingestion Endpoint:  $dcrEndpoint"
Write-Host "Key Vault:           $keyVaultName"
Write-Host "Function App:        $functionAppName (Flex Consumption, Python 3.11)"
Write-Host "Managed Identity:    $principalId"
Write-Host ""
Write-Host "The function runs every 1 minute. Check Application Insights" -ForegroundColor Yellow
Write-Host "for execution logs, or query CloudflareFirewall_CL in Log Analytics." -ForegroundColor Yellow
