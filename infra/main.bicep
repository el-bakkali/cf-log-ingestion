// ============================================================================
// Cloudflare Log Ingestion — Azure Infrastructure
// Deploys: Log Analytics, Custom Table, DCR, Storage, Key Vault, App Insights
// Usage: az deployment group create -g <rg-name> -f main.bicep -p cfApiToken='<token>'
// ============================================================================

@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Cloudflare API token (read-only, stored in Key Vault).')
@secure()
param cfApiToken string

@description('Cloudflare zones as a JSON array. Example: [{"id":"abc123","name":"example.com"}]')
param cfZones string

@description('Log Analytics workspace name.')
param workspaceName string = 'law-cf-security'

@description('Data Collection Rule name.')
param dcrName string = 'dcr-cf-firewall'

@description('Storage account name (must be globally unique, 3-24 chars, lowercase alphanumeric).')
param storageName string

@description('Function App name (must be globally unique).')
param functionAppName string

@description('Key Vault name (must be globally unique, 3-24 chars).')
param keyVaultName string

@description('Log Analytics daily cap in GB. Set to -1 for unlimited.')
param lawDailyCapGb int = 1

@description('App Insights daily cap in GB.')
param appInsightsDailyCapGb string = '0.5'

// ============================================================================
// Log Analytics Workspace
// ============================================================================

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 90
    workspaceCapping: {
      dailyQuotaGb: lawDailyCapGb
    }
  }
}

// ============================================================================
// Custom Table: CloudflareFirewall_CL (23 columns)
// ============================================================================

resource table 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  parent: workspace
  name: 'CloudflareFirewall_CL'
  properties: {
    schema: {
      name: 'CloudflareFirewall_CL'
      columns: [
        { name: 'TimeGenerated', type: 'dateTime', description: 'Event timestamp from Cloudflare' }
        { name: 'Zone', type: 'string', description: 'Cloudflare zone name' }
        { name: 'Action', type: 'string', description: 'Firewall action taken (block, challenge, etc.)' }
        { name: 'ClientIP', type: 'string', description: 'Source IP address' }
        { name: 'ClientCountry', type: 'string', description: 'Source country' }
        { name: 'ClientASN', type: 'string', description: 'Source AS number' }
        { name: 'ClientASNDescription', type: 'string', description: 'Source ASN organisation name' }
        { name: 'RequestPath', type: 'string', description: 'HTTP request path' }
        { name: 'RequestQuery', type: 'string', description: 'HTTP query string' }
        { name: 'RequestMethod', type: 'string', description: 'HTTP method (GET, POST, etc.)' }
        { name: 'RequestHost', type: 'string', description: 'HTTP Host header value' }
        { name: 'UserAgent', type: 'string', description: 'Client User-Agent string' }
        { name: 'RayID', type: 'string', description: 'Cloudflare Ray ID (unique request identifier)' }
        { name: 'RuleDescription', type: 'string', description: 'WAF rule description that matched' }
        { name: 'Source', type: 'string', description: 'Firewall event source (firewallCustom, ratelimit, etc.)' }
        { name: 'RuleId', type: 'string', description: 'WAF rule ID' }
        { name: 'RefererHost', type: 'string', description: 'HTTP Referer host' }
        { name: 'EdgeResponseStatus', type: 'int', description: 'HTTP response status code from Cloudflare edge' }
        { name: 'ClientIPClass', type: 'string', description: 'IP classification (clean, badHost, etc.)' }
        { name: 'HttpProtocol', type: 'string', description: 'HTTP protocol version (HTTP/1.1, HTTP/2, etc.)' }
        { name: 'RulesetId', type: 'string', description: 'Ruleset ID containing the matched rule' }
        { name: 'SampleInterval', type: 'int', description: 'Sampling interval (1 = every event captured)' }
        { name: 'Kind', type: 'string', description: 'Event kind (firewall)' }
      ]
    }
    retentionInDays: 90
  }
}

// ============================================================================
// Data Collection Rule (Direct ingestion, no DCE required)
// ============================================================================

resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dcrName
  location: location
  kind: 'Direct'
  properties: {
    streamDeclarations: {
      'Custom-CloudflareFirewall_CL': {
        columns: [
          { name: 'TimeGenerated', type: 'datetime' }
          { name: 'Zone', type: 'string' }
          { name: 'Action', type: 'string' }
          { name: 'ClientIP', type: 'string' }
          { name: 'ClientCountry', type: 'string' }
          { name: 'ClientASN', type: 'string' }
          { name: 'ClientASNDescription', type: 'string' }
          { name: 'RequestPath', type: 'string' }
          { name: 'RequestQuery', type: 'string' }
          { name: 'RequestMethod', type: 'string' }
          { name: 'RequestHost', type: 'string' }
          { name: 'UserAgent', type: 'string' }
          { name: 'RayID', type: 'string' }
          { name: 'RuleDescription', type: 'string' }
          { name: 'Source', type: 'string' }
          { name: 'RuleId', type: 'string' }
          { name: 'RefererHost', type: 'string' }
          { name: 'EdgeResponseStatus', type: 'int' }
          { name: 'ClientIPClass', type: 'string' }
          { name: 'HttpProtocol', type: 'string' }
          { name: 'RulesetId', type: 'string' }
          { name: 'SampleInterval', type: 'int' }
          { name: 'Kind', type: 'string' }
        ]
      }
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: workspace.id
          name: 'LogAnalyticsDest'
        }
      ]
    }
    dataFlows: [
      {
        streams: [ 'Custom-CloudflareFirewall_CL' ]
        destinations: [ 'LogAnalyticsDest' ]
        transformKql: 'source'
        outputStream: 'Custom-CloudflareFirewall_CL'
      }
    ]
  }
  dependsOn: [ table ]
}

// ============================================================================
// Storage Account
// ============================================================================

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
  }
}

// ============================================================================
// Key Vault (RBAC auth, purge protection enabled)
// ============================================================================

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
    enablePurgeProtection: true
    softDeleteRetentionInDays: 90
  }
}

resource cfApiTokenSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'cf-api-token'
  properties: {
    value: cfApiToken
  }
}

// ============================================================================
// Application Insights (linked to Log Analytics workspace)
// ============================================================================

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: functionAppName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: workspace.id
  }
}

// ============================================================================
// Outputs (used by deploy.ps1 for Function App configuration)
// ============================================================================

output workspaceId string = workspace.id
output workspaceCustomerId string = workspace.properties.customerId
output dcrImmutableId string = dcr.properties.immutableId
output dcrEndpoint string = dcr.properties.logsIngestion.endpoint
output dcrResourceId string = dcr.id
output keyVaultName string = keyVault.name
output keyVaultId string = keyVault.id
output appInsightsKey string = appInsights.properties.InstrumentationKey
output appInsightsConnectionString string = appInsights.properties.ConnectionString
