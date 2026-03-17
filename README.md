# Cloudflare Log Ingestion to Azure Log Analytics

Automated pipeline that ingests Cloudflare WAF firewall events into Azure Log Analytics using a Python Azure Function and the Log Ingestion API. Runs every minute, queries the Cloudflare GraphQL Analytics API, and writes to a custom table for alerting, threat hunting, and security monitoring.

## Architecture

```
Cloudflare GraphQL API
        |
        | (every 1 minute)
        v
Azure Function (Python 3.11, Flex Consumption)
        |
        | DefaultAzureCredential + Managed Identity
        v
Data Collection Rule (Direct ingestion, no DCE)
        |
        v
Log Analytics: CloudflareFirewall_CL (23 columns)
```

The function authenticates to Cloudflare using an API token stored in Azure Key Vault (referenced via `@Microsoft.KeyVault()` syntax). It authenticates to Azure using a system-assigned managed identity with the `Monitoring Metrics Publisher` role on the Data Collection Rule.

No Data Collection Endpoint (DCE) is required. DCRs with `kind: Direct` expose their own ingestion endpoint.

## What Gets Ingested

Each firewall event is mapped to a 23-column custom table:

| Column | Type | Description |
|--------|------|-------------|
| TimeGenerated | datetime | Event timestamp from Cloudflare |
| Zone | string | Cloudflare zone name |
| Action | string | Firewall action (block, challenge, managed_challenge, etc.) |
| ClientIP | string | Source IP address |
| ClientCountry | string | Source country |
| ClientASN | string | Source AS number |
| ClientASNDescription | string | ASN organisation name |
| RequestPath | string | HTTP request path |
| RequestQuery | string | HTTP query string |
| RequestMethod | string | HTTP method |
| RequestHost | string | HTTP Host header |
| UserAgent | string | Client User-Agent string |
| RayID | string | Cloudflare Ray ID (unique request identifier) |
| RuleDescription | string | WAF rule description that matched |
| Source | string | Event source (firewallCustom, ratelimit, botFight, etc.) |
| RuleId | string | WAF rule ID |
| RefererHost | string | HTTP Referer host |
| EdgeResponseStatus | int | Response status code from Cloudflare edge |
| ClientIPClass | string | IP classification (clean, badHost, searchEngine, etc.) |
| HttpProtocol | string | HTTP protocol version |
| RulesetId | string | Ruleset ID containing the matched rule |
| SampleInterval | int | Sampling interval (1 = every event captured) |
| Kind | string | Event kind |

## Prerequisites

- An Azure subscription
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) installed and authenticated
- [Azure Functions Core Tools](https://learn.microsoft.com/en-us/azure/azure-functions/functions-run-local) v4+
- PowerShell 7+
- A Cloudflare account with at least one zone
- A Cloudflare API token with **Zone > Analytics > Read** permission

### Creating the Cloudflare API Token

1. Go to [Cloudflare Dashboard > My Profile > API Tokens](https://dash.cloudflare.com/profile/api-tokens)
2. Click **Create Token**
3. Use the **Custom token** template
4. Set permissions: **Zone > Analytics > Read**
5. Set zone resources: **Include > Specific zone** (select your zones)
6. Create the token and save it

## Deployment

### 1. Clone the repository

```bash
git clone https://github.com/el-bakkali/cf-log-ingestion.git
cd cf-log-ingestion
```

### 2. Configure

Edit `infra/deploy.ps1` and fill in the configuration section at the top:

```powershell
$subscriptionId   = "<your-azure-subscription-id>"
$resourceGroup    = "rg-cf-log-ingestion"
$location         = "uksouth"
$storageName      = "<your-storage-account-name>"    # Globally unique
$functionAppName  = "<your-function-app-name>"       # Globally unique
$keyVaultName     = "<your-keyvault-name>"           # Globally unique
$cfApiToken       = "<your-cloudflare-api-token>"
$cfZones          = '[{"id":"<zone-id-1>","name":"example.com"}]'
```

Your Cloudflare zone ID is on the **Overview** page of each zone in the Cloudflare dashboard (right sidebar).

### 3. Deploy

```powershell
cd infra
.\deploy.ps1
```

The script will:

1. Create the resource group
2. Deploy all Azure infrastructure via Bicep (Log Analytics workspace, custom table, DCR, storage account, Key Vault, Application Insights)
3. Create a Flex Consumption Function App (Python 3.11, 512 MB, max 2 instances)
4. Enable a system-assigned managed identity
5. Assign RBAC roles (Monitoring Metrics Publisher on DCR, Key Vault Secrets User)
6. Configure app settings with Key Vault references
7. Deploy the function code

## Querying the Data

Once events start flowing, query them in Log Analytics:

```kusto
// All events from the last hour
CloudflareFirewall_CL
| where TimeGenerated > ago(1h)
| project TimeGenerated, Zone, Action, ClientIP, ClientCountry, RequestPath, Source, RuleDescription
| order by TimeGenerated desc

// Top blocked IPs
CloudflareFirewall_CL
| where Action == "block"
| summarize Count = count() by ClientIP, ClientCountry
| order by Count desc
| take 20

// Events by source type
CloudflareFirewall_CL
| summarize Count = count() by Source
| order by Count desc

// Suspicious activity from hosting/datacenter IPs
CloudflareFirewall_CL
| where ClientIPClass != "clean"
| summarize Count = count() by ClientIP, ClientIPClass, ClientASNDescription
| order by Count desc
```

## How It Works

The function runs on a 1-minute timer trigger. Each execution:

1. Calculates a 3-minute lookback window (current time minus 3 minutes). The overlap between consecutive runs handles Cloudflare's slight ingestion delay.
2. Queries the Cloudflare GraphQL Analytics API (`firewallEventsAdaptive` node) for each configured zone, requesting up to 10,000 events per zone.
3. Transforms the events from Cloudflare's field naming to the Log Analytics table schema.
4. Deduplicates by Ray ID to prevent duplicate records from the overlapping time windows.
5. Sends the batch to Log Analytics via the Logs Ingestion API using a Data Collection Rule.

### Cloudflare GraphQL Rate Limits

The Cloudflare GraphQL Analytics API has the following rate limits:

| Limit | Value |
|-------|-------|
| GraphQL-specific | 300 requests per 5 minutes |
| General API | 1,200 requests per 5 minutes |
| Max page size (firewallEventsAdaptive) | 10,000 records |
| Max query duration | 86,400 seconds (24 hours) |

At 1-minute polling with 2 zones, the function uses approximately 2 requests per minute (24 per 5 minutes), which is well under the 300/5min GraphQL limit.

### Sampling

On the Cloudflare Free plan, high-volume events may be sampled. Each event includes a `SampleInterval` field:

- `SampleInterval = 1` means every event was captured (no sampling)
- `SampleInterval = N` means the event represents approximately N real events

The function ingests all sampled records as-is. Use `SampleInterval` in KQL queries to estimate true event counts when needed:

```kusto
CloudflareFirewall_CL
| summarize EstimatedEvents = sum(SampleInterval) by bin(TimeGenerated, 1h)
```

## Azure Resources

The deployment creates the following resources:

| Resource | Type | Purpose |
|----------|------|---------|
| Log Analytics Workspace | PerGB2018 (Analytics plan) | Log storage and KQL querying |
| CloudflareFirewall_CL | Custom table (23 columns) | Firewall event data |
| Data Collection Rule | Direct (no DCE) | Routes ingested data to the table |
| Storage Account | Standard LRS | Function App backing storage |
| Key Vault | Standard, RBAC auth | Stores the Cloudflare API token |
| Application Insights | Workspace-based | Function App monitoring and diagnostics |
| Function App | Flex Consumption, Python 3.11 | Runs the ingestion function |

### Security

- The Cloudflare API token is stored in Key Vault and accessed via `@Microsoft.KeyVault()` references. It never appears in app settings or code.
- The function authenticates to Azure using a system-assigned managed identity. No credentials are stored in code.
- Key Vault has RBAC authorisation enabled with purge protection.
- The managed identity has least-privilege access: `Monitoring Metrics Publisher` on the DCR only, and `Key Vault Secrets User` on the vault only.
- The storage account enforces TLS 1.2.

## Cost

Under typical usage on a low-traffic site, this pipeline costs nothing:

| Component | Normal Usage | Monthly Cost |
|-----------|-------------|:------------:|
| Log Analytics (Analytics plan) | ~10 MB/month | Free (within 5 GB/month allowance) |
| Application Insights | ~84 MB/month | Free (within 5 GB/month allowance) |
| Function App (Flex Consumption) | ~1,440 executions/day | Free (within 100K/month allowance) |
| Key Vault | Minimal operations | Free tier |

Daily caps are configured by default (1 GB for Log Analytics, 0.5 GB for App Insights) to prevent unexpected costs during traffic spikes. Even at 100x normal traffic, ingestion typically stays within free tier limits.

## Project Structure

```
cf-log-ingestion/
├── function_app.py      # Azure Function (timer trigger, 1-min interval)
├── requirements.txt     # Python dependencies
├── host.json            # Functions host configuration
├── .gitignore
└── infra/
    ├── main.bicep       # Azure infrastructure (Bicep template)
    └── deploy.ps1       # One-step deployment script
```

## License

MIT
