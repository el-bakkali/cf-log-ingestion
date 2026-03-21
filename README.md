# Cloudflare Log Ingestion to Azure Log Analytics

Automated pipeline that ingests Cloudflare firewall events, HTTP request logs, and DNS query logs into Azure Log Analytics using Python Azure Functions and the Logs Ingestion API. Three timer-triggered functions run every minute, querying the Cloudflare GraphQL Analytics API, and writing to separate custom tables for alerting, threat hunting, and security monitoring.

## Architecture

```
Cloudflare GraphQL API
        |
        | (every 1 minute, 3 functions)
        v
Azure Function App (Python 3.11, Flex Consumption)
        |
        |-- cf_fw_ingestion     (firewallEventsAdaptive)
        |   -> DCR: dcr-cf-firewall -> CloudflareFirewall_CL (23 columns)
        |
        |-- cf_http_ingestion   (httpRequestsAdaptive)
        |   -> DCR: dcr-cf-http-requests -> CloudflareHTTPRequests_CL (21 columns)
        |
        |-- cf_dns_ingestion    (dnsAnalyticsAdaptive)
            -> DCR: dcr-cf-dns -> CloudflareDNS_CL (14 columns)
```

All functions authenticate to Cloudflare using an API token stored in Azure Key Vault (referenced via `@Microsoft.KeyVault()` syntax). They authenticate to Azure using a shared system-assigned managed identity with the `Monitoring Metrics Publisher` role on each Data Collection Rule.

No Data Collection Endpoints (DCEs) are required. DCRs with `kind: Direct` expose their own ingestion endpoints.

## What Gets Ingested

### Firewall Events (`CloudflareFirewall_CL`)

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

### HTTP Requests (`CloudflareHTTPRequests_CL`)

Each HTTP request is mapped to a 21-column custom table (free plan fields):

| Column | Type | Description |
|--------|------|-------------|
| TimeGenerated | datetime | Event timestamp from Cloudflare |
| Zone | string | Cloudflare zone name |
| RequestHost | string | HTTP host header |
| RequestPath | string | HTTP request path |
| RequestQuery | string | HTTP query string |
| RequestMethod | string | HTTP method |
| HttpProtocol | string | HTTP protocol version |
| RequestScheme | string | HTTP or HTTPS |
| EdgeResponseStatus | int | Edge response status code |
| OriginResponseStatus | int | Origin response status code |
| OriginResponseDurationMs | int | Origin response time in ms |
| CacheStatus | string | Cache status (HIT, MISS, etc.) |
| ClientIP | string | Client IP address |
| ClientCountry | string | Client country name |
| ClientASN | string | Client AS number |
| ClientASNDescription | string | Client ASN organisation name |
| ClientDeviceType | string | Device type (desktop, mobile, etc.) |
| TLSVersion | string | TLS protocol version |
| UserAgent | string | User agent string |
| UserAgentBrowser | string | Browser name |
| UserAgentOS | string | OS name |

### DNS Queries (`CloudflareDNS_CL`)

Each DNS query is mapped to a 14-column custom table:

| Column | Type | Description |
|--------|------|-------------|
| TimeGenerated | datetime | Query timestamp |
| Zone | string | Cloudflare zone name |
| QueryName | string | Domain queried |
| QueryType | string | DNS record type (A, AAAA, MX, TXT, etc.) |
| ResponseCode | string | DNS response status (NOERROR, NXDOMAIN, etc.) |
| SourceIP | string | Resolver IP address |
| Protocol | string | Transport protocol (UDP, TCP) |
| ColoName | string | Cloudflare data centre code |
| DestinationIP | string | CF nameserver IP |
| IPVersion | int | IP version (4 or 6) |
| QuerySize | int | Query size in bytes |
| ResponseSize | int | Response size in bytes |
| ResponseCached | int | Whether response was served from cache |
| SampleInterval | int | Sampling interval |

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

## KQL Queries

The `queries/` folder contains 42 ready-to-use KQL queries organised into four categories. All queries use `sum(SampleInterval)` instead of `count()` to correct for Cloudflare adaptive sampling.

### Dashboard (`queries/dashboard/`)

10 operational queries for day-to-day monitoring: security overview tiles, top blocked IPs, WAF rule effectiveness, geographic threats, targeted endpoints, ASN intelligence, and IP deep-dive.

### Alerts (`queries/alerts/`)

10 queries designed for Azure Monitor alert rules: block spikes, new source countries, distributed attacks, path scanning, rate-limit surges, suspicious IP passthrough, ML-triggered anomalies, new rules firing, multi-zone attackers, and data ingestion gaps.

### Threat Hunting (`queries/hunting/`)

10 proactive hunting queries: attack campaign clustering with `autocluster()`, repeat offenders, user-agent analysis, hourly heatmaps, credential stuffing patterns, HTTP method abuse, referer analysis, week-over-week comparisons, logged-but-not-blocked review, and status code analysis.

### ML & Trends (`queries/trends/`)

12 machine-learning queries using KQL time-series functions: volume anomaly detection (`series_decompose_anomalies`), per-action/per-zone/per-source anomalies, anomaly scoring tables, block-rate anomalies, unique-IP anomalies, root-cause correlation, traffic forecasting (`series_decompose_forecast`), seasonality detection (`series_periods_detect`), full time-series decomposition, and country-level anomalies.

### Quick Start

Run any `.kql` file directly in the Log Analytics query editor:

```kusto
// Example: security overview with sampling correction
CloudflareFirewall_CL
| summarize
    EstimatedEvents = sum(SampleInterval),
    UniqueIPs       = dcount(ClientIP),
    Countries       = dcount(ClientCountry),
    BlockRate       = round(100.0 * sumif(SampleInterval, Action == "block") / max_of(sum(SampleInterval), 1), 1)
```

## Workbook

The `workbook/` folder contains a deployment script that creates an Azure Monitor Workbook for visualising the firewall data. The workbook is a single scrollable page with:

- **Security summary tiles** — total events, unique IPs, countries, block rate, zones, active rules
- **Events by action over time** — area chart with hourly granularity
- **Source breakdown** — pie chart of security products (WAF, rate limiting, bot fight, etc.)
- **Top blocked IPs** — table with country, ASN, IP class, targeted paths, and triggering rules
- **Threat intelligence** — blocked traffic by country and top ASN threat sources
- **WAF rule effectiveness** — hit counts, attacker diversity (broad vs narrow), top paths per rule
- **Targeted endpoints** — most-hit paths with HTTP status code distribution
- **ML anomaly detection** — 14-day volume anomaly timechart, scored anomaly table, 24h traffic forecast
- **Threat hunting** — autocluster attack campaigns, repeat offenders, user-agent category breakdown
- **IP investigation** — enter any IP to see its full summary and event log

### Deploy the Workbook

```powershell
.\workbook\deploy-workbook.ps1 `
    -SubscriptionId "<your-subscription-id>" `
    -ResourceGroup  "<your-resource-group>" `
    -WorkspaceName  "<your-workspace-name>" `
    -Location       "uksouth"
```

The script deploys via the Azure Monitor Workbooks REST API (`2023-06-01`). It requires the Azure CLI logged in with Contributor access on the resource group.

## How It Works

The function app contains three timer-triggered functions, all running on a 1-minute schedule. Each execution:

1. Calculates a non-overlapping 1-minute query window with a 1-minute delay (`[now-2min, now-1min)`). The delay gives Cloudflare time to make events available. Consecutive windows never overlap, so no deduplication is needed.
2. Queries the Cloudflare GraphQL Analytics API for each configured zone, requesting up to 10,000 records per zone.
3. Transforms the events from Cloudflare's field naming to the Log Analytics table schema.
4. Sends the batch to Log Analytics via the Logs Ingestion API using the appropriate Data Collection Rule.

| Function | GraphQL Node | Target Table |
|----------|-------------|-------------|
| `cf_fw_ingestion` | `firewallEventsAdaptive` | `CloudflareFirewall_CL` |
| `cf_http_ingestion` | `httpRequestsAdaptive` | `CloudflareHTTPRequests_CL` |
| `cf_dns_ingestion` | `dnsAnalyticsAdaptive` | `CloudflareDNS_CL` |

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
| CloudflareHTTPRequests_CL | Custom table (21 columns) | HTTP request log data |
| CloudflareDNS_CL | Custom table (14 columns) | DNS query log data |
| DCR: dcr-cf-firewall | Direct (no DCE) | Routes firewall events to table |
| DCR: dcr-cf-http-requests | Direct (no DCE) | Routes HTTP request logs to table |
| DCR: dcr-cf-dns | Direct (no DCE) | Routes DNS query logs to table |
| Storage Account | Standard LRS | Function App backing storage |
| Key Vault | Standard, RBAC auth | Stores the Cloudflare API token |
| Application Insights | Workspace-based | Function App monitoring and diagnostics |
| Function App | Flex Consumption, Python 3.11 | Runs all three ingestion functions |

### Security

- The Cloudflare API token is stored in Key Vault and accessed via `@Microsoft.KeyVault()` references. It never appears in app settings or code.
- The function authenticates to Azure using a system-assigned managed identity. No credentials are stored in code.
- Key Vault has RBAC authorisation enabled with purge protection.
- The managed identity has least-privilege access: `Monitoring Metrics Publisher` on each of the three DCRs, and `Key Vault Secrets User` on the vault only.
- The storage account enforces TLS 1.2.

## Cost

Under typical usage on a low-traffic site, this pipeline costs nothing:

| Component | Normal Usage | Monthly Cost |
|-----------|-------------|:------------:|
| Log Analytics (Analytics plan) | ~10 MB/month | Free (within 5 GB/month allowance) |
| Application Insights | ~84 MB/month | Free (within 5 GB/month allowance) |
| Function App (Flex Consumption) | ~4,320 executions/day | Free (within 100K/month allowance) |
| Key Vault | Minimal operations | Free tier |

Daily caps are configured by default (1 GB for Log Analytics, 0.5 GB for App Insights) to prevent unexpected costs during traffic spikes. Even at 100x normal traffic, ingestion typically stays within free tier limits.

## Project Structure

```
cf-log-ingestion/
├── function_app.py          # Three Azure Functions (cf_fw_ingestion, cf_http_ingestion, cf_dns_ingestion)
├── requirements.txt         # Python dependencies
├── host.json                # Functions host configuration
├── .gitignore
├── infra/
│   ├── main.bicep           # Azure infrastructure (workspace, 3 tables, 3 DCRs, KV, etc.)
│   └── deploy.ps1           # One-step deployment script
├── queries/
│   ├── dashboard/           # 10 operational monitoring queries
│   ├── alerts/              # 10 alert rule queries
│   ├── hunting/             # 10 threat hunting queries
│   └── trends/              # 12 ML anomaly detection queries
└── workbook/
    └── deploy-workbook.ps1  # Workbook deployment script
```

## License

MIT
