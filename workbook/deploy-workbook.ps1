<#
.SYNOPSIS
    Deploys the Cloudflare Firewall Security Workbook to Azure Monitor.

.DESCRIPTION
    Creates a single-page scrollable workbook with security summary tiles,
    threat intelligence tables, WAF rule analysis, ML anomaly detection,
    threat hunting, and IP investigation — all querying CloudflareFirewall_CL.

.NOTES
    Requires: Azure CLI logged in with Contributor on the resource group.
    Run from repo root: .\workbook\deploy-workbook.ps1

.EXAMPLE
    .\workbook\deploy-workbook.ps1 `
        -SubscriptionId "00000000-0000-0000-0000-000000000000" `
        -ResourceGroup  "rg-my-resource-group" `
        -WorkspaceName  "law-my-workspace" `
        -Location       "uksouth"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SubscriptionId,

    [Parameter(Mandatory)]
    [string]$ResourceGroup,

    [Parameter(Mandatory)]
    [string]$WorkspaceName,

    [string]$Location = "uksouth"
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$wsId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"

# Deterministic workbook GUID from a fixed seed
$md5  = [System.Security.Cryptography.MD5]::Create()
$hash = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("cf-firewall-workbook-v1"))
$hash[6] = ($hash[6] -band 0x0F) -bor 0x30
$hash[8] = ($hash[8] -band 0x3F) -bor 0x80
$wbId = [guid]::new(
    [BitConverter]::ToInt32($hash,0), [BitConverter]::ToInt16($hash,4),
    [BitConverter]::ToInt16($hash,6), $hash[8],$hash[9],$hash[10],
    $hash[11],$hash[12],$hash[13],$hash[14],$hash[15]
).ToString()

Write-Host "`nDeploying Cloudflare Firewall Workbook..." -ForegroundColor Cyan

# ── Items array ──────────────────────────────────────────────────────────────
$items = [System.Collections.ArrayList]::new()

# --- Title ---
$null = $items.Add([ordered]@{
    type = 1
    content = [ordered]@{ json = "## Cloudflare Firewall Security Dashboard`n> Counts use **sum(SampleInterval)** for adaptive sampling correction." }
    name = "title"
})

# --- Time range ---
$null = $items.Add([ordered]@{
    type = 9
    content = [ordered]@{
        version = "KqlParameterItem/1.0"
        parameters = @(
            [ordered]@{
                id    = "a0b1c2d3-e4f5-6789-abcd-ef0123456789"
                version = "KqlParameterItem/1.0"
                name  = "timeRange"
                label = "Time Range"
                type  = 4
                isRequired = $true
                typeSettings = [ordered]@{
                    selectableValues = @(
                        [ordered]@{ durationMs = 3600000 }
                        [ordered]@{ durationMs = 14400000 }
                        [ordered]@{ durationMs = 43200000 }
                        [ordered]@{ durationMs = 86400000 }
                        [ordered]@{ durationMs = 259200000 }
                        [ordered]@{ durationMs = 604800000 }
                        [ordered]@{ durationMs = 1209600000 }
                    )
                    allowCustom = $true
                }
                value = [ordered]@{ durationMs = 86400000 }
            }
        )
        style = "pills"
        queryType = 0
        resourceType = "microsoft.operationalinsights/workspaces"
    }
    name = "params"
})

# --- Tiles: key metrics ---
$null = $items.Add([ordered]@{
    type = 3
    content = [ordered]@{
        version  = "KqlItem/1.0"
        query    = @'
CloudflareFirewall_CL
| summarize v = sum(SampleInterval) | project Metric="Total Events", Value=v
| union (CloudflareFirewall_CL | summarize v = dcount(ClientIP) | project Metric="Unique IPs", Value=v)
| union (CloudflareFirewall_CL | summarize v = dcount(ClientCountry) | project Metric="Countries", Value=v)
| union (CloudflareFirewall_CL | summarize v = tolong(round(100.0*sumif(SampleInterval, Action=="block")/max_of(sum(SampleInterval),1),0)) | project Metric="Block Rate %", Value=v)
| union (CloudflareFirewall_CL | summarize v = dcount(Zone) | project Metric="Zones", Value=v)
| union (CloudflareFirewall_CL | summarize v = dcount(RuleId) | project Metric="Active Rules", Value=v)
'@
        size     = 4
        title    = "Security Summary"
        queryType = 0
        resourceType = "microsoft.operationalinsights/workspaces"
        visualization = "tiles"
        tileSettings = [ordered]@{
            titleContent = [ordered]@{ columnMatch = "Metric"; formatter = 1 }
            leftContent  = [ordered]@{ columnMatch = "Value"; formatter = 12; numberFormat = [ordered]@{ unit = 17; options = [ordered]@{ style = "decimal"; maximumFractionDigits = 0 } } }
            showBorder = $false
        }
        timeContextFromParameter = "timeRange"
    }
    name = "tiles"
})

# --- Events by action over time ---
$null = $items.Add([ordered]@{
    type = 3
    content = [ordered]@{
        version  = "KqlItem/1.0"
        query    = @'
CloudflareFirewall_CL
| summarize Events=sum(SampleInterval) by bin(TimeGenerated,1h), Action
| order by TimeGenerated asc
'@
        size     = 0
        title    = "Firewall Events by Action Over Time"
        queryType = 0
        resourceType = "microsoft.operationalinsights/workspaces"
        visualization = "areachart"
        timeContextFromParameter = "timeRange"
    }
    name = "events-time"
})

# --- Events by source (pie) + Top blocked IPs (table) side by side ---
$null = $items.Add([ordered]@{
    type = 3
    content = [ordered]@{
        version  = "KqlItem/1.0"
        query    = "CloudflareFirewall_CL | summarize Events=sum(SampleInterval) by Source | order by Events desc"
        size     = 1
        title    = "Events by Security Product"
        queryType = 0
        resourceType = "microsoft.operationalinsights/workspaces"
        visualization = "piechart"
        timeContextFromParameter = "timeRange"
    }
    customWidth = "35"
    name = "source-pie"
})

$null = $items.Add([ordered]@{
    type = 3
    content = [ordered]@{
        version  = "KqlItem/1.0"
        query    = @'
CloudflareFirewall_CL
| where Action == "block"
| summarize Blocks=sum(SampleInterval), Country=take_any(ClientCountry), ASN=take_any(ClientASNDescription), IPClass=take_any(ClientIPClass), TopPaths=make_set(RequestPath,5), TopRules=make_set(RuleDescription,3) by ClientIP
| order by Blocks desc | take 20
'@
        size     = 1
        title    = "Top 20 Blocked IPs"
        queryType = 0
        resourceType = "microsoft.operationalinsights/workspaces"
        visualization = "table"
        timeContextFromParameter = "timeRange"
    }
    customWidth = "65"
    name = "top-blocked"
})

# ── Threat Intelligence section ──────────────────────────────────────────────
$null = $items.Add([ordered]@{
    type = 1
    content = [ordered]@{ json = "---`n### Threat Intelligence" }
    name = "hdr-threats"
})

$null = $items.Add([ordered]@{
    type = 3
    content = [ordered]@{
        version  = "KqlItem/1.0"
        query    = @'
CloudflareFirewall_CL
| where Action in ("block","managed_challenge","challenge","js_challenge")
| summarize Events=sum(SampleInterval), UniqueIPs=dcount(ClientIP), TopASNs=make_set(ClientASNDescription,3) by ClientCountry
| order by Events desc | take 15
'@
        size     = 0
        title    = "Blocked Traffic by Country"
        queryType = 0
        resourceType = "microsoft.operationalinsights/workspaces"
        visualization = "table"
        timeContextFromParameter = "timeRange"
    }
    customWidth = "50"
    name = "geo"
})

$null = $items.Add([ordered]@{
    type = 3
    content = [ordered]@{
        version  = "KqlItem/1.0"
        query    = @'
CloudflareFirewall_CL
| where Action in ("block","managed_challenge","challenge")
| summarize Events=sum(SampleInterval), UniqueIPs=dcount(ClientIP), Countries=make_set(ClientCountry,5) by ClientASN, ClientASNDescription
| extend EventsPerIP=round(toreal(Events)/max_of(UniqueIPs,1),1)
| order by Events desc | take 15
'@
        size     = 0
        title    = "Top ASN Threat Sources"
        queryType = 0
        resourceType = "microsoft.operationalinsights/workspaces"
        visualization = "table"
        timeContextFromParameter = "timeRange"
    }
    customWidth = "50"
    name = "asn"
})

# ── WAF Rules & Endpoints section ───────────────────────────────────────────
$null = $items.Add([ordered]@{
    type = 1
    content = [ordered]@{ json = "---`n### WAF Rules & Targeted Endpoints" }
    name = "hdr-rules"
})

$null = $items.Add([ordered]@{
    type = 3
    content = [ordered]@{
        version  = "KqlItem/1.0"
        query    = @'
CloudflareFirewall_CL
| where isnotempty(RuleDescription)
| summarize Hits=sum(SampleInterval), UniqueIPs=dcount(ClientIP), Countries=dcount(ClientCountry), Actions=make_set(Action,5), TopPaths=make_set(RequestPath,5) by RuleId, RuleDescription, Source
| extend Diversity=iff(UniqueIPs>10 and Countries>3,"Broad","Narrow")
| order by Hits desc | take 20
'@
        size     = 0
        title    = "WAF Rule Effectiveness"
        queryType = 0
        resourceType = "microsoft.operationalinsights/workspaces"
        visualization = "table"
        timeContextFromParameter = "timeRange"
    }
    name = "waf-rules"
})

$null = $items.Add([ordered]@{
    type = 3
    content = [ordered]@{
        version  = "KqlItem/1.0"
        query    = @'
CloudflareFirewall_CL
| summarize Events=sum(SampleInterval), UniqueIPs=dcount(ClientIP), Actions=make_set(Action,5), Methods=make_set(RequestMethod,5) by RequestPath, RequestHost
| order by Events desc | take 20
'@
        size     = 0
        title    = "Most Targeted Endpoints"
        queryType = 0
        resourceType = "microsoft.operationalinsights/workspaces"
        visualization = "table"
        timeContextFromParameter = "timeRange"
    }
    customWidth = "60"
    name = "endpoints"
})

$null = $items.Add([ordered]@{
    type = 3
    content = [ordered]@{
        version  = "KqlItem/1.0"
        query    = "CloudflareFirewall_CL | summarize Events=sum(SampleInterval) by tostring(EdgeResponseStatus) | order by Events desc"
        size     = 0
        title    = "HTTP Status Codes"
        queryType = 0
        resourceType = "microsoft.operationalinsights/workspaces"
        visualization = "piechart"
        timeContextFromParameter = "timeRange"
    }
    customWidth = "40"
    name = "status-codes"
})

# ── ML Anomaly Detection section ────────────────────────────────────────────
$null = $items.Add([ordered]@{
    type = 1
    content = [ordered]@{ json = "---`n### ML Anomaly Detection`n*Fixed 14-day baseline — not affected by the time picker above.*" }
    name = "hdr-ml"
})

$null = $items.Add([ordered]@{
    type = 3
    content = [ordered]@{
        version  = "KqlItem/1.0"
        query    = @'
let lookback=14d; let grain=1h;
CloudflareFirewall_CL
| where TimeGenerated > ago(lookback)
| make-series EstimatedEvents=sum(SampleInterval) default=0 on TimeGenerated from ago(lookback) to now() step grain
| extend (AnomalyFlag, AnomalyScore, ExpectedEvents) = series_decompose_anomalies(EstimatedEvents, 1.5, -1, 'linefit')
'@
        size     = 0
        title    = "Traffic Volume — Anomaly Detection (14d)"
        queryType = 0
        resourceType = "microsoft.operationalinsights/workspaces"
        visualization = "timechart"
        timeContext = [ordered]@{ durationMs = 1209600000 }
    }
    name = "ml-volume"
})

$null = $items.Add([ordered]@{
    type = 3
    content = [ordered]@{
        version  = "KqlItem/1.0"
        query    = @'
let lookback=14d; let grain=1h;
CloudflareFirewall_CL
| where TimeGenerated > ago(lookback)
| make-series EstimatedEvents=sum(SampleInterval) default=0 on TimeGenerated from ago(lookback) to now() step grain
| extend (AnomalyFlag, AnomalyScore, ExpectedEvents) = series_decompose_anomalies(EstimatedEvents, 1.5, -1, 'linefit')
| mv-expand TimeGenerated to typeof(datetime), EstimatedEvents to typeof(double), AnomalyFlag to typeof(double), AnomalyScore to typeof(double), ExpectedEvents to typeof(double)
| where AnomalyFlag != 0
| extend Direction=iff(AnomalyFlag>0,"Spike","Dip"), Severity=case(abs(AnomalyScore)>=5.0,"Extreme",abs(AnomalyScore)>=3.0,"Significant","Mild"), Deviation=round(EstimatedEvents-ExpectedEvents,0)
| project TimeGenerated, EstimatedEvents=round(EstimatedEvents,0), ExpectedEvents=round(ExpectedEvents,0), Deviation, AnomalyScore=round(AnomalyScore,2), Direction, Severity
| order by abs(AnomalyScore) desc
'@
        size     = 0
        title    = "Detected Anomalies — Scored"
        queryType = 0
        resourceType = "microsoft.operationalinsights/workspaces"
        visualization = "table"
        timeContext = [ordered]@{ durationMs = 1209600000 }
    }
    customWidth = "50"
    name = "ml-anomaly-tbl"
})

$null = $items.Add([ordered]@{
    type = 3
    content = [ordered]@{
        version  = "KqlItem/1.0"
        query    = @'
let lookback=14d; let grain=1h; let horizon=24h;
CloudflareFirewall_CL
| where TimeGenerated > ago(lookback)
| make-series EstimatedEvents=sum(SampleInterval) default=0 on TimeGenerated from ago(lookback) to now()+horizon step grain
| extend Forecast=series_decompose_forecast(EstimatedEvents, toint(horizon/grain))
'@
        size     = 0
        title    = "24h Traffic Forecast"
        queryType = 0
        resourceType = "microsoft.operationalinsights/workspaces"
        visualization = "timechart"
        timeContext = [ordered]@{ durationMs = 1209600000 }
    }
    customWidth = "50"
    name = "ml-forecast"
})

# ── Threat Hunting section ───────────────────────────────────────────────────
$null = $items.Add([ordered]@{
    type = 1
    content = [ordered]@{ json = "---`n### Threat Hunting" }
    name = "hdr-hunt"
})

$null = $items.Add([ordered]@{
    type = 3
    content = [ordered]@{
        version  = "KqlItem/1.0"
        query    = @'
CloudflareFirewall_CL
| where Action in ("block","managed_challenge","challenge")
| project ClientCountry, ClientASNDescription, ClientIPClass, RequestPath, RequestMethod, RequestHost, Source, RuleDescription, UserAgent, EdgeResponseStatus
| evaluate autocluster()
'@
        size     = 0
        title    = "Attack Campaign Clusters (autocluster)"
        queryType = 0
        resourceType = "microsoft.operationalinsights/workspaces"
        visualization = "table"
        timeContextFromParameter = "timeRange"
    }
    name = "clusters"
})

$null = $items.Add([ordered]@{
    type = 3
    content = [ordered]@{
        version  = "KqlItem/1.0"
        query    = @'
CloudflareFirewall_CL
| where Action in ("block","managed_challenge","challenge")
| summarize Days=dcount(bin(TimeGenerated,1d)), Events=sum(SampleInterval), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated), Zones=make_set(Zone,5), TopPaths=make_set(RequestPath,5), TopRules=make_set(RuleDescription,3) by ClientIP, ClientASNDescription, ClientCountry
| where Days >= 2
| order by Days desc, Events desc | take 20
'@
        size     = 0
        title    = "Repeat Offenders (multi-day attackers)"
        queryType = 0
        resourceType = "microsoft.operationalinsights/workspaces"
        visualization = "table"
        timeContextFromParameter = "timeRange"
    }
    customWidth = "50"
    name = "repeat-offenders"
})

$null = $items.Add([ordered]@{
    type = 3
    content = [ordered]@{
        version  = "KqlItem/1.0"
        query    = @'
CloudflareFirewall_CL
| where Action in ("block","managed_challenge","challenge")
| extend UA_Cat=case(
    isempty(UserAgent) or UserAgent=="-","Empty",
    UserAgent has_any("python","go-http","curl","wget","axios","node-fetch"),"Script",
    UserAgent has_any("scan","nikto","sqlmap","nmap","zgrab","nuclei"),"Scanner",
    UserAgent has_any("bot","crawler","spider"),"Bot",
    UserAgent has_any("Chrome","Firefox","Safari","Edge") and not(UserAgent has_any("bot","crawler")),"Browser-Like",
    "Other")
| summarize Events=sum(SampleInterval), IPs=dcount(ClientIP) by UA_Cat
| order by Events desc
'@
        size     = 0
        title    = "Blocked Traffic by User-Agent Type"
        queryType = 0
        resourceType = "microsoft.operationalinsights/workspaces"
        visualization = "barchart"
        timeContextFromParameter = "timeRange"
    }
    customWidth = "50"
    name = "ua-analysis"
})

# ── IP Investigation section ─────────────────────────────────────────────────
$null = $items.Add([ordered]@{
    type = 1
    content = [ordered]@{ json = "---`n### IP Investigation`nEnter an IP address to see its full activity." }
    name = "hdr-ip"
})

$null = $items.Add([ordered]@{
    type = 9
    content = [ordered]@{
        version = "KqlParameterItem/1.0"
        parameters = @(
            [ordered]@{
                id      = "b1c2d3e4-f5a6-7890-bcde-f01234567890"
                version = "KqlParameterItem/1.0"
                name    = "targetIP"
                label   = "Target IP"
                type    = 1
                value   = ""
            }
        )
        style = "pills"
        queryType = 0
        resourceType = "microsoft.operationalinsights/workspaces"
    }
    name = "ip-param"
})

$null = $items.Add([ordered]@{
    type = 3
    content = [ordered]@{
        version  = "KqlItem/1.0"
        query    = @'
CloudflareFirewall_CL
| where ClientIP == "{targetIP}"
| summarize Events=sum(SampleInterval), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated), Actions=make_set(Action,10), Zones=make_set(Zone,10), TopPaths=make_set(RequestPath,15), TopRules=make_set(RuleDescription,10), Country=take_any(ClientCountry), ASN=take_any(ClientASNDescription), IPClass=take_any(ClientIPClass)
'@
        size     = 4
        title    = "IP Summary"
        queryType = 0
        resourceType = "microsoft.operationalinsights/workspaces"
        visualization = "table"
        timeContextFromParameter = "timeRange"
    }
    name = "ip-summary"
})

$null = $items.Add([ordered]@{
    type = 3
    content = [ordered]@{
        version  = "KqlItem/1.0"
        query    = @'
CloudflareFirewall_CL
| where ClientIP == "{targetIP}"
| project TimeGenerated, Zone, Action, Source, RuleDescription, RequestMethod, RequestHost, RequestPath, EdgeResponseStatus, UserAgent, ClientCountry, ClientASNDescription, SampleInterval
| order by TimeGenerated desc | take 200
'@
        size     = 0
        title    = "Event Log"
        queryType = 0
        resourceType = "microsoft.operationalinsights/workspaces"
        visualization = "table"
        timeContextFromParameter = "timeRange"
    }
    name = "ip-events"
})

# ── Assemble & Deploy ────────────────────────────────────────────────────────
$workbook = [ordered]@{
    version = "Notebook/1.0"
    items   = [array]$items
    fallbackResourceIds = @($wsId)
    '$schema' = "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json"
}

$serialized = $workbook | ConvertTo-Json -Depth 30 -Compress

$body = [ordered]@{
    location   = $Location
    tags       = [ordered]@{ "hidden-title" = "Cloudflare Firewall Security Dashboard" }
    kind       = "shared"
    properties = [ordered]@{
        displayName    = "Cloudflare Firewall Security Dashboard"
        category       = "workbook"
        serializedData = $serialized
        sourceId       = $wsId
    }
}

$bodyJson = $body | ConvertTo-Json -Depth 5
$tmp = Join-Path $env:TEMP "cf-workbook-deploy.json"
[System.IO.File]::WriteAllText($tmp, $bodyJson, [System.Text.UTF8Encoding]::new($false))

$uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/workbooks/${wbId}?api-version=2023-06-01"

$result = az rest --method PUT --uri $uri --body "@$tmp" 2>$null
if ($LASTEXITCODE -ne 0) {
    $err = az rest --method PUT --uri $uri --body "@$tmp" 2>&1 | Out-String
    Remove-Item $tmp -Force
    throw "Deploy failed: $err"
}

$parsed = $result | ConvertFrom-Json
Remove-Item $tmp -Force

Write-Host ""
Write-Host "Workbook deployed: $($parsed.properties.displayName)" -ForegroundColor Green
Write-Host "$($parsed.id)" -ForegroundColor Gray
Write-Host ""
Write-Host "https://portal.azure.com/#@/resource$($parsed.id)" -ForegroundColor Cyan
