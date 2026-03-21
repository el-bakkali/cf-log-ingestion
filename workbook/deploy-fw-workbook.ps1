<#
.SYNOPSIS
    Deploys the Cloudflare Firewall Security Azure Monitor Workbook.
.DESCRIPTION
    Production-grade security workbook for CloudflareFirewall_CL with 9 sections:
    Overview, Traffic & Actions, Blocked/Challenged, Rules, Client Intel,
    Request Analysis, Geographic, Anomalies, Raw Events. Incorporates KQL
    patterns from the cf-log-ingestion query library.
.EXAMPLE
    .\deploy-fw-workbook.ps1 -SubscriptionId "..." -ResourceGroup "rg-cf-log-ingestion" -WorkspaceName "law-cf-security"
#>
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$WorkspaceName,
    [string]$Location = "uksouth"
)
$ErrorActionPreference = "Stop"
Write-Host "Deploying Cloudflare Firewall Security Workbook..." -ForegroundColor Cyan

$workspaceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"
$workbookId = [guid]::NewGuid().ToString()
$workbookName = "Cloudflare Firewall Security"

$f = @'
| where TimeGenerated {TimeRange}
| where ('*' in ({Zone}) or Zone in ({Zone}))
| where ('*' in ({Action}) or Action in ({Action}))
| where ('*' in ({Country}) or ClientCountry in ({Country}))
| where ('*' in ({Source}) or Source in ({Source}))
'@

$serializedNotebook = @{
    version = "Notebook/1.0"
    items = @(
        # === PARAMETERS ===
        @{
            type = 9
            content = @{
                version = "KqlParameterItem/1.0"
                parameters = @(
                    @{ id=[guid]::NewGuid().ToString(); version="KqlParameterItem/1.0"; name="TimeRange"; type=4; isRequired=$true; value=@{durationMs=86400000}; typeSettings=@{selectableValues=@(@{durationMs=3600000},@{durationMs=14400000},@{durationMs=43200000},@{durationMs=86400000},@{durationMs=604800000})}; label="Time Range" }
                    @{ id=[guid]::NewGuid().ToString(); version="KqlParameterItem/1.0"; name="Zone"; type=2; multiSelect=$true; quote="'"; delimiter=","; query="CloudflareFirewall_CL | distinct Zone | sort by Zone asc"; typeSettings=@{additionalResourceOptions=@("value::all")}; defaultValue="value::all"; queryType=0; resourceType="microsoft.operationalinsights/workspaces"; label="Zone" }
                    @{ id=[guid]::NewGuid().ToString(); version="KqlParameterItem/1.0"; name="Action"; type=2; multiSelect=$true; quote="'"; delimiter=","; query="CloudflareFirewall_CL | distinct Action | sort by Action asc"; typeSettings=@{additionalResourceOptions=@("value::all")}; defaultValue="value::all"; queryType=0; resourceType="microsoft.operationalinsights/workspaces"; label="Action" }
                    @{ id=[guid]::NewGuid().ToString(); version="KqlParameterItem/1.0"; name="Country"; type=2; multiSelect=$true; quote="'"; delimiter=","; query="CloudflareFirewall_CL | distinct ClientCountry | where isnotempty(ClientCountry) | sort by ClientCountry asc"; typeSettings=@{additionalResourceOptions=@("value::all")}; defaultValue="value::all"; queryType=0; resourceType="microsoft.operationalinsights/workspaces"; label="Country" }
                    @{ id=[guid]::NewGuid().ToString(); version="KqlParameterItem/1.0"; name="Source"; type=2; multiSelect=$true; quote="'"; delimiter=","; query="CloudflareFirewall_CL | distinct Source | sort by Source asc"; typeSettings=@{additionalResourceOptions=@("value::all")}; defaultValue="value::all"; queryType=0; resourceType="microsoft.operationalinsights/workspaces"; label="Source" }
                )
                style = "pills"; queryType = 0; resourceType = "microsoft.operationalinsights/workspaces"
            }
            name = "parameters"
        }
        # === 1. OVERVIEW ===
        @{ type=12; content=@{ version="NotebookGroup/1.0"; groupType=0; title="Overview"; expandable=$true; expanded=$true; items=@(
            @{ type=3; content=@{ version="KqlItem/1.0"; query="let base = CloudflareFirewall_CL $f;`nlet total = toscalar(base | summarize sum(SampleInterval));`nlet blocks = toscalar(base | where Action == 'block' | summarize sum(SampleInterval));`nlet challenges = toscalar(base | where Action in ('challenge','managed_challenge') | summarize sum(SampleInterval));`nprint TotalEvents=total, BlockRate=round(blocks*100.0/max_of(total,1),1), ChallengeRate=round(challenges*100.0/max_of(total,1),1), UniqueIPs=toscalar(base|summarize dcount(ClientIP)), UniqueRules=toscalar(base|summarize dcount(RuleDescription)), Countries=toscalar(base|summarize dcount(ClientCountry))"; size=4; title="Security Summary"; queryType=0; resourceType="microsoft.operationalinsights/workspaces"; visualization="table" }; name="overview-tiles" }
            @{ type=3; content=@{ version="KqlItem/1.0"; query="CloudflareFirewall_CL $f`n| summarize Events=sum(SampleInterval) by bin(TimeGenerated,5m), Action`n| order by TimeGenerated asc"; size=0; title="Events Over Time by Action"; queryType=0; resourceType="microsoft.operationalinsights/workspaces"; visualization="timechart"; chartSettings=@{seriesLabelSettings=@(@{series="block";color="redBright"},@{series="challenge";color="orange"},@{series="managed_challenge";color="yellow"},@{series="log";color="blue"})} }; name="events-over-time" }
        )}; name="s1" }
        # === 2. TRAFFIC & ACTIONS ===
        @{ type=12; content=@{ version="NotebookGroup/1.0"; groupType=0; title="Traffic & Actions"; expandable=$true; expanded=$false; items=@(
            @{ type=3; content=@{ version="KqlItem/1.0"; query="CloudflareFirewall_CL $f`n| summarize Events=sum(SampleInterval) by Action`n| order by Events desc"; size=0; title="Events by Action"; queryType=0; resourceType="microsoft.operationalinsights/workspaces"; visualization="piechart" }; name="by-action" }
            @{ type=3; content=@{ version="KqlItem/1.0"; query="CloudflareFirewall_CL $f`n| summarize Events=sum(SampleInterval) by Source`n| order by Events desc"; size=0; title="Events by Source"; queryType=0; resourceType="microsoft.operationalinsights/workspaces"; visualization="barchart" }; name="by-source" }
        )}; name="s2" }
        # === 3. BLOCKED & CHALLENGED ===
        @{ type=12; content=@{ version="NotebookGroup/1.0"; groupType=0; title="Blocked & Challenged Requests"; expandable=$true; expanded=$false; items=@(
            @{ type=3; content=@{ version="KqlItem/1.0"; query="CloudflareFirewall_CL $f`n| where Action in ('block','challenge','managed_challenge')`n| summarize Blocked=sumif(SampleInterval,Action=='block'), Challenged=sumif(SampleInterval,Action in ('challenge','managed_challenge')) by bin(TimeGenerated,5m)`n| order by TimeGenerated asc"; size=0; title="Block & Challenge Trends"; queryType=0; resourceType="microsoft.operationalinsights/workspaces"; visualization="timechart"; chartSettings=@{seriesLabelSettings=@(@{series="Blocked";color="redBright"},@{series="Challenged";color="orange"})} }; name="block-trends" }
            @{ type=3; content=@{ version="KqlItem/1.0"; query="CloudflareFirewall_CL $f`n| where Action == 'block'`n| summarize Events=sum(SampleInterval), UniqueIPs=dcount(ClientIP) by RequestPath`n| top 20 by Events`n| order by Events desc"; size=0; title="Top 20 Blocked Paths"; queryType=0; resourceType="microsoft.operationalinsights/workspaces"; visualization="table" }; name="blocked-paths" }
            @{ type=3; content=@{ version="KqlItem/1.0"; query="CloudflareFirewall_CL $f`n| where Action == 'block'`n| summarize Events=sum(SampleInterval) by tostring(EdgeResponseStatus)`n| order by Events desc"; size=0; title="Response Status Distribution (Blocked)"; queryType=0; resourceType="microsoft.operationalinsights/workspaces"; visualization="piechart" }; name="blocked-status" }
        )}; name="s3" }
        # === 4. RULES & EFFECTIVENESS ===
        @{ type=12; content=@{ version="NotebookGroup/1.0"; groupType=0; title="Top Rules & Effectiveness"; expandable=$true; expanded=$false; items=@(
            @{ type=3; content=@{ version="KqlItem/1.0"; query="CloudflareFirewall_CL $f`n| where isnotempty(RuleDescription)`n| summarize Events=sum(SampleInterval), UniqueIPs=dcount(ClientIP), Countries=dcount(ClientCountry), BlockRate=round(sumif(SampleInterval,Action=='block')*100.0/sum(SampleInterval),1), TopPath=any(RequestPath) by RuleDescription, Source`n| top 20 by Events`n| order by Events desc"; size=0; title="Top 20 Rules (with attacker diversity)"; queryType=0; resourceType="microsoft.operationalinsights/workspaces"; visualization="table"; gridSettings=@{formatters=@(@{columnMatch="BlockRate";formatter=8;formatOptions=@{palette="redGreen"}})} }; name="top-rules" }
            @{ type=3; content=@{ version="KqlItem/1.0"; query="CloudflareFirewall_CL $f`n| where Action == 'log' and isnotempty(RuleDescription)`n| summarize LoggedNotBlocked=sum(SampleInterval), UniqueIPs=dcount(ClientIP) by RuleDescription`n| top 15 by LoggedNotBlocked`n| order by LoggedNotBlocked desc"; size=0; title="Logged but NOT Blocked (review candidates)"; queryType=0; resourceType="microsoft.operationalinsights/workspaces"; visualization="table" }; name="logged-not-blocked" }
        )}; name="s4" }
        # === 5. CLIENT & THREAT INTEL ===
        @{ type=12; content=@{ version="NotebookGroup/1.0"; groupType=0; title="Client & Threat Intelligence"; expandable=$true; expanded=$false; items=@(
            @{ type=3; content=@{ version="KqlItem/1.0"; query="CloudflareFirewall_CL $f`n| where Action == 'block'`n| summarize Events=sum(SampleInterval), Paths=dcount(RequestPath), Rules=dcount(RuleDescription), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by ClientIP, ClientCountry, ClientASNDescription, ClientIPClass`n| top 30 by Events`n| order by Events desc"; size=0; title="Top 30 Blocked IPs (full context)"; queryType=0; resourceType="microsoft.operationalinsights/workspaces"; visualization="table" }; name="top-blocked-ips" }
            @{ type=3; content=@{ version="KqlItem/1.0"; query="CloudflareFirewall_CL $f`n| where ClientIPClass != 'clean' and isnotempty(ClientIPClass)`n| summarize Events=sum(SampleInterval), UniqueIPs=dcount(ClientIP) by ClientIPClass`n| order by Events desc"; size=0; title="Suspicious IP Classes"; queryType=0; resourceType="microsoft.operationalinsights/workspaces"; visualization="barchart" }; name="ip-classes" }
            @{ type=3; content=@{ version="KqlItem/1.0"; query="CloudflareFirewall_CL $f`n| where Action in ('block','challenge','managed_challenge')`n| summarize Events=sum(SampleInterval), UniqueIPs=dcount(ClientIP), EventsPerIP=round(sum(SampleInterval)*1.0/max_of(dcount(ClientIP),1),1) by ClientASNDescription`n| top 20 by Events`n| order by Events desc"; size=0; title="Top ASNs (threat sources)"; queryType=0; resourceType="microsoft.operationalinsights/workspaces"; visualization="table" }; name="top-asns" }
        )}; name="s5" }
        # === 6. REQUEST ANALYSIS ===
        @{ type=12; content=@{ version="NotebookGroup/1.0"; groupType=0; title="Request Analysis"; expandable=$true; expanded=$false; items=@(
            @{ type=3; content=@{ version="KqlItem/1.0"; query="CloudflareFirewall_CL $f`n| summarize Events=sum(SampleInterval), UniqueIPs=dcount(ClientIP), Methods=make_set(RequestMethod) by RequestPath`n| top 20 by Events`n| order by Events desc"; size=0; title="Top 20 Targeted Paths"; queryType=0; resourceType="microsoft.operationalinsights/workspaces"; visualization="table" }; name="top-paths" }
            @{ type=3; content=@{ version="KqlItem/1.0"; query="CloudflareFirewall_CL $f`n| summarize Events=sum(SampleInterval) by RequestMethod`n| order by Events desc"; size=0; title="HTTP Methods"; queryType=0; resourceType="microsoft.operationalinsights/workspaces"; visualization="piechart" }; name="methods" }
            @{ type=3; content=@{ version="KqlItem/1.0"; query="CloudflareFirewall_CL $f`n| where isnotempty(UserAgent)`n| extend UACategory = case(`n    UserAgent == '' or UserAgent == '-', 'Empty',`n    UserAgent has_any ('python','requests','urllib','httplib','aiohttp','scrapy'), 'Python',`n    UserAgent has_any ('Go-http','Go/'), 'Go',`n    UserAgent has_any ('curl','wget','libcurl'), 'curl/wget',`n    UserAgent has_any ('nikto','sqlmap','nmap','masscan','nuclei'), 'Scanner',`n    UserAgent has_any ('bot','crawl','spider','slurp'), 'Bot',`n    UserAgent has_any ('Chrome','Firefox','Safari','Edge'), 'Browser',`n    'Other')`n| summarize Events=sum(SampleInterval) by UACategory`n| order by Events desc"; size=0; title="User Agent Categories (blocked traffic)"; queryType=0; resourceType="microsoft.operationalinsights/workspaces"; visualization="piechart" }; name="ua-categories" }
        )}; name="s6" }
        # === 7. GEOGRAPHIC ===
        @{ type=12; content=@{ version="NotebookGroup/1.0"; groupType=0; title="Geographic Distribution"; expandable=$true; expanded=$false; items=@(
            @{ type=3; content=@{ version="KqlItem/1.0"; query="CloudflareFirewall_CL $f`n| where Action in ('block','challenge','managed_challenge')`n| summarize Events=sum(SampleInterval), UniqueIPs=dcount(ClientIP), TopASN=any(ClientASNDescription) by ClientCountry`n| top 20 by Events`n| order by Events desc"; size=0; title="Top 20 Attack Source Countries"; queryType=0; resourceType="microsoft.operationalinsights/workspaces"; visualization="barchart" }; name="geo-countries" }
            @{ type=3; content=@{ version="KqlItem/1.0"; query="CloudflareFirewall_CL $f`n| summarize Total=sum(SampleInterval), Blocked=sumif(SampleInterval,Action=='block'), BlockRate=round(sumif(SampleInterval,Action=='block')*100.0/sum(SampleInterval),1) by ClientCountry`n| where Total > 5`n| top 20 by BlockRate`n| order by BlockRate desc"; size=0; title="Highest Block Rate by Country"; queryType=0; resourceType="microsoft.operationalinsights/workspaces"; visualization="table"; gridSettings=@{formatters=@(@{columnMatch="BlockRate";formatter=8;formatOptions=@{palette="redGreen"}})} }; name="block-rate-country" }
        )}; name="s7" }
        # === 8. ANOMALIES & SECURITY SIGNALS ===
        @{ type=12; content=@{ version="NotebookGroup/1.0"; groupType=0; title="Anomalies & Security Signals"; expandable=$true; expanded=$false; items=@(
            @{ type=3; content=@{ version="KqlItem/1.0"; query="CloudflareFirewall_CL $f`n| summarize Requests=sum(SampleInterval), Paths=dcount(RequestPath), Rules=dcount(RuleDescription), BlockRate=round(sumif(SampleInterval,Action=='block')*100.0/sum(SampleInterval),1) by ClientIP, ClientCountry, ClientASNDescription`n| where Requests > 20 and Paths > 5`n| top 15 by Requests`n| order by Requests desc"; size=0; title="High Volume IPs Scanning Multiple Paths"; queryType=0; resourceType="microsoft.operationalinsights/workspaces"; visualization="table"; gridSettings=@{formatters=@(@{columnMatch="BlockRate";formatter=8;formatOptions=@{palette="redGreen"}})} }; name="scanners" }
            @{ type=3; content=@{ version="KqlItem/1.0"; query="CloudflareFirewall_CL $f`n| where Action in ('block','challenge','managed_challenge')`n| summarize Events=sum(SampleInterval) by ClientIP`n| where Events > 3`n| summarize RepeatingIPs=dcount(ClientIP), TotalEvents=sum(Events) by DayBucket=bin(now(),1d)`n| extend AvgEventsPerIP=round(TotalEvents*1.0/max_of(RepeatingIPs,1),1)`n| project RepeatingIPs, TotalEvents, AvgEventsPerIP"; size=0; title="Repeat Offender Summary"; queryType=0; resourceType="microsoft.operationalinsights/workspaces"; visualization="table" }; name="repeat-offenders" }
            @{ type=3; content=@{ version="KqlItem/1.0"; query="CloudflareFirewall_CL $f`n| where Action != 'block' and ClientIPClass in ('badHost','tor','scan')`n| summarize Allowed=sum(SampleInterval), Paths=make_set(RequestPath,5) by ClientIP, ClientIPClass, ClientCountry, Action`n| top 15 by Allowed`n| order by Allowed desc"; size=0; title="Suspicious IPs Passing Through (not blocked)"; queryType=0; resourceType="microsoft.operationalinsights/workspaces"; visualization="table" }; name="passthrough" }
        )}; name="s8" }
        # === 9. RAW EVENTS ===
        @{ type=12; content=@{ version="NotebookGroup/1.0"; groupType=0; title="Raw Events Explorer"; expandable=$true; expanded=$false; items=@(
            @{ type=3; content=@{ version="KqlItem/1.0"; query="CloudflareFirewall_CL $f`n| project TimeGenerated, Zone, Action, Source, ClientIP, ClientCountry, ClientASNDescription, ClientIPClass, RequestMethod, RequestHost, RequestPath, RuleDescription, EdgeResponseStatus, UserAgent, RayID, HttpProtocol, SampleInterval`n| order by TimeGenerated desc`n| take 500"; size=0; title="Recent Events (last 500)"; queryType=0; resourceType="microsoft.operationalinsights/workspaces"; visualization="table"; gridSettings=@{filter=$true; formatters=@(@{columnMatch="Action";formatter=18;formatOptions=@{thresholdsOptions="icons";thresholdsGrid=@(@{operator="==";thresholdValue="block";representation="4";text="{0}"},@{operator="==";thresholdValue="challenge";representation="2";text="{0}"},@{operator="==";thresholdValue="managed_challenge";representation="2";text="{0}"},@{operator="Default";representation="success";text="{0}"})}})} }; name="raw-events" }
        )}; name="s9" }
    )
    isLocked = $false
    fallbackResourceIds = @($workspaceId)
} | ConvertTo-Json -Depth 30 -Compress

$workbookBody = @{
    location = $Location
    tags = @{ "hidden-title" = $workbookName }
    kind = "shared"
    properties = @{
        displayName = $workbookName
        serializedData = $serializedNotebook
        version = "1.0"
        sourceId = $workspaceId
        category = "workbook"
    }
} | ConvertTo-Json -Depth 5

$token = az account get-access-token --query accessToken --output tsv
$headers = @{ "Authorization" = "Bearer $token"; "Content-Type" = "application/json" }
$uri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/workbooks/${workbookId}?api-version=2023-06-01"

try {
    Invoke-RestMethod -Uri $uri -Method PUT -Headers $headers -Body $workbookBody | Out-Null
    Write-Host "`nWorkbook deployed successfully!" -ForegroundColor Green
    Write-Host "Name:     $workbookName"
    Write-Host "ID:       $workbookId"
    Write-Host "Location: Azure Portal > Monitor > Workbooks"
} catch {
    Write-Host "Failed: $($_.Exception.Message)" -ForegroundColor Red
}


