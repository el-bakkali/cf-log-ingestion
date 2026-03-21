<#
.SYNOPSIS
    Deploys the Cloudflare DNS Analytics Azure Monitor Workbook.
.DESCRIPTION
    Creates a workbook for analyzing CloudflareDNS_CL data with interactive
    filters, traffic analysis, performance metrics, error tracking, cache
    effectiveness, resolver insights, infrastructure, security anomalies,
    and raw log exploration.
.PARAMETER SubscriptionId
    Azure subscription ID.
.PARAMETER ResourceGroup
    Resource group containing the Log Analytics workspace.
.PARAMETER WorkspaceName
    Log Analytics workspace name.
.PARAMETER Location
    Azure region (default: uksouth).
.EXAMPLE
    .\deploy-dns-workbook.ps1 -SubscriptionId "880a2b0e-..." -ResourceGroup "rg-cf-log-ingestion" -WorkspaceName "law-cf-security"
#>

param(
    [Parameter(Mandatory)]
    [string]$SubscriptionId,

    [Parameter(Mandatory)]
    [string]$ResourceGroup,

    [Parameter(Mandatory)]
    [string]$WorkspaceName,

    [string]$Location = "uksouth"
)

$ErrorActionPreference = "Stop"

Write-Host "Deploying Cloudflare DNS Analytics Workbook..." -ForegroundColor Cyan

$workspaceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"

$workbookId = [guid]::NewGuid().ToString()
$workbookName = "Cloudflare DNS Analytics"

# Common filter block used in all queries
$filter = @'
| where TimeGenerated {TimeRange}
| where ('*' in ({Zone}) or Zone in ({Zone}))
| where ('*' in ({QueryType}) or QueryType in ({QueryType}))
| where ('*' in ({ResponseCode}) or ResponseCode in ({ResponseCode}))
| where ('*' in ({Protocol}) or Protocol in ({Protocol}))
| where ('*' in ({Colo}) or ColoName in ({Colo}))
'@

$serializedNotebook = @{
    version = "Notebook/1.0"
    items = @(
        # ================================================================
        # GLOBAL PARAMETERS
        # ================================================================
        @{
            type = 9
            content = @{
                version = "KqlParameterItem/1.0"
                parameters = @(
                    @{
                        id = [guid]::NewGuid().ToString()
                        version = "KqlParameterItem/1.0"
                        name = "TimeRange"
                        type = 4
                        isRequired = $true
                        value = @{ durationMs = 86400000 }
                        typeSettings = @{
                            selectableValues = @(
                                @{ durationMs = 3600000 }
                                @{ durationMs = 14400000 }
                                @{ durationMs = 43200000 }
                                @{ durationMs = 86400000 }
                                @{ durationMs = 172800000 }
                                @{ durationMs = 604800000 }
                            )
                        }
                        label = "Time Range"
                    }
                    @{
                        id = [guid]::NewGuid().ToString()
                        version = "KqlParameterItem/1.0"
                        name = "Zone"
                        type = 2
                        multiSelect = $true
                        quote = "'"
                        delimiter = ","
                        query = "CloudflareDNS_CL | distinct Zone | sort by Zone asc"
                        typeSettings = @{ additionalResourceOptions = @("value::all") }
                        defaultValue = "value::all"
                        queryType = 0
                        resourceType = "microsoft.operationalinsights/workspaces"
                        label = "Zone"
                    }
                    @{
                        id = [guid]::NewGuid().ToString()
                        version = "KqlParameterItem/1.0"
                        name = "QueryType"
                        type = 2
                        multiSelect = $true
                        quote = "'"
                        delimiter = ","
                        query = "CloudflareDNS_CL | distinct QueryType | sort by QueryType asc"
                        typeSettings = @{ additionalResourceOptions = @("value::all") }
                        defaultValue = "value::all"
                        queryType = 0
                        resourceType = "microsoft.operationalinsights/workspaces"
                        label = "Query Type"
                    }
                    @{
                        id = [guid]::NewGuid().ToString()
                        version = "KqlParameterItem/1.0"
                        name = "ResponseCode"
                        type = 2
                        multiSelect = $true
                        quote = "'"
                        delimiter = ","
                        query = "CloudflareDNS_CL | distinct ResponseCode | sort by ResponseCode asc"
                        typeSettings = @{ additionalResourceOptions = @("value::all") }
                        defaultValue = "value::all"
                        queryType = 0
                        resourceType = "microsoft.operationalinsights/workspaces"
                        label = "Response Code"
                    }
                    @{
                        id = [guid]::NewGuid().ToString()
                        version = "KqlParameterItem/1.0"
                        name = "Protocol"
                        type = 2
                        multiSelect = $true
                        quote = "'"
                        delimiter = ","
                        query = "CloudflareDNS_CL | distinct Protocol | sort by Protocol asc"
                        typeSettings = @{ additionalResourceOptions = @("value::all") }
                        defaultValue = "value::all"
                        queryType = 0
                        resourceType = "microsoft.operationalinsights/workspaces"
                        label = "Protocol"
                    }
                    @{
                        id = [guid]::NewGuid().ToString()
                        version = "KqlParameterItem/1.0"
                        name = "Colo"
                        type = 2
                        multiSelect = $true
                        quote = "'"
                        delimiter = ","
                        query = "CloudflareDNS_CL | distinct ColoName | where isnotempty(ColoName) | sort by ColoName asc"
                        typeSettings = @{ additionalResourceOptions = @("value::all") }
                        defaultValue = "value::all"
                        queryType = 0
                        resourceType = "microsoft.operationalinsights/workspaces"
                        label = "Colo"
                    }
                )
                style = "pills"
                queryType = 0
                resourceType = "microsoft.operationalinsights/workspaces"
            }
            name = "parameters"
        }

        # ================================================================
        # SECTION 1: OVERVIEW
        # ================================================================
        @{
            type = 12
            content = @{
                version = "NotebookGroup/1.0"
                groupType = 0
                title = "Overview"
                expandable = $true
                expanded = $true
                items = @(
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = "let base = CloudflareDNS_CL $filter;`nlet total = toscalar(base | count);`nlet cached = toscalar(base | where ResponseCached == 1 | count);`nlet errors = toscalar(base | where ResponseCode != 'NOERROR' | count);`nprint TotalQueries = total, CacheHitRate = round(cached * 100.0 / max_of(total, 1), 1), ErrorRate = round(errors * 100.0 / max_of(total, 1), 1), UniqueResolvers = toscalar(base | summarize dcount(SourceIP)), UniqueDomains = toscalar(base | summarize dcount(QueryName))"
                            size = 4
                            title = "Key Metrics"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "table"
                        }
                        name = "overview-tiles"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = "CloudflareDNS_CL $filter`n| summarize Queries = count() by bin(TimeGenerated, 5m)`n| order by TimeGenerated asc"
                            size = 0
                            title = "Query Rate Over Time"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "timechart"
                        }
                        name = "query-rate"
                    }
                )
            }
            name = "overview-section"
        }

        # ================================================================
        # SECTION 2: DNS TRAFFIC ANALYSIS
        # ================================================================
        @{
            type = 12
            content = @{
                version = "NotebookGroup/1.0"
                groupType = 0
                title = "DNS Traffic Analysis"
                expandable = $true
                expanded = $false
                items = @(
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = "CloudflareDNS_CL $filter`n| summarize Queries = count() by QueryType`n| order by Queries desc"
                            size = 0
                            title = "Queries by Record Type"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "barchart"
                        }
                        name = "queries-by-type"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = "CloudflareDNS_CL $filter`n| summarize Queries = count(), Types = make_set(QueryType) by QueryName`n| top 20 by Queries`n| order by Queries desc"
                            size = 0
                            title = "Top 20 Queried Domains"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "table"
                        }
                        name = "top-domains"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = "CloudflareDNS_CL $filter`n| summarize Queries = count() by bin(TimeGenerated, 5m), QueryType`n| order by TimeGenerated asc"
                            size = 0
                            title = "Queries Over Time by Type"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "timechart"
                        }
                        name = "queries-over-time"
                    }
                )
            }
            name = "traffic-section"
        }

        # ================================================================
        # SECTION 3: PERFORMANCE & SIZE METRICS
        # ================================================================
        @{
            type = 12
            content = @{
                version = "NotebookGroup/1.0"
                groupType = 0
                title = "Performance & Size Metrics"
                expandable = $true
                expanded = $false
                items = @(
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = "CloudflareDNS_CL $filter`n| summarize AvgQuerySize = avg(QuerySize), AvgResponseSize = avg(ResponseSize) by bin(TimeGenerated, 5m)`n| order by TimeGenerated asc"
                            size = 0
                            title = "Average Query & Response Size Over Time (bytes)"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "timechart"
                        }
                        name = "size-over-time"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = "CloudflareDNS_CL $filter`n| summarize P50 = percentile(ResponseSize, 50), P95 = percentile(ResponseSize, 95), P99 = percentile(ResponseSize, 99), AvgBytes = round(avg(ResponseSize), 0), MaxBytes = max(ResponseSize) by QueryType`n| order by AvgBytes desc"
                            size = 0
                            title = "Response Size Percentiles by Query Type"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "table"
                        }
                        name = "size-percentiles"
                    }
                )
            }
            name = "performance-section"
        }

        # ================================================================
        # SECTION 4: ERRORS & FAILURES
        # ================================================================
        @{
            type = 12
            content = @{
                version = "NotebookGroup/1.0"
                groupType = 0
                title = "Errors & Failures"
                expandable = $true
                expanded = $false
                items = @(
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = "CloudflareDNS_CL $filter`n| summarize Queries = count() by ResponseCode`n| order by Queries desc"
                            size = 0
                            title = "Response Code Distribution"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "piechart"
                        }
                        name = "response-codes"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = "CloudflareDNS_CL $filter`n| where ResponseCode == 'NXDOMAIN'`n| summarize NXDOMAIN = count() by bin(TimeGenerated, 5m)`n| order by TimeGenerated asc"
                            size = 0
                            title = "NXDOMAIN Trends Over Time"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "timechart"
                            chartSettings = @{ seriesLabelSettings = @(@{ series = "NXDOMAIN"; color = "redBright" }) }
                        }
                        name = "nxdomain-trends"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = "CloudflareDNS_CL $filter`n| where ResponseCode != 'NOERROR'`n| summarize Failures = count() by QueryName, ResponseCode`n| top 20 by Failures`n| order by Failures desc"
                            size = 0
                            title = "Top Failing Domains"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "table"
                        }
                        name = "top-failures"
                    }
                )
            }
            name = "errors-section"
        }

        # ================================================================
        # SECTION 5: CACHE EFFECTIVENESS
        # ================================================================
        @{
            type = 12
            content = @{
                version = "NotebookGroup/1.0"
                groupType = 0
                title = "Cache Effectiveness"
                expandable = $true
                expanded = $false
                items = @(
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = "CloudflareDNS_CL $filter`n| summarize Queries = count() by CacheStatus = iff(ResponseCached == 1, 'Cached', 'Not Cached')`n| order by Queries desc"
                            size = 0
                            title = "Cache Hit vs Miss"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "piechart"
                        }
                        name = "cache-ratio"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = "CloudflareDNS_CL $filter`n| summarize Total = count(), Cached = countif(ResponseCached == 1), HitRate = round(countif(ResponseCached == 1) * 100.0 / count(), 1) by QueryType`n| order by Total desc"
                            size = 0
                            title = "Cache Hit Rate by Query Type"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "table"
                            gridSettings = @{ formatters = @(@{ columnMatch = "HitRate"; formatter = 8; formatOptions = @{ palette = "greenRed" } }) }
                        }
                        name = "cache-by-type"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = "CloudflareDNS_CL $filter`n| summarize HitRate = round(countif(ResponseCached == 1) * 100.0 / count(), 1) by bin(TimeGenerated, 15m)`n| order by TimeGenerated asc"
                            size = 0
                            title = "Cache Hit Rate Over Time (%)"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "timechart"
                        }
                        name = "cache-over-time"
                    }
                )
            }
            name = "cache-section"
        }

        # ================================================================
        # SECTION 6: CLIENT & RESOLVER INSIGHTS
        # ================================================================
        @{
            type = 12
            content = @{
                version = "NotebookGroup/1.0"
                groupType = 0
                title = "Client & Resolver Insights"
                expandable = $true
                expanded = $false
                items = @(
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = "CloudflareDNS_CL $filter`n| summarize Queries = count(), UniqueDomains = dcount(QueryName), Types = make_set(QueryType) by SourceIP`n| top 20 by Queries`n| order by Queries desc"
                            size = 0
                            title = "Top 20 Resolvers by Query Volume"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "table"
                        }
                        name = "top-resolvers"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = "CloudflareDNS_CL $filter`n| summarize Queries = count() by IPVersion = iff(IPVersion == 4, 'IPv4', 'IPv6')`n| order by Queries desc"
                            size = 0
                            title = "IPv4 vs IPv6"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "piechart"
                        }
                        name = "ip-version"
                    }
                )
            }
            name = "client-section"
        }

        # ================================================================
        # SECTION 7: INFRASTRUCTURE (COLO / PROTOCOL)
        # ================================================================
        @{
            type = 12
            content = @{
                version = "NotebookGroup/1.0"
                groupType = 0
                title = "Infrastructure (Colo / Protocol)"
                expandable = $true
                expanded = $false
                items = @(
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = "CloudflareDNS_CL $filter`n| summarize Queries = count() by ColoName`n| top 20 by Queries`n| order by Queries desc"
                            size = 0
                            title = "Top Cloudflare PoPs"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "barchart"
                        }
                        name = "top-colos"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = "CloudflareDNS_CL $filter`n| summarize Queries = count() by Protocol`n| order by Queries desc"
                            size = 0
                            title = "Protocol Distribution"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "piechart"
                        }
                        name = "protocol-dist"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = "CloudflareDNS_CL $filter`n| summarize Queries = count() by DestinationIP`n| top 10 by Queries`n| order by Queries desc"
                            size = 0
                            title = "Destination Nameserver Usage"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "table"
                        }
                        name = "destination-ips"
                    }
                )
            }
            name = "infra-section"
        }

        # ================================================================
        # SECTION 8: SECURITY & ANOMALIES
        # ================================================================
        @{
            type = 12
            content = @{
                version = "NotebookGroup/1.0"
                groupType = 0
                title = "Security & Anomalies"
                expandable = $true
                expanded = $false
                items = @(
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = "CloudflareDNS_CL $filter`n| where ResponseCode == 'NXDOMAIN'`n| summarize NXDOMAINs = count(), UniqueNames = dcount(QueryName) by SourceIP`n| where NXDOMAINs > 5`n| top 20 by NXDOMAINs`n| order by NXDOMAINs desc"
                            size = 0
                            title = "High NXDOMAIN Sources (possible DGA / enumeration)"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "table"
                            gridSettings = @{ formatters = @(@{ columnMatch = "NXDOMAINs"; formatter = 8; formatOptions = @{ palette = "redGreen" } }) }
                        }
                        name = "dga-detection"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = "CloudflareDNS_CL $filter`n| extend DomainLength = strlen(QueryName)`n| where DomainLength > 40`n| summarize Queries = count() by QueryName, SourceIP`n| top 20 by Queries`n| order by Queries desc"
                            size = 0
                            title = "Unusually Long Domain Names (>40 chars)"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "table"
                        }
                        name = "long-domains"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = "CloudflareDNS_CL $filter`n| summarize Queries = count(), UniqueDomains = dcount(QueryName), ErrorRate = round(countif(ResponseCode != 'NOERROR') * 100.0 / count(), 1) by SourceIP`n| where Queries > 20`n| top 15 by Queries`n| order by Queries desc"
                            size = 0
                            title = "High Volume Resolvers (>20 queries)"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "table"
                            gridSettings = @{ formatters = @(@{ columnMatch = "ErrorRate"; formatter = 8; formatOptions = @{ palette = "redGreen" } }) }
                        }
                        name = "high-volume-resolvers"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = "CloudflareDNS_CL $filter`n| where QueryType !in ('A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'DNSKEY', 'DS', 'HTTPS')`n| summarize Queries = count() by QueryType, QueryName, SourceIP`n| top 20 by Queries`n| order by Queries desc"
                            size = 0
                            title = "Rare Query Types (non-standard)"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "table"
                        }
                        name = "rare-types"
                    }
                )
            }
            name = "security-section"
        }

        # ================================================================
        # SECTION 9: RAW QUERY EXPLORER
        # ================================================================
        @{
            type = 12
            content = @{
                version = "NotebookGroup/1.0"
                groupType = 0
                title = "Raw Query Explorer"
                expandable = $true
                expanded = $false
                items = @(
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = "CloudflareDNS_CL $filter`n| project TimeGenerated, Zone, QueryName, QueryType, ResponseCode, ResponseCached, SourceIP, Protocol, ColoName, DestinationIP, IPVersion, QuerySize, ResponseSize, SampleInterval`n| order by TimeGenerated desc`n| take 500"
                            size = 0
                            title = "Recent DNS Queries (last 500)"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "table"
                            gridSettings = @{
                                filter = $true
                                formatters = @(
                                    @{
                                        columnMatch = "ResponseCode"
                                        formatter = 18
                                        formatOptions = @{
                                            thresholdsOptions = "icons"
                                            thresholdsGrid = @(
                                                @{ operator = "=="; thresholdValue = "NXDOMAIN"; representation = "4"; text = "{0}" }
                                                @{ operator = "=="; thresholdValue = "SERVFAIL"; representation = "4"; text = "{0}" }
                                                @{ operator = "=="; thresholdValue = "NOERROR"; representation = "success"; text = "{0}" }
                                                @{ operator = "Default"; representation = "2"; text = "{0}" }
                                            )
                                        }
                                    }
                                )
                            }
                        }
                        name = "raw-logs"
                    }
                )
            }
            name = "raw-section"
        }
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
$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type"  = "application/json"
}

$workbookUri = "https://management.azure.com/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/workbooks/${workbookId}?api-version=2023-06-01"

try {
    Invoke-RestMethod -Uri $workbookUri -Method PUT -Headers $headers -Body $workbookBody | Out-Null
    Write-Host "`nWorkbook deployed successfully!" -ForegroundColor Green
    Write-Host "Name:     $workbookName"
    Write-Host "ID:       $workbookId"
    Write-Host "Location: Azure Portal > Monitor > Workbooks"
} catch {
    Write-Host "Failed to deploy workbook: $($_.Exception.Message)" -ForegroundColor Red
}

