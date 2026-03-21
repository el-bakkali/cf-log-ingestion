<#
.SYNOPSIS
    Deploys the Cloudflare HTTP Requests Azure Monitor Workbook.
.DESCRIPTION
    Creates a workbook for analyzing CloudflareHTTPRequests_CL data with
    interactive filters, traffic analysis, performance metrics, error tracking,
    client insights, security anomalies, and raw log exploration.
.PARAMETER SubscriptionId
    Azure subscription ID.
.PARAMETER ResourceGroup
    Resource group containing the Log Analytics workspace.
.PARAMETER WorkspaceName
    Log Analytics workspace name.
.PARAMETER Location
    Azure region (default: uksouth).
.EXAMPLE
    .\deploy-http-workbook.ps1 -SubscriptionId "880a2b0e-..." -ResourceGroup "rg-cf-log-ingestion" -WorkspaceName "law-cf-security"
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

Write-Host "Deploying Cloudflare HTTP Requests Workbook..." -ForegroundColor Cyan

$workspaceId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName"

$workbookId = [guid]::NewGuid().ToString()
$workbookName = "Cloudflare HTTP Requests"

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
                        isRequired = $false
                        multiSelect = $true
                        quote = "'"
                        delimiter = ","
                        query = "CloudflareHTTPRequests_CL | distinct Zone | sort by Zone asc"
                        typeSettings = @{ additionalResourceOptions = @("value::all") }
                        defaultValue = "value::all"
                        queryType = 0
                        resourceType = "microsoft.operationalinsights/workspaces"
                        label = "Zone"
                    }
                    @{
                        id = [guid]::NewGuid().ToString()
                        version = "KqlParameterItem/1.0"
                        name = "Country"
                        type = 2
                        isRequired = $false
                        multiSelect = $true
                        quote = "'"
                        delimiter = ","
                        query = "CloudflareHTTPRequests_CL | distinct ClientCountry | where isnotempty(ClientCountry) | sort by ClientCountry asc"
                        typeSettings = @{ additionalResourceOptions = @("value::all") }
                        defaultValue = "value::all"
                        queryType = 0
                        resourceType = "microsoft.operationalinsights/workspaces"
                        label = "Country"
                    }
                    @{
                        id = [guid]::NewGuid().ToString()
                        version = "KqlParameterItem/1.0"
                        name = "Host"
                        type = 2
                        isRequired = $false
                        multiSelect = $true
                        quote = "'"
                        delimiter = ","
                        query = "CloudflareHTTPRequests_CL | distinct RequestHost | sort by RequestHost asc"
                        typeSettings = @{ additionalResourceOptions = @("value::all") }
                        defaultValue = "value::all"
                        queryType = 0
                        resourceType = "microsoft.operationalinsights/workspaces"
                        label = "Host"
                    }
                    @{
                        id = [guid]::NewGuid().ToString()
                        version = "KqlParameterItem/1.0"
                        name = "Method"
                        type = 2
                        isRequired = $false
                        multiSelect = $true
                        quote = "'"
                        delimiter = ","
                        query = "CloudflareHTTPRequests_CL | distinct RequestMethod | sort by RequestMethod asc"
                        typeSettings = @{ additionalResourceOptions = @("value::all") }
                        defaultValue = "value::all"
                        queryType = 0
                        resourceType = "microsoft.operationalinsights/workspaces"
                        label = "Method"
                    }
                )
                style = "pills"
                queryType = 0
                resourceType = "microsoft.operationalinsights/workspaces"
            }
            name = "parameters"
        }

        # ================================================================
        # SECTION: OVERVIEW
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
                    # --- Overview Tiles ---
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = @"
let baseFilter = CloudflareHTTPRequests_CL
| where TimeGenerated {TimeRange}
| where ('*' in ({Zone}) or Zone in ({Zone}))
| where ('*' in ({Country}) or ClientCountry in ({Country}))
| where ('*' in ({Host}) or RequestHost in ({Host}))
| where ('*' in ({Method}) or RequestMethod in ({Method}));
let total = baseFilter | count;
let errors = baseFilter | where EdgeResponseStatus >= 400 | count;
let errorRate = toscalar(errors) * 100.0 / max_of(toscalar(total), 1);
let avgDuration = baseFilter | summarize avg(OriginResponseDurationMs);
let uniqueIPs = baseFilter | summarize dcount(ClientIP);
let countries = baseFilter | summarize dcount(ClientCountry);
let cacheHitRate = baseFilter | summarize hits = countif(CacheStatus == "hit"), total = count() | extend rate = round(hits * 100.0 / max_of(total, 1), 1);
print
    TotalRequests = toscalar(total),
    ErrorRate = round(errorRate, 1),
    AvgOriginMs = toscalar(avgDuration),
    UniqueIPs = toscalar(uniqueIPs),
    Countries = toscalar(countries),
    CacheHitRate = toscalar(cacheHitRate | project rate)
"@
                            size = 4
                            title = "Key Metrics"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "table"
                            tileSettings = @{
                                titleContent = @{ columnMatch = "Column1"; formatter = 1 }
                                subtitleContent = @{ columnMatch = "Column2" }
                                showBorder = $false
                            }
                        }
                        name = "overview-tiles"
                    }
                    # --- Requests Over Time ---
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = @"
CloudflareHTTPRequests_CL
| where TimeGenerated {TimeRange}
| where ('*' in ({Zone}) or Zone in ({Zone}))
| where ('*' in ({Country}) or ClientCountry in ({Country}))
| where ('*' in ({Host}) or RequestHost in ({Host}))
| where ('*' in ({Method}) or RequestMethod in ({Method}))
| summarize
    Total = count(),
    Errors = countif(EdgeResponseStatus >= 400),
    Success = countif(EdgeResponseStatus < 400)
    by bin(TimeGenerated, 5m)
| order by TimeGenerated asc
"@
                            size = 0
                            title = "Requests Over Time"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "timechart"
                            chartSettings = @{
                                seriesLabelSettings = @(
                                    @{ series = "Errors"; color = "redBright" }
                                    @{ series = "Success"; color = "green" }
                                    @{ series = "Total"; color = "blue" }
                                )
                            }
                        }
                        name = "requests-over-time"
                    }
                    # --- Top Countries ---
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = @"
CloudflareHTTPRequests_CL
| where TimeGenerated {TimeRange}
| where ('*' in ({Zone}) or Zone in ({Zone}))
| where ('*' in ({Host}) or RequestHost in ({Host}))
| where ('*' in ({Method}) or RequestMethod in ({Method}))
| summarize Requests = count() by ClientCountry
| top 15 by Requests
| order by Requests desc
"@
                            size = 0
                            title = "Top Countries"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "barchart"
                        }
                        name = "top-countries"
                    }
                )
            }
            name = "overview-section"
        }

        # ================================================================
        # SECTION: TRAFFIC ANALYSIS
        # ================================================================
        @{
            type = 12
            content = @{
                version = "NotebookGroup/1.0"
                groupType = 0
                title = "Traffic Analysis"
                expandable = $true
                expanded = $false
                items = @(
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = @"
CloudflareHTTPRequests_CL
| where TimeGenerated {TimeRange}
| where ('*' in ({Zone}) or Zone in ({Zone}))
| where ('*' in ({Country}) or ClientCountry in ({Country}))
| where ('*' in ({Host}) or RequestHost in ({Host}))
| where ('*' in ({Method}) or RequestMethod in ({Method}))
| summarize Requests = count(), ErrorRate = round(countif(EdgeResponseStatus >= 400) * 100.0 / count(), 1) by RequestHost
| order by Requests desc
"@
                            size = 0
                            title = "Requests by Host"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "table"
                            gridSettings = @{
                                formatters = @(
                                    @{ columnMatch = "ErrorRate"; formatter = 8; formatOptions = @{ palette = "redGreen" } }
                                )
                            }
                        }
                        name = "requests-by-host"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = @"
CloudflareHTTPRequests_CL
| where TimeGenerated {TimeRange}
| where ('*' in ({Zone}) or Zone in ({Zone}))
| where ('*' in ({Country}) or ClientCountry in ({Country}))
| where ('*' in ({Host}) or RequestHost in ({Host}))
| where ('*' in ({Method}) or RequestMethod in ({Method}))
| summarize Requests = count() by RequestMethod
| order by Requests desc
"@
                            size = 0
                            title = "Requests by Method"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "piechart"
                        }
                        name = "requests-by-method"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = @"
CloudflareHTTPRequests_CL
| where TimeGenerated {TimeRange}
| where ('*' in ({Zone}) or Zone in ({Zone}))
| where ('*' in ({Country}) or ClientCountry in ({Country}))
| where ('*' in ({Host}) or RequestHost in ({Host}))
| where ('*' in ({Method}) or RequestMethod in ({Method}))
| summarize Requests = count() by RequestPath
| top 20 by Requests
| order by Requests desc
"@
                            size = 0
                            title = "Top 20 Request Paths"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "barchart"
                        }
                        name = "top-paths"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = @"
CloudflareHTTPRequests_CL
| where TimeGenerated {TimeRange}
| where ('*' in ({Zone}) or Zone in ({Zone}))
| where ('*' in ({Country}) or ClientCountry in ({Country}))
| where ('*' in ({Host}) or RequestHost in ({Host}))
| where ('*' in ({Method}) or RequestMethod in ({Method}))
| summarize Requests = count(), HitRate = round(countif(CacheStatus == "hit") * 100.0 / count(), 1) by CacheStatus
| order by Requests desc
"@
                            size = 0
                            title = "Cache Status Distribution"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "piechart"
                        }
                        name = "cache-status"
                    }
                )
            }
            name = "traffic-section"
        }

        # ================================================================
        # SECTION: PERFORMANCE
        # ================================================================
        @{
            type = 12
            content = @{
                version = "NotebookGroup/1.0"
                groupType = 0
                title = "Performance"
                expandable = $true
                expanded = $false
                items = @(
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = @"
CloudflareHTTPRequests_CL
| where TimeGenerated {TimeRange}
| where ('*' in ({Zone}) or Zone in ({Zone}))
| where ('*' in ({Country}) or ClientCountry in ({Country}))
| where ('*' in ({Host}) or RequestHost in ({Host}))
| where ('*' in ({Method}) or RequestMethod in ({Method}))
| where OriginResponseDurationMs > 0
| summarize
    P50 = percentile(OriginResponseDurationMs, 50),
    P95 = percentile(OriginResponseDurationMs, 95),
    P99 = percentile(OriginResponseDurationMs, 99),
    Avg = avg(OriginResponseDurationMs)
    by bin(TimeGenerated, 5m)
| order by TimeGenerated asc
"@
                            size = 0
                            title = "Origin Response Time Over Time (ms)"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "timechart"
                            chartSettings = @{
                                seriesLabelSettings = @(
                                    @{ series = "P99"; color = "redBright" }
                                    @{ series = "P95"; color = "orange" }
                                    @{ series = "P50"; color = "green" }
                                    @{ series = "Avg"; color = "blue" }
                                )
                            }
                        }
                        name = "perf-timechart"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = @"
CloudflareHTTPRequests_CL
| where TimeGenerated {TimeRange}
| where ('*' in ({Zone}) or Zone in ({Zone}))
| where ('*' in ({Country}) or ClientCountry in ({Country}))
| where ('*' in ({Host}) or RequestHost in ({Host}))
| where ('*' in ({Method}) or RequestMethod in ({Method}))
| where OriginResponseDurationMs > 0
| summarize
    Requests = count(),
    AvgMs = round(avg(OriginResponseDurationMs), 0),
    P50 = round(percentile(OriginResponseDurationMs, 50), 0),
    P95 = round(percentile(OriginResponseDurationMs, 95), 0),
    P99 = round(percentile(OriginResponseDurationMs, 99), 0),
    MaxMs = max(OriginResponseDurationMs)
    by RequestHost
| order by AvgMs desc
"@
                            size = 0
                            title = "Performance by Host"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "table"
                            gridSettings = @{
                                formatters = @(
                                    @{ columnMatch = "P99"; formatter = 8; formatOptions = @{ palette = "redGreen" } }
                                )
                            }
                        }
                        name = "perf-by-host"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = @"
CloudflareHTTPRequests_CL
| where TimeGenerated {TimeRange}
| where ('*' in ({Zone}) or Zone in ({Zone}))
| where ('*' in ({Country}) or ClientCountry in ({Country}))
| where ('*' in ({Host}) or RequestHost in ({Host}))
| where ('*' in ({Method}) or RequestMethod in ({Method}))
| where OriginResponseDurationMs > 0
| summarize
    Requests = count(),
    AvgMs = round(avg(OriginResponseDurationMs), 0),
    P95 = round(percentile(OriginResponseDurationMs, 95), 0)
    by RequestPath
| top 15 by AvgMs
| order by AvgMs desc
"@
                            size = 0
                            title = "Slowest Paths (Top 15)"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "table"
                        }
                        name = "slowest-paths"
                    }
                )
            }
            name = "performance-section"
        }

        # ================================================================
        # SECTION: ERRORS & FAILURES
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
                            query = @"
CloudflareHTTPRequests_CL
| where TimeGenerated {TimeRange}
| where ('*' in ({Zone}) or Zone in ({Zone}))
| where ('*' in ({Country}) or ClientCountry in ({Country}))
| where ('*' in ({Host}) or RequestHost in ({Host}))
| where ('*' in ({Method}) or RequestMethod in ({Method}))
| summarize Requests = count() by tostring(EdgeResponseStatus)
| order by Requests desc
"@
                            size = 0
                            title = "Edge Response Status Distribution"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "piechart"
                        }
                        name = "status-distribution"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = @"
CloudflareHTTPRequests_CL
| where TimeGenerated {TimeRange}
| where ('*' in ({Zone}) or Zone in ({Zone}))
| where ('*' in ({Country}) or ClientCountry in ({Country}))
| where ('*' in ({Host}) or RequestHost in ({Host}))
| where ('*' in ({Method}) or RequestMethod in ({Method}))
| where EdgeResponseStatus >= 400
| summarize Errors = count() by bin(TimeGenerated, 5m), StatusGroup = case(
    EdgeResponseStatus >= 500, "5xx Server",
    EdgeResponseStatus >= 400, "4xx Client",
    "Other")
| order by TimeGenerated asc
"@
                            size = 0
                            title = "Error Trends Over Time"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "timechart"
                            chartSettings = @{
                                seriesLabelSettings = @(
                                    @{ series = "5xx Server"; color = "redBright" }
                                    @{ series = "4xx Client"; color = "orange" }
                                )
                            }
                        }
                        name = "error-trends"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = @"
CloudflareHTTPRequests_CL
| where TimeGenerated {TimeRange}
| where ('*' in ({Zone}) or Zone in ({Zone}))
| where ('*' in ({Country}) or ClientCountry in ({Country}))
| where ('*' in ({Host}) or RequestHost in ({Host}))
| where ('*' in ({Method}) or RequestMethod in ({Method}))
| where EdgeResponseStatus >= 400
| summarize Errors = count(), StatusCodes = make_set(EdgeResponseStatus) by RequestPath, RequestHost
| top 20 by Errors
| order by Errors desc
"@
                            size = 0
                            title = "Top Failing Paths"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "table"
                        }
                        name = "top-failing-paths"
                    }
                )
            }
            name = "errors-section"
        }

        # ================================================================
        # SECTION: CLIENT INSIGHTS
        # ================================================================
        @{
            type = 12
            content = @{
                version = "NotebookGroup/1.0"
                groupType = 0
                title = "Client Insights"
                expandable = $true
                expanded = $false
                items = @(
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = @"
CloudflareHTTPRequests_CL
| where TimeGenerated {TimeRange}
| where ('*' in ({Zone}) or Zone in ({Zone}))
| where ('*' in ({Country}) or ClientCountry in ({Country}))
| where ('*' in ({Host}) or RequestHost in ({Host}))
| where ('*' in ({Method}) or RequestMethod in ({Method}))
| where isnotempty(UserAgentBrowser)
| summarize Requests = count() by UserAgentBrowser
| top 10 by Requests
| order by Requests desc
"@
                            size = 0
                            title = "Browser Distribution"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "piechart"
                        }
                        name = "browser-dist"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = @"
CloudflareHTTPRequests_CL
| where TimeGenerated {TimeRange}
| where ('*' in ({Zone}) or Zone in ({Zone}))
| where ('*' in ({Country}) or ClientCountry in ({Country}))
| where ('*' in ({Host}) or RequestHost in ({Host}))
| where ('*' in ({Method}) or RequestMethod in ({Method}))
| where isnotempty(UserAgentOS)
| summarize Requests = count() by UserAgentOS
| top 10 by Requests
| order by Requests desc
"@
                            size = 0
                            title = "OS Distribution"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "piechart"
                        }
                        name = "os-dist"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = @"
CloudflareHTTPRequests_CL
| where TimeGenerated {TimeRange}
| where ('*' in ({Zone}) or Zone in ({Zone}))
| where ('*' in ({Country}) or ClientCountry in ({Country}))
| where ('*' in ({Host}) or RequestHost in ({Host}))
| where ('*' in ({Method}) or RequestMethod in ({Method}))
| where isnotempty(ClientDeviceType)
| summarize Requests = count() by ClientDeviceType
| order by Requests desc
"@
                            size = 0
                            title = "Device Types"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "piechart"
                        }
                        name = "device-types"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = @"
CloudflareHTTPRequests_CL
| where TimeGenerated {TimeRange}
| where ('*' in ({Zone}) or Zone in ({Zone}))
| where ('*' in ({Country}) or ClientCountry in ({Country}))
| where ('*' in ({Host}) or RequestHost in ({Host}))
| where ('*' in ({Method}) or RequestMethod in ({Method}))
| where isnotempty(ClientASNDescription)
| summarize Requests = count(), UniqueIPs = dcount(ClientIP), ErrorRate = round(countif(EdgeResponseStatus >= 400) * 100.0 / count(), 1) by ClientASN, ClientASNDescription
| top 15 by Requests
| order by Requests desc
"@
                            size = 0
                            title = "Top ASNs"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "table"
                        }
                        name = "top-asns"
                    }
                )
            }
            name = "client-section"
        }

        # ================================================================
        # SECTION: SECURITY & ANOMALIES
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
                            query = @"
CloudflareHTTPRequests_CL
| where TimeGenerated {TimeRange}
| where ('*' in ({Zone}) or Zone in ({Zone}))
| where ('*' in ({Country}) or ClientCountry in ({Country}))
| where ('*' in ({Host}) or RequestHost in ({Host}))
| where ('*' in ({Method}) or RequestMethod in ({Method}))
| summarize Requests = count(), Paths = dcount(RequestPath), ErrorRate = round(countif(EdgeResponseStatus >= 400) * 100.0 / count(), 1) by ClientIP, ClientCountry, ClientASNDescription
| where Requests > 10
| top 20 by Requests
| order by Requests desc
"@
                            size = 0
                            title = "High Volume IPs (>10 requests)"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "table"
                            gridSettings = @{
                                formatters = @(
                                    @{ columnMatch = "ErrorRate"; formatter = 8; formatOptions = @{ palette = "redGreen" } }
                                )
                            }
                        }
                        name = "high-volume-ips"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = @"
CloudflareHTTPRequests_CL
| where TimeGenerated {TimeRange}
| where ('*' in ({Zone}) or Zone in ({Zone}))
| where ('*' in ({Country}) or ClientCountry in ({Country}))
| where ('*' in ({Host}) or RequestHost in ({Host}))
| where ('*' in ({Method}) or RequestMethod in ({Method}))
| summarize Requests = count() by TLSVersion
| order by Requests desc
"@
                            size = 0
                            title = "TLS Version Distribution"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "piechart"
                        }
                        name = "tls-versions"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = @"
CloudflareHTTPRequests_CL
| where TimeGenerated {TimeRange}
| where ('*' in ({Zone}) or Zone in ({Zone}))
| where ('*' in ({Country}) or ClientCountry in ({Country}))
| where ('*' in ({Host}) or RequestHost in ({Host}))
| where ('*' in ({Method}) or RequestMethod in ({Method}))
| where isnotempty(UserAgent)
| summarize Requests = count(), UniqueIPs = dcount(ClientIP) by UserAgent
| where Requests == 1 or strlen(UserAgent) < 20
| top 20 by Requests
| order by Requests desc
"@
                            size = 0
                            title = "Rare / Short User Agents (potential bots)"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "table"
                        }
                        name = "rare-user-agents"
                    }
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = @"
CloudflareHTTPRequests_CL
| where TimeGenerated {TimeRange}
| where ('*' in ({Zone}) or Zone in ({Zone}))
| where ('*' in ({Country}) or ClientCountry in ({Country}))
| where ('*' in ({Host}) or RequestHost in ({Host}))
| where ('*' in ({Method}) or RequestMethod in ({Method}))
| where isnotempty(RequestQuery) and RequestQuery != "?"
| summarize Requests = count() by RequestQuery
| top 20 by Requests
| order by Requests desc
"@
                            size = 0
                            title = "Top Query Strings"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "table"
                        }
                        name = "query-strings"
                    }
                )
            }
            name = "security-section"
        }

        # ================================================================
        # SECTION: RAW LOGS EXPLORER
        # ================================================================
        @{
            type = 12
            content = @{
                version = "NotebookGroup/1.0"
                groupType = 0
                title = "Raw Logs Explorer"
                expandable = $true
                expanded = $false
                items = @(
                    @{
                        type = 3
                        content = @{
                            version = "KqlItem/1.0"
                            query = @"
CloudflareHTTPRequests_CL
| where TimeGenerated {TimeRange}
| where ('*' in ({Zone}) or Zone in ({Zone}))
| where ('*' in ({Country}) or ClientCountry in ({Country}))
| where ('*' in ({Host}) or RequestHost in ({Host}))
| where ('*' in ({Method}) or RequestMethod in ({Method}))
| project TimeGenerated, Zone, RequestHost, RequestMethod, RequestPath, RequestQuery, EdgeResponseStatus, OriginResponseStatus, OriginResponseDurationMs, CacheStatus, ClientIP, ClientCountry, ClientASNDescription, ClientDeviceType, TLSVersion, UserAgentBrowser, UserAgentOS, HttpProtocol, RequestScheme
| order by TimeGenerated desc
| take 500
"@
                            size = 0
                            title = "Recent Requests (last 500)"
                            queryType = 0
                            resourceType = "microsoft.operationalinsights/workspaces"
                            visualization = "table"
                            gridSettings = @{
                                filter = $true
                                formatters = @(
                                    @{
                                        columnMatch = "EdgeResponseStatus"
                                        formatter = 18
                                        formatOptions = @{
                                            thresholdsOptions = "icons"
                                            thresholdsGrid = @(
                                                @{ operator = ">="; thresholdValue = 500; representation = "4"; text = "{0}" }
                                                @{ operator = ">="; thresholdValue = 400; representation = "2"; text = "{0}" }
                                                @{ operator = "Default"; representation = "success"; text = "{0}" }
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
            name = "raw-logs-section"
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


