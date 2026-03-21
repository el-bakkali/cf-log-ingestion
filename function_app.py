"""
Azure Function: Cloudflare Log Ingestion to Azure Log Analytics
Two timer triggers:
  1. cf_log_ingestion     — Firewall events (firewallEventsAdaptive)
  2. cf_http_ingestion    — HTTP request logs (httpRequestsAdaptiveGroups)
Both run every 1 minute, pulling from Cloudflare GraphQL API and ingesting
into separate custom Log Analytics tables via the Logs Ingestion API.
"""

import os
import json
import logging
import datetime
import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.monitor.ingestion import LogsIngestionClient
from azure.core.exceptions import HttpResponseError
import requests

app = func.FunctionApp()

GRAPHQL_URL = "https://api.cloudflare.com/client/v4/graphql"

FIREWALL_QUERY = """
{
  viewer {
    zones(filter: {zoneTag: "%s"}) {
      firewallEventsAdaptive(
        filter: {datetime_gt: "%s", datetime_lt: "%s"}
        limit: 10000
        orderBy: [datetime_ASC]
      ) {
        datetime
        action
        clientIP
        clientRequestPath
        clientRequestQuery
        clientRequestHTTPMethodName
        clientRequestHTTPHost
        clientRequestHTTPProtocol
        clientCountryName
        clientAsn
        clientASNDescription
        clientIPClass
        userAgent
        rayName
        description
        source
        ruleId
        rulesetId
        clientRefererHost
        edgeResponseStatus
        sampleInterval
        kind
      }
    }
  }
}
"""


def query_cloudflare(cf_token: str, zone_id: str, time_start: str, time_end: str) -> list:
    """Query Cloudflare GraphQL API for firewall events in a time window."""
    headers = {
        "Authorization": f"Bearer {cf_token}",
        "Content-Type": "application/json",
    }
    query = FIREWALL_QUERY % (zone_id, time_start, time_end)
    payload = json.dumps({"query": query})

    response = requests.post(GRAPHQL_URL, headers=headers, data=payload, timeout=30)
    response.raise_for_status()
    result = response.json()

    if result.get("errors"):
        error_msg = result["errors"][0].get("message", "Unknown GraphQL error")
        logging.error("Cloudflare GraphQL error for zone %s: %s", zone_id, error_msg)
        return []

    zones = result.get("data", {}).get("viewer", {}).get("zones", [])
    if not zones:
        return []

    return zones[0].get("firewallEventsAdaptive", [])


def transform_events(events: list, zone_name: str) -> list:
    """Transform Cloudflare events into the Log Analytics table schema."""
    transformed = []
    for event in events:
        transformed.append({
            "TimeGenerated": event["datetime"],
            "Zone": zone_name,
            "Action": event.get("action", ""),
            "ClientIP": event.get("clientIP", ""),
            "ClientCountry": event.get("clientCountryName", ""),
            "ClientASN": str(event.get("clientAsn", "")),
            "ClientASNDescription": event.get("clientASNDescription", ""),
            "RequestPath": event.get("clientRequestPath", ""),
            "RequestQuery": event.get("clientRequestQuery", ""),
            "RequestMethod": event.get("clientRequestHTTPMethodName", ""),
            "RequestHost": event.get("clientRequestHTTPHost", ""),
            "UserAgent": event.get("userAgent", ""),
            "RayID": event.get("rayName", ""),
            "RuleDescription": event.get("description", ""),
            "Source": event.get("source", ""),
            "RuleId": event.get("ruleId", ""),
            "RefererHost": event.get("clientRefererHost", ""),
            "EdgeResponseStatus": event.get("edgeResponseStatus", 0),
            "ClientIPClass": event.get("clientIPClass", ""),
            "HttpProtocol": event.get("clientRequestHTTPProtocol", ""),
            "RulesetId": event.get("rulesetId", ""),
            "SampleInterval": event.get("sampleInterval", 1),
            "Kind": event.get("kind", ""),
        })
    return transformed


def send_to_log_analytics(logs: list, dcr_id: str, stream_name: str, endpoint: str):
    """Send transformed logs to Azure Log Analytics via Ingestion API."""
    credential = DefaultAzureCredential()
    client = LogsIngestionClient(endpoint=endpoint, credential=credential)

    try:
        client.upload(rule_id=dcr_id, stream_name=stream_name, logs=logs)
        logging.info("Successfully uploaded %d events to Log Analytics", len(logs))
    except HttpResponseError as e:
        logging.error("Failed to upload logs: %s", e.message)
        raise


@app.timer_trigger(
    schedule="0 */1 * * * *",
    arg_name="timer",
    run_on_startup=False,
)
def cf_log_ingestion(timer: func.TimerRequest) -> None:
    """Timer trigger: runs every 1 minute to pull Cloudflare firewall events."""

    if timer.past_due:
        logging.warning("Timer is past due, running anyway")

    cf_token = os.environ["CF_API_TOKEN"]
    dcr_id = os.environ["DCR_IMMUTABLE_ID"]
    stream_name = os.environ.get("DCR_STREAM_NAME", "Custom-CloudflareFirewall_CL")
    endpoint = os.environ["DCR_ENDPOINT"]
    zones = json.loads(os.environ["CF_ZONES"])

    # 1-minute non-overlapping window with 1-minute delay.
    # Each run queries [now-2min, now-1min) so Cloudflare has time to
    # make events available, consecutive runs never overlap, and no
    # deduplication is needed.
    now = datetime.datetime.now(datetime.timezone.utc)
    time_end = (now - datetime.timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    time_start = (now - datetime.timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")

    logging.info("Querying Cloudflare: %s to %s", time_start, time_end)

    all_events = []
    for zone in zones:
        events = query_cloudflare(cf_token, zone["id"], time_start, time_end)
        logging.info("Zone %s: %d events", zone["name"], len(events))
        transformed = transform_events(events, zone["name"])
        all_events.extend(transformed)

    if not all_events:
        logging.info("No events to ingest")
        return

    logging.info("Total events to ingest: %d", len(all_events))
    send_to_log_analytics(all_events, dcr_id, stream_name, endpoint)


# ============================================================================
# Function 2: Cloudflare HTTP Request Logs
# ============================================================================

HTTP_REQUESTS_QUERY = """
{
  viewer {
    zones(filter: {zoneTag: "%s"}) {
      httpRequestsAdaptiveGroups(
        filter: {datetime_gt: "%s", datetime_lt: "%s"}
        limit: 10000
        orderBy: [datetime_ASC]
      ) {
        count
        dimensions {
          datetime
          clientRequestHTTPHost
          clientRequestPath
          clientRequestQuery
          clientRequestHTTPMethodName
          clientRequestHTTPProtocol
          clientRequestScheme
          edgeResponseStatus
          cacheStatus
          clientIP
          clientCountryName
          clientAsn
          clientASNDescription
          clientDeviceType
          clientSSLProtocol
          coloCode
          userAgent
          clientRefererHost
          edgeResponseContentTypeName
          sampleInterval
          originResponseStatus
          upperTierColoName
        }
      }
    }
  }
}
"""


def query_cloudflare_http(cf_token: str, zone_id: str, time_start: str, time_end: str) -> list:
    """Query Cloudflare GraphQL API for HTTP request events in a time window."""
    headers = {
        "Authorization": f"Bearer {cf_token}",
        "Content-Type": "application/json",
    }
    query = HTTP_REQUESTS_QUERY % (zone_id, time_start, time_end)
    payload = json.dumps({"query": query})

    response = requests.post(GRAPHQL_URL, headers=headers, data=payload, timeout=30)
    response.raise_for_status()
    result = response.json()

    if result.get("errors"):
        error_msg = result["errors"][0].get("message", "Unknown GraphQL error")
        logging.error("Cloudflare GraphQL error for zone %s: %s", zone_id, error_msg)
        return []

    zones = result.get("data", {}).get("viewer", {}).get("zones", [])
    if not zones:
        return []

    return zones[0].get("httpRequestsAdaptiveGroups", [])


def transform_http_events(events: list, zone_name: str) -> list:
    """Transform Cloudflare HTTP request events into Log Analytics table schema."""
    transformed = []
    for event in events:
        dims = event.get("dimensions", {})
        count = event.get("count", 1)
        transformed.append({
            "TimeGenerated": dims.get("datetime", ""),
            "Zone": zone_name,
            "RequestHost": dims.get("clientRequestHTTPHost", ""),
            "RequestPath": dims.get("clientRequestPath", ""),
            "RequestQuery": dims.get("clientRequestQuery", ""),
            "RequestMethod": dims.get("clientRequestHTTPMethodName", ""),
            "HttpProtocol": dims.get("clientRequestHTTPProtocol", ""),
            "RequestScheme": dims.get("clientRequestScheme", ""),
            "EdgeResponseStatus": dims.get("edgeResponseStatus", 0),
            "OriginResponseStatus": dims.get("originResponseStatus", 0),
            "CacheStatus": dims.get("cacheStatus", ""),
            "ClientIP": dims.get("clientIP", ""),
            "ClientCountry": dims.get("clientCountryName", ""),
            "ClientASN": str(dims.get("clientAsn", "")),
            "ClientASNDescription": dims.get("clientASNDescription", ""),
            "ClientDeviceType": dims.get("clientDeviceType", ""),
            "TLSVersion": dims.get("clientSSLProtocol", ""),
            "EdgeColo": dims.get("coloCode", ""),
            "UserAgent": dims.get("userAgent", ""),
            "RefererHost": dims.get("clientRefererHost", ""),
            "ContentType": dims.get("edgeResponseContentTypeName", ""),
            "SampleInterval": dims.get("sampleInterval", 1),
            "RequestCount": count,
        })
    return transformed


@app.timer_trigger(
    schedule="0 */1 * * * *",
    arg_name="timer",
    run_on_startup=False,
)
def cf_http_ingestion(timer: func.TimerRequest) -> None:
    """Timer trigger: runs every 1 minute to pull Cloudflare HTTP request events."""

    if timer.past_due:
        logging.warning("HTTP ingestion timer is past due, running anyway")

    cf_token = os.environ["CF_API_TOKEN"]
    dcr_id = os.environ["HTTP_DCR_IMMUTABLE_ID"]
    stream_name = os.environ.get("HTTP_DCR_STREAM_NAME", "Custom-CloudflareHTTPRequests_CL")
    endpoint = os.environ["HTTP_DCR_ENDPOINT"]
    zones = json.loads(os.environ["CF_ZONES"])

    now = datetime.datetime.now(datetime.timezone.utc)
    time_end = (now - datetime.timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    time_start = (now - datetime.timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")

    logging.info("Querying Cloudflare HTTP requests: %s to %s", time_start, time_end)

    all_events = []
    for zone in zones:
        events = query_cloudflare_http(cf_token, zone["id"], time_start, time_end)
        logging.info("Zone %s: %d HTTP request groups", zone["name"], len(events))
        transformed = transform_http_events(events, zone["name"])
        all_events.extend(transformed)

    if not all_events:
        logging.info("No HTTP request events to ingest")
        return

    logging.info("Total HTTP request events to ingest: %d", len(all_events))
    send_to_log_analytics(all_events, dcr_id, stream_name, endpoint)
