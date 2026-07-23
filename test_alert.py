"""
Test script for Meraki DHCP alerting.

Runs a real Meraki API scan filtered to NETWORK_NAME, then sends any
alerts to ZABBIX_HOST instead of the auto-generated "{network}-Firewall" host.

Usage:
    python test_alert.py
"""

import argparse
import logging
import os
import ssl
import sys

from dotenv import load_dotenv

from meraki_client import scan_all_dhcp_pools
from zabbix_client import ALERT_ITEM_KEY, STATUS_ITEM_KEY

# ── TEST CONFIGURATION ───────────────────────────────────────────────────────
NETWORK_NAME = "Industrious - NYC - 107 Greenwich St"   # Meraki network name to scan
ZABBIX_HOST  = "IND-NYC-107Greenwich-Firewall"          # Zabbix host to send alerts to
# ─────────────────────────────────────────────────────────────────────────────

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


ITEM_DESCRIPTIONS = {
    ALERT_ITEM_KEY:  "Type: Zabbix trapper, Value type: Text",
    STATUS_ITEM_KEY: "Type: Zabbix trapper, Value type: Numeric unsigned",
}


def run_diagnostics() -> tuple[list[str], dict]:
    """
    Run pre-send diagnostics.
    Returns (issues, item_ids) where item_ids = {"alert": id, "status": id}.
    """
    # Zabbix API item check (optional — requires ZABBIX_API_URL + ZABBIX_API_TOKEN)
    api_url = os.environ.get("ZABBIX_API_URL")
    api_token = os.environ.get("ZABBIX_API_TOKEN")

    if not api_url or not api_token:
        logger.info(
            "  Skipping item check — add ZABBIX_API_URL and ZABBIX_API_TOKEN to .env "
            "for item-level diagnostics."
        )
        return [], {}

    try:
        from zabbix_utils import ZabbixAPI
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        api = ZabbixAPI(url=api_url, token=api_token, ssl_context=ctx)

        version = api.apiinfo.version()
        logger.info(f"  Zabbix server version: {version}")

        hosts = api.host.get(
            filter={"host": ZABBIX_HOST},
            output=["hostid", "host", "status", "proxy_hostid", "proxyid"],
        )
        if not hosts:
            logger.error(f"  Host '{ZABBIX_HOST}' not found in Zabbix.")
            sys.exit(1)

        api_host_name = hosts[0]["host"]
        logger.info(f"  Zabbix host technical name (from API): '{api_host_name}'")
        logger.info(f"  Alerts will be sent to Zabbix host:   '{ZABBIX_HOST}'")
        if api_host_name != ZABBIX_HOST:
            logger.warning("  NAME MISMATCH — update ZABBIX_HOST in test_alert.py to match exactly.")

        hostid = hosts[0]["hostid"]
        issues = []
        behind_proxy = False

        if hosts[0]["status"] == "1":
            logger.warning(f"  Host '{ZABBIX_HOST}' is DISABLED in Zabbix.")
            issues.append("host disabled")

        # Support both pre-6.2 (proxy_hostid) and 6.2+ (proxyid) field names
        proxy_id = hosts[0].get("proxyid") or hosts[0].get("proxy_hostid") or "0"
        if proxy_id and proxy_id != "0":
            try:
                proxies = api.proxy.get(proxyids=[proxy_id], output=["host"])
                proxy_name = proxies[0]["host"] if proxies else f"id={proxy_id}"
            except Exception:
                proxy_name = f"id={proxy_id}"
            logger.info(f"  Host is monitored by proxy '{proxy_name}'. Using history.push API.")
            issues.append(f"behind proxy '{proxy_name}'")
            behind_proxy = True

        items = api.item.get(
            hostids=[hostid],
            filter={"key_": [ALERT_ITEM_KEY, STATUS_ITEM_KEY]},
            output=["itemid", "key_", "type", "status"],
        )
        found_keys = {i["key_"] for i in items}
        missing = [k for k in [ALERT_ITEM_KEY, STATUS_ITEM_KEY] if k not in found_keys]

        item_ids = {}
        if missing:
            logger.warning(f"  Missing Zabbix items on '{ZABBIX_HOST}':")
            for k in missing:
                logger.warning(f"    - {k}  ({ITEM_DESCRIPTIONS[k]})")
            issues.extend(missing)
        else:
            item_by_key = {i["key_"]: i for i in items}
            item_ids = {
                "alert": item_by_key[ALERT_ITEM_KEY]["itemid"],
                "status": item_by_key[STATUS_ITEM_KEY]["itemid"],
            }
            for key in [ALERT_ITEM_KEY, STATUS_ITEM_KEY]:
                item = item_by_key[key]
                item_type = int(item["type"])
                item_status = item["status"]
                if item_type != 2:
                    logger.warning(
                        f"  Item '{key}' has type={item_type} — "
                        f"must be type 2 (Zabbix trapper) to accept Sender data."
                    )
                    issues.append(f"{key}: wrong type ({item_type})")
                elif item_status == "1":
                    logger.warning(f"  Item '{key}' is DISABLED — enable it in Zabbix.")
                    issues.append(f"{key}: disabled")
                else:
                    logger.info(f"  Item '{key}': OK (trapper, enabled).")

        # Store api and behind_proxy flag on item_ids for use in history.push fallback
        item_ids["_api"] = api
        item_ids["_behind_proxy"] = behind_proxy
        return issues, item_ids

    except Exception as e:
        logger.warning(f"  Zabbix API check failed: {e}")
        return [], {}


def try_history_push(item_ids: dict, msg: str | None, is_alert: bool) -> bool:
    """Try sending via Zabbix 7.0 history.push API as a fallback to Sender."""
    api = item_ids.get("_api")
    alert_id = item_ids.get("alert")
    status_id = item_ids.get("status")

    if not api or not alert_id or not status_id:
        return False

    logger.info("Attempting history.push via Zabbix API...")
    try:
        payload = [{"itemid": status_id, "value": "1" if is_alert else "0"}]
        if is_alert and msg:
            payload.append({"itemid": alert_id, "value": msg})

        response = api.history.push(payload)

        if isinstance(response, dict):
            if response.get("response") != "failed":
                logger.info("SUCCESS — data pushed via Zabbix API.")
                return True
            logger.error(f"  history.push rejected: {response.get('data', 'unknown')}")
            return False

        # Fallback: list-of-dicts format
        failed = sum(1 for r in response if isinstance(r, dict) and r.get("error"))
        processed = len(payload) - failed
        logger.info(f"  history.push response: processed={processed}, failed={failed}")
        if failed == 0:
            logger.info("SUCCESS — data pushed via Zabbix API.")
            return True
        for r in response:
            if isinstance(r, dict) and r.get("error"):
                logger.error(f"  history.push error: {r['error']}")
        return False
    except Exception as e:
        logger.error(f"  history.push failed: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Test Meraki DHCP alerting to Zabbix.")
    parser.add_argument("--resolve", action="store_true", help="Send a resolved/clear status to Zabbix without scanning.")
    args = parser.parse_args()

    # Load config from .env
    try:
        api_key = os.environ["MERAKI_API_KEY"]
    except KeyError as e:
        logger.error(f"Missing required environment variable: {e}")
        sys.exit(1)

    threshold = float(os.environ.get("ALERT_THRESHOLD", 90))

    if args.resolve:
        logger.info(f"Sending RESOLVED status to '{ZABBIX_HOST}'...")
        diag_issues, item_ids = run_diagnostics()
        behind_proxy = item_ids.get("_behind_proxy", False)

        api_ok = try_history_push(item_ids, None, is_alert=False)
        if not api_ok:
            logger.error("history.push failed.")
        return

    # Run real Meraki scan
    logger.info(f"Scanning Meraki network: '{NETWORK_NAME}'...")
    all_pools = scan_all_dhcp_pools(api_key)

    if not all_pools:
        logger.warning("No DHCP pools returned — check API key and org access.")
        sys.exit(1)

    # Filter to the target network
    pools = [p for p in all_pools if p["network_name"] == NETWORK_NAME]

    if not pools:
        logger.warning(
            f"No pools found for network '{NETWORK_NAME}'. "
            f"Available networks: {sorted({p['network_name'] for p in all_pools})}"
        )
        sys.exit(1)

    # Print all pools found
    logger.info(f"Found {len(pools)} DHCP pool(s) in '{NETWORK_NAME}':")
    for p in sorted(pools, key=lambda p: p["vlan_id"] or 0):
        flag = " <-- ALERT" if p["usage_pct"] > threshold else ""
        logger.info(
            f"  VLAN {p['vlan_id']} ({p['subnet']}): "
            f"{p['usage_pct']:.1f}% ({p['used']}/{p['total']} addresses){flag}"
        )

    # Build alerts above threshold
    alerts = [p for p in pools if p["usage_pct"] > threshold]
    logger.info(
        f"{len(alerts)} pool(s) above {threshold:.0f}% threshold -> "
        f"sending to Zabbix host '{ZABBIX_HOST}'"
    )

    # Diagnostics: TCP check + optional item/proxy check via API
    diag_issues, item_ids = run_diagnostics()

    # Build message
    is_alert = len(alerts) > 0
    if is_alert:
        msg = " | ".join(
            f"VLAN {a['vlan_id']} ({a['subnet']}): {a['usage_pct']:.1f}% "
            f"({a['used']}/{a['total']} addresses)"
            for a in sorted(alerts, key=lambda a: a["vlan_id"] or 0)
        )
        logger.info(f"  Alert message: {msg}")
    else:
        msg = None
        logger.info("  No pools over threshold — sending clear (status=0)")

    api_ok = try_history_push(item_ids, msg, is_alert)
    if not api_ok:
        logger.error("history.push failed.")
        if not os.environ.get("ZABBIX_API_URL"):
            logger.error("  Add ZABBIX_API_URL and ZABBIX_API_TOKEN to .env for diagnostics.")


if __name__ == "__main__":
    main()
