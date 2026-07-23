import logging
import ssl
from collections import defaultdict

logger = logging.getLogger(__name__)

ALERT_ITEM_KEY = "meraki.dhcp.pool.alert"
STATUS_ITEM_KEY = "meraki.dhcp.pool.status"


def _make_api(api_url: str, api_token: str):
    """Create a ZabbixAPI instance with SSL verification disabled (supports IP-based URLs)."""
    from zabbix_utils import ZabbixAPI
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ZabbixAPI(url=api_url, token=api_token, ssl_context=ctx)


def send_alerts(
    alerts: list[dict],
    all_network_names: list[str],
    api_url: str,
    api_token: str,
) -> bool:
    """
    Send DHCP pool alerts to the correct Zabbix hosts via history.push API.

    Each alert targets host "{network_name}-Firewall" — matching the existing
    Zabbix host naming convention.

    Multiple VLANs alerting on the same host are grouped into one message so
    the alert text always shows all affected VLANs, e.g.:
      "VLAN 10 (10.0.1.0/24): 95.0% | VLAN 20 (192.168.20.0/24): 91.5%"

    Items pushed:
      - meraki.dhcp.pool.alert  (text):    combined VLAN alert message
      - meraki.dhcp.pool.status (numeric): 1 if alerting, 0 if clear

    Networks with no alerts receive status=0 to clear any previous trigger.
    """
    api = _make_api(api_url, api_token)

    # Batch-fetch item IDs for all relevant hosts in one API call
    hosts_needed = [f"{n}-Firewall" for n in all_network_names]
    try:
        items = api.item.get(
            filter={"key_": [ALERT_ITEM_KEY, STATUS_ITEM_KEY]},
            host=hosts_needed,
            output=["itemid", "key_"],
            selectHosts=["host"],
        )
    except Exception as e:
        logger.error(f"Failed to fetch item IDs from Zabbix API: {e}")
        return False

    # Build lookup: (host_name, item_key) -> itemid
    item_id_map: dict[tuple[str, str], str] = {}
    for item in items:
        host_name = item["hosts"][0]["host"]
        item_id_map[(host_name, item["key_"])] = item["itemid"]

    # Group alerts by network so multiple VLANs are combined into one message
    by_network: dict[str, list[dict]] = defaultdict(list)
    for alert in alerts:
        by_network[alert["network_name"]].append(alert)

    payload = []

    for network_name, network_alerts in by_network.items():
        zabbix_host = f"{network_name}-Firewall"
        alert_id = item_id_map.get((zabbix_host, ALERT_ITEM_KEY))
        status_id = item_id_map.get((zabbix_host, STATUS_ITEM_KEY))

        if not alert_id or not status_id:
            logger.warning(
                f"  Skipping {zabbix_host} — items not found in Zabbix "
                f"(alert_id={alert_id}, status_id={status_id})"
            )
            continue

        msg = " | ".join(
            f"VLAN {a['vlan_id']} ({a['subnet']}): {a['usage_pct']:.1f}% "
            f"({a['used']}/{a['total']} addresses)"
            for a in sorted(network_alerts, key=lambda a: a["vlan_id"] or 0)
        )

        payload.append({"itemid": alert_id, "value": msg})
        payload.append({"itemid": status_id, "value": "1"})
        logger.warning(f"  ALERT -> {zabbix_host}: {msg}")

    # Send status=0 to networks that are now clear (resolves previous triggers)
    for network_name in all_network_names:
        if network_name not in by_network:
            zabbix_host = f"{network_name}-Firewall"
            status_id = item_id_map.get((zabbix_host, STATUS_ITEM_KEY))
            if status_id:
                payload.append({"itemid": status_id, "value": "0"})

    if not payload:
        logger.info("No Zabbix values to send.")
        return True

    try:
        response = api.history.push(payload)
        if isinstance(response, dict):
            success = response.get("response") != "failed"
            if success:
                logger.info(f"Zabbix history.push: {len(payload)} value(s) sent successfully.")
            else:
                logger.error(f"Zabbix history.push rejected: {response.get('data', 'unknown')}")
            return success
        # List-of-dicts format (future versions)
        failed = sum(1 for r in response if isinstance(r, dict) and r.get("error"))
        logger.info(f"Zabbix history.push: processed={len(payload) - failed}, failed={failed}")
        return failed == 0
    except Exception as e:
        logger.error(f"Zabbix history.push error: {e}")
        return False
