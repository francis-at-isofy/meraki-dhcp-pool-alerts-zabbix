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
    all_isofy_ids: list[str],
    api_url: str,
    api_token: str,
) -> bool:
    """
    Send DHCP pool alerts to the correct Zabbix hosts via history.push.

    Routing: each site's isofy_id (from the Meraki network's `notes` field)
    matches a Zabbix hostgroup of the same name (e.g. "CA-D-30-Adelaide-St").
    The firewall host inside that group is the one whose name contains
    "Firewall" (e.g. "IND-Toronto-30Adelaide-Firewall").

    Multiple VLANs alerting on the same site are grouped into one message:
      "VLAN 10 (10.0.1.0/24): 95.0% | VLAN 20 (192.168.20.0/24): 91.5%"

    Items pushed:
      - meraki.dhcp.pool.alert  (text):    combined VLAN alert message
      - meraki.dhcp.pool.status (numeric): 1 if alerting, 0 if clear

    Sites with no alerts receive status=0 to clear any previous trigger.
    """
    if not all_isofy_ids:
        logger.info("No isofy_ids to route — nothing to send.")
        return True

    api = _make_api(api_url, api_token)

    try:
        groups = api.hostgroup.get(
            filter={"name": all_isofy_ids},
            selectHosts=["hostid", "host"],
            output=["groupid", "name"],
        )
    except Exception as e:
        logger.error(f"Failed to fetch hostgroups from Zabbix API: {e}")
        return False

    isofy_to_firewall: dict[str, dict] = {}
    found_names = {g["name"] for g in groups}
    for missing in set(all_isofy_ids) - found_names:
        logger.warning(f"  No Zabbix hostgroup found for isofy_id '{missing}'")

    for group in groups:
        isofy_id = group["name"]
        firewalls = [h for h in group.get("hosts", []) if "firewall" in h["host"].lower()]
        if not firewalls:
            logger.warning(
                f"  Hostgroup '{isofy_id}' has no host containing 'Firewall' — skipping"
            )
            continue
        if len(firewalls) > 1:
            names = ", ".join(h["host"] for h in firewalls)
            logger.warning(
                f"  Hostgroup '{isofy_id}' has multiple Firewall hosts ({names}) — "
                f"using '{firewalls[0]['host']}'"
            )
        isofy_to_firewall[isofy_id] = firewalls[0]

    if not isofy_to_firewall:
        logger.warning("No Zabbix firewall hosts resolved — nothing to send.")
        return True

    firewall_hostids = [h["hostid"] for h in isofy_to_firewall.values()]
    try:
        items = api.item.get(
            hostids=firewall_hostids,
            filter={"key_": [ALERT_ITEM_KEY, STATUS_ITEM_KEY]},
            output=["itemid", "key_", "hostid"],
        )
    except Exception as e:
        logger.error(f"Failed to fetch item IDs from Zabbix API: {e}")
        return False

    item_id_map: dict[tuple[str, str], str] = {
        (item["hostid"], item["key_"]): item["itemid"] for item in items
    }

    by_isofy: dict[str, list[dict]] = defaultdict(list)
    for alert in alerts:
        by_isofy[alert["isofy_id"]].append(alert)

    payload = []

    for isofy_id, site_alerts in by_isofy.items():
        firewall = isofy_to_firewall.get(isofy_id)
        if not firewall:
            continue
        hostid = firewall["hostid"]
        zabbix_host = firewall["host"]
        alert_id = item_id_map.get((hostid, ALERT_ITEM_KEY))
        status_id = item_id_map.get((hostid, STATUS_ITEM_KEY))

        if not alert_id or not status_id:
            logger.warning(
                f"  Skipping {zabbix_host} (isofy_id '{isofy_id}') — items not found "
                f"(alert_id={alert_id}, status_id={status_id})"
            )
            continue

        msg = " | ".join(
            f"VLAN {a['vlan_id']} ({a['subnet']}): {a['usage_pct']:.1f}% "
            f"({a['used']}/{a['total']} addresses)"
            for a in sorted(site_alerts, key=lambda a: a["vlan_id"] or 0)
        )

        payload.append({"itemid": alert_id, "value": msg})
        payload.append({"itemid": status_id, "value": "1"})
        logger.warning(f"  ALERT -> {zabbix_host} [{isofy_id}]: {msg}")

    for isofy_id, firewall in isofy_to_firewall.items():
        if isofy_id in by_isofy:
            continue
        status_id = item_id_map.get((firewall["hostid"], STATUS_ITEM_KEY))
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
        failed = sum(1 for r in response if isinstance(r, dict) and r.get("error"))
        logger.info(f"Zabbix history.push: processed={len(payload) - failed}, failed={failed}")
        return failed == 0
    except Exception as e:
        logger.error(f"Zabbix history.push error: {e}")
        return False
