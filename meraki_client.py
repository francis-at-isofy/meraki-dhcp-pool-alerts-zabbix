import logging
import meraki

logger = logging.getLogger(__name__)


def scan_all_dhcp_pools(api_key: str) -> list[dict]:
    """
    Scan all orgs -> networks -> MX appliances -> DHCP subnets.

    API call strategy (minimized to avoid rate limits):
      1. getOrganizations()                    - 1 call total
      2. getOrganizationNetworks(orgId)        - 1 call per org (already returns `notes`)
      3. getOrganizationDevices(orgId)         - 1 call per org (not per-network)
      4. getDeviceApplianceDhcpSubnets(serial) - 1 call per MX device

    The Meraki network `notes` field holds the site's isofy_id (e.g.
    "CA-D-30-Adelaide-St"), which matches the Zabbix hostgroup name for the
    same site. Networks with an empty notes field are skipped with a warning.

    Returns list of dicts:
      {org_name, network_name, isofy_id, vlan_id, subnet, used, free, total, usage_pct}
    """
    dashboard = meraki.DashboardAPI(
        api_key=api_key,
        suppress_logging=True,
        print_console=False,
    )

    all_pools = []

    try:
        orgs = dashboard.organizations.getOrganizations()
    except meraki.APIError as e:
        logger.error(f"Failed to get organizations: {e}")
        return []

    logger.info(f"Found {len(orgs)} organization(s)")

    for org in orgs:
        org_id = org["id"]
        org_name = org["name"]

        try:
            networks = dashboard.organizations.getOrganizationNetworks(org_id)
            devices = dashboard.organizations.getOrganizationDevices(org_id)
        except meraki.APIError as e:
            logger.error(f"Failed to get data for org '{org_name}': {e}")
            continue

        network_map = {n["id"]: n["name"] for n in networks}
        isofy_map = {n["id"]: (n.get("notes") or "").strip() for n in networks}

        mx_devices = [d for d in devices if d.get("productType") == "appliance"]

        if not mx_devices:
            continue

        logger.info(
            f"Org '{org_name}': {len(networks)} networks, {len(mx_devices)} MX appliance(s)"
        )

        for device in mx_devices:
            serial = device["serial"]
            network_id = device.get("networkId", "")
            network_name = network_map.get(network_id, network_id)
            isofy_id = isofy_map.get(network_id, "")

            if not isofy_id:
                logger.warning(
                    f"  Skipping '{network_name}' ({serial}): "
                    f"network notes field is empty — expected an isofy_id"
                )
                continue

            try:
                subnets = dashboard.appliance.getDeviceApplianceDhcpSubnets(serial)
            except meraki.APIError as e:
                logger.warning(f"  Skipping device '{serial}': {e}")
                continue

            for subnet_info in subnets:
                used = subnet_info.get("usedCount", 0)
                free = subnet_info.get("freeCount", 0)
                total = used + free
                usage_pct = (used / total * 100) if total else 0.0

                all_pools.append({
                    "org_name": org_name,
                    "network_name": network_name,
                    "isofy_id": isofy_id,
                    "vlan_id": subnet_info.get("vlanId"),
                    "subnet": subnet_info.get("subnet", ""),
                    "used": used,
                    "free": free,
                    "total": total,
                    "usage_pct": usage_pct,
                })

    logger.info(f"Total DHCP pools found: {len(all_pools)}")
    return all_pools
