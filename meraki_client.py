import logging
import meraki

logger = logging.getLogger(__name__)


def scan_all_dhcp_pools(api_key: str) -> list[dict]:
    """
    Scan all orgs -> networks -> MX appliances -> DHCP subnets.

    API call strategy (minimized to avoid rate limits):
      1. getOrganizations()                    - 1 call total
      2. getOrganizationNetworks(orgId)        - 1 call per org
      3. getOrganizationDevices(orgId)         - 1 call per org (not per-network)
      4. getDeviceApplianceDhcpSubnets(serial) - 1 call per MX device

    Returns list of dicts:
      {org_name, network_name, vlan_id, subnet, used, free, total, usage_pct}
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

        if "Industrious_C" in org_name:

            try:
                networks = dashboard.organizations.getOrganizationNetworks(org_id)
                devices = dashboard.organizations.getOrganizationDevices(org_id)
            except meraki.APIError as e:
                logger.error(f"Failed to get data for org '{org_name}': {e}")
                continue

            for n in networks:
                if "Industrious - NYC - 107 Greenwich St" == n["name"]:

                    # Build network_id -> network_name lookup
                    network_map = {n["id"]: n["name"] for n in networks}



                    # Filter to MX appliances in this specific network only
                    mx_devices = [
                        d for d in devices
                        if d.get("productType") == "appliance"
                        and d.get("networkId") == n["id"]
                    ]

                    # Skip log message if there isn't an MX in it
                    if len(mx_devices) != 0:
                        logger.info(
                            f"Org '{org_name}': {len(networks)} networks, {len(mx_devices)} MX appliance(s)"
                        )

                        for device in mx_devices:
                            serial = device["serial"]
                            network_id = device.get("networkId", "")
                            network_name = network_map.get(network_id, network_id)

                            try:
                                subnets = dashboard.appliance.getDeviceApplianceDhcpSubnets(serial)
                            except meraki.APIError as e:
                                logger.warning(
                                    f"  Skipping device '{serial}': {e}"
                                )
                                continue

                            for subnet_info in subnets:
                                used = subnet_info.get("usedCount", 0)
                                free = subnet_info.get("freeCount", 0)
                                total = used + free

                                if total == 0:
                                    usage_pct = 0.0
                                else:
                                    usage_pct = (used / total) * 100

                                all_pools.append({
                                    "org_name": org_name,
                                    "network_name": network_name,
                                    "vlan_id": subnet_info.get("vlanId"),
                                    "subnet": subnet_info.get("subnet", ""),
                                    "used": used,
                                    "free": free,
                                    "total": total,
                                    "usage_pct": usage_pct,
                                })
                else:
                    continue

    logger.info(f"Total DHCP pools found: {len(all_pools)}")
    return all_pools
