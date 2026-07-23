import argparse
import logging
import os
import signal
import sys
import time

from dotenv import load_dotenv

from meraki_client import scan_all_dhcp_pools
from zabbix_client import send_alerts

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

_shutdown = False


def _handle_signal(signum, frame):
    global _shutdown
    logger.info("Shutdown signal received, stopping after current scan...")
    _shutdown = True


def get_config() -> dict:
    return {
        "meraki_api_key": os.environ["MERAKI_API_KEY"],
        "zabbix_api_url": os.environ["ZABBIX_API_URL"],
        "zabbix_api_token": os.environ["ZABBIX_API_TOKEN"],
        "alert_threshold": float(os.environ.get("ALERT_THRESHOLD", 90)),
        "scan_interval": int(os.environ.get("SCAN_INTERVAL", 30)),
    }


def run_scan(config: dict):
    logger.info("Starting Meraki DHCP pool scan...")

    pools = scan_all_dhcp_pools(config["meraki_api_key"])

    if not pools:
        logger.warning("No DHCP pools found — check API key and org access.")
        return

    threshold = config["alert_threshold"]
    alerts = [p for p in pools if p["usage_pct"] > threshold]
    all_isofy_ids = list({p["isofy_id"] for p in pools if p.get("isofy_id")})

    logger.info(
        f"Scan complete: {len(pools)} pools across {len(all_isofy_ids)} sites, "
        f"{len(alerts)} over {threshold:.0f}% threshold."
    )

    if alerts:
        for a in alerts:
            logger.warning(
                f"  [{a['network_name']} / {a['isofy_id']}] VLAN {a['vlan_id']} "
                f"({a['subnet']}): {a['usage_pct']:.1f}% "
                f"({a['used']}/{a['total']} addresses used)"
            )

    send_alerts(
        alerts=alerts,
        all_isofy_ids=all_isofy_ids,
        api_url=config["zabbix_api_url"],
        api_token=config["zabbix_api_token"],
    )


def main():
    parser = argparse.ArgumentParser(
        description="Monitor Meraki DHCP pool usage and alert via Zabbix."
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single scan then exit (useful for testing).",
    )
    args = parser.parse_args()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    try:
        config = get_config()
    except KeyError as e:
        logger.error(f"Missing required environment variable: {e}")
        sys.exit(1)

    if args.once:
        run_scan(config)
        return

    interval_seconds = config["scan_interval"] * 60
    logger.info(
        f"Starting scheduler: scanning every {config['scan_interval']} minutes. "
        f"Alert threshold: {config['alert_threshold']:.0f}%."
    )

    while not _shutdown:
        run_scan(config)
        if _shutdown:
            break
        logger.info(f"Next scan in {config['scan_interval']} minutes.")
        for _ in range(interval_seconds):
            if _shutdown:
                break
            time.sleep(1)

    logger.info("Stopped.")


if __name__ == "__main__":
    main()
