# Meraki DHCP Lease Alerts

Monitors Cisco Meraki DHCP pool usage across all networks and sends alerts to Zabbix when any pool exceeds a configurable threshold (default: 90%). Alerts are sent to the existing `{NetworkName}-Firewall` Zabbix hosts so they appear under the correct host groups.

---

## How It Works

1. Queries the Meraki Dashboard API for all organizations, networks, and MX appliances
2. Retrieves live DHCP subnet usage (`usedCount` / `freeCount`) per device
3. Flags any VLAN where usage exceeds the configured threshold
4. Pushes alerts to Zabbix via the Sender protocol (port 10051), targeting the correct firewall host per network
5. Automatically clears resolved alerts on the next scan

**API efficiency:** Uses org-level `getOrganizationDevices()` instead of per-network calls — minimizes API calls to avoid rate limits.

---

## Requirements

- Python 3.10+
- Outbound HTTPS to `api.meraki.com` (port 443)
- Outbound TCP to your Zabbix server on port **10051**
- A Meraki API key with read access to your organizations

---

## Quick Start

```bash
# 1. Clone / copy the project
git clone <repo-url> /opt/meraki-dhcp-alerts
cd /opt/meraki-dhcp-alerts

# 2. Create a virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 3. Configure environment variables
cp .env.example .env
# Edit .env and fill in your values

# 4. Test with a single scan
python main.py --once

# 5. Run continuously (scans every SCAN_INTERVAL minutes)
python main.py
```

---

## Configuration

All configuration is via environment variables. Copy `.env.example` to `.env` and set the following:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MERAKI_API_KEY` | Yes | — | Meraki Dashboard API key |
| `ZABBIX_SERVER` | Yes | — | Zabbix server hostname or IP |
| `ZABBIX_PORT` | No | `10051` | Zabbix Sender port |
| `ALERT_THRESHOLD` | No | `90` | Pool usage % that triggers an alert |
| `SCAN_INTERVAL` | No | `30` | Minutes between scans (continuous mode) |

---

## Zabbix Setup

Add the following to your existing **Meraki MX Firewalls template** so all `*-Firewall` hosts get the items automatically.

### Items

| Name | Type | Key | Data Type | History |
|------|------|-----|-----------|---------|
| DHCP Pool Alert Message | Zabbix trapper | `meraki.dhcp.pool.alert` | Text | 7d |
| DHCP Pool Alert Status | Zabbix trapper | `meraki.dhcp.pool.status` | Numeric (unsigned) | 90d |

### Trigger

| Setting | Value |
|---------|-------|
| **Name** | DHCP pool over 90% capacity |
| **Severity** | High |
| **Expression** | `last(/YourTemplateName/meraki.dhcp.pool.status)=1` |
| **Problem description** | `{ITEM.VALUE2}` |
| **Manual close** | Yes |

> Setting **Problem description** to `{ITEM.VALUE2}` includes the VLAN IDs, subnets, and usage percentages in the Zabbix notification.

### Verify Port 10051

From the script host, confirm connectivity to Zabbix:

```bash
nc -zv your-zabbix-server 10051
```

---

## How Alerts Flow

```
Script runs every 30 min
  → Pool on "IND-Toronto-30Adelaide" VLAN 10 reaches 95%
  → Sends to Zabbix host "IND-Toronto-30Adelaide-Firewall":
      meraki.dhcp.pool.status = 1
      meraki.dhcp.pool.alert  = "VLAN 10 (10.0.1.0/24): 95.0% (190/200 addresses)"
  → Trigger fires → alert appears under the correct Zabbix host group

Next scan — usage drops below 90%
  → Sends meraki.dhcp.pool.status = 0
  → Trigger resolves automatically
```

If multiple VLANs on the same firewall are over threshold, they are combined into one message:

```
VLAN 10 (10.0.1.0/24): 95.0% (190/200 addresses) | VLAN 20 (192.168.20.0/24): 91.5% (183/200 addresses)
```

---

## Deployment

### Recommended: Run as a systemd Service

Create `/etc/systemd/system/meraki-dhcp-alerts.service`:

```ini
[Unit]
Description=Meraki DHCP Pool Alert Monitor
After=network.target

[Service]
Type=simple
User=zabbix
WorkingDirectory=/opt/meraki-dhcp-alerts
EnvironmentFile=/opt/meraki-dhcp-alerts/.env
ExecStart=/opt/meraki-dhcp-alerts/.venv/bin/python main.py
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable meraki-dhcp-alerts
systemctl start meraki-dhcp-alerts
systemctl status meraki-dhcp-alerts
```

### Alternative: Cron Job

Use `--once` to run a single scan on a schedule:

```
*/30 * * * * /opt/meraki-dhcp-alerts/.venv/bin/python /opt/meraki-dhcp-alerts/main.py --once >> /var/log/meraki-dhcp.log 2>&1
```

---

## Project Structure

```
MerakiDHCPLeaseAlerts/
├── main.py            # Entry point, scheduler, CLI
├── meraki_client.py   # Meraki API scanning logic
├── zabbix_client.py   # Zabbix Sender integration
├── requirements.txt   # Python dependencies
├── .env               # Your config (not committed)
└── .env.example       # Config template
```
