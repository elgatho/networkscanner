<!-- Short description (max 100 chars): -->
Self-hosted network discovery & IP scanner: finds free IPs, tracks devices, Proxmox/Docker/DHCP aware.

<!-- Full description (paste into the Docker Hub "Overview"): -->
# IP Scanner – Network Discovery & Free IP Finder

Self-hosted web dashboard that scans your LAN, combines what it sees with your infrastructure inventories, and tells you **the first available IP in each subnet** – with a confidence level, not a blind guess.

## Features
- **First Available IP** per subnet (HIGH / MEDIUM / LOW confidence). Silence on ping alone never marks an address as free; sources, reservations, DHCP leases, neighbour table and scan history are all checked.
- **Multiple IPv4/IPv6 subnets**, VLAN tags, gateways, excluded ranges (e.g. DHCP pools).
- **Scanning**: ICMP, ARP/NDP, reverse DNS, MAC vendor (OUI), optional port scan and arp-scan. Only configured subnets are ever probed; no parallel scans of the same subnet.
- **Integrations (all read-only, direct REST – no MCP):** Proxmox VE (VMs, LXC, guest agent IPs), Dockhand / Docker Engine, ESPHome (optional), OPNsense (Kea/ISC/Dnsmasq leases), UniFi (connected clients).
- **Conflict detection** (duplicate IPs / MACs) with per-rule silencing.
- **History** of IP/MAC changes, new devices, availability.
- **Webhook notifications** (new host, MAC/IP change, conflict, source down), **CSV export**, password-protected Settings page.
- Data in SQLite on a persistent volume.

## Quick start
```yaml
services:
  ip-scanner:
    image: YOURUSER/ip-scanner:latest
    restart: unless-stopped
    network_mode: host          # needed for ARP/NDP and the host neighbour table
    cap_drop: [ALL]
    cap_add: [NET_RAW]          # ICMP/ARP; no privileged mode, no NET_ADMIN
    security_opt: ["no-new-privileges:true"]
    environment:
      PORT: "8080"
      SETTINGS_PASSWORD: "change-me-please"   # optional, can be set in the UI
      # ACCESS_TOKEN: ""                      # optional, protects the whole API
    volumes:
      - scanner-data:/data
volumes:
  scanner-data:
```
Open `http://<host>:8080`, add your subnets and integrations in **Settings**, use **Test connection** for each.

## Configuration
| Variable | Purpose |
|---|---|
| `PORT` / `BIND_HOST` | listen port / address (default `8080` / `0.0.0.0`) |
| `SETTINGS_PASSWORD` | fixes the Settings password (otherwise set in the UI; until set, Settings is open) |
| `ACCESS_TOKEN` | optional token required for `/api` (header `X-Access-Token`) |
| `DATABASE_URL` | default `sqlite:////data/scanner.db` |
| `LOG_LEVEL` | default `INFO` |

Integration credentials (Proxmox API token, Dockhand token, OPNsense key/secret, UniFi API key, webhook URL) are entered in the GUI or via `.env`; they are never baked into the image.

## Security notes
- Do **not** expose the dashboard publicly; put it behind a reverse proxy with HTTPS if you need remote access.
- Use a least-privilege Proxmox token (`PVEAuditor`, plus guest-agent audit for IPs) and read-only keys elsewhere.
- TLS verification is on; for self-signed certificates use certificate pinning (SHA-256 fingerprint) or a CA bundle per integration.
- The scanner makes no changes to your router, DHCP server, Proxmox or Dockhand. Results are a recommendation – an address may still be reserved in an external DHCP server.

## Status
Core scanning, free-IP logic and the UI are covered by unit tests. Integrations with OPNsense and UniFi are parsed from documented/typical API shapes and should be verified in your environment with *Test connection* – please report problems.

Tags: `latest`, and version tags (`1.0.0`, …). Architectures: `amd64` (add `arm64` with `./publish.sh … --multiarch`).
