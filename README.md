# Network Discovery & IP Scanner

Self-hosted scanner that merges Dockhand, Proxmox VE, ESPHome and active network scans (nmap, arp-scan, `ip neigh`) into one inventory and recommends the **first available IP** per subnet. No MCP; direct REST APIs and system tools only. Read-only toward all external systems.

## Docker image
Published to GitHub Container Registry on every version tag (`v1.2.3`), built for amd64 and arm64:
```bash
docker pull ghcr.io/elgatho/networkscanner:latest      # or a version, e.g. :1.0.0
```
In `docker-compose.yml` use `image: ghcr.io/elgatho/networkscanner:1.0.0` instead of `build: .`.

## Install
```bash
cp .env.example .env      # set PORT, optionally ACCESS_TOKEN
docker compose up -d --build
```
Open `http://<host>:8080`. Then: **Subnets → Add subnet** (CIDR, gateway, VLAN, exclusions such as your DHCP pool), **Settings** to enter integration credentials and use *Test connection*.

Update: `git pull; docker compose up -d --build` (data lives in volume `scanner-data`).

## Permissions
`network_mode: host` (needed for ARP/NDP and the host neighbour table), `cap_drop: ALL`, `cap_add: NET_RAW`, `no-new-privileges`. No `privileged`, no `NET_ADMIN`. Only configured subnets are ever probed. Use `BIND_HOST`/firewall and `ACCESS_TOKEN`; do not expose publicly.

## Integrations
- **Dockhand**: `Authorization: Bearer dh_…` token; uses `/api/environments`, `/api/containers`, `/api/containers/{id}/inspect`, `/api/networks`. Dockhand's response schemas are not documented, so the parser is tolerant; optional Docker Engine URL fallback.
- **Proxmox**: create an API token with role `PVEAuditor` (add `VM.Monitor`/`VM.GuestAgent.Audit` for guest-agent IPs). IP origin is tagged `configured` / `guest-agent` / `observed` (scan). VMs without agent are still listed.
- **ESPHome** (optional): dashboard API, optional native API, plus extra hosts.
- **OPNsense** (DHCP source, read-only): create an API key/secret for a user with only the DHCP/Kea lease (and reservation) privileges. Tries Kea, ISC and Dnsmasq lease endpoints and skips those absent. Response field names were not documented, so parsing is tolerant — check with *Test connection*.
- **UniFi** (DHCP clients, read-only): Integration API key (Network → Settings → Control Plane → Integrations). It lists *connected clients and their IPs*, not the controller's lease table or fixed-IP reservations.
- DHCP sources mark addresses as used (so they are never offered as free) but never cause name conflicts.
- TLS verification is on by default; per-integration CA bundle path available.

## Dashboard (first tab)

- **Proxmox overview**: nodes online, VMs/LXC running, CPU, RAM and disk per cluster and per node (from `/cluster/resources`).
- **Services**: one tile per Docker container from Dockhand, grouped by category, with icon, description and link, and a search box.
  Details (IP, ports, labels) are read from Dockhand only when a container first appears, or on **Settings → Dashboard → Odśwież teraz**. Hand edits are kept on refresh.
  Default link: a container with its own LAN address (macvlan, same /24 as its Docker host) links to that address on port 80 (https if only 443 is exposed); otherwise the published port on the Docker host; otherwise the host on port 80. DNS names from AdGuard rewrites are shown as IPs.
  **Edit tiles** (✎ Edytuj kafelki): change name, category, description, link, icon, make a tile non-clickable, or hide it. "Przywróć z Dockhand" drops the edits.
  **Search**: Enter with no matching tile opens the query in SearXNG (`search_url`, default `http://search.lan`). Both are set in Settings → Dashboard.
  Optional container labels (set on the container / in compose):
  `dashboard.url` (full link), `dashboard.port`, `dashboard.name`, `dashboard.category`, `dashboard.description`, `dashboard.icon` (dashboard-icons slug or image URL), `dashboard.hide=true`.
  Icons come from [dashboardicons.com](https://dashboardicons.com) (the homarr-labs/dashboard-icons repo, via jsdelivr) and are cached locally in `DATA_DIR/icons`; a letter is shown when an icon is missing.

## First available IP
Skips network/broadcast, gateway, all source IPs, manual reservations, exclusions, hosts alive, with an ARP/NDP entry, or seen within `free_after_hours` (168). Confidence: HIGH (all checks available), MEDIUM (a source failing or no L2 evidence), LOW (no recent full scan, stale, or recent loss). It is a recommendation: an external DHCP server may still hold the address.

## Schedule
Defaults: Dockhand 5 min, Proxmox 5, ESPHome 10, discovery 15, full scan 60 (per-subnet override). Editable in Settings; manual scans in the UI. One scan per subnet at a time. IPv6 ranges are not swept (known addresses + NDP only).

## Settings password, conflicts, webhook, CSV
- **HTTPS**: Settings → *HTTPS — własny certyfikat*: wklej certyfikat (PEM, z łańcuchem) i klucz prywatny (PEM, bez hasła). Pliki trafiają do `DATA_DIR/tls/` (klucz 0600). Po restarcie kontenera aplikacja działa na HTTPS na tym samym porcie. Usunięcie certyfikatu wraca do HTTP po restarcie. Zmienna `HTTPS` steruje trybem: `auto` (domyślnie, HTTPS gdy jest certyfikat), `0`/`http` (zawsze HTTP), `1`/`https` (wymagany certyfikat, inaczej start się nie uda).
- **Settings password**: Settings (and `/api/settings`, `/api/test/*`, `/api/records`) require login once a password is set. Set it in Settings → *Settings password*, or fix it with `SETTINGS_PASSWORD` in `.env` (then it cannot be changed in the UI). Until one is set the page is open — set it on first run. Stored as PBKDF2-SHA256 hash; session cookie is HttpOnly/SameSite=Strict (12 h); 5 failed logins → 5 min lock. Serve over HTTPS (reverse proxy) if the network is not trusted.
- **Silencing conflicts**: click *Ignore* next to a conflict on the dashboard (creates a rule for that IP; removable in Settings). Containers in `host` network mode no longer cause conflicts (option *Ignore conflicts caused by host-network containers*).
- **Webhook**: JSON `POST {event,title,message,ip,mac,timestamp,source}`; optional `Authorization` header. Events: new_host, mac_changed, ip_changed, online, offline, conflict, source_down. First run only records the current state (no flood). Max 20 messages per minute; failed delivery is retried.
- **CSV export**: *Export CSV* on the dashboard exports the currently filtered table (also `GET /api/export/ips.csv?q=&subnet=&vlan=&status=&source=`); cells starting with `= + - @` are prefixed with `'` to prevent spreadsheet formula injection.

## Tests
`pip install -r requirements.txt pytest && pytest -q`

## Verification status
Verified: unit tests (30 pass); real full scan of a /24 (52 hosts found, first-free computed); API and UI served.
**Not verified** (no credentials / no Docker access in the build environment): OPNsense and UniFi against live servers (tested only against recorded-shape HTTP responses), webhook delivery to a real receiver, Dockhand and Proxmox against live servers, ESPHome native API, arp-scan, Docker image build and container restart persistence (persistence is unit-tested at DB level). Run these on your side with *Test connection*.
