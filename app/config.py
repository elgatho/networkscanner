import os
from pathlib import Path

_VERSION_FILE = Path(__file__).resolve().parent.parent / "VERSION"
APP_VERSION = os.environ.get("APP_VERSION") or (_VERSION_FILE.read_text().strip() if _VERSION_FILE.exists() else "dev")

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:////data/scanner.db")
ACCESS_TOKEN = os.environ.get("ACCESS_TOKEN", "")  # optional; protects /api when set
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")

# Runtime settings (editable in GUI, stored in DB). Env vars with the same
# upper-case name provide the initial defaults (.env).
DEFAULTS = {
    "dockhand_enabled": False,
    "dockhand_url": "",
    "dockhand_token": "",
    "dockhand_verify_tls": True,
    "dockhand_ca_bundle": "",
    "docker_engine_url": "",  # optional fallback, e.g. tcp://docker-socket-proxy:2375
    "dockhand_interval": 5,
    "proxmox_enabled": False,
    "proxmox_url": "",
    "proxmox_token_id": "",       # user@realm!tokenid
    "proxmox_token_secret": "",
    "proxmox_cluster_name": "",
    "proxmox_verify_tls": True,
    "proxmox_ca_bundle": "",
    "proxmox_fingerprint": "",
    "dockhand_fingerprint": "",
    "proxmox_interval": 5,
    "esphome_enabled": False,
    "esphome_dashboard_url": "",
    "esphome_dashboard_user": "",
    "esphome_dashboard_password": "",
    "esphome_hosts": "",          # extra devices: comma separated "host" or "name=host"
    "esphome_noise_psk": "",
    "esphome_api_password": "",
    "esphome_native_api": True,
    "esphome_interval": 10,
    "opnsense_enabled": False,
    "opnsense_url": "",
    "opnsense_key": "",
    "opnsense_secret": "",
    "opnsense_verify_tls": True,
    "opnsense_ca_bundle": "",
    "opnsense_fingerprint": "",
    "opnsense_reservations": True,
    "opnsense_interval": 5,
    "unifi_enabled": False,
    "unifi_url": "",
    "unifi_api_key": "",
    "unifi_site": "",
    "unifi_verify_tls": True,
    "unifi_ca_bundle": "",
    "unifi_fingerprint": "",
    "unifi_interval": 5,
    "adguard_enabled": False,
    "adguard_url": "",
    "adguard_username": "",
    "adguard_password": "",
    "adguard_verify_tls": True,
    "adguard_ca_bundle": "",
    "adguard_fingerprint": "",
    "adguard_interval": 5,
    "ignore_host_mode_conflicts": True,
    "webhook_enabled": False,
    "webhook_url": "",
    "webhook_auth_header": "",   # e.g. "Bearer xyz" or "Basic ..."
    "webhook_events": "new_host,mac_changed,ip_changed,conflict,source_down",
    "webhook_verify_tls": True,
    "discovery_interval": 15,
    "full_scan_interval": 60,
    "reverse_dns": True,
    "arp_scan": False,
    "port_scan": False,
    "port_list": "22,80,443",
    "nmap_max_rate": 100,
    "max_scan_hosts": 4096,
    "free_after_hours": 168,
    "search_fallback_enabled": True,  # dashboard search with no match -> open SearXNG results
    "search_url": "http://search.lan",
    "top_used_enabled": True,   # dashboard: row of the most opened tiles under the search bar
    "top_used_count": 6,        # how many tiles that row shows (1-24)
}
SECRETS = {"dockhand_token", "proxmox_token_secret", "esphome_dashboard_password",
           "esphome_noise_psk", "esphome_api_password", "opnsense_key", "opnsense_secret",
           "unifi_api_key", "adguard_password", "webhook_url", "webhook_auth_header"}
SETTINGS_PASSWORD = os.environ.get("SETTINGS_PASSWORD", "")  # optional; overrides the UI-managed password
SESSION_HOURS = 12
SOURCES = ("dockhand", "proxmox", "esphome", "opnsense", "unifi", "adguard")
