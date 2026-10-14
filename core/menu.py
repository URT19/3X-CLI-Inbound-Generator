"""Interactive terminal menu.

Each panel-changing action follows the same flow:
  1. Show the dry-run preview (exact request and current state).
  2. Ask the user to type CONFIRM exactly. Anything else cancels.
  3. Call the write method with confirmed=True and report the verified result.
Input, output, screen clearing and styling are injectable so the menu can be
tested without a terminal.
"""

import json
import os
import shutil
from typing import Callable, Dict, List, Optional, Tuple

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any

from config.settings import NetworkSettings, Settings, SettingsError, load_settings, mask_token, save_settings
from templates.loader import load_library
from config.version import APP_VERSION
from certs.acme import AcmeError, DEFAULT_ACME_BIN, acme_available, build_issue_plan, run_plan
from certs.checker import CertStatus, check_domain_cert, default_runner, Runner
from config.settings import DEFAULT_CERT_ROOT
from network.cloudflare import CloudflarePorts
from network.fingerprint import DEFAULT_FINGERPRINT, PRESETS, validate_fingerprint
from network.paths import PATH_KEYS, PATH_LABELS, TEMPLATE_PATH_KEYS, path_key, random_path, validate_path
from network.ports import PortError, check_port
from network.validators import is_loopback_or_private, parse_ip, parse_ip_list, parse_port, is_valid_domain
from panel.client import PanelClient
from panel.errors import PanelError
from panel.writes import ConfirmationRequired
from core.preflight import ip_compatible, resolve_values, validate_payload
from state.inventory import compare
from core.prereq import check_prerequisites, install_plan, ubuntu_info
from state.export import build_inventory, export_inventory
from state.reports import summarize as summarize_report
from config.protocols import PROTOCOL_TAG, load_protocol_catalog
import time
from network.validators import connection_address, parse_fake_destination, parse_ip, resolve_ipv4
from network.hosts import apply_ip_host, direct_host_payload, is_ipv4_literal
import copy
from network.reality import DEFAULT_TARGETS, RealityError, validate_dest, validate_sni
from network.amnezia import ALL_KEYS, BOOL_KEYS, INT_KEYS, AmneziaError, apply_to_payload as apply_amnezia_to_payload, generate_proposal, validate as validate_amnezia
from panel.writes import eligible_fallback_master
from utils.backup import BackupError, create_backup, restore_backup, summarize
from config.version import APP_VERSION as _APP_VERSION
from state.records import RECORD_TYPES, RecordError, append_record, load_records
from templates.loader import TemplateError, render, render_hosts
from network.fingerprint import apply_fingerprint
from ui.style import Style
from utils.naming import NamingError, build_name, validate_custom_name

CONFIRM_WORD = "y"  # kept for tests; the prompt is Y/n now
YES_ANSWERS = ("", "y", "yes")
CONNECTION_TYPES = ("direct", "cdn", "fake", "relay", "local")

MAIN_ITEMS: List[Tuple[str, str]] = [
    ("1", "Check and install prerequisites"),
    ("2", "Panel connection"),
    ("3", "Network and connection settings"),
    ("4", "Generate DIRECT Inbounds"),
    ("5", "Generate CDN Inbounds"),
    ("6", "Generate FAKE SITE Inbounds"),
    ("7", "Generate RELAY Inbounds"),
    ("8", "SSL certificate management"),
    ("9", "Manage panel inbounds"),
    ("10", "Create inbound from template"),
    ("11", "Export inbound inventory (JSON and YAML)"),
    ("12", "Reports and statistics"),
    ("13", "Backup and restore"),
    ("0", "Exit"),
]
CONNECTION_ITEMS: List[Tuple[str, str]] = [
    ("1", "Check connection"),
    ("2", "Edit address and token"),
    ("0", "Back"),
]
PANEL_ITEMS: List[Tuple[str, str]] = [
    ("1", "List inbounds"),
    ("2", "Show inbound details"),
    ("3", "Add inbound from JSON file"),
    ("4", "Update inbound from JSON file"),
    ("5", "Enable or disable inbound"),
    ("6", "Delete inbound"),
    ("7", "Compare local records with panel (read-only)"),
    ("8", "Repair addresses of managed inbounds (host entries, IP Host headers)"),
    ("0", "Back"),
]
NETWORK_ITEMS: List[Tuple[str, str]] = [
    ("1", "Show network settings"),
    ("2", "Cloudflare IP addresses"),
    ("3", "Direct IP"),
    ("4", "Direct domain"),
    ("5", "CDN domain (behind Cloudflare)"),
    ("6", "Port mode (fixed port or random range)"),
    ("7", "Local address for HAProxy and Nginx"),
    ("8", "Request paths (random 12 characters or manual)"),
    ("9", "TLS fingerprint"),
    ("10", "Relay: use IP instead of domain for the relay address (on/off)"),
    ("11", "Relay address (Iran server domain or IP)"),
    ("12", "AmneziaWG parameters (proposal, confirm or edit)"),
    ("0", "Back"),
]
SSL_ITEMS: List[Tuple[str, str]] = [
    ("1", "SSL for a domain (check or issue)"),
    ("2", "Show stored SSL status"),
    ("0", "Back"),
]
BACKUP_ITEMS: List[Tuple[str, str]] = [
    ("1", "Create backup (templates, settings, local records)"),
    ("2", "Restore from backup"),
    ("0", "Back"),
]
NOT_IMPLEMENTED = set()
MAIN_LABELS = dict(MAIN_ITEMS)


def _default_client_factory(settings: Settings) -> PanelClient:
    return PanelClient(settings.panel_address, token=settings.api_token, verify_tls=settings.verify_tls)


@dataclass
class Prepared:
    template: Any
    payload: Dict[str, Any]
    values: Dict[str, Any]
    fingerprint: str
    address: Optional[str] = None
    warnings: List[str] = field(default_factory=list)


class Menu:
    def __init__(
        self,
        client=None,
        input_fn: Callable[[str], str] = input,
        output_fn: Callable[[str], None] = print,
        read_file: Optional[Callable[[str], str]] = None,
        library: Optional[dict] = None,
        settings: Optional[Settings] = None,
        settings_path: Optional[str] = None,
        client_factory: Optional[Callable[[Settings], object]] = None,
        secret_fn: Optional[Callable[[str], str]] = None,
        clear_fn: Optional[Callable[[], None]] = None,
        style: Optional[Style] = None,
        pause: bool = False,
        cloudflare: Optional[CloudflarePorts] = None,
        auto_check: bool = False,
        runner: Optional[Runner] = None,
        acme_bin: str = DEFAULT_ACME_BIN,
        state_dir: Optional[str] = None,
        root: Optional[str] = None,
        library_dir: Optional[str] = None,
        settings_path_for_reload: Optional[str] = None,
    ):
        self._state_dir = state_dir
        self._root = root
        self._library_dir = library_dir
        self.client = client
        self.cloudflare = cloudflare
        self._auto_check = auto_check
        self._runner = runner or default_runner
        self._acme_bin = acme_bin
        self.settings = settings
        self.settings_path = settings_path
        self._input = input_fn
        self._out = output_fn
        self._secret = secret_fn or input_fn
        self._read_file = read_file or (lambda p: open(p, encoding="utf-8").read())
        self._library = library or {}
        self._client_factory = client_factory or _default_client_factory
        self._clear = clear_fn
        self._pause_enabled = pause
        self.style = style or Style(enabled=False)
        self._last_check: Optional[Tuple[str, object]] = None

    # ---- screen ---------------------------------------------------------

    def _clear_screen(self) -> None:
        if self._clear:
            self._clear()

    def _pause(self) -> None:
        if self._pause_enabled:
            self._input(self.style.muted("Press Enter to continue..."))

    def _library_line(self) -> str:
        counts = {k: 0 for k in CONNECTION_TYPES}
        for t in self._library.values():
            counts[t.connection_mode] = counts.get(t.connection_mode, 0) + 1
        return "  ".join(f"{k}={counts.get(k, 0)}" for k in CONNECTION_TYPES)

    def _panel_line(self) -> str:
        if self.client is None:
            return self.style.warn("not configured (menu 2)")
        token = mask_token(self.settings.api_token) if self.settings else "set"
        if self._last_check is None:
            state = self.style.muted("not checked this session")
        elif self._last_check[0] == "ok":
            state = self.style.ok(f"connected, {self._last_check[1]} inbounds")
        else:
            state = self.style.error(f"last check failed: {self._last_check[1]}")
        return f"{self.client.base_url}  token {token}  {state}"

    def _render_header(self) -> None:
        s = self.style
        versions = sorted({t.template_version for t in self._library.values()}) or ["none"]
        self._out(s.accent(f"3x-ui Inbound Manager  v{APP_VERSION}"))
        self._out(s.muted(f"Templates {', '.join(versions)}  |  {self._library_line()}"))
        self._out(s.muted("Panel: ") + self._panel_line())
        self._out(s.muted("-" * 60))

    def _render_items(self, items: List[Tuple[str, str]]) -> None:
        for key, label in items:
            self._out(f"  {self.style.accent(key.rjust(2))}) {label}")

    def _need_client(self) -> bool:
        if self.client is None:
            self._out(self.style.warn("Panel is not configured. Open menu 2 first."))
            return False
        return True

    def _ask_int(self, prompt: str) -> Optional[int]:
        raw = self._input(prompt).strip()
        try:
            return int(raw)
        except ValueError:
            self._out(self.style.error("Expected a number."))
            return None

    def _load_payload(self, path: str) -> Optional[dict]:
        try:
            data = json.loads(self._read_file(path))
        except (OSError, json.JSONDecodeError) as exc:
            self._out(self.style.error(f"Cannot read JSON payload: {exc.__class__.__name__}"))
            return None
        if not isinstance(data, dict):
            self._out(self.style.error("Payload must be a JSON object."))
            return None
        return data

    def _confirm(self, summary: str) -> bool:
        """Y/n prompt. Enter means yes. Anything other than y or yes means no."""
        self._out(self.style.warn(summary))
        return self._input(self.style.accent("Apply? [Y/n]: ")).strip().lower() in YES_ANSWERS

    def _ask_yes(self, question: str) -> bool:
        return self._input(f"{question} [Y/n]: ").strip().lower() in YES_ANSWERS

    def _run_write(self, preview_fn, apply_fn, label: str):
        """Preview, confirm, apply, and report. Returns the verified result or None."""
        try:
            preview = preview_fn()
        except PanelError as exc:
            self._out(self.style.error(f"Refused before sending: {exc}"))
            return None
        self._out(json.dumps(preview, ensure_ascii=False, indent=2, default=str))
        if not self._confirm(f"About to: {label}"):
            self._out(self.style.muted("Cancelled. Nothing was sent to the panel."))
            return None
        try:
            result = apply_fn()
        except ConfirmationRequired as exc:
            self._out(self.style.error(f"Refused: {exc}"))
            return None
        except PanelError as exc:
            self._out(self.style.error(f"Failed: {exc}. Local state was not changed."))
            return None
        self._out(self.style.ok(f"Done and verified: {result}"))
        return result

    # ---- submenus -------------------------------------------------------

    def _submenu(self, title: str, items, handlers: Dict[str, Callable[[], None]]) -> None:
        while True:
            self._clear_screen()
            self._out(self.style.heading(title))
            self._render_items(items)
            choice = self._input("Select: ").strip()
            if choice == "0":
                return
            handler = handlers.get(choice)
            if handler is None:
                self._out(self.style.error("Unknown option."))
                self._pause()
                continue
            handler()
            self._pause()

    def connection_menu(self) -> None:
        self._submenu("Panel connection", CONNECTION_ITEMS, {
            "1": self.check_connection,
            "2": self.edit_settings,
        })

    def panel_menu(self) -> None:
        self._submenu("Manage panel inbounds", PANEL_ITEMS, {
            "1": self.list_inbounds,
            "2": self.show_details,
            "3": self.add_inbound,
            "4": self.update_inbound,
            "5": self.set_enable,
            "6": self.delete_inbound,
            "7": self.compare_records,
            "8": self.repair_addresses,
        })

    # ---- connection -----------------------------------------------------

    def check_connection(self) -> None:
        if not self._need_client():
            return
        try:
            rows = self.client.list_inbounds_slim()
        except PanelError as exc:
            self._last_check = ("fail", str(exc))
            self._out(self.style.error(f"Connection failed: {exc}"))
            return
        self._last_check = ("ok", len(rows))
        self._out(self.style.ok(f"Connection OK: the panel reports {len(rows)} inbounds."))

    def edit_settings(self) -> None:
        current = self.settings or Settings()
        address = self._input(f"Panel address [{current.panel_address or 'none'}]: ").strip()
        address = address or current.panel_address
        token_in = self._secret("API token (blank keeps the current one): ").strip()
        token = token_in or current.api_token
        if not address or not token:
            self._out(self.style.error("Address and token are required."))
            return
        candidate = Settings(
            panel_address=address,
            api_token=token,
            verify_tls=current.verify_tls,
            cert_root=current.cert_root,
        )
        try:
            new_client = self._client_factory(candidate)
        except (PanelError, ValueError) as exc:
            self._out(self.style.error(f"Invalid address: {exc}. Nothing was saved."))
            return
        if self.settings_path:
            try:
                save_settings(self.settings_path, candidate)
            except (OSError, SettingsError) as exc:
                self._out(self.style.error(f"Cannot save settings: {exc.__class__.__name__}"))
                return
            self._out(self.style.ok(f"Saved to {self.settings_path} (permissions 600)."))
        self.settings = candidate
        self.client = new_client
        self._last_check = None
        self._out(f"Token: {mask_token(token)}")

    # ---- network --------------------------------------------------------

    def network_menu(self) -> None:
        self._submenu("Network and connection settings", NETWORK_ITEMS, {
            "1": self.show_network,
            "2": self.set_cloudflare_ips,
            "3": self.set_direct_ip,
            "4": self.set_direct_domain,
            "5": self.set_cdn_domain,
            "6": self.set_port_mode,
            "7": self.set_local_address,
            "8": self.paths_menu,
            "9": self.fingerprint_menu,
            "10": self.toggle_use_ip,
            "11": self.set_relay_address,
            "12": self.amnezia_menu,
        })

    def _network(self) -> NetworkSettings:
        return self.settings.network if self.settings else NetworkSettings()

    def _persist(self, candidate: Settings) -> bool:
        if self.settings_path:
            try:
                save_settings(self.settings_path, candidate)
            except (OSError, SettingsError) as exc:
                self._out(self.style.error(f"Cannot save settings: {exc.__class__.__name__}"))
                return False
        self.settings = candidate
        return True

    def _save_network(self, net: NetworkSettings) -> bool:
        if not self._persist(replace(self.settings or Settings(), network=net)):
            return False
        self._out(self.style.ok("Network setting saved."))
        return True

    def amnezia_menu(self) -> None:
        """Propose AmneziaWG values, then let the user accept them or change each one."""
        proposal = generate_proposal()
        self._out(self.style.heading("Proposed AmneziaWG values"))
        for key in ALL_KEYS:
            shown = "(hidden, generated)" if key in ("privateKey",) else proposal[key]
            self._out(f"  {key:<24} {shown}")
        if self._ask_yes("Use these proposed values?"):
            params = proposal
        else:
            params = {}
            for key in ALL_KEYS:
                default = proposal[key]
                shown = "(generated)" if key == "privateKey" else default
                raw = self._input(f"  {key} [{shown}]: ").strip()
                if raw == "":
                    params[key] = default
                elif key in INT_KEYS:
                    try:
                        params[key] = int(raw)
                    except ValueError:
                        self._fail(f"{key} must be a whole number.")
                        return
                elif key in BOOL_KEYS:
                    params[key] = raw.lower() in ("y", "yes", "true", "1")
                else:
                    params[key] = raw
        try:
            validate_amnezia(params)
        except AmneziaError as exc:
            self._fail(str(exc))
            return
        if self._save_settings_fields(amnezia=params):
            self._out(self.style.ok("AmneziaWG parameters saved to settings.json."))

    def toggle_use_ip(self) -> None:
        current = self._network().use_ip_addresses
        self._out(f"Currently: {'on' if current else 'off'}")
        answer = self._input("Use IP instead of domain in connection addresses? [y/n]: ").strip().lower()
        if answer not in ("y", "n", "yes", "no"):
            self._fail("Expected y or n.")
            return
        self._save_network(replace(self._network(), use_ip_addresses=answer in ("y", "yes")))

    def set_relay_address(self) -> None:
        raw = self._input("Relay address (Iran server domain or IP): ").strip().lower()
        if is_valid_domain(raw):
            value = raw
        else:
            try:
                value = parse_ip(raw)
            except ValueError as exc:
                self._fail(f"Not a valid domain or IP: {exc}")
                return
        self._save_network(replace(self._network(), relay_address=value))

    def _save_settings_fields(self, **changes) -> bool:
        return self._persist(replace(self.settings or Settings(), **changes))

    def paths_menu(self) -> None:
        """Generate every request path at once (default: yes), or set them one by one."""
        current = dict(self.settings.paths if self.settings else {})
        auto = self._input(self.style.accent("Generate all paths automatically? [Y/n]: ")).strip().lower()
        if auto in YES_ANSWERS:
            generated = {key: random_path() for key in PATH_KEYS}
            self._out(self.style.heading("Generated paths"))
            for key in PATH_KEYS:
                self._out(f"  {key:<18} {generated[key]}")
            if self._ask_yes("Save these paths and continue?"):
                if self._save_settings_fields(paths=generated):
                    self._out(self.style.ok("Request paths saved."))
            else:
                self._out(self.style.muted("Cancelled. Paths were not changed."))
            return
        new_paths = dict(current)
        for key in PATH_KEYS:
            candidate = random_path()
            existing = current.get(key, "")
            self._out(self.style.heading(f"{PATH_LABELS[key]} ({key})"))
            self._out(f"  current:   {existing or 'not set'}")
            self._out(f"  generated: {candidate}")
            choice = self._input("  [a] accept generated  [m] type my own  [k] keep current: ").strip().lower()
            if choice == "a":
                new_paths[key] = candidate
            elif choice == "m":
                try:
                    new_paths[key] = validate_path(self._input("  Path: "))
                except ValueError as exc:
                    self._fail(str(exc))
                    return
            elif choice == "k" and existing:
                new_paths[key] = existing
            else:
                self._fail("Expected a, m or k (k needs an existing value).")
                return
        if self._save_settings_fields(paths=new_paths):
            self._out(self.style.ok("Request paths saved."))

    def fingerprint_menu(self) -> None:
        current = self.settings.fingerprint if self.settings else DEFAULT_FINGERPRINT
        self._out(f"Current fingerprint: {current}")
        options = list(PRESETS) + ["custom"]
        for index, name in enumerate(options, start=1):
            self._out(f"  {index}) {name}")
        raw = self._input("Choose a number, or type a fingerprint name: ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            choice = options[int(raw) - 1]
            if choice == "custom":
                raw = self._input("Custom fingerprint: ").strip()
            else:
                raw = choice
        try:
            value = validate_fingerprint(raw)
        except ValueError as exc:
            self._fail(str(exc))
            return
        if self._save_settings_fields(fingerprint=value):
            self._out(self.style.ok(f"Fingerprint set to {value}."))

    # ---- SSL ------------------------------------------------------------

    def ssl_menu(self) -> None:
        self._submenu("SSL certificate management", SSL_ITEMS, {
            "1": self.ssl_flow,
            "2": self.show_ssl_records,
        })

    def _cert_root(self) -> str:
        return self.settings.cert_root if self.settings else DEFAULT_CERT_ROOT

    def _yes_no(self, prompt: str) -> Optional[bool]:
        answer = self._input(prompt).strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        return None

    def _show_status(self, status: CertStatus) -> None:
        colour = self.style.ok if status.state == "ok" else self.style.warn
        if status.state in ("invalid", "mismatch", "expired", "missing"):
            colour = self.style.error
        self._out(colour(f"{status.domain}: {status.state}. {status.message}"))
        if status.not_after:
            self._out(f"  expires: {status.not_after}")
        if status.names:
            self._out(f"  names:   {', '.join(status.names)}")
        if status.key_permissions_ok is False:
            self._out(self.style.warn("  private key is readable by other users; run chmod 600 on it."))

    def _record_ssl(self, domain: str, record: dict) -> None:
        base = self.settings or Settings()
        domains = dict(base.ssl_domains)
        domains[domain] = record
        self._persist(replace(base, ssl_domains=domains))

    def ssl_flow(self) -> None:
        domain = self._input("Domain: ").strip().lower()
        if not is_valid_domain(domain):
            self._fail("Not a valid domain name.")
            return
        needed = self._yes_no("Does this domain need SSL? (y/n): ")
        if needed is None:
            self._fail("Expected y or n.")
            return
        if not needed:
            self._record_ssl(domain, {"needed": False})
            self._out(self.style.ok(f"{domain}: SSL not needed. Saved."))
            return
        taken = self._yes_no("Has an SSL certificate already been issued for this domain? (y/n): ")
        if taken is None:
            self._fail("Expected y or n.")
            return
        root = self._cert_root()
        if taken:
            status = check_domain_cert(root, domain, runner=self._runner)
            self._show_status(status)
            self._record_ssl(domain, {"needed": True, "last_state": status.state,
                                      "not_after": status.not_after})
            if status.state == "ok":
                return
            if not self._yes_no("Issue or renew with acme.sh now? (y/n): "):
                return
        self._issue_certificate(domain, root)

    def _issue_certificate(self, domain: str, root: str) -> None:
        if not acme_available(self._acme_bin):
            self._fail(f"acme.sh not found at {self._acme_bin}. Installing it is not implemented yet.")
            return
        port_text = self._input("HTTP-01 port [80]: ").strip() or "80"
        try:
            port = int(port_text)
            plan = build_issue_plan(domain, root, port, acme_bin=self._acme_bin)
        except (ValueError, AcmeError) as exc:
            self._fail(str(exc))
            return
        self._out(self.style.heading("Planned commands (no shell):"))
        for argv in plan:
            self._out("  " + " ".join(argv))
        self._out(self.style.warn(
            f"Let's Encrypt must reach this server on port {port} from the internet. "
            "No service will be restarted."
        ))
        if not self._confirm(f"About to issue a certificate for {domain} into {root}/{domain}"):
            self._out(self.style.muted("Cancelled. No certificate was requested."))
            return
        error = run_plan(plan, root, domain, self._runner)
        if error:
            self._fail(error)
            return
        status = check_domain_cert(root, domain, runner=self._runner)
        self._show_status(status)
        if status.state != "ok":
            self._fail("Verification failed. The stored status was not updated.")
            return
        self._record_ssl(domain, {"needed": True, "last_state": "ok", "not_after": status.not_after})
        self._out(self.style.ok("Done and verified."))

    def show_ssl_records(self) -> None:
        records = (self.settings.ssl_domains if self.settings else {})
        if not records:
            self._out("No domains stored yet.")
            return
        for domain, record in sorted(records.items()):
            if not record.get("needed"):
                self._out(f"  {domain:<32} SSL not needed")
            else:
                self._out(f"  {domain:<32} {record.get('last_state', 'unchecked')}  "
                          f"expires {record.get('not_after', 'unknown')}")

    def _fail(self, message: str) -> None:
        self._out(self.style.error(message))

    def show_network(self) -> None:
        net = self._network()
        if net.port_mode == "fixed":
            port_text = f"fixed {net.fixed_port}" if net.fixed_port else "fixed (not set)"
        else:
            port_text = f"random {net.random_port_low}-{net.random_port_high}"
        rows = [
            ("Cloudflare IPs", ", ".join(net.cloudflare_ips) or "not set"),
            ("Direct IP", net.direct_ip or "not set"),
            ("Direct domain", net.direct_domain or "not set"),
            ("CDN domain", net.cdn_domain or "not set"),
            ("Port mode", port_text),
            ("Local address", f"{net.local_ip}:{net.local_port}" if net.local_port else f"{net.local_ip} (port not set)"),
        ]
        rows.append(("Relay address", net.relay_address or "not set"))
        rows.append(("Use IP", "on" if net.use_ip_addresses else "off"))
        for label, value in rows:
            self._out(f"  {label:<16} {value}")

    def set_cloudflare_ips(self) -> None:
        raw = self._input("Cloudflare IPs, comma separated: ")
        try:
            ips = parse_ip_list(raw)
        except ValueError as exc:
            self._fail(str(exc))
            return
        self._save_network(replace(self._network(), cloudflare_ips=ips))

    def set_direct_ip(self) -> None:
        try:
            ip = parse_ip(self._input("Direct IP: "))
        except ValueError as exc:
            self._fail(str(exc))
            return
        self._save_network(replace(self._network(), direct_ip=ip))

    def set_direct_domain(self) -> None:
        domain = self._input("Direct domain (for example sub.example.com): ").strip().lower()
        if not is_valid_domain(domain):
            self._fail("Not a valid domain name.")
            return
        if self._save_network(replace(self._network(), direct_domain=domain)):
            self._offer_ssl(domain)

    def set_cdn_domain(self) -> None:
        domain = self._input("CDN domain behind Cloudflare (for example cdn.example.com): ").strip().lower()
        if not is_valid_domain(domain):
            self._fail("Not a valid domain name.")
            return
        if self._save_network(replace(self._network(), cdn_domain=domain)):
            self._offer_ssl(domain)

    def _offer_ssl(self, domain: str) -> None:
        """Check the certificate for a domain that was just set, and offer to obtain one if needed."""
        root = self._cert_root()
        status = check_domain_cert(root, domain, runner=self._runner)
        self._show_status(status)
        self._record_ssl(domain, {"needed": True, "last_state": status.state,
                                  "not_after": status.not_after})
        if status.state == "ok":
            return
        if status.state == "renew":
            if self._ask_yes(f"Renew the SSL certificate for {domain} now?"):
                self._issue_certificate(domain, root)
            return
        if self._ask_yes(f"No valid SSL certificate for {domain}. Obtain one now?"):
            self._issue_certificate(domain, root)

    def set_port_mode(self) -> None:
        choice = self._input("Port mode: f = fixed port, r = random range: ").strip().lower()
        if choice == "f":
            try:
                port = parse_port(self._input("Fixed port: "))
                check_port(port, "any", [], self.cloudflare)
            except (ValueError, PortError) as exc:
                self._fail(str(exc))
                return
            self._save_network(replace(self._network(), port_mode="fixed", fixed_port=port))
        elif choice == "r":
            try:
                low = parse_port(self._input("Random range low: "))
                high = parse_port(self._input("Random range high: "))
            except ValueError as exc:
                self._fail(str(exc))
                return
            if low > high:
                self._fail("Range low must not be greater than high.")
                return
            for edge in (low, high):
                try:
                    check_port(edge, "any", [], self.cloudflare)
                except PortError as exc:
                    self._fail(str(exc))
                    return
            self._save_network(replace(self._network(), port_mode="random",
                                       random_port_low=low, random_port_high=high))
        else:
            self._fail("Expected f or r.")

    def set_local_address(self) -> None:
        try:
            ip = parse_ip(self._input("Local IP (loopback or private, for example 127.0.0.1): "))
        except ValueError as exc:
            self._fail(str(exc))
            return
        if not is_loopback_or_private(ip):
            self._fail("Local address must be loopback or private. Public IPs are refused.")
            return
        try:
            port = parse_port(self._input("Local port: "))
            check_port(port, "local", [], self.cloudflare)
        except (ValueError, PortError) as exc:
            self._fail(str(exc))
            return
        self._save_network(replace(self._network(), local_ip=ip, local_port=port))

    # ---- panel inbounds -------------------------------------------------

    def list_inbounds(self) -> None:
        if not self._need_client():
            return
        try:
            rows = self.client.list_inbounds_slim()
        except PanelError as exc:
            self._out(self.style.error(f"Cannot list inbounds: {exc}"))
            return
        if not rows:
            self._out("The panel reports no inbounds.")
            return
        for row in rows:
            self._out(
                f"[{row.get('id')}] {str(row.get('remark')):<24} "
                f"{str(row.get('protocol')):<10} port={row.get('port')} "
                f"enabled={row.get('enable', 'n/a')}"
            )

    def show_details(self) -> None:
        if not self._need_client():
            return
        inbound_id = self._ask_int("Inbound id: ")
        if inbound_id is None:
            return
        try:
            data = self.client.get_inbound(inbound_id)
        except PanelError as exc:
            self._out(self.style.error(f"Cannot read inbound: {exc}"))
            return
        self._out(json.dumps(data, ensure_ascii=False, indent=2, default=str))

    def add_inbound(self) -> None:
        if not self._need_client():
            return
        path = self._input("Path to inbound JSON payload: ").strip()
        payload = self._load_payload(path)
        if payload is None:
            return
        self._run_write(
            lambda: self.client.add_inbound(payload, dry_run=True),
            lambda: self.client.add_inbound(payload, confirmed=True),
            f"add inbound {payload.get('remark')!r} on port {payload.get('port')}",
        )

    def update_inbound(self) -> None:
        if not self._need_client():
            return
        inbound_id = self._ask_int("Inbound id to update: ")
        if inbound_id is None:
            return
        path = self._input("Path to inbound JSON payload: ").strip()
        payload = self._load_payload(path)
        if payload is None:
            return
        self._run_write(
            lambda: self.client.update_inbound(inbound_id, payload, dry_run=True),
            lambda: self.client.update_inbound(inbound_id, payload, confirmed=True),
            f"update inbound id {inbound_id}",
        )

    def set_enable(self) -> None:
        if not self._need_client():
            return
        inbound_id = self._ask_int("Inbound id: ")
        if inbound_id is None:
            return
        choice = self._input("Enable (e) or disable (d)? ").strip().lower()
        if choice not in ("e", "d"):
            self._out(self.style.error("Expected e or d."))
            return
        enable = choice == "e"
        self._run_write(
            lambda: self.client.set_enable(inbound_id, enable, dry_run=True),
            lambda: self.client.set_enable(inbound_id, enable, confirmed=True),
            f"{'enable' if enable else 'disable'} inbound id {inbound_id}",
        )

    def delete_inbound(self) -> None:
        if not self._need_client():
            return
        inbound_id = self._ask_int("Inbound id to DELETE: ")
        if inbound_id is None:
            return
        self._run_write(
            lambda: self.client.delete_inbound(inbound_id, dry_run=True),
            lambda: self.client.delete_inbound(inbound_id, confirmed=True),
            f"DELETE inbound id {inbound_id} (cannot be undone)",
        )

    def compare_records(self) -> None:
        if not self._need_client():
            return
        if not self._state_dir:
            self._out(self.style.warn("No state directory set."))
            return
        try:
            rows = self.client.list_inbounds_slim()
        except PanelError as exc:
            self._out(self.style.error(f"Cannot read the panel: {exc}"))
            return
        try:
            local = {t: load_records(self._state_dir, t) for t in RECORD_TYPES}
        except RecordError as exc:
            self._out(self.style.error(str(exc)))
            return
        inv = compare(local, rows)
        self._out(self.style.heading("Matched (local record and panel agree)"))
        for item in inv.matched:
            self._out(self.style.ok(f"  [{item['id']}] {item['name']} ({item['type']}, port {item['port']})"))
        self._out(self.style.heading("Local records not found on the panel (no changes made)"))
        for item in inv.missing_on_panel:
            self._out(self.style.warn(f"  {item['name']} ({item['type']}, id {item['id']}, port {item['port']})"))
        self._out(self.style.heading("Panel inbounds with no local record"))
        for item in inv.unknown_on_panel:
            self._out(f"  [{item['id']}] {item['name']} (port {item['port']})")
        if inv.port_conflicts:
            self._out(self.style.error(f"Ports used more than once on the panel: {inv.port_conflicts}"))
        if not (inv.matched or inv.missing_on_panel or inv.unknown_on_panel):
            self._out("Nothing to compare yet.")

    # ---- templates ------------------------------------------------------

    def _status_fn(self):
        cert_root = self._cert_root()
        return lambda domain: check_domain_cert(cert_root, domain, runner=self._runner)

    def _prepare(self, template, state: Dict[str, list], relay: bool = False,
                 connection_address: Optional[str] = None) -> Tuple[Optional["Prepared"], List[str]]:
        """Resolve, render and check one template. state['existing'] and state['in_use'] are
        updated so that later templates in the same batch do not reuse a name or port."""
        resolution = resolve_values(
            template, self._network(), (self.settings.paths if self.settings else {}),
            self._cert_root(), self.cloudflare, state["in_use"], status_fn=self._status_fn(),
            amnezia=(self.settings.amnezia if self.settings else None),
            connection_address=connection_address,
            cdn_via=getattr(self, "_cdn_via", "cloudflare"),
            reality=getattr(self, "_reality", None),
            fingerprint=(self.settings.fingerprint if self.settings else DEFAULT_FINGERPRINT),
        )
        if resolution.problems:
            return None, resolution.problems
        try:
            remark = build_name(template, state["existing"], mode_label="RELAY" if relay else None)
            payload = render(template, resolution.values, remark=remark)
            if template.protocol == "amneziawg":
                apply_amnezia_to_payload(payload, self.settings.amnezia if self.settings else {})
            if (template.connection_mode == "direct" and connection_address
                    and is_ipv4_literal(connection_address) and connection_address != "127.0.0.1"):
                apply_ip_host(payload, connection_address)  # direct over an IP: Host header is the IP
        except (NamingError, TemplateError, AmneziaError) as exc:
            return None, [str(exc)]
        fingerprint = self.settings.fingerprint if self.settings else DEFAULT_FINGERPRINT
        apply_fingerprint(payload, fingerprint)
        problems = validate_payload(payload)
        if problems:
            return None, problems
        state["existing"].append(payload["remark"])
        state["in_use"].append(payload["port"])
        return Prepared(template, payload, resolution.values, fingerprint, address=connection_address,
                        warnings=list(resolution.warnings)), []

    def _load_state(self) -> Optional[Dict[str, list]]:
        try:
            rows = self.client.list_inbounds_slim()
        except PanelError as exc:
            self._fail(f"Refused: cannot read the panel inbound list ({exc}).")
            return None
        return {
            "existing": [r.get("remark") or "" for r in rows],
            "in_use": [r.get("port") for r in rows if isinstance(r.get("port"), int)],
        }

    def _choose_direct_address(self) -> Optional[str]:
        """Ask once per run which address DIRECT configs use. Returns None if the user stops."""
        domain = self._network().direct_domain
        self._out(self.style.heading("Address for DIRECT configs"))
        self._out(f"  1) domain name  ({domain or 'not set'})")
        self._out("  2) IP resolved from the domain")
        self._out("  3) 127.0.0.1")
        choice = self._input("Choose 1, 2 or 3 [1]: ").strip() or "1"
        if choice == "1":
            if not domain:
                self._fail("Direct domain is not set (menu 3, item 4).")
                return None
            return domain
        if choice == "2":
            if not domain:
                self._fail("Direct domain is not set (menu 3, item 4).")
                return None
            try:
                resolved = resolve_ipv4(domain)
            except ValueError as exc:
                self._fail(str(exc))
                return None
            self._out(f"  resolved {domain} -> {resolved}")
            if self._ask_yes("Use this IP as the address?"):
                return resolved
            try:
                return parse_ip(self._input("  Enter the address you want: "))
            except ValueError as exc:
                self._fail(str(exc))
                return None
        if choice == "3":
            return "127.0.0.1"
        self._fail("Expected 1, 2 or 3.")
        return None

    def _choose_cdn_ip(self) -> Optional[str]:
        """CDN route, three options: Cloudflare with a domain, Cloudflare with an IP, or local.
        Returns the address used for the CDN configs."""
        net = self._network()
        self._out(self.style.heading("CDN route"))
        self._out(f"  1) through Cloudflare, domain name  ({net.cdn_domain or 'not set'})")
        self._out("  2) through Cloudflare, IP address  (choose one of the Cloudflare IPs)")
        self._out(f"  3) local, HAProxy or Nginx  ({net.local_ip or '127.0.0.1'})")
        self._out(self.style.muted("  Cloudflare routes: ports from Cloudflare's list, never 80 or 443."))
        route = self._input("Choose 1, 2 or 3 [1]: ").strip() or "1"
        if route == "3":
            self._cdn_via = "local"
            return net.local_ip or "127.0.0.1"
        if route == "1":
            if not net.cdn_domain:
                self._fail("CDN domain is not set (menu 3, item 5).")
                return None
            self._cdn_via = "cloudflare"
            return net.cdn_domain
        if route != "2":
            self._fail("Expected 1, 2 or 3.")
            return None
        self._cdn_via = "cloudflare"
        return self._choose_cloudflare_ip()

    def _choose_reality_target(self) -> Optional[Dict[str, str]]:
        """REALITY target: a default site from the list, or a custom dest and SNI (last item)."""
        self._out(self.style.heading("REALITY target (dest and server name)"))
        for index, (label, dest, sni) in enumerate(DEFAULT_TARGETS, start=1):
            self._out(f"  {index:>2}) {label}  (dest {dest}, SNI {sni})")
        custom = len(DEFAULT_TARGETS) + 1
        self._out(f"  {custom:>2}) custom")
        self._out(self.style.muted("  Check each target from the server first: TLS 1.3 and HTTP/2 are required."))
        raw = self._input(f"Choose 1-{custom} [1]: ").strip() or "1"
        if not raw.isdigit() or not 1 <= int(raw) <= custom:
            self._fail("Invalid choice.")
            return None
        if int(raw) == custom:
            dest_text = self._input("  Target (host:443): ")
            sni_text = self._input("  Server name (SNI): ")
        else:
            _label, dest_text, sni_text = DEFAULT_TARGETS[int(raw) - 1]
        try:
            return {"dest": validate_dest(dest_text), "sni": validate_sni(sni_text)}
        except RealityError as exc:
            self._fail(str(exc))
            return None

    def _choose_cloudflare_ip(self) -> Optional[str]:
        """Pick one of the Cloudflare IPs from settings for CDN configs."""
        ips = self._network().cloudflare_ips
        if not ips:
            self._fail("Cloudflare IP is not set (menu 3, item 2).")
            return None
        if len(ips) == 1:
            return ips[0]
        self._out(self.style.heading("Cloudflare IP for CDN configs"))
        for index, ip in enumerate(ips, start=1):
            self._out(f"  {index}) {ip}")
        raw = self._input(f"Choose 1-{len(ips)} [1]: ").strip() or "1"
        if not raw.isdigit() or not 1 <= int(raw) <= len(ips):
            self._fail("Invalid choice.")
            return None
        return ips[int(raw) - 1]

    def add_from_template(self, mode: Optional[str] = None, title: str = "Inbound from template",
                          relay: bool = False, direct_address: bool = False,
                          cdn_address: bool = False) -> None:
        """List templates for a connection type. Choose one, or 'a' to create all of them."""
        if not self._library:
            self._out(self.style.warn("No templates loaded."))
            return
        if not self._need_client():
            return
        if relay and not self._network().relay_address:
            self._fail("Relay address is not set (menu 3, item 11).")
            return
        ordered = sorted(
            (t for t in self._library.values() if mode is None or t.connection_mode == mode),
            key=lambda t: (t.number, t.template_id),
        )
        if not ordered:
            self._out(self.style.heading(title))
            self._out(self.style.warn(
                f"No templates for '{mode}' yet. Add JSON files with connection_mode '{mode}' to inbounds/."
            ))
            return
        # 1) Ask the address question first (DIRECT and CDN only).
        connection_address = None
        self._cdn_via = "cloudflare"
        if direct_address:
            connection_address = self._choose_direct_address()
        elif cdn_address:
            connection_address = self._choose_cdn_ip()
        if (direct_address or cdn_address) and connection_address is None:
            return
        # 2) Clear the screen, then show the configs.
        self._reality = None
        if direct_address or cdn_address:
            self._clear_screen()
            if connection_address:
                self._out(self.style.muted(f"Address: {connection_address}"))
        self._out(self.style.heading(title))
        for index, t in enumerate(ordered, start=1):
            flag = "  [deprecated]" if t.deprecated else ""
            self._out(
                f"  {index:>2}) {t.name}  [{t.connection_mode}, {t.protocol}, {t.security}]"
                f"  v{t.template_version}{flag}"
            )
        self._out(f"  {'a':>2}) all {len(ordered)} templates above")
        # 3) Then the next question.
        raw = self._input("Template number, or a for all: ").strip().lower()
        state = self._load_state()
        if state is None:
            return
        if raw == "a":
            self._create_all(ordered, state, relay, connection_address)
            return
        try:
            choice = int(raw)
        except ValueError:
            self._fail("Invalid template number.")
            return
        if not 1 <= choice <= len(ordered):
            self._fail("Invalid template number.")
            return
        chosen = ordered[choice - 1]
        if chosen.deprecated:
            self._out(self.style.warn(
                f"Deprecated: {chosen.deprecated['reason']}. Use instead: {chosen.deprecated['replace']}."))
        self._create_one(chosen, state, relay, connection_address)

    def _ensure_reality(self, templates) -> bool:
        """Ask for the REALITY target only when a chosen template needs it. Returns False to stop."""
        if not any("REALITY_" in json.dumps(t.content) for t in templates):
            return True
        if getattr(self, "_reality", None) is None:
            self._reality = self._choose_reality_target()
        return self._reality is not None

    def _create_one(self, template, state, relay: bool = False, connection_address: Optional[str] = None) -> None:
        if not self._ensure_reality([template]):
            return
        prep, problems = self._prepare(template, state, relay, connection_address)
        if problems:
            self._fail("Refused before sending. Missing or invalid parameters:")
            for problem in problems:
                self._fail(f"  - {problem}")
            return
        self._out(self.style.heading("Parameters"))
        self._out(f"  name:        {prep.payload['remark']}")
        self._out(f"  port:        {prep.payload['port']}")
        self._out(f"  protocol:    {prep.payload['protocol']} / {prep.template.transport} / {prep.template.security}")
        self._out(f"  fingerprint: {prep.fingerprint}")
        for key in sorted(prep.values):
            if key in ("PORT", "WHITELIST_IP", "HY_PASSWORD"):
                continue
            if key.startswith("PATH_"):
                transport = TEMPLATE_PATH_KEYS.get(key, "")
                used = path_key(prep.template.connection_mode, transport)
                self._out(f"  {key:<17} {prep.values[key]}   <- settings key {used}")
            elif key.startswith("AWG_"):
                continue
            else:
                self._out(f"  {key:<17} {prep.values[key]}")
        result = self._run_write(
            lambda: self.client.add_inbound(prep.payload, dry_run=True),
            lambda: self.client.add_inbound(prep.payload, confirmed=True),
            f"add inbound {prep.payload['remark']} on port {prep.payload['port']}",
        )
        if result is None:
            return
        self._save_local_record(prep.template, prep.payload, result["id"], prep.values, prep.fingerprint, relay,
                                address=prep.address)
        if relay:
            self._add_relay_host(prep.payload, result["id"])
        elif prep.template.external_proxies:
            self._add_template_hosts(prep.template, prep.values, result["id"])
        else:
            self._add_direct_host(prep, result["id"])

    def _direct_host_for(self, prep: "Prepared", inbound_id: int) -> Optional[Dict[str, Any]]:
        """Host entry carrying the chosen direct address (domain, resolved IP, or 127.0.0.1).
        Templates that already have external proxy entries carry their own address and are skipped."""
        if prep.template.connection_mode != "direct" or not prep.address or prep.template.external_proxies:
            return None
        sni_domain = (prep.values.get("REALITY_SNI") or prep.values.get("SUBDOMAIN_DIRECT")
                      or self._network().direct_domain or "")
        return direct_host_payload(inbound_id, prep.payload["remark"], prep.address,
                                   prep.payload["port"], prep.template.security, sni_domain)

    def _add_direct_host(self, prep: "Prepared", inbound_id: int, confirmed_batch: bool = False) -> None:
        host = self._direct_host_for(prep, inbound_id)
        if host is None:
            return
        try:
            done = self.client.add_host(host, confirmed=True)
            self._out(self.style.ok(f"Host entry for {prep.payload['remark']}: address {host['address']}"
                                    f" (verified, id {done.get('id')})"))
        except PanelError as exc:
            self._fail(f"Host entry for {prep.payload['remark']} failed: {exc}")

    def _add_relay_host(self, payload, inbound_id: int) -> None:
        """A relay inbound is served under the relay address. Create one host entry for it."""
        net = self._network()
        host = {
            "inboundId": inbound_id,
            "remark": payload["remark"],
            "address": connection_address(net.relay_address, net.use_ip_addresses),
            "port": payload["port"],
            "security": "same",
            "sni": "",
            "alpn": [],
            "sortOrder": 0,
        }
        try:
            result = self.client.add_host(host, dry_run=True)
            self._out(self.style.heading("Relay host entry (preview)"))
            self._out(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        except PanelError as exc:
            self._fail(f"Relay host preview failed: {exc}")
            return
        if not self._confirm("Create the relay host entry for this inbound"):
            self._out(self.style.muted("Relay host entry cancelled. The inbound exists without it."))
            return
        try:
            done = self.client.add_host(host, confirmed=True)
            self._out(self.style.ok(f"Relay host done and verified: {done}"))
        except PanelError as exc:
            self._fail(f"Relay host failed: {exc}")

    def _create_all(self, templates, state, relay: bool = False, connection_address: Optional[str] = None) -> None:
        deprecated_count = sum(1 for t in templates if t.deprecated)
        if deprecated_count:
            self._out(self.style.warn(
                f"{deprecated_count} of these use Xray-deprecated features; they are included as requested."))
        if not self._ensure_reality(templates):
            return
        prepared: List[Prepared] = []
        skipped: List[str] = []
        for template in templates:
            prep, problems = self._prepare(template, state, relay, connection_address)
            if problems:
                skipped.append(f"{template.name}: {'; '.join(problems)}")
            else:
                prepared.append(prep)
        self._out(self.style.heading(f"Ready: {len(prepared)} of {len(templates)}"))
        for prep in prepared:
            self._out(f"  {prep.payload['remark']:<32} port {prep.payload['port']}")
        warnings = [w for prep in prepared for w in prep.warnings]
        for warning in dict.fromkeys(warnings):
            self._out(self.style.warn(warning))
        for line in skipped:
            self._out(self.style.error(f"  skipped - {line}"))
        if not prepared:
            return
        if not self._confirm(f"Create {len(prepared)} inbounds (and their host entries) on the panel"):
            self._out(self.style.muted("Cancelled. Nothing was sent to the panel."))
            return
        created = 0
        for prep in prepared:
            try:
                result = self.client.add_inbound(prep.payload, confirmed=True)
            except PanelError as exc:
                self._fail(f"Stopped at {prep.payload['remark']}: {exc}. {created} created before this.")
                return
            created += 1
            self._out(self.style.ok(f"Created {prep.payload['remark']} (id {result['id']})"))
            self._save_local_record(prep.template, prep.payload, result["id"], prep.values, prep.fingerprint, relay,
                                    address=prep.address)
            if relay:
                self._add_relay_host(prep.payload, result["id"])
                continue
            if not prep.template.external_proxies:
                self._add_direct_host(prep, result["id"])
                continue
            for host in (render_hosts(prep.template, prep.values, result["id"]) if prep.template.external_proxies else []):
                try:
                    self.client.add_host(host, confirmed=True)
                except PanelError as exc:
                    self._fail(f"Host for {prep.payload['remark']} failed: {exc}")
        self._out(self.style.ok(f"Done: {created} inbounds created and verified."))

    def _save_local_record(self, template, payload, inbound_id, values, fingerprint, relay: bool = False,
                           address: Optional[str] = None) -> None:
        record_type = "relay" if relay else template.connection_mode
        if record_type not in RECORD_TYPES:
            return
        if not self._state_dir:
            self._out(self.style.warn("No state directory set; the local record was not saved."))
            return
        net = self._network()
        domain = net.cdn_domain if template.connection_mode == "cdn" else net.direct_domain
        if "SUBDOMAIN_CDN" not in values and "SUBDOMAIN_DIRECT" not in values:
            domain = None  # IP-based direct inbound
        if relay:
            address = connection_address(net.relay_address, net.use_ip_addresses)
        elif address is None:
            address = connection_address(domain or net.direct_ip, net.use_ip_addresses)
        suffix = "CDN" if template.connection_mode == "cdn" else "DIRECT"
        record_type = "relay" if relay else template.connection_mode
        path_values = [v for k, v in values.items() if k.startswith("PATH_")]
        record = {
            "hysteria_password": values.get("HY_PASSWORD"),
            "reality_public_key": values.get("REALITY_PUBLIC_KEY"),
            "reality_short_id": values.get("REALITY_SHORT_ID"),
            "reality_dest": values.get("REALITY_DEST"),
            "reality_sni": values.get("REALITY_SNI"),
            "inbound_id": inbound_id,
            "name": payload["remark"],
            "port": payload["port"],
            "template_id": template.template_id,
            "template_version": template.template_version,
            "protocol": payload["protocol"],
            "transport": template.transport,
            "security": template.security,
            "domain": domain,
            "address": address,
            "path": path_values[0] if path_values else None,
            "cert_fullchain": values.get(f"CERT_{suffix}"),
            "cert_privkey": values.get(f"KEY_{suffix}"),
            "fingerprint": fingerprint,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        if values.get("HY_PASSWORD"):
            base = self.settings or Settings()
            passwords = dict(base.hysteria_passwords)
            passwords[payload["remark"]] = values["HY_PASSWORD"]
            self._persist(replace(base, hysteria_passwords=passwords))
        if values.get("REALITY_PRIVATE_KEY"):
            base = self.settings or Settings()
            keys = dict(base.reality_keys)
            keys[payload["remark"]] = {
                "privateKey": values["REALITY_PRIVATE_KEY"],
                "publicKey": values["REALITY_PUBLIC_KEY"],
                "shortId": values["REALITY_SHORT_ID"],
                "dest": values["REALITY_DEST"],
                "sni": values["REALITY_SNI"],
            }
            self._persist(replace(base, reality_keys=keys))
        try:
            append_record(self._state_dir, record_type, record)
            self._out(self.style.ok(f"Local record saved to {record_type}.json."))
        except RecordError as exc:
            self._out(self.style.error(f"Inbound created, but the local record failed: {exc}"))

    def _add_template_hosts(self, template, values, inbound_id: int) -> None:
        """Create the template's host entries for the new inbound, after its own confirmation."""
        try:
            hosts = render_hosts(template, values, inbound_id)
        except TemplateError as exc:
            self._out(self.style.error(f"Inbound created, but host entries were not built: {exc}"))
            return
        previews = [self.client.add_host(h, dry_run=True) for h in hosts]
        self._out(json.dumps(previews, ensure_ascii=False, indent=2, default=str))
        if not self._confirm(f"About to add {len(hosts)} host entr(y/ies) for inbound id {inbound_id}"):
            self._out(self.style.muted("Host entries cancelled. The inbound exists without them."))
            return
        for index, host in enumerate(hosts, start=1):
            try:
                result = self.client.add_host(host, confirmed=True)
            except PanelError as exc:
                self._out(self.style.error(f"Host {index} failed: {exc}. Earlier host entries were kept."))
                return
            self._out(self.style.ok(f"Host {index} done and verified: {result}"))

    # ---- fake site ------------------------------------------------------

    def fake_site(self) -> None:
        """Set one fake-site address as a fallback on a VLESS or Trojan TLS/REALITY master inbound."""
        if not self._need_client():
            return
        try:
            rows = self.client.list_inbounds()
        except PanelError as exc:
            self._fail(f"Cannot read the panel: {exc}")
            return
        masters = [r for r in rows if eligible_fallback_master(r)]
        if not masters:
            self._fail("No VLESS or Trojan inbound on TCP with TLS or REALITY exists. Create one first.")
            return
        self._out(self.style.heading("Master inbounds"))
        for row in masters:
            self._out(f"  [{row.get('id')}] {row.get('remark')}  ({row.get('protocol')}, port {row.get('port')})")
        master_id = self._ask_int("Master inbound id: ")
        if master_id is None or master_id not in [r.get("id") for r in masters]:
            self._fail("Choose one of the listed master inbound ids.")
            return
        try:
            dest = parse_fake_destination(self._input("Fake site address (port, or host:port): "))
        except ValueError as exc:
            self._fail(str(exc))
            return
        self._run_write(
            lambda: self.client.set_fake_site(master_id, dest, dry_run=True),
            lambda: self.client.set_fake_site(master_id, dest, confirmed=True),
            f"set fake site {dest} on master inbound {master_id}",
        )
        self._out(self.style.warn("Xray must restart before the fake site is used."))

    # ---- reports --------------------------------------------------------

    def reports(self) -> None:
        if not self._state_dir:
            self._fail("No state directory set.")
            return
        rows = None
        if self.client is not None:
            try:
                rows = self.client.list_inbounds_slim()
            except PanelError as exc:
                self._fail(f"Panel unavailable, showing local records only: {exc}")
        try:
            local = {t: load_records(self._state_dir, t) for t in RECORD_TYPES}
        except RecordError as exc:
            self._fail(str(exc))
            return
        rep = summarize_report(rows, local)
        self._out(self.style.heading(f"Report ({rep['source']})"))
        self._out(f"  local records: {rep['local_total']}  {rep['local_by_connection']}")
        self._out(f"  transports:    {rep['local_by_transport']}")
        self._out(f"  security:      {rep['local_by_security']}")
        self._out(f"  templates:     {rep['local_templates']}")
        if "panel_total" in rep:
            self._out(f"  panel inbounds: {rep['panel_total']} (enabled {rep['panel_enabled']})")
            self._out(f"  panel protocols: {rep['panel_by_protocol']}")
            self._out(f"  matched: {rep['matched']}   missing on panel: {rep['missing_on_panel']}"
                      f"   not created here: {rep['unmanaged_on_panel']}")
            if rep["port_conflicts"]:
                self._out(self.style.error(f"  ports used more than once: {rep['port_conflicts']}"))
        self._out(self.style.heading("Protocol support (panel source " + PROTOCOL_TAG + ")"))
        for item in load_protocol_catalog():
            line = f"  {item['name']:<10} {item['status']:<10} {item['note']}"
            self._out(self.style.ok(line) if item["status"] == "templates" else self.style.warn(line))

    # ---- export ---------------------------------------------------------

    def export_inventory(self) -> None:
        """Write every inbound on the panel, merged with local records, to JSON and YAML."""
        if not self._need_client():
            return
        if not self._state_dir or not self._root:
            self._fail("No state or project directory set; export is not available.")
            return
        try:
            rows = self.client.list_inbounds_slim()
        except PanelError as exc:
            self._fail(f"Cannot read the panel: {exc}")
            return
        try:
            local = {t: load_records(self._state_dir, t) for t in RECORD_TYPES}
        except RecordError as exc:
            self._fail(str(exc))
            return
        data = build_inventory(rows, local)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        paths = export_inventory(os.path.join(self._root, "exports"), data, stamp)
        self._out(self.style.ok(
            f"Exported {data['count']} panel inbounds ({data['managed_count']} created by this tool)."))
        self._out(f"  JSON: {paths['json']}")
        self._out(f"  YAML: {paths['yaml']}")

    # ---- prerequisites --------------------------------------------------

    def prereq_menu(self) -> None:
        items = check_prerequisites(self._acme_bin)
        for item in items:
            kind = "required" if item.required else "optional"
            line = f"  {item.name:<10} {kind:<9} {item.detail}"
            self._out(self.style.ok(line) if item.ok else self.style.warn(line))
        system = ubuntu_info()
        self._out(self.style.muted(f"  system: {system[1]}"))
        missing = [i for i in items if not i.ok and i.name in ("openssl", "curl")]
        if not missing:
            self._out(self.style.ok("Nothing to install from the apt list."))
            return
        plan = install_plan(missing, apt_available=shutil.which("apt-get") is not None) if system[0] else None
        if plan is None:
            self._out(self.style.warn("Install these packages manually: " + ", ".join(i.name for i in missing)))
            return
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            plan = ["sudo"] + plan
        self._out(self.style.heading("Planned command (no shell):"))
        self._out("  " + " ".join(plan))
        if not self._confirm("About to install packages with apt-get"):
            self._out(self.style.muted("Cancelled. Nothing was installed."))
            return
        rc, _out, _err = self._runner(plan)
        if rc != 0:
            self._fail(f"Install failed (exit {rc}).")
            return
        again = check_prerequisites(self._acme_bin)
        still = [i.name for i in again if not i.ok and i.name in ("openssl", "curl")]
        if still:
            self._fail("Still missing after install: " + ", ".join(still))
        else:
            self._out(self.style.ok("Installed and verified."))

    # ---- backup and restore ---------------------------------------------

    def backup_menu(self) -> None:
        self._submenu("Backup and restore", BACKUP_ITEMS, {
            "1": self.create_backup,
            "2": self.restore_backup,
        })

    def create_backup(self) -> None:
        if not self._root:
            self._fail("No project root set; backup is not available.")
            return
        try:
            path = create_backup(self._root, os.path.join(self._root, "backups"), _APP_VERSION)
        except BackupError as exc:
            self._fail(str(exc))
            return
        self._out(self.style.ok(f"Backup written: {path}"))
        self._out(self.style.warn("The archive contains settings.json with the API token. Keep it private."))

    def restore_backup(self) -> None:
        if not self._root:
            self._fail("No project root set; restore is not available.")
            return
        path = self._input("Path to backup archive: ").strip()
        try:
            manifest = summarize(path)
        except BackupError as exc:
            self._fail(str(exc))
            return
        self._out(f"  created:     {manifest.get('created_at')}")
        self._out(f"  app version: {manifest.get('app_version')}")
        self._out(f"  files:       {len(manifest.get('files', []))}")
        if not self._confirm("About to restore these files. Current files are saved to backups/ first."):
            self._out(self.style.muted("Cancelled. Nothing was restored."))
            return
        try:
            restored = restore_backup(path, self._root, _APP_VERSION)
        except BackupError as exc:
            self._fail(str(exc))
            return
        self._reload_after_restore()
        self._out(self.style.ok(f"Restored {len(restored)} files and reloaded settings and templates."))

    def _reload_after_restore(self) -> None:
        if self.settings_path and os.path.exists(self.settings_path):
            try:
                self.settings = load_settings(self.settings_path)
                self.client = self._client_factory(self.settings) if self.settings.is_configured() else None
                self._last_check = None
            except (SettingsError, PanelError, ValueError) as exc:
                self._fail(f"Restored settings could not be loaded: {exc}")
        if self._library_dir:
            try:
                self._library = load_library(self._library_dir)
            except TemplateError as exc:
                self._fail(f"Restored templates could not be loaded: {exc}")

    # ---- main loop ------------------------------------------------------

    def _not_implemented(self, key: str) -> None:
        self._out(self.style.warn(f"{MAIN_LABELS[key]}: not implemented yet."))

    def repair_addresses(self) -> None:
        """Make existing managed inbounds match their saved address: host entries, and the Host
        header of direct inbounds that use an IP. Shows the plan, then one confirmation."""
        if not self._need_client():
            return
        if not self._state_dir:
            self._fail("No state directory set.")
            return
        try:
            rows = self.client.list_inbounds()
            local = {t: load_records(self._state_dir, t) for t in ("direct", "cdn")}
        except (PanelError, RecordError) as exc:
            self._fail(f"Cannot read the panel or records: {exc}")
            return
        by_id = {r.get("id"): r for r in rows}
        plan = []  # (description, callable)
        for kind, records in local.items():
            for rec in records:
                rid, addr = rec.get("inbound_id"), rec.get("address")
                row = by_id.get(rid)
                if not addr or row is None or row.get("remark") != rec.get("name"):
                    continue
                groups = self.client.list_host_groups(rid)
                if not groups and kind == "direct":
                    host = direct_host_payload(rid, rec["name"], addr, rec["port"], rec.get("security") or "none",
                                               self._network().direct_domain or "")
                    plan.append((f"{rec['name']}: add host entry address {addr}",
                                 lambda h=host: self.client.add_host(h, confirmed=True)))
                want_sni = ""
                if kind == "direct" and rec.get("security") == "reality":
                    want_sni = rec.get("reality_sni") or ""
                elif kind == "direct" and is_ipv4_literal(addr) and rec.get("security") == "tls":
                    want_sni = rec.get("domain") or self._network().direct_domain or ""
                for group in groups:
                    address_ok = any(h == addr or h.startswith(f"{addr}:") for h in (group.get("hosts") or []))
                    sni_ok = not want_sni or group.get("sni") == want_sni
                    if not address_ok or not sni_ok:
                        plan.append((f"{rec['name']}: host address -> {addr}"
                                     + (f", sni -> {want_sni}" if want_sni else ""),
                                     lambda g=group, a=addr, s=want_sni: self.client.update_host_address(
                                         g, a, confirmed=True, sni=(s if s else None))))
                if kind == "direct" and is_ipv4_literal(addr) and addr != "127.0.0.1":
                    inbound = self.client.get_inbound(rid)
                    fixed = copy.deepcopy(inbound)
                    if apply_ip_host(fixed, addr):
                        plan.append((f"{rec['name']}: Host header -> {addr}",
                                     lambda f=fixed: self.client.update_inbound(f["id"], f, confirmed=True)))
        if not plan:
            self._out(self.style.ok("Nothing to repair: every managed inbound matches its saved address."))
            return
        self._out(self.style.heading(f"Planned repairs ({len(plan)})"))
        for description, _apply in plan:
            self._out(f"  - {description}")
        if not self._confirm("Apply these repairs on the panel"):
            self._out(self.style.muted("Cancelled. Nothing was changed."))
            return
        done = 0
        for description, apply in plan:
            try:
                apply()
                done += 1
                self._out(self.style.ok(f"  done: {description}"))
            except PanelError as exc:
                self._fail(f"  failed: {description}: {exc}")
        self._out(self.style.ok(f"Repairs finished: {done} of {len(plan)}."))

    def _session_check(self) -> None:
        """At start-up, when a panel is configured, check the connection once and show the result in the header."""
        if self.client is None:
            return
        try:
            rows = self.client.list_inbounds_slim()
            self._last_check = ("ok", len(rows))
        except PanelError as exc:
            self._last_check = ("fail", str(exc))

    def run(self) -> None:
        if self._auto_check:
            self._session_check()
        handlers: Dict[str, Callable[[], None]] = {
            "1": self.prereq_menu,
            "2": self.connection_menu,
            "3": self.network_menu,
            "4": lambda: self.add_from_template(mode="direct", title="DIRECT inbounds", direct_address=True),
            "5": lambda: self.add_from_template(mode="cdn", title="CDN inbounds", cdn_address=True),
            "6": self.fake_site,
            "7": lambda: self.add_from_template(mode="direct", title="RELAY inbounds", relay=True),
            "8": self.ssl_menu,
            "9": self.panel_menu,
            "10": lambda: self.add_from_template(),
            "11": self.export_inventory,
            "12": self.reports,
            "13": self.backup_menu,
        }
        for key in NOT_IMPLEMENTED:
            handlers[key] = (lambda k: (lambda: self._not_implemented(k)))(key)

        while True:
            self._clear_screen()
            self._render_header()
            self._render_items(MAIN_ITEMS)
            choice = self._input("Select: ").strip()
            if choice == "0":
                self._out(self.style.muted("Bye."))
                return
            handler = handlers.get(choice)
            if handler is None:
                self._out(self.style.error("Unknown option."))
                self._pause()
                continue
            handler()
            self._pause()
