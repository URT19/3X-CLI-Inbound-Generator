"""Persistent settings stored as JSON in config/settings.json.

The API token is stored in plain text, so the file is written with mode 0600
and the token is only ever shown masked.
"""

import json
import os
import tempfile
from dataclasses import asdict, dataclass, field, fields
from typing import List, Optional

SETTINGS_VERSION = 1
DEFAULT_CERT_ROOT = "/cert_folder/cert"


class SettingsError(Exception):
    """The settings file is unreadable or has invalid content."""


@dataclass
class NetworkSettings:
    cloudflare_ips: List[str] = field(default_factory=list)
    direct_ip: str = ""
    direct_domain: str = ""
    cdn_domain: str = ""
    port_mode: str = "random"          # "random" or "fixed"
    fixed_port: Optional[int] = None
    random_port_low: int = 20000
    random_port_high: int = 29999
    local_ip: str = "127.0.0.1"
    local_port: Optional[int] = None
    relay_address: str = ""             # Iran server domain or IP used by relay inbounds
    use_ip_addresses: bool = False      # on: connection addresses use the IP behind the domain
    public_port: Optional[int] = None   # port written in host entries (for example 443 behind HAProxy)
    direct_domain2: str = ""            # second direct domain: used by VLESS TCP TLS Vision
    proxy_protocol: bool = False        # PROXY protocol between HAProxy, Nginx and the inbounds


@dataclass
class Settings:
    panel_address: str = ""
    api_token: str = ""
    verify_tls: bool = True
    cert_root: str = DEFAULT_CERT_ROOT
    network: NetworkSettings = field(default_factory=NetworkSettings)
    ssl_domains: dict = field(default_factory=dict)
    paths: dict = field(default_factory=dict)
    fingerprint: str = "chrome"
    amnezia: dict = field(default_factory=dict)
    hysteria_passwords: dict = field(default_factory=dict)
    reality_keys: dict = field(default_factory=dict)
    client_credentials: dict = field(default_factory=dict)
    services: dict = field(default_factory=dict)
    settings_version: int = SETTINGS_VERSION

    def is_configured(self) -> bool:
        return bool(self.panel_address and self.api_token)


NETWORK_MODES = ("random", "fixed")


def _check_network(net: NetworkSettings) -> None:
    if not isinstance(net.cloudflare_ips, list) or not all(isinstance(x, str) for x in net.cloudflare_ips):
        raise SettingsError("network.cloudflare_ips must be a list of strings")
    for name in ("direct_ip", "direct_domain", "direct_domain2", "cdn_domain", "local_ip", "relay_address"):
        if not isinstance(getattr(net, name), str):
            raise SettingsError(f"network.{name} must be a string")
    if not isinstance(net.proxy_protocol, bool):
        raise SettingsError("network.proxy_protocol must be true or false")
    if not isinstance(net.use_ip_addresses, bool):
        raise SettingsError("network.use_ip_addresses must be true or false")
    if net.port_mode not in NETWORK_MODES:
        raise SettingsError("network.port_mode must be random or fixed")
    for name in ("fixed_port", "local_port", "public_port"):
        value = getattr(net, name)
        if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
            raise SettingsError(f"network.{name} must be an integer or null")
    for name in ("random_port_low", "random_port_high"):
        if not isinstance(getattr(net, name), int) or isinstance(getattr(net, name), bool):
            raise SettingsError(f"network.{name} must be an integer")


def _check_types(settings: Settings) -> None:
    if not isinstance(settings.panel_address, str):
        raise SettingsError("panel_address must be a string")
    if not isinstance(settings.api_token, str):
        raise SettingsError("api_token must be a string")
    if not isinstance(settings.verify_tls, bool):
        raise SettingsError("verify_tls must be true or false")
    if not isinstance(settings.cert_root, str) or not settings.cert_root.startswith("/"):
        raise SettingsError("cert_root must be an absolute path")
    _check_network(settings.network)
    if not isinstance(settings.amnezia, dict):
        raise SettingsError("amnezia must be an object")
    if not isinstance(settings.services, dict) or not all(
        isinstance(k, str) and isinstance(v, dict) for k, v in settings.services.items()
    ):
        raise SettingsError("services must map template ids to objects")
    if not isinstance(settings.client_credentials, dict) or not all(
        isinstance(k, str) and isinstance(v, dict) for k, v in settings.client_credentials.items()
    ):
        raise SettingsError("client_credentials must map inbound names to objects")
    if not isinstance(settings.reality_keys, dict) or not all(
        isinstance(k, str) and isinstance(v, dict) for k, v in settings.reality_keys.items()
    ):
        raise SettingsError("reality_keys must map inbound names to objects")
    if not isinstance(settings.hysteria_passwords, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in settings.hysteria_passwords.items()
    ):
        raise SettingsError("hysteria_passwords must map inbound names to strings")
    if not isinstance(settings.paths, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in settings.paths.items()
    ):
        raise SettingsError("paths must map names to strings")
    if not isinstance(settings.fingerprint, str) or not settings.fingerprint:
        raise SettingsError("fingerprint must be a non-empty string")
    if not isinstance(settings.ssl_domains, dict) or not all(
        isinstance(k, str) and isinstance(v, dict) for k, v in settings.ssl_domains.items()
    ):
        raise SettingsError("ssl_domains must map domain names to objects")


def load_settings(path: str) -> Settings:
    if not os.path.exists(path):
        return Settings()
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise SettingsError(f"Cannot read settings file: {exc.__class__.__name__}") from exc
    if not isinstance(data, dict):
        raise SettingsError("Settings file must contain a JSON object")
    version = data.get("settings_version", SETTINGS_VERSION)
    if version != SETTINGS_VERSION:
        raise SettingsError(f"Unsupported settings_version: {version}")
    known = {f.name for f in fields(Settings)}
    net_known = {f.name for f in fields(NetworkSettings)}
    values = {k: v for k, v in data.items() if k in known and k != "network"}
    net_data = data.get("network", {})
    if not isinstance(net_data, dict):
        raise SettingsError("network must be a JSON object")
    values["network"] = NetworkSettings(**{k: v for k, v in net_data.items() if k in net_known})
    settings = Settings(**values)
    _check_types(settings)
    return settings


def save_settings(path: str, settings: Settings) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".settings-", suffix=".tmp")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(asdict(settings), fh, indent=2)
            fh.write("\n")
        os.replace(tmp_path, path)
    except OSError:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def mask_token(token: str) -> str:
    if not token:
        return "not set"
    if len(token) <= 4:
        return "****"
    return "*" * 8 + token[-4:]
