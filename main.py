"""Entry point. Settings come from config/settings.json and are edited in menu 2."""

import getpass
import os
import sys

from config.settings import SettingsError, load_settings
from core.menu import Menu
from network.cloudflare import CloudflareDataError, load_cloudflare_ports
from panel.client import PanelClient
from panel.errors import PanelError
from templates.loader import TemplateError, load_library
from ui.io import safe_input
from ui.style import CLEAR_SCREEN, style_for

ROOT = os.path.dirname(os.path.abspath(__file__))
SETTINGS_PATH = os.path.join(ROOT, "config", "settings.json")
INBOUNDS_DIR = os.path.join(ROOT, "inbounds")
STATE_DIR = os.path.join(ROOT, "state", "local_inbounds")
CLOUDFLARE_PORTS_PATH = os.path.join(ROOT, "config", "cloudflare_ports.json")


def build_client(settings):
    if not settings.is_configured():
        return None
    return PanelClient(settings.panel_address, token=settings.api_token, verify_tls=settings.verify_tls)


def clear_screen() -> None:
    sys.stdout.write(CLEAR_SCREEN)
    sys.stdout.flush()


def main() -> int:
    style = style_for(sys.stdout)
    try:
        settings = load_settings(SETTINGS_PATH)
    except SettingsError as exc:
        print(style.error(f"Settings error: {exc}"))
        return 1
    try:
        client = build_client(settings)
    except (PanelError, ValueError) as exc:
        print(style.warn(f"Panel settings are invalid: {exc}. Fix them in menu 2."))
        client = None
    try:
        library = load_library(INBOUNDS_DIR)
    except TemplateError as exc:
        print(style.error(f"Template library error: {exc}"))
        return 1
    try:
        cloudflare = load_cloudflare_ports(CLOUDFLARE_PORTS_PATH)
    except CloudflareDataError as exc:
        print(style.warn(f"Cloudflare port list unavailable: {exc}. Local ports will be refused."))
        cloudflare = None
    Menu(
        cloudflare=cloudflare,
        client=client,
        settings=settings,
        settings_path=SETTINGS_PATH,
        library=library,
        client_factory=build_client,
        secret_fn=getpass.getpass,
        clear_fn=clear_screen,
        style=style,
        pause=True,
        input_fn=safe_input,
        auto_check=True,
        state_dir=STATE_DIR,
        root=ROOT,
        library_dir=INBOUNDS_DIR,
        settings_path_for_reload=SETTINGS_PATH,
    ).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
