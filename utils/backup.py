"""Backup and restore of inbound templates, settings and local inbound records.

Archive contents (tar.gz, mode 0600 because settings.json holds the API token):
  manifest.json                 version, time, and SHA-256 of every file
  inbounds/*.json               inbound templates
  config/settings.json          settings (includes the API token)
  config/cloudflare_ports.json  Cloudflare port list
  state/local_inbounds/*.json   records of inbounds created by this tool

Restore checks every member name and every hash before anything is written. Current
files are saved to a safety backup first, and rolled back if writing fails.
"""

import hashlib
import io
import json
import os
import shutil
import tarfile
import tempfile
import time
from typing import Dict, List, Optional, Tuple

from config.settings import SettingsError, load_settings
from state.records import RecordError, load_records
from templates.loader import TemplateError, load_library

BACKUP_VERSION = 1
MANIFEST = "manifest.json"
ALLOWED_PREFIXES = ("inbounds/", "config/", "state/local_inbounds/")
FIXED_FILES = ("config/settings.json", "config/cloudflare_ports.json")


class BackupError(RuntimeError):
    """A backup cannot be created, or an archive is not valid."""


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_files(root: str) -> List[str]:
    rels = list(FIXED_FILES)
    for folder, prefix in (("inbounds", "inbounds/"), (os.path.join("state", "local_inbounds"), "state/local_inbounds/")):
        full = os.path.join(root, folder)
        if os.path.isdir(full):
            rels.extend(prefix + name for name in sorted(os.listdir(full)) if name.endswith(".json"))
    return [r for r in rels if os.path.isfile(os.path.join(root, r))]


def create_backup(root: str, dest_dir: str, app_version: str, now: Optional[float] = None) -> str:
    rels = collect_files(root)
    if not rels:
        raise BackupError("Nothing to back up: no templates, settings or records were found")
    manifest = {
        "backup_version": BACKUP_VERSION,
        "app_version": app_version,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(now)),
        "files": [{"path": r, "sha256": _sha256(os.path.join(root, r)),
                   "size": os.path.getsize(os.path.join(root, r))} for r in rels],
    }
    os.makedirs(dest_dir, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(now))
    path = os.path.join(dest_dir, f"3xui-backup-{stamp}.tar.gz")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as raw, tarfile.open(fileobj=raw, mode="w:gz") as tar:
        data = json.dumps(manifest, indent=2).encode("utf-8")
        info = tarfile.TarInfo(MANIFEST)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
        for rel in rels:
            tar.add(os.path.join(root, rel), arcname=rel, recursive=False)
    return path


def _safe_member(name: str) -> bool:
    if name == MANIFEST:
        return True
    if name.startswith("/") or ".." in name.split("/") or "\\" in name:
        return False
    return name.startswith(ALLOWED_PREFIXES) and name.endswith(".json")


def read_archive(archive: str, staging: str) -> Dict:
    """Extract members into staging after checking names. Returns the manifest."""
    if not os.path.isfile(archive):
        raise BackupError(f"Backup file not found: {archive}")
    try:
        tar = tarfile.open(archive, mode="r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise BackupError("Not a valid backup archive") from exc
    with tar:
        members = tar.getmembers()
        for member in members:
            if not member.isfile() or not _safe_member(member.name):
                raise BackupError(f"Archive contains an unexpected entry: {member.name!r}")
        names = [m.name for m in members]
        if MANIFEST not in names:
            raise BackupError("Archive has no manifest.json")
        for member in members:
            data = tar.extractfile(member).read()
            target = os.path.join(staging, member.name)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as fh:
                fh.write(data)
    try:
        with open(os.path.join(staging, MANIFEST), encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise BackupError("manifest.json is not valid") from exc
    if manifest.get("backup_version") != BACKUP_VERSION:
        raise BackupError(f"Unsupported backup_version: {manifest.get('backup_version')}")
    listed = {entry["path"]: entry for entry in manifest.get("files", [])}
    extracted = {n for n in names if n != MANIFEST}
    if set(listed) != extracted:
        raise BackupError("Archive files do not match the manifest")
    for path, entry in listed.items():
        if _sha256(os.path.join(staging, path)) != entry["sha256"]:
            raise BackupError(f"Hash mismatch for {path}; the backup is damaged")
    return manifest


def validate_staged(staging: str) -> None:
    """Make sure the restored content would load before anything is written."""
    if os.path.isdir(os.path.join(staging, "inbounds")):
        try:
            load_library(os.path.join(staging, "inbounds"))
        except TemplateError as exc:
            raise BackupError(f"Templates in backup are invalid: {exc}") from exc
    settings_path = os.path.join(staging, "config", "settings.json")
    if os.path.exists(settings_path):
        try:
            load_settings(settings_path)
        except SettingsError as exc:
            raise BackupError(f"Settings in backup are invalid: {exc}") from exc
    records_dir = os.path.join(staging, "state", "local_inbounds")
    if os.path.isdir(records_dir):
        for name in ("direct", "cdn"):
            path = os.path.join(records_dir, f"{name}.json")
            if os.path.exists(path):
                with open(path, encoding="utf-8") as fh:
                    if not isinstance(json.load(fh), list):
                        raise BackupError(f"{name}.json must contain a list")


def restore_backup(archive: str, root: str, app_version: str) -> List[str]:
    staging = tempfile.mkdtemp(prefix="3xui-restore-")
    try:
        read_archive(archive, staging)
        validate_staged(staging)
        if collect_files(root):
            create_backup(root, os.path.join(root, "backups"), app_version)  # safety copy first
        rels = []
        for top in ("inbounds", "config", "state"):
            base = os.path.join(staging, top)
            if os.path.isdir(base):
                for dirpath, _dirs, names in os.walk(base):
                    for name in names:
                        rels.append(os.path.relpath(os.path.join(dirpath, name), staging))
        previous: Dict[str, Optional[bytes]] = {}
        try:
            for rel in sorted(rels):
                target = os.path.join(root, rel)
                if os.path.isfile(target):
                    with open(target, "rb") as fh:
                        previous[rel] = fh.read()
                else:
                    previous[rel] = None
                os.makedirs(os.path.dirname(target), exist_ok=True)
                tmp = target + ".restore-tmp"
                shutil.copyfile(os.path.join(staging, rel), tmp)
                if rel.startswith("config/"):
                    os.chmod(tmp, 0o600)
                os.replace(tmp, target)
        except OSError as exc:
            for rel, data in previous.items():
                target = os.path.join(root, rel)
                if data is None:
                    if os.path.exists(target):
                        os.remove(target)
                else:
                    with open(target, "wb") as fh:
                        fh.write(data)
            raise BackupError(f"Restore failed and was rolled back: {exc.__class__.__name__}") from exc
        return sorted(rels)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def summarize(archive: str) -> Dict:
    staging = tempfile.mkdtemp(prefix="3xui-inspect-")
    try:
        manifest = read_archive(archive, staging)
        validate_staged(staging)
        return manifest
    finally:
        shutil.rmtree(staging, ignore_errors=True)
