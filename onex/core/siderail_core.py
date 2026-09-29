"""SideRail core for ONEX: local **Xray-core** listeners for the SideRail protocols.

Mirrors the SideRail architecture exactly: the panel owns the public port and
pipes client connections to local Xray inbounds which do the real protocol work.

  * VMess + WebSocket      127.0.0.1:18501  path /siderail/vmess
  * VLESS + XHTTP (auto)   127.0.0.1:18503  path /siderail/xhttp

FIX: the previous version used sing-box here. sing-box has NO "xhttp"
transport (it is Xray-only), so `sing-box check` rejected the whole config as
soon as one XHTTP link existed, and the core never started -> both VMess-WS
and VLESS-XHTTP died together. SideRail itself runs Xray-core, so we do too.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import platform
import shutil
import stat
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

logger = logging.getLogger("ONEX.SideRail")

VMESS_PORT = int(os.environ.get("ONEX_SR_VMESS_PORT", "18501"))
XHTTP_PORT = int(os.environ.get("ONEX_SR_XHTTP_PORT", "18503"))

VMESS_PATH = "/siderail/vmess"
XHTTP_PATH = "/siderail/xhttp"

VMESS_PROTOCOLS = {"vmess-ws"}
XHTTP_PROTOCOLS = {"siderail-vless-xhttp"}

XRAY_VERSION = os.environ.get("ONEX_XRAY_VERSION", os.environ.get("XRAY_VERSION", "v26.9.9")).strip()
if XRAY_VERSION and not XRAY_VERSION.startswith("v"):
    XRAY_VERSION = "v" + XRAY_VERSION


def _asset_name() -> str:
    m = platform.machine().lower()
    if m in {"aarch64", "arm64"}:
        return "Xray-linux-arm64-v8a.zip"
    return "Xray-linux-64.zip"


def _uuids_for(links: dict[str, dict[str, Any]], wanted: set[str]) -> list[str]:
    users: list[str] = []
    seen = set()
    for uid, link in (links or {}).items():
        if not isinstance(link, dict) or not link.get("active", True):
            continue
        proto = str(link.get("protocol") or "")
        bundle = {str(p) for p in (link.get("bundle_protocols") or [])}
        if proto not in wanted and not (bundle & wanted):
            continue
        uid = str(uid)
        if uid and uid not in seen:
            seen.add(uid)
            users.append(uid)
    return users


class SiderailCore:
    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.core_dir = self.data_dir / "siderail-xray"
        self.bin_path = self.core_dir / "xray"
        self.config_path = self.core_dir / "config.json"
        self.previous_path = self.core_dir / "config.previous.json"
        self.proc: asyncio.subprocess.Process | None = None
        self.last_error = ""
        self.ad_blocker: dict[str, Any] = {"enabled": False, "domains": []}
        self.sync_lock = asyncio.Lock()
        self.last_status: dict[str, Any] = {"running": False, "listeners": 0}

    # ---------------- binary ----------------
    def _find_binary(self) -> Path | None:
        configured = os.getenv("ONEX_XRAY_BIN", "").strip()
        if configured and Path(configured).is_file():
            return Path(configured)
        if self.bin_path.is_file():
            return self.bin_path
        found = shutil.which("xray")
        return Path(found) if found else None

    def binary_exists(self) -> bool:
        return self._find_binary() is not None

    async def ensure_binary(self) -> str | None:
        found = self._find_binary()
        if found:
            return str(found)
        self.core_dir.mkdir(parents=True, exist_ok=True)
        asset = _asset_name()
        urls = []
        if XRAY_VERSION:
            urls.append(f"https://github.com/XTLS/Xray-core/releases/download/{XRAY_VERSION}/{asset}")
        urls.append(f"https://github.com/XTLS/Xray-core/releases/latest/download/{asset}")
        errors = []
        for url in urls:
            archive = self.core_dir / "xray.zip"
            try:
                await asyncio.to_thread(self._download, url, archive)
                await asyncio.to_thread(self._extract, archive)
                if self.bin_path.is_file():
                    self.bin_path.chmod(self.bin_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                    logger.info("SideRail core: Xray installed from %s", url)
                    return str(self.bin_path)
            except Exception as exc:
                errors.append(f"{url}: {exc}")
        self.last_error = "Xray download/install failed: " + " | ".join(errors)
        return None

    @staticmethod
    def _download(url: str, dst: Path) -> None:
        req = urllib.request.Request(url, headers={"User-Agent": "ONEX/1.1"})
        with urllib.request.urlopen(req, timeout=60) as src, open(dst, "wb") as out:
            shutil.copyfileobj(src, out)

    def _extract(self, archive: Path) -> None:
        with zipfile.ZipFile(archive) as zf:
            for name in zf.namelist():
                base = name.rsplit("/", 1)[-1]
                if base in {"xray", "geoip.dat", "geosite.dat"}:
                    with zf.open(name) as src, open(self.core_dir / base, "wb") as out:
                        shutil.copyfileobj(src, out)
        archive.unlink(missing_ok=True)
        if not self.bin_path.is_file():
            raise RuntimeError("xray binary not found in release archive")

    # ---------------- config ----------------
    def build_config(self, links: dict[str, dict[str, Any]]) -> dict[str, Any]:
        vmess_users = _uuids_for(links, VMESS_PROTOCOLS)
        xhttp_users = _uuids_for(links, XHTTP_PROTOCOLS)
        inbounds: list[dict[str, Any]] = []
        if vmess_users:
            inbounds.append({
                "tag": "siderail-vmess-ws",
                "listen": "127.0.0.1",
                "port": VMESS_PORT,
                "protocol": "vmess",
                "settings": {"clients": [{"id": u, "email": u} for u in vmess_users]},
                "streamSettings": {"network": "ws", "wsSettings": {"path": VMESS_PATH}},
                "sniffing": {"enabled": False},
            })
        if xhttp_users:
            inbounds.append({
                "tag": "siderail-vless-xhttp",
                "listen": "127.0.0.1",
                "port": XHTTP_PORT,
                "protocol": "vless",
                "settings": {
                    "clients": [{"id": u, "email": u, "flow": ""} for u in xhttp_users],
                    "decryption": "none",
                },
                "streamSettings": {"network": "xhttp", "xhttpSettings": {"path": XHTTP_PATH, "mode": "auto"}},
                "sniffing": {"enabled": False},
            })
        outbounds: list[dict[str, Any]] = [
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "blocked", "protocol": "blackhole", "settings": {}},
        ]
        rules: list[dict[str, Any]] = []
        blocker = self.ad_blocker or {}
        domains = [str(x).strip().lower() for x in (blocker.get("domains") or []) if str(x).strip()]
        if blocker.get("enabled") and domains and inbounds:
            rules.append({
                "type": "field",
                "inboundTag": [i["tag"] for i in inbounds],
                "domain": [f"domain:{d}" for d in domains],
                "outboundTag": "blocked",
            })
        return {
            "log": {"loglevel": os.environ.get("ONEX_XRAY_LOG_LEVEL", "warning")},
            "inbounds": inbounds,
            "outbounds": outbounds,
            "routing": {"domainStrategy": "AsIs", "rules": rules},
        }

    # ---------------- lifecycle ----------------
    def is_running(self) -> bool:
        return bool(self.proc and self.proc.returncode is None)

    def status(self) -> dict[str, Any]:
        return {
            "engine": "xray",
            "installed": self.binary_exists(),
            "running": self.is_running(),
            "error": self.last_error,
            **self.last_status,
            "ports": {"vmess_ws": VMESS_PORT, "vless_xhttp": XHTTP_PORT},
            "paths": {"vmess_ws": VMESS_PATH, "vless_xhttp": XHTTP_PATH},
        }

    async def stop(self) -> None:
        if self.proc and self.proc.returncode is None:
            self.proc.terminate()
            try:
                await asyncio.wait_for(self.proc.wait(), timeout=3)
            except asyncio.TimeoutError:
                self.proc.kill()
                await self.proc.wait()
        self.proc = None

    async def _start(self, binary: str) -> None:
        self.proc = await asyncio.create_subprocess_exec(
            binary, "run", "-c", str(self.config_path),
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE,
            env={"XRAY_LOCATION_ASSET": str(self.core_dir), **os.environ},
        )

    async def sync(self, links: dict[str, dict[str, Any]]) -> bool:
        async with self.sync_lock:
            return await self._sync_impl(links)

    async def _sync_impl(self, links) -> bool:
        config = self.build_config(links)
        if not config["inbounds"]:
            await self.stop()
            self.last_status = {"running": False, "listeners": 0}
            return True
        binary = await self.ensure_binary()
        if not binary:
            self.last_status = {"running": False, "listeners": 0, "error": self.last_error}
            logger.warning("SideRail core: xray binary unavailable: %s", self.last_error)
            return False
        try:
            self.core_dir.mkdir(parents=True, exist_ok=True)
            staged = self.core_dir / "config.staged.json"
            staged.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")
            check = await asyncio.create_subprocess_exec(
                binary, "run", "-test", "-c", str(staged),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                env={"XRAY_LOCATION_ASSET": str(self.core_dir), **os.environ},
            )
            out, err = await check.communicate()
            if check.returncode != 0:
                raise RuntimeError((err or out).decode(errors="ignore").strip() or "xray config test failed")
            if self.config_path.is_file():
                shutil.copy2(self.config_path, self.previous_path)
            await self.stop()
            os.replace(staged, self.config_path)
            await self._start(binary)
            await asyncio.sleep(0.5)
            if self.proc.returncode is not None:
                err_out = await self.proc.stderr.read()
                raise RuntimeError(err_out.decode(errors="ignore").strip() or "xray exited")
            self.last_error = ""
            self.last_status = {"running": True, "listeners": len(config["inbounds"])}
            logger.info("SideRail core (xray) running: %d listener(s)", len(config["inbounds"]))
            return True
        except Exception as exc:
            self.last_error = str(exc)
            if self.previous_path.is_file():
                try:
                    await self.stop()
                    shutil.copy2(self.previous_path, self.config_path)
                    await self._start(binary)
                    await asyncio.sleep(0.25)
                except Exception as rb_exc:
                    self.last_error = f"{self.last_error}; rollback failed: {rb_exc}"
            self.last_status = {"running": self.is_running(), "listeners": 0, "error": self.last_error}
            logger.warning("SideRail core sync failed: %s", self.last_error)
            return False
