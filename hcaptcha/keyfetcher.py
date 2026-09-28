"""
hCaptcha AES master-key acquisition.

Uses CircuitSavage's local extractor (hcaptcha-hsj-hsw-reversed) which
runs a Node subprocess to AST-patch hsj.js and WASM-patch hsw.js.

The GitHub Action snapshot only refreshes every 12h and uses a different
version identifier than the live build hash, so we always run the
extractor locally for the live build instead of trying to match snapshots.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from loguru import logger

from config import KEY_CACHE_FILE, EXTRACTOR_DIR
from hcaptcha.errors import KeyFetchError


class KeyFetcher:
    """Extracts and caches hCaptcha AES keys by running the local extractor."""

    def __init__(self, timeout: int = 180):
        self.timeout = timeout
        self.extractor_dir = Path(EXTRACTOR_DIR)
        self._cache: Dict[str, Any] = self._load_cache()

    # ── public ────────────────────────────────────────────────
    def fetch(self, build_hash: Optional[str] = None) -> Dict[str, Any]:
        if build_hash is None:
            build_hash = self.live_build_hash()

        build_hash = build_hash.strip().lstrip("/").replace("c/", "")

        # cache hit
        if build_hash in self._cache:
            entry = self._cache[build_hash]
            if self._is_fresh(entry):
                logger.debug(f"key cache hit: {build_hash[:16]}…")
                return entry

        # run the extractor
        try:
            bundle = self._run_extractor()
            bundle["build"] = build_hash
            bundle["fetched_at"] = int(time.time())
            self._store(build_hash, bundle)
            logger.info(f"keys extracted for build {build_hash[:16]}…")
            return bundle
        except Exception as exc:
            raise KeyFetchError(f"extractor failed: {exc}") from exc

    def live_build_hash(self) -> str:
        """Scrape the current build hash from hCaptcha's asset URL."""
        for url in (
            "https://js.hcaptcha.com/1/api.js",
            "https://hcaptcha.com/1/api.js",
        ):
            try:
                r = requests.get(url, timeout=15)
                if r.status_code != 200:
                    continue
                m = re.search(
                    r"newassets\.hcaptcha\.com/captcha/v1/([a-f0-9]{6,64})/",
                    r.text,
                )
                if m:
                    logger.info(f"build hash discovered via {url}")
                    return m.group(1)
            except Exception as exc:
                logger.debug(f"probe {url} failed: {exc}")

        # fallback: JWT `l` field
        try:
            import base64
            url = "https://api.hcaptcha.com/checksiteconfig"
            params = {
                "v": "1", "host": "discord.com",
                "sitekey": "a9b5fb07-92ff-493f-86fe-352a2803b3df",
                "sc": "1", "swa": "1", "spst": "1",
            }
            r = requests.post(url, params=params, json={}, timeout=15)
            r.raise_for_status()
            req_jwt = r.json()["c"]["req"]
            parts = req_jwt.split(".")
            pad = "=" * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + pad))
            m = re.search(r"/c/([a-f0-9]{6,64})", payload.get("l", ""))
            if m:
                logger.info("build hash discovered via checksiteconfig JWT")
                return m.group(1)
        except Exception as exc:
            logger.debug(f"jwt probe failed: {exc}")

        raise KeyFetchError("could not discover build hash")

    # ── extractor invocation ──────────────────────────────────
    def _run_extractor(self) -> Dict[str, Any]:
        if not self.extractor_dir.exists():
            raise KeyFetchError(f"extractor not found at {self.extractor_dir}")

        # find Python 3.11/3.12 (jsbeautifier formatting differs on 3.14)
        candidates = [
            self.extractor_dir.parent / "venv-extractor" / "Scripts" / "python.exe",
            self.extractor_dir.parent / "venv-extractor" / "bin" / "python",
        ]
        python = None
        for c in candidates:
            if c.exists():
                python = str(c)
                break

        env = os.environ.copy()
        env["PYTHONPATH"] = str(self.extractor_dir / "src")

        if python:
            cmd = [python, "-m", "hcaptcha", "--json"]
        else:
            # fall back to `py -3.11`
            cmd = ["py", "-3.11", "-m", "hcaptcha", "--json"]

        try:
            out = subprocess.run(
                cmd,
                cwd=str(self.extractor_dir),
                env=env,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise KeyFetchError(f"extractor timed out after {self.timeout}s") from exc
        except FileNotFoundError as exc:
            raise KeyFetchError(f"python not found: {exc}") from exc

        if out.returncode != 0:
            raise KeyFetchError(
                f"extractor exit {out.returncode}\n"
                f"stdout: {out.stdout[-800:]}\n"
                f"stderr: {out.stderr[-800:]}"
            )

        text = out.stdout.strip()
        start = text.find("{")
        end = text.rfind("}")
        if start < 0 or end <= start:
            raise KeyFetchError(f"no JSON in extractor output:\n{text[-500:]}")

        return self._normalise(json.loads(text[start:end + 1]))

    def _normalise(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        hsj = raw.get("hsj", {})
        hsw = raw.get("hsw", {})
        return {
            "build": raw.get("version", raw.get("build", "")),
            "hsj": {
                "n_key":                hsj.get("n_key"),
                "response_decrypt_key": hsj.get("response_decrypt_key"),
                "payload_encrypt_key":  hsj.get("payload_encrypt_key"),
            },
            "hsw": {
                "encrypt_key":          hsw.get("encrypt_key"),
                "decrypt_key":          hsw.get("decrypt_key"),
                "n_key":                hsw.get("n_key"),
                "fingerprint_blob_key": hsw.get("fingerprint_blob_key"),
            },
            "cipher": raw.get("cipher", "AES-256-GCM"),
            "wire_format": raw.get("wire_format", {
                "hsj": "ct(N) || tag(16) || iv(12) || 0x00",
                "hsw": "iv(12) || ct(N) || tag(16)",
            }),
            "pow": raw.get("pow", {
                "algorithm": "Hashcash v1 + SHA-1",
                "date_format": "YYYYMMDD (UTC)",
            }),
            "verified": raw.get("verified", {}),
        }

    # ── cache ─────────────────────────────────────────────────
    def _load_cache(self) -> Dict[str, Any]:
        if KEY_CACHE_FILE.exists():
            try:
                return json.loads(KEY_CACHE_FILE.read_text())
            except Exception:
                return {}
        return {}

    def _store(self, build_hash: str, bundle: Dict[str, Any]) -> None:
        self._cache[build_hash] = bundle
        if len(self._cache) > 20:
            for k in sorted(
                self._cache, key=lambda x: self._cache[x].get("fetched_at", 0)
            )[:-20]:
                del self._cache[k]
        KEY_CACHE_FILE.write_text(json.dumps(self._cache, indent=2))

    @staticmethod
    def _is_fresh(entry: Dict[str, Any], max_age_s: int = 6 * 3600) -> bool:
        return (time.time() - entry.get("fetched_at", 0)) < max_age_s