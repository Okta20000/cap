"""
End-to-end request-based hCaptcha solver.

Flow:
  1. checksiteconfig  → c.req JWT + build hash
  2. KeyFetcher       → AES keys for that build
  3. Solve PoW        → Hashcash SHA-1 stamp
  4. Build n-token    → fingerprint + CRC-32 + HSJ AES-GCM
  5. getcaptcha       → send encrypted request + motionData
  6. Decrypt response → HSW decrypt key
  7. Solve challenge  → ONNX / CoT
  8. checkcaptcha     → send encrypted answers
  9. Return P1_ token
"""
from __future__ import annotations

import json
import random
import string
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from loguru import logger

from config import (
    HCAPTCHA_API, DISCORD_HCAPTCHA_SITEKEY,
    HCAPTCHA_POW_DIFFICULTY,
)
from hcaptcha.crypto import (
    hsj_encrypt, hsw_encrypt, hsw_decrypt,
    ntoken_encrypt, compute_rand,
)
from hcaptcha.errors import (
    BuildRotatedError, KeyFetchError, PowError,
    ChallengeSolveError, TokenExtractionError,
)
from hcaptcha.fingerprint import build_events
from hcaptcha.keyfetcher import KeyFetcher
from hcaptcha.motion import generate as gen_motion, motion_data
from hcaptcha.pow import solve as solve_pow
from hcaptcha.challenge import ChallengeSolver


class HCaptchaSolver:
    def __init__(
        self,
        sitekey: str = DISCORD_HCAPTCHA_SITEKEY,
        host: str = "discord.com",
        proxy: Optional[str] = None,
    ):
        self.sitekey = sitekey
        self.host = host
        self.session = requests.Session()
        if proxy:
            self.session.proxies.update({"http": proxy, "https": proxy})
        self.session.headers.update({
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/120.0.0.0 Safari/537.36"),
            "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
            "Origin": "https://newassets.hcaptcha.com",
            "Referer": "https://newassets.hcaptcha.com/",
        })
        self.keys = KeyFetcher()
        self.challenges = ChallengeSolver()
        self.c_req: Optional[str] = None
        self.build: Optional[str] = None
        self.key_bundle: Optional[Dict[str, Any]] = None

    # ── public ────────────────────────────────────────────────
    def solve(self) -> str:
        """
        Run the full flow once. Returns the P1_ token.
        Raises on any stage failure.
        """
        self._checksiteconfig()
        self._load_keys()
        token = self._run_round()
        return token

    # ── stages ────────────────────────────────────────────────
    def _checksiteconfig(self) -> None:
        url = f"{HCAPTCHA_API}/checksiteconfig"
        params = {
            "v": "5ea3feff9cf1292d7051510930d98c4719f64575",
            "host": self.host,
            "sitekey": self.sitekey,
            "sc": "1", "swa": "1", "spst": "1",
        }
        r = self.session.post(url, params=params, json={}, timeout=20)
        r.raise_for_status()
        data = r.json()
        self.c_req = data["c"]["req"]
        self.build = data["c"].get("v") or data.get("build")
        logger.info(f"checksiteconfig ok · build={self.build}")

    def _load_keys(self) -> None:
        self.key_bundle = self.keys.fetch(self.build)
        logger.info("AES keys loaded")

    def _run_round(self) -> str:
        for attempt in range(1, 9):
            logger.info(f"round {attempt}")

            # 3. PoW
            stamp = solve_pow(self.c_req, HCAPTCHA_POW_DIFFICULTY, self.sitekey)
            if not stamp:
                raise PowError("empty stamp")

            # 4. n-token
            n_token = self._build_ntoken()

            # 5. getcaptcha
            challenge = self._post_getcaptcha(stamp, n_token)

            # 6. decrypt
            try:
                payload = self._decrypt_response(challenge)
            except Exception as exc:
                raise BuildRotatedError(
                    f"response decrypt failed (build rotated?): {exc}"
                ) from exc

            # 7. solve
            answers = self._solve_visual(payload)

            # 8. checkcaptcha
            token = self._post_checkcaptcha(answers, n_token)
            if token:
                logger.success(f"token acquired: {token[:30]}…")
                return token

        raise TokenExtractionError("no token after 8 rounds")

    # ── n-token ───────────────────────────────────────────────
    def _build_ntoken(self) -> str:
        events = build_events()
        payload = {
            "v": 1,
            "sitekey": self.sitekey,
            "host": self.host,
            "fingerprint_events": events,
            "ts": int(time.time() * 1000),
        }
        raw = json.dumps(payload, separators=(",", ":")).encode()
        payload["rand"] = compute_rand(raw)          # integrity
        raw = json.dumps(payload, separators=(",", ":")).encode()

        hsj_key = self.key_bundle["hsj"]["payload_encrypt_key"]
        blob = hsj_encrypt(raw, hsj_key)
        import base64
        return base64.b64encode(blob).decode()

    # ── HTTP stages ───────────────────────────────────────────
    def _post_getcaptcha(self, stamp: str, n_token: str) -> Dict[str, Any]:
        url = f"{HCAPTCHA_API}/getcaptcha/{self.sitekey}"
        movements = gen_motion(
            start=(random.randint(200, 400), random.randint(200, 400)),
            end=(random.randint(700, 1000), random.randint(400, 700)),
        )
        body = {
            "v": "5ea3feff9cf1292d7051510930d98c4719f64575",
            "sitekey": self.sitekey,
            "host": self.host,
            "hl": "en",
            "motionData": motion_data(movements),
            "c": {"req": self.c_req},
            "n": n_token,
            "pow": stamp,
            "sw": "1920",
            "sh": "1080",
        }
        r = self.session.post(url, json=body, timeout=25)
        r.raise_for_status()
        return r.json()

    def _decrypt_response(self, resp: Dict[str, Any]) -> Dict[str, Any]:
        # The server may return the challenge encrypted under the HSW key.
        blob_b64 = resp.get("challenge") or resp.get("payload")
        if not blob_b64:
            # unencrypted fallback (older builds)
            return resp

        import base64
        blob = base64.b64decode(blob_b64)
        key = self.key_bundle["hsw"]["decrypt_key"]
        plain = hsw_decrypt(blob, key)
        return json.loads(plain)

    def _solve_visual(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        kind = payload.get("type") or payload.get("request_type")
        prompt = payload.get("requester_question", "")

        if kind == "image_label_binary":
            paths = self._download_all(payload.get("tasklist", []))
            selected = self.challenges.solve_image_binary(paths, prompt)
            return {
                "answers": [
                    {"task_key": t["task_key"], "answer": "true"}
                    for i, t in enumerate(payload["tasklist"]) if i in selected
                ]
            }

        if kind == "image_label_area_select":
            path = self._download_one(payload["tasklist"][0])
            coords = self.challenges.solve_area_select(path, prompt)
            return {"answers": coords}

        if kind == "image_drag_drop":
            path = self._download_one(payload["tasklist"][0])
            coords = self.challenges.solve_drag_drop(path, prompt)
            return {"answers": coords}

        raise ChallengeSolveError(f"unknown challenge type: {kind}")

    def _post_checkcaptcha(self, answers: Dict[str, Any], n_token: str) -> Optional[str]:
        url = f"{HCAPTCHA_API}/checkcaptcha/{self.sitekey}"
        body = {
            "v": "5ea3feff9cf1292d7051510930d98c4719f64575",
            "sitekey": self.sitekey,
            "host": self.host,
            "hl": "en",
            "c": {"req": self.c_req},
            "n": n_token,
            "answers": answers,
        }
        r = self.session.post(url, json=body, timeout=25)
        r.raise_for_status()
        data = r.json()
        return data.get("generated_pass_UUID") or data.get("key")

    # ── asset helpers ─────────────────────────────────────────
    def _download_one(self, task: Dict[str, Any]) -> Path:
        url = task.get("datapoint_uri") or task.get("datapoint")
        return self._download(url)

    def _download_all(self, tasks: List[Dict[str, Any]]) -> List[Path]:
        return [self._download_one(t) for t in tasks]

    def _download(self, url: str) -> Path:
        r = self.session.get(url, timeout=20)
        r.raise_for_status()
        out = Path("./tmp_challenges") / (
            "".join(random.choices(string.ascii_lowercase, k=12)) + ".png"
        )
        out.parent.mkdir(exist_ok=True)
        out.write_bytes(r.content)
        return out