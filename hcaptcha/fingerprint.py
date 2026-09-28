"""
hCaptcha fingerprint collection.

hsw.js collects 15 unique properties from the browser environment and
hashes each with XxHash3 (twox-hash 1.6.x) using a fixed seed:
    5575352424011909552

The hashed output is packed into the `fingerprint_events` array inside
the n-token payload. Property IDs run 101–602.

This module builds a *consistent, plausible* fingerprint for a Windows
Chrome desktop. If you need to mimic a specific real device, replace
`build_profile()` with values captured from that device.
"""
from __future__ import annotations

import hashlib
import platform
import random
import struct
from typing import Any, Dict, List

import xxhash

from config import HCAPTCHA_FINGERPRINT_SEED


# Property IDs as observed in roralsorom/hcaptcha analysis
PROPERTY_IDS = {
    "window_functions":   101,
    "webgl_vendor":       201,
    "webgl_renderer":     202,
    "css_properties":     301,
    "canvas_hash":        401,
    "math_fingerprint":   402,
    "screen":             403,
    "navigator":          404,
    "media_sources":      501,
    "fonts":              502,
    "timezone":           503,
    "languages":          504,
    "touch_points":       601,
    "color_depth":        602,
    "hardware_concurrency": 603,
}


def _hash_property(value: str, hashed: bool = True) -> Dict[str, Any]:
    """Hash a single property with XxHash3 + hCaptcha's seed."""
    if hashed:
        h = xxhash.xxh3_64(value.encode(), seed=HCAPTCHA_FINGERPRINT_SEED)
        return {"hash": h.intdigest()}
    return {"value": value}


def build_profile() -> Dict[str, Any]:
    """
    Build a Windows / Chrome desktop profile.

    Values are deliberately stable across runs so the same machine
    produces the same fingerprint.
    """
    return {
        # ── WebGL ──
        "webgl_vendor":    "Google Inc. (Intel)",
        "webgl_renderer":  "ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 "
                           "vs_5_0 ps_5_0, D3D11)",

        # ── Canvas ──
        "canvas_hash":     _stable_hash("canvas-v2"),

        # ── Math fingerprint ──
        "math_fingerprint": _stable_hash("math-v2"),

        # ── Screen ──
        "screen": {
            "width": 1920, "height": 1080,
            "availWidth": 1920, "availHeight": 1040,
            "colorDepth": 24, "pixelDepth": 24,
            "devicePixelRatio": 1,
        },

        # ── Navigator ──
        "navigator": {
            "userAgent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.0.0 Safari/537.36"),
            "platform": "Win32",
            "hardwareConcurrency": 8,
            "deviceMemory": 8,
            "maxTouchPoints": 0,
        },

        # ── Media ──
        "media_sources":   "audioinput,audiooutput,videoinput",

        # ── Fonts (Windows base set) ──
        "fonts": sorted([
            "Arial", "Calibri", "Cambria", "Candara", "Comic Sans MS",
            "Consolas", "Constantia", "Corbel", "Courier New", "Ebrima",
            "Franklin Gothic Medium", "Gabriola", "Gadugi", "Georgia",
            "Impact", "Ink Free", "Javanese Text", "Leelawadee UI",
            "Lucida Console", "Malgun Gothic", "Marlett", "Microsoft Himalaya",
            "Microsoft JhengHei", "Microsoft New Tai Lue", "Microsoft PhagsPa",
            "Microsoft Sans Serif", "Microsoft Tai Le", "Microsoft YaHei",
            "MingLiU-ExtB", "Mongolian Baiti", "MS Gothic", "MV Boli",
            "Myanmar Text", "Nirmala UI", "Palatino Linotype",
            "Segoe MDL2 Assets", "Segoe Print", "Segoe Script",
            "Segoe UI", "SimSun", "Sitka", "Sylfaen", "Symbol",
            "Tahoma", "Times New Roman", "Trebuchet MS", "Verdana",
            "Webdings", "Wingdings", "Yu Gothic",
        ]),

        # ── Locale ──
        "timezone":   "America/New_York",
        "languages":  "en-US,en",

        # ── Misc ──
        "touch_points":         0,
        "color_depth":          24,
        "hardware_concurrency": 8,
    }


def _stable_hash(seed: str) -> str:
    """Deterministic hash so the same profile yields the same value."""
    return hashlib.sha256(seed.encode()).hexdigest()[:16]


def build_events(profile: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
    """
    Build the `fingerprint_events` list pushed into the n-token payload.
    """
    p = profile or build_profile()
    events: List[Dict[str, Any]] = []

    for name, pid in PROPERTY_IDS.items():
        value = p.get(name)
        if value is None:
            continue
        if isinstance(value, (dict, list)):
            serialised = repr(sorted(value.items())) if isinstance(value, dict) \
                         else ",".join(map(str, value))
        else:
            serialised = str(value)

        entry = {"id": pid, **_hash_property(serialised, hashed=True)}
        events.append(entry)

    return events