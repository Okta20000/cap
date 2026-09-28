import os
from pathlib import Path

# Discord
DISCORD_API = "https://discord.com/api/v9"
DISCORD_HCAPTCHA_SITEKEY = "a9b5fb07-92ff-493f-86fe-352a2803b3df"

# hCaptcha
HCAPTCHA_API = "https://api.hcaptcha.com"
HCAPTCHA_ASSETS = "https://newassets.hcaptcha.com"
HCAPTCHA_POW_DIFFICULTY = 1000          # from JWT `c` field, usually 1000
HCAPTCHA_FINGERPRINT_SEED = 5575352424011909552
HCAPTCHA_CRC32_POLY = 79764919
EXTRACTOR_DIR = Path(os.getenv("EXTRACTOR_DIR", "./extractor"))


# Key snapshot (auto-refreshed every 12h by CircuitSavage's GitHub Action)
KEY_SNAPSHOT_URL = (
    "https://raw.githubusercontent.com/CircuitSavage/hcaptcha-hsj-hsw-reversed/"
    "main/data/keys.json"
)

# Local cache
CACHE_DIR = Path(os.getenv("HCAPTCHA_CACHE_DIR", "./cache"))
CACHE_DIR.mkdir(exist_ok=True)

# Known build hash → keys cache file
KEY_CACHE_FILE = CACHE_DIR / "keys_by_build.json"

# Wire format markers (from CircuitSavage docs/04)
WIRE_FORMAT_HSJ = "ct(N) || tag(16) || iv(12) || 0x00"
WIRE_FORMAT_HSW = "iv(12) || ct(N) || tag(16)"
WIRE_FORMAT_NTOKEN = "ct(N) || tag(16) || iv(12) || 0x02"   # version byte 0x02

# AES parameters
AES_KEY_BYTES = 32
GCM_IV_BYTES = 12
GCM_TAG_BYTES = 16