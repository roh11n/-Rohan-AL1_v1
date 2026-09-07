"""Threat Intelligence enrichment (VirusTotal, AbuseIPDB, MISP).
All calls short-timeout so investigation stays snappy; graceful failure when keys absent."""
import logging
import threading
import time
from typing import Any, Optional
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

TIMEOUT = 8


# ---------- VirusTotal API-key rotation ----------
_VT_LOCK = threading.Lock()
_VT_POINTER = 0  # round-robin index across the configured key list
_VT_BLACKLIST: dict[str, float] = {}  # key -> unix ts until which it is temporarily disabled
_VT_BACKOFF_SECONDS = 60 * 60  # 1h cooldown after 429/401 on a key


def parse_vt_keys(vt_multiline: str, vt_single: str = "") -> list[str]:
    """Return the effective list of VirusTotal API keys.
    Multiline field (one key per line) takes precedence over the legacy single-key field."""
    keys: list[str] = []
    if vt_multiline:
        for line in vt_multiline.splitlines():
            k = line.strip()
            if k and k not in keys:
                keys.append(k)
    if not keys and vt_single:
        keys.append(vt_single.strip())
    return [k for k in keys if k]


def _next_vt_key(keys: list[str]) -> Optional[str]:
    """Return the next healthy key (round-robin, skipping recently-throttled ones)."""
    global _VT_POINTER
    if not keys:
        return None
    now = time.time()
    with _VT_LOCK:
        # Purge expired blacklist entries
        for k, until in list(_VT_BLACKLIST.items()):
            if until <= now:
                _VT_BLACKLIST.pop(k, None)
        for _ in range(len(keys)):
            _VT_POINTER = (_VT_POINTER + 1) % len(keys)
            candidate = keys[_VT_POINTER]
            if candidate not in _VT_BLACKLIST:
                return candidate
        # All keys blacklisted → return the one closest to expiry so caller may still try
        return min(keys, key=lambda k: _VT_BLACKLIST.get(k, 0))


def _blacklist_vt_key(key: str) -> None:
    with _VT_LOCK:
        _VT_BLACKLIST[key] = time.time() + _VT_BACKOFF_SECONDS


def vt_key_health(keys: list[str]) -> dict:
    """Snapshot for the UI: how many keys are healthy vs cooling-off right now."""
    now = time.time()
    healthy, cooling = [], []
    with _VT_LOCK:
        for k in keys:
            masked = ("••••" + k[-4:]) if len(k) > 4 else "••••"
            until = _VT_BLACKLIST.get(k, 0)
            if until > now:
                cooling.append({"key": masked, "cools_off_in_seconds": int(until - now)})
            else:
                healthy.append({"key": masked})
    return {"total": len(keys), "healthy": len(healthy), "cooling_off": len(cooling),
            "keys_healthy": healthy, "keys_cooling": cooling}


def _vt_request(path: str, api_keys: list[str]) -> Optional[dict]:
    """Perform a GET against VirusTotal, rotating across keys on 429/401/403."""
    if not api_keys:
        return None
    tried = 0
    while tried < len(api_keys):
        key = _next_vt_key(api_keys)
        if not key:
            return None
        try:
            r = requests.get(f"https://www.virustotal.com/api/v3/{path}",
                             headers={"x-apikey": key}, timeout=TIMEOUT)
            if r.status_code == 200:
                return r.json()
            if r.status_code in (401, 403):
                logger.warning("VT key rejected (HTTP %s); rotating.", r.status_code)
                _blacklist_vt_key(key)
                tried += 1
                continue
            if r.status_code == 429:
                logger.info("VT quota exhausted for key; rotating.")
                _blacklist_vt_key(key)
                tried += 1
                continue
            logger.info("VT %s -> HTTP %s", path, r.status_code)
            return None
        except Exception as e:
            logger.info("VT %s failed: %s", path, e)
            tried += 1
    return None



def _safe_get(url: str, headers: dict | None = None, params: dict | None = None, verify: bool = True) -> dict | None:
    try:
        r = requests.get(url, headers=headers or {}, params=params or {}, timeout=TIMEOUT, verify=verify)
        if r.status_code == 200:
            return r.json()
        logger.info("TI %s -> HTTP %s", url, r.status_code)
    except Exception as e:
        logger.info("TI %s failed: %s", url, e)
    return None


def _safe_post(url: str, headers: dict | None = None, json_body: dict | None = None, verify: bool = True) -> dict | None:
    try:
        r = requests.post(url, headers=headers or {}, json=json_body or {}, timeout=TIMEOUT, verify=verify)
        if r.status_code in (200, 201):
            return r.json()
        logger.info("TI POST %s -> HTTP %s", url, r.status_code)
    except Exception as e:
        logger.info("TI POST %s failed: %s", url, e)
    return None


# ---------- VirusTotal ----------
def _first_arg_to_list(api_keys_or_key) -> list[str]:
    if isinstance(api_keys_or_key, list):
        return [k for k in api_keys_or_key if k]
    return [api_keys_or_key] if api_keys_or_key else []


def vt_ip(ip: str, api_keys_or_key) -> dict | None:
    keys = _first_arg_to_list(api_keys_or_key)
    if not keys:
        return None
    data = _vt_request(f"ip_addresses/{ip}", keys)
    if not data:
        return None
    attr = (data.get("data") or {}).get("attributes") or {}
    stats = attr.get("last_analysis_stats") or {}
    return {
        "ip": ip,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "country": attr.get("country"),
        "as_owner": attr.get("as_owner"),
        "reputation": attr.get("reputation"),
    }


def vt_hash(sha_or_md5: str, api_keys_or_key) -> dict | None:
    keys = _first_arg_to_list(api_keys_or_key)
    if not keys:
        return None
    data = _vt_request(f"files/{sha_or_md5}", keys)
    if not data:
        return None
    attr = (data.get("data") or {}).get("attributes") or {}
    stats = attr.get("last_analysis_stats") or {}
    return {
        "hash": sha_or_md5,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "type": attr.get("type_description"),
        "meaningful_name": attr.get("meaningful_name"),
    }


def vt_domain(domain: str, api_keys_or_key) -> dict | None:
    keys = _first_arg_to_list(api_keys_or_key)
    if not keys:
        return None
    data = _vt_request(f"domains/{domain}", keys)
    if not data:
        return None
    attr = (data.get("data") or {}).get("attributes") or {}
    stats = attr.get("last_analysis_stats") or {}
    return {
        "domain": domain,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "categories": list((attr.get("categories") or {}).values())[:3],
    }


# ---------- AbuseIPDB ----------
def abuseipdb_ip(ip: str, api_key: str) -> dict | None:
    if not api_key:
        return None
    data = _safe_get("https://api.abuseipdb.com/api/v2/check",
                     headers={"Key": api_key, "Accept": "application/json"},
                     params={"ipAddress": ip, "maxAgeInDays": 90})
    if not data:
        return None
    d = data.get("data") or {}
    return {
        "ip": ip,
        "abuse_confidence": d.get("abuseConfidenceScore", 0),
        "country_code": d.get("countryCode"),
        "isp": d.get("isp"),
        "total_reports": d.get("totalReports", 0),
        "last_reported_at": d.get("lastReportedAt"),
    }


# ---------- MISP ----------
_PRIVATE_HOSTS_PATTERN = None


def _is_safe_misp_url(url: str) -> bool:
    """Reject MISP URLs pointing at loopback / RFC1918 / link-local / metadata.
    Only http(s) schemes allowed."""
    from urllib.parse import urlparse
    import ipaddress
    try:
        p = urlparse(url)
    except Exception:
        return False
    if p.scheme not in ("http", "https"):
        return False
    host = (p.hostname or "").strip().lower()
    if not host or host in ("localhost", "metadata", "metadata.google.internal"):
        return False
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
    except ValueError:
        pass  # hostname (not IP) — allowed
    return True


def misp_search(value: str, misp_url: str, api_key: str, verify: bool = False) -> dict | None:
    if not api_key or not misp_url:
        return None
    if not _is_safe_misp_url(misp_url):
        logger.warning("MISP URL rejected (internal/invalid host): %s", misp_url)
        return None
    url = misp_url.rstrip("/") + "/attributes/restSearch"
    headers = {"Authorization": api_key, "Accept": "application/json", "Content-Type": "application/json"}
    data = _safe_post(url, headers=headers, json_body={"value": value, "limit": 5}, verify=verify)
    if not data:
        return None
    attrs = ((data.get("response") or {}).get("Attribute")) or []
    if not attrs:
        return None
    events = list({a.get("event_id") for a in attrs if a.get("event_id")})
    return {
        "value": value,
        "hits": len(attrs),
        "events": events[:5],
        "categories": list({a.get("category") for a in attrs})[:5],
        "first_seen": attrs[0].get("timestamp") if attrs else None,
    }


# ---------- Orchestrator ----------
def enrich(iocs: dict, ti_settings: dict, max_items: int = 5) -> dict:
    """Enrich IOCs with configured TI sources. Returns per-IOC-type results."""
    result = {
        "queried": False,
        "sources_enabled": [],
        "external_ips": [],
        "hashes": [],
        "domains": [],
        "urls": [],
        "verdicts": {"malicious": 0, "suspicious": 0, "clean": 0},
    }
    ts = ti_settings or {}
    vt_keys = parse_vt_keys(ts.get("virustotal_api_keys", ""),
                            ts.get("virustotal_api_key", "")) if ts.get("virustotal_enabled") else []
    vt_key = vt_keys  # pass list downstream
    abuse_key = ts.get("abuseipdb_api_key") if ts.get("abuseipdb_enabled") else ""
    misp_url = ts.get("misp_url") if ts.get("misp_enabled") else ""
    misp_key = ts.get("misp_api_key") if ts.get("misp_enabled") else ""
    misp_verify = ts.get("misp_verify_ssl", False)

    if vt_key: result["sources_enabled"].append("VirusTotal")
    if abuse_key: result["sources_enabled"].append("AbuseIPDB")
    if misp_key and misp_url: result["sources_enabled"].append("MISP")
    if not result["sources_enabled"]:
        return result
    result["queried"] = True

    for ip in (iocs.get("ipv4_external") or [])[:max_items]:
        entry: dict[str, Any] = {"ip": ip, "sources": {}}
        v = vt_ip(ip, vt_key)
        if v:
            entry["sources"]["virustotal"] = v
            if v["malicious"] > 0:
                result["verdicts"]["malicious"] += 1
            elif v["suspicious"] > 0:
                result["verdicts"]["suspicious"] += 1
            else:
                result["verdicts"]["clean"] += 1
        a = abuseipdb_ip(ip, abuse_key)
        if a:
            entry["sources"]["abuseipdb"] = a
            if a["abuse_confidence"] >= 75:
                result["verdicts"]["malicious"] += 1
            elif a["abuse_confidence"] >= 40:
                result["verdicts"]["suspicious"] += 1
        m = misp_search(ip, misp_url, misp_key, verify=misp_verify)
        if m:
            entry["sources"]["misp"] = m
            result["verdicts"]["malicious"] += 1
        if entry["sources"]:
            result["external_ips"].append(entry)

    all_hashes = (iocs.get("sha256") or []) + (iocs.get("sha1") or []) + (iocs.get("md5") or [])
    for h in all_hashes[:max_items]:
        entry = {"hash": h, "sources": {}}
        v = vt_hash(h, vt_key)
        if v:
            entry["sources"]["virustotal"] = v
            if v["malicious"] > 0:
                result["verdicts"]["malicious"] += 1
        m = misp_search(h, misp_url, misp_key, verify=misp_verify)
        if m:
            entry["sources"]["misp"] = m
            result["verdicts"]["malicious"] += 1
        if entry["sources"]:
            result["hashes"].append(entry)

    for d in (iocs.get("domain") or [])[:max_items]:
        entry = {"domain": d, "sources": {}}
        v = vt_domain(d, vt_key)
        if v:
            entry["sources"]["virustotal"] = v
            if v["malicious"] > 0:
                result["verdicts"]["malicious"] += 1
        m = misp_search(d, misp_url, misp_key, verify=misp_verify)
        if m:
            entry["sources"]["misp"] = m
            result["verdicts"]["malicious"] += 1
        if entry["sources"]:
            result["domains"].append(entry)

    return result
