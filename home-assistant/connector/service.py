"""Home Assistant ingress setup UI and connector process supervisor."""
import asyncio
import hashlib
import hmac
import html
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

import aiohttp
from aiohttp import web
import policy

STATE = Path("/data/state")
PAIRING = STATE / "pairing.json"
CONNECTION = STATE / "connection.json"
FINALIZE = STATE / "finalize.json"
TOKEN = STATE / "tunnel-token.txt"
TOKEN_NEXT = STATE / "tunnel-token.next"
BLOCKS = STATE / "blocks.json"
ALERTS = STATE / "alerts.json"
RELAY_HEALTH = STATE / "relay-health.json"
STATUS = STATE / "status.json"
SETTINGS = STATE / "settings.json"
METRICS_TOKEN = Path("/secrets/metrics-token.txt")
METRICS_TOKEN_STATE = STATE / "metrics-token.txt"
RELAY_RELEASE = STATE / "relay-release.json"
RELAY_VERSION = STATE / "relay-version.json"
SETUP_PAGE = Path("/app/setup.html")
APP_CONFIG = Path("/app/app-config.yaml")
METRICS_URL = "http://127.0.0.1:8100/metrics"
METRICS_CLEAR_IPS_URL = "http://127.0.0.1:8100/ip-history/clear"
HISTORY_URL = "http://127.0.0.1:8100/history"
RELAY_FEATURES = ("rotate", "unpair", "blocks", "refused")
REFUSED_CHECK_INTERVAL = 60
REFUSED_REASONS = ("path", "origin")
SUPERVISOR_API = "http://supervisor/core/api"
BLOCK_LIMIT = 256
BLOCK_PUSH_INTERVAL = 300
WATCH_INTERVAL = 15
CERT_CHECK_INTERVAL = 6 * 60 * 60
OFFLINE_ALERT_AFTER = 180
NOTIFY_TARGET_PATTERN = re.compile(r"\A(persistent_notification|notify\.[a-z0-9_]{1,64})\Z")
NOTIFY_EVENTS = ("offline", "signin", "attention", "blocked", "relay_update", "certificate")
DEFAULT_LOCKDOWN = {"enabled": True, "denied": 20, "logins": 15, "minutes": 60}
DEFAULT_NOTIFICATIONS = {"target": "", "events": {name: True for name in NOTIFY_EVENTS}}
COUNTRY_PATTERN = re.compile(r"\A[A-Z]{2}\Z")
DEFAULT_COUNTRIES = {"mode": "off", "codes": [], "minutes": 30 * 24 * 60}
GEOLOCATION_CACHE_TTL = 24 * 60 * 60
GEOLOCATION_CACHE_LIMIT = 512
GEOLOCATION_LOOKUP_LIMIT = 200
GEOLOCATION_URL = "https://ipapi.co/{}/json/"
GEOLOCATION_CACHE = {}
GEOLOCATION_WINDOW_STARTED = 0
GEOLOCATION_LOOKUP_COUNT = 0
RELEASE_MANIFEST_URL = "https://raw.githubusercontent.com/amartins14/HA-Home-Tunnel/main/release-manifest.json"
RELEASE_CHECK_INTERVAL = 6 * 60 * 60
RELAY_VERSION_CHECK_INTERVAL = 5 * 60
PAIR_TIMEOUT = 86400
CODE_PATTERN = re.compile(r"\A[0-9a-f]{64}\Z")
VERSION_PATTERN = re.compile(r"\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?\Z")
PAIR_LABEL = "home-tunnel-pair-v1"
LOG = logging.getLogger("home-tunnel-service")
child = None


async def read_limited(response, limit):
    """The whole response body, refusing anything larger than limit bytes."""
    if response.content_length is not None and response.content_length > limit:
        raise ValueError("response too large")
    body = bytearray()
    async for block in response.content.iter_chunked(65536):
        body.extend(block)
        if len(body) > limit:
            raise ValueError("response too large")
    return bytes(body)


def read_json(path, limit=8192):
    try:
        if path.stat().st_size > limit:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def write_private(path, content):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(content, encoding="utf-8")
    os.chmod(temp, 0o600)
    os.replace(temp, path)


def save_json(path, data):
    write_private(path, json.dumps(data, separators=(",", ":")))


def ensure_settings():
    configured_url = policy.homeassistant_origin(os.environ.get("HOMEASSISTANT_URL", "http://homeassistant:8123"))
    try:
        app_options = json.loads(Path("/data/options.json").read_text(encoding="utf-8"))
    except (FileNotFoundError, PermissionError, ValueError):
        app_options = {}
    configured_geo = app_options.get("geolocation_lookup", False) is True
    settings = read_json(SETTINGS)
    if settings is None:
        if SETTINGS.exists():
            raise ValueError("Home Tunnel settings file is unreadable")
        save_json(SETTINGS, {"homeassistant_url": configured_url, "app_option_url": configured_url,
                             "geolocation_enabled": configured_geo, "app_option_geolocation": configured_geo})
        return configured_url
    if not isinstance(settings, dict):
        raise ValueError("Home Tunnel settings file is invalid")
    changed = False
    if "app_option_url" not in settings:
        settings["app_option_url"] = configured_url
        changed = True
    elif settings["app_option_url"] != configured_url:
        settings["homeassistant_url"] = configured_url
        settings["app_option_url"] = configured_url
        changed = True
    if "app_option_geolocation" not in settings:
        settings["app_option_geolocation"] = configured_geo
        settings["geolocation_enabled"] = configured_geo
        changed = True
    elif settings["app_option_geolocation"] != configured_geo:
        settings["app_option_geolocation"] = configured_geo
        settings["geolocation_enabled"] = configured_geo
        changed = True
    elif type(settings.get("geolocation_enabled")) is not bool:
        settings["geolocation_enabled"] = configured_geo
        changed = True
    value = policy.homeassistant_origin(settings.get("homeassistant_url"))
    if value != settings.get("homeassistant_url"):
        # Keep the app's Supervisor option as a fallback while preserving the
        # value saved in this dashboard until the option itself changes.
        settings["homeassistant_url"] = value
        changed = True
    if changed:
        save_json(SETTINGS, settings)
    return value


def ensure_metrics_token():
    configured = os.environ.get("HOME_TUNNEL_METRICS_TOKEN", "").strip()
    if configured:
        return configured
    for path in (METRICS_TOKEN, METRICS_TOKEN_STATE):
        try:
            value = path.read_text(encoding="ascii").strip()
        except OSError:
            continue
        if CODE_PATTERN.fullmatch(value):
            return value
    value = secrets.token_hex(32)
    write_private(METRICS_TOKEN_STATE, value + "\n")
    return value


def app_version():
    try:
        config = APP_CONFIG.read_text(encoding="utf-8")
    except OSError:
        return "unknown"
    match = re.search(r"(?m)^version:\s*[\"']?([^\"'\s#]+)", config)
    return match.group(1) if match else "unknown"


def version_key(value):
    match = VERSION_PATTERN.fullmatch(value) if isinstance(value, str) else None
    if not match:
        return None
    core = tuple(int(match.group(index)) for index in range(1, 4))
    prerelease = match.group(4)
    if prerelease is None:
        return core, (1,)
    identifiers = []
    for identifier in prerelease.split("."):
        if identifier.isdigit():
            identifiers.append((0, int(identifier)))
        else:
            identifiers.append((1, identifier))
    return core, (0, *identifiers)


def safe_github_url(value):
    if not isinstance(value, str) or len(value) > 512:
        return None
    parsed = urlsplit(value)
    if parsed.scheme != "https" or parsed.hostname != "github.com" or parsed.username or parsed.password:
        return None
    return value


def valid_release_manifest(data):
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        return None
    latest = data.get("latest_relay_version")
    if version_key(latest) is None:
        return None
    compatible = data.get("compatible_home_tunnel_versions")
    if (not isinstance(compatible, list) or len(compatible) > 32
            or any(not isinstance(value, str) or len(value) > 64 for value in compatible)):
        return None
    links = {key: safe_github_url(data.get(key)) for key in ("release_url", "changelog_url", "manual_update_url")}
    if any(value is None for value in links.values()):
        return None
    return {"latest_relay_version": latest, "compatible_home_tunnel_versions": compatible, **links}


def compare_versions(left, right):
    left_key, right_key = version_key(left), version_key(right)
    if left_key is None or right_key is None:
        return None
    left_core, left_pre = left_key
    right_core, right_pre = right_key
    if left_core != right_core:
        return (left_core > right_core) - (left_core < right_core)
    # SemVer prerelease identifiers compare one by one; a release outranks its prerelease.
    if left_pre == right_pre:
        return 0
    if left_pre == (1,):
        return 1
    if right_pre == (1,):
        return -1
    left_ids, right_ids = left_pre[1:], right_pre[1:]
    for left_id, right_id in zip(left_ids, right_ids):
        if left_id != right_id:
            return (left_id > right_id) - (left_id < right_id)
    return (len(left_ids) > len(right_ids)) - (len(left_ids) < len(right_ids))


async def release_checker():
    await asyncio.sleep(5)
    while True:
        try:
            timeout = aiohttp.ClientTimeout(total=8, connect=4)
            async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as session:
                async with session.get(RELEASE_MANIFEST_URL, allow_redirects=False) as response:
                    if response.status != 200 or (response.content_length is not None and response.content_length > 16384):
                        raise ValueError("release metadata unavailable")
                    raw = await read_limited(response, 16384)
                    metadata = valid_release_manifest(json.loads(raw))
                    if metadata is None:
                        raise ValueError("release metadata invalid")
                    save_json(RELAY_RELEASE, {**metadata, "checked_at": time.time(), "last_error": None})
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, json.JSONDecodeError) as error:
            cached = read_json(RELAY_RELEASE) or {}
            cached["last_error"] = type(error).__name__
            cached.setdefault("checked_at", None)
            save_json(RELAY_RELEASE, cached)
            LOG.info("Relay release check unavailable (%s)", type(error).__name__)
        await asyncio.sleep(RELEASE_CHECK_INTERVAL)


async def relay_version_checker():
    while True:
        connection = read_json(CONNECTION)
        if connection and TOKEN.exists():
            try:
                started = time.monotonic()
                status_code, body = await relay_request(connection, "version")
                latency = round((time.monotonic() - started) * 1000)
                if status_code == 200 and isinstance(body.get("version"), str) and version_key(body["version"]):
                    features = body.get("features")
                    features = [value for value in features if value in RELAY_FEATURES] if isinstance(features, list) else []
                    native = body.get("native_clients")
                    save_json(RELAY_VERSION, {"version": body["version"], "features": features,
                                              "checked_at": time.time(), "latency_ms": latency,
                                              "native_clients": native if type(native) is bool else None})
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass
        await asyncio.sleep(RELAY_VERSION_CHECK_INTERVAL)


def public_urls(value):
    if not isinstance(value, str) or len(value) > 512:
        raise ValueError("Enter your public Home Tunnel URL")
    parsed = urlsplit(value.strip())
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("The URL has an invalid port") from error
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment
            or port is not None and not 1 <= port <= 65535):
        raise ValueError("Enter an HTTPS origin without a path")
    host = parsed.hostname.lower()
    authority = f"[{host}]" if ":" in host else host
    default_port = port is None or port == 443
    origin = f"https://{authority}" + (f":{port}" if not default_port else "")
    return origin, f"wss://{authority}" + (f":{port}" if not default_port else "") + "/_connect.ashx"


def ingress_only(request):
    return request.remote == "172.30.32.2"


@web.middleware
async def restrict_to_ingress(request, handler):
    if not ingress_only(request):
        raise web.HTTPForbidden()
    return await handler(request)


async def setup_page(request):
    try:
        page = SETUP_PAGE.read_text(encoding="utf-8")
    except OSError:
        raise web.HTTPServiceUnavailable(text="Setup UI is unavailable")
    ingress_path = request.headers.get("X-Ingress-Path", "").rstrip("/")
    page = page.replace("__INGRESS_BASE__", html.escape(ingress_path, quote=True))
    return web.Response(text=page, content_type="text/html", charset="utf-8", headers={
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'self'",
    })


async def status(request):
    pairing = read_json(PAIRING)
    connection = read_json(CONNECTION)
    live = read_json(STATUS) or {}
    now = time.time()
    code_expires = pairing.get("expires_at", 0) if pairing else 0
    if pairing and code_expires < now:
        PAIRING.unlink(missing_ok=True)
        pairing = None
    connected = live.get("connection") == "connected" and now - live.get("updated_at", 0) < 20
    release = read_json(RELAY_RELEASE) or {}
    relay_version = read_json(RELAY_VERSION) or {}
    installed_relay = relay_version.get("version")
    latest_relay = release.get("latest_relay_version")
    comparison = compare_versions(latest_relay, installed_relay) if latest_relay and installed_relay else None
    current_app = app_version()
    homeassistant_url = ensure_settings()
    saved_settings = app_settings()
    result = {
        "homeassistant_url": homeassistant_url,
        "geolocation_enabled": saved_settings["geolocation_enabled"],
        "paired": bool(connection and TOKEN.exists()),
        "claim_ready": bool(pairing and not pairing.get("started")),
        "pairing_pending": bool(pairing and pairing.get("started")),
        "pairing_expires_in": max(0, int(code_expires - now)) if pairing else 0,
        "setup_code": pairing.get("setup_code") if pairing and not pairing.get("started") else None,
        "bootstrap_snippet": (f'<add key="HaTunnelBootstrapCodeHash" value="{pairing["code_hash"]}" />' if pairing and not pairing.get("started") else None),
        "connected": connected,
        "forwarding_enabled": bool(live.get("forwarding_enabled", False)),
        "relay_url": connection.get("public_url") if connection else None,
        "home_tunnel_version": current_app,
        "relay_version": installed_relay,
        "relay_version_checked_at": relay_version.get("checked_at"),
        "latest_relay_version": latest_relay,
        "relay_update_available": comparison == 1,
        "relay_compatible": current_app in release.get("compatible_home_tunnel_versions", []) if release else None,
        "release_checked_at": release.get("checked_at"),
        "release_url": release.get("release_url"),
        "changelog_url": release.get("changelog_url"),
        "manual_update_url": release.get("manual_update_url"),
        "error": live.get("error") if now - live.get("updated_at", 0) < 90 else None,
        "relay_features": relay_version.get("features") if isinstance(relay_version.get("features"), list) else [],
        "relay_native_clients": relay_version.get("native_clients"),
        "geolocation_status": {"error": GEOLOCATION_STATUS["error"], "at": GEOLOCATION_STATUS["at"],
                               "remaining_today": max(0, GEOLOCATION_LOOKUP_LIMIT - GEOLOCATION_LOOKUP_COUNT)},
        "relay_refused": REFUSED["items"],
        "relay_refused_at": REFUSED["at"],
        "relay_latency_ms": relay_version.get("latency_ms"),
        "relay_health": read_json(RELAY_HEALTH) or {},
        "rotation_pending": TOKEN_NEXT.exists(),
        "notifications_available": bool(SUPERVISOR_TOKEN),
        **{key: value for key, value in saved_settings.items() if key != "geolocation_enabled"},
    }
    return web.json_response(result, headers={"Cache-Control": "no-store"})


def sanitize_telemetry(data):
    if not isinstance(data, dict):
        return None
    fields = {
        "version", "status", "healthy", "public_reachable", "risk_status", "risk_issues",
        "requests_per_minute", "http_kib_per_second", "recent_latency_ms", "active_http",
        "active_ws", "uptime_seconds", "automatic_reconnects", "public_check_age_seconds",
        "public_check_failures", "telemetry_age_seconds", "denied_5m", "failures_5m",
        "events_dropped", "audit_healthy", "recent_requests",
        "caller_ips", "caller_ip_retention_days", "caller_ip_history_ok",
        "unique_ips_15m", "authenticated_connections", "queued_http",
        "lockdown_candidates", "recent_request_count",
    }
    safe = {key: value for key, value in data.items() if key in fields}
    events = safe.get("recent_requests")
    if isinstance(events, list):
        safe["recent_requests"] = [
            {key: event[key] for key in ("ip", "method", "route", "status", "duration_ms", "request_bytes", "response_bytes", "observed_at") if key in event}
            for event in events if isinstance(event, dict)
        ]
    return safe


async def telemetry(request):
    token = ensure_metrics_token()
    if not CODE_PATTERN.fullmatch(token):
        return web.json_response({"available": False, "reason": "invalid_configuration"}, headers={"Cache-Control": "no-store"})
    timeout = aiohttp.ClientTimeout(total=2)
    try:
        async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as session:
            async with session.get(METRICS_URL, headers={"Authorization": f"Bearer {token}"}) as response:
                if response.status != 200:
                    return web.json_response({"available": False, "reason": "endpoint_unavailable"}, headers={"Cache-Control": "no-store"})
                data = sanitize_telemetry(await response.json())
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, OSError):
        return web.json_response({"available": False, "reason": "endpoint_unavailable"}, headers={"Cache-Control": "no-store"})
    if data is None:
        return web.json_response({"available": False, "reason": "endpoint_unavailable"}, headers={"Cache-Control": "no-store"})
    return web.json_response({"available": True, "metrics": data}, headers={"Cache-Control": "no-store"})


async def clear_caller_ips(request):
    token = ensure_metrics_token()
    if not CODE_PATTERN.fullmatch(token):
        return web.json_response({"error": "endpoint_unavailable"}, status=503, headers={"Cache-Control": "no-store"})
    timeout = aiohttp.ClientTimeout(total=2)
    try:
        async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as session:
            async with session.post(METRICS_CLEAR_IPS_URL, headers={"Authorization": f"Bearer {token}"}) as response:
                if response.status != 200:
                    return web.json_response({"error": "storage_unavailable"}, status=503, headers={"Cache-Control": "no-store"})
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
        return web.json_response({"error": "endpoint_unavailable"}, status=503, headers={"Cache-Control": "no-store"})
    return web.json_response({"cleared": True}, headers={"Cache-Control": "no-store"})


def valid_lockdown(value):
    if not isinstance(value, dict) or set(value) != set(DEFAULT_LOCKDOWN) or type(value["enabled"]) is not bool:
        raise ValueError("Invalid lockdown settings")
    for key, low, high in (("denied", 5, 1000), ("logins", 5, 1000), ("minutes", 5, 7 * 24 * 60)):
        if type(value[key]) is not int or not low <= value[key] <= high:
            raise ValueError(f"Lockdown {key} must be between {low} and {high}")
    return dict(value)


def valid_notifications(value):
    if not isinstance(value, dict) or set(value) != {"target", "events"}:
        raise ValueError("Invalid notification settings")
    target, events = value["target"], value["events"]
    if not isinstance(target, str) or (target and not NOTIFY_TARGET_PATTERN.fullmatch(target)):
        raise ValueError("Pick persistent_notification or a notify service")
    if not isinstance(events, dict) or set(events) != set(NOTIFY_EVENTS) or any(type(v) is not bool for v in events.values()):
        raise ValueError("Invalid notification events")
    return {"target": target, "events": dict(events)}


def valid_countries(value):
    if not isinstance(value, dict) or set(value) != set(DEFAULT_COUNTRIES) or value["mode"] not in ("off", "block", "allow"):
        raise ValueError("Invalid country settings")
    codes = value["codes"]
    if not isinstance(codes, list) or len(codes) > 250 or any(not isinstance(code, str) or not COUNTRY_PATTERN.fullmatch(code) for code in codes):
        raise ValueError("Countries must be two-letter codes, like PT or US")
    minutes = value["minutes"]
    if minutes is not None and (type(minutes) is not int or not 60 <= minutes <= 366 * 24 * 60):
        raise ValueError("Pick how long country blocks last")
    if value["mode"] == "allow" and not codes:
        raise ValueError("List at least one country to allow")
    return {"mode": value["mode"], "codes": sorted(set(codes)), "minutes": minutes}


def app_settings():
    settings = read_json(SETTINGS) or {}
    lockdown, notifications = settings.get("lockdown"), settings.get("notifications")
    try:
        countries = valid_countries(settings.get("countries"))
    except ValueError:
        countries = dict(DEFAULT_COUNTRIES)
    try:
        lockdown = valid_lockdown(lockdown)
    except ValueError:
        lockdown = dict(DEFAULT_LOCKDOWN)
    try:
        notifications = valid_notifications(notifications)
    except ValueError:
        notifications = {"target": "", "events": dict(DEFAULT_NOTIFICATIONS["events"])}
    return {"geolocation_enabled": settings.get("geolocation_enabled", False) is True,
            "lockdown": lockdown, "notifications": notifications, "countries": countries}


async def update_settings(request):
    data = await request.json()
    simple = {"geolocation_enabled", "lockdown", "notifications", "countries"}
    if isinstance(data, dict) and data and set(data) <= simple:
        try:
            if "geolocation_enabled" in data and type(data["geolocation_enabled"]) is not bool:
                raise ValueError("geolocation_enabled must be true or false")
            validators = {"lockdown": valid_lockdown, "notifications": valid_notifications, "countries": valid_countries}
            changes = {key: validators[key](value) if key in validators else value for key, value in data.items()}
        except ValueError as error:
            raise web.HTTPBadRequest(text=str(error))
        ensure_settings()
        settings = read_json(SETTINGS) or {}
        settings.update(changes)
        save_json(SETTINGS, settings)
        return web.json_response(app_settings(), headers={"Cache-Control": "no-store"})
    if not isinstance(data, dict) or set(data) != {"homeassistant_url"}:
        raise web.HTTPBadRequest(text="Set a supported Home Tunnel setting")
    try:
        value = policy.homeassistant_origin(data.get("homeassistant_url"))
    except ValueError as error:
        raise web.HTTPBadRequest(text=str(error))
    current = ensure_settings()
    restarting = value != current and child is not None and child.returncode is None
    if value != current:
        settings = read_json(SETTINGS) or {"app_option_url": current}
        save_json(SETTINGS, {**settings, "homeassistant_url": value})
        if restarting:
            child.terminate()
    return web.json_response({"homeassistant_url": value, "restarting": restarting}, headers={"Cache-Control": "no-store"})


GEOLOCATION_STATUS = {"error": None, "at": None, "paused_until": 0.0}


def refund_location_slots(count):
    global GEOLOCATION_LOOKUP_COUNT
    GEOLOCATION_LOOKUP_COUNT = max(0, GEOLOCATION_LOOKUP_COUNT - count)


def fetch_location_slots(count, now):
    """Reserve up to `count` new ipapi.co lookups under the shared daily cap."""
    global GEOLOCATION_WINDOW_STARTED, GEOLOCATION_LOOKUP_COUNT
    if now - GEOLOCATION_WINDOW_STARTED >= GEOLOCATION_CACHE_TTL:
        GEOLOCATION_WINDOW_STARTED = now
        GEOLOCATION_LOOKUP_COUNT = 0
    allowed = max(0, min(count, GEOLOCATION_LOOKUP_LIMIT - GEOLOCATION_LOOKUP_COUNT))
    GEOLOCATION_LOOKUP_COUNT += allowed
    return allowed


def parse_location(data):
    """(label, ISO country code) from an ipapi.co answer; empty strings when unknown."""
    if not isinstance(data, dict) or data.get("error"):
        return "", ""
    parts = [data.get("city"), data.get("region"), data.get("country_name")]
    label = ", ".join(dict.fromkeys(part.strip() for part in parts if isinstance(part, str) and part.strip()))[:160]
    code = data.get("country_code") if isinstance(data.get("country_code"), str) else ""
    return label, code.upper() if COUNTRY_PATTERN.fullmatch(code.upper()) else ""


async def lookup_locations(ips, max_new=10):
    """{ip: (label, country code)} for public addresses, from the cache or ipapi.co.

    Callers must check that caller locations are turned on. New lookups count toward
    the daily cap shared by the dashboard and country blocking.
    """
    now = time.monotonic()
    found, missing = {}, []
    for value in dict.fromkeys(ips):
        try:
            address = ipaddress.ip_address(value)
        except (ValueError, TypeError):
            continue
        if not address.is_global:
            continue
        cached = GEOLOCATION_CACHE.get(value)
        cache_ttl = GEOLOCATION_CACHE_TTL if cached and cached[1] else 15 * 60
        if cached and now - cached[0] < cache_ttl:
            found[value] = (cached[1], cached[2] if len(cached) > 2 else "")
        else:
            missing.append(value)
    if missing and time.monotonic() < GEOLOCATION_STATUS["paused_until"]:
        return found  # the provider asked us to slow down
    missing = missing[:fetch_location_slots(min(len(missing), max_new), now)]

    def remember(value, label, code):
        if len(GEOLOCATION_CACHE) >= GEOLOCATION_CACHE_LIMIT:
            GEOLOCATION_CACHE.pop(next(iter(GEOLOCATION_CACHE)))
        GEOLOCATION_CACHE[value] = (now, label, code)

    if missing:
        # One at a time: ipapi.co's free tier refuses bursts of parallel lookups.
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5), trust_env=False) as session:
            for index, value in enumerate(missing):
                try:
                    async with session.get(GEOLOCATION_URL.format(value)) as response:
                        if response.status == 429:
                            refund_location_slots(len(missing) - index)
                            GEOLOCATION_STATUS.update({"error": "rate_limited", "at": time.time(), "paused_until": time.monotonic() + 120})
                            LOG.info("Location lookups rate-limited by ipapi.co; pausing")
                            break
                        data = await response.json(content_type=None) if response.status == 200 else None
                except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, OSError):
                    data = None
                label, code = parse_location(data)
                if isinstance(data, dict) and data.get("reason") == "RateLimited":
                    refund_location_slots(len(missing) - index)
                    GEOLOCATION_STATUS.update({"error": "rate_limited", "at": time.time(), "paused_until": time.monotonic() + 120})
                    break
                if code or label:
                    GEOLOCATION_STATUS.update({"error": None, "at": time.time()})
                else:
                    GEOLOCATION_STATUS.update({"error": "failed", "at": time.time()})
                found[value] = (label, code)
                remember(value, label, code)
                await asyncio.sleep(0.25)
    return found


async def geolocation(request):
    settings = read_json(SETTINGS) or {}
    if settings.get("geolocation_enabled") is not True:
        return web.json_response({"enabled": False, "locations": {}, "countries": {}}, headers={"Cache-Control": "no-store"})
    ips = list(dict.fromkeys(ip for value in request.query.getall("ips", []) for ip in value.split(",") if ip))
    if not ips or len(ips) > 10:
        raise web.HTTPBadRequest(text="Request up to 10 recent IP addresses")
    found = await lookup_locations(ips)
    return web.json_response({"enabled": True, "locations": {ip: label for ip, (label, _) in found.items()},
                              "countries": {ip: code for ip, (_, code) in found.items() if code}},
                             headers={"Cache-Control": "no-store"})


def apply_country_rules(found, rows, policy, trusted, now=None):
    """Block addresses first seen from a blocked (or not allowed) country. Returns new blocks."""
    now = time.time() if now is None else now
    if policy["mode"] == "off":
        return []
    codes = set(policy["codes"])
    added = []
    for ip, (label, code) in found.items():
        if not code or ip in trusted or blocked(rows, ip) or len(rows) >= BLOCK_LIMIT:
            continue
        listed = code in codes
        if listed if policy["mode"] == "block" else not listed:
            try:
                cidr = normalize_cidr(ip)
            except ValueError:
                continue
            place = label.rsplit(", ", 1)[-1] if label else code
            reason = f"Country: {place} ({code}) is {'blocked' if policy['mode'] == 'block' else 'not on the allowed list'}"
            row = {"cidr": cidr, "until": now + policy["minutes"] * 60 if policy["minutes"] else None,
                   "reason": reason, "source": "country", "created": now}
            rows.insert(0, row)
            added.append(row)
    return added


async def generate_claim_code(request):
    if CONNECTION.exists() or TOKEN.exists():
        raise web.HTTPConflict(text="Home Tunnel is already paired")
    code = secrets.token_hex(32)
    code_hash = hashlib.sha256(code.encode("ascii")).hexdigest()
    save_json(PAIRING, {"setup_code": code, "code_hash": code_hash, "created_at": time.time(),
                        "expires_at": time.time() + PAIR_TIMEOUT, "started": False})
    STATUS.unlink(missing_ok=True)
    return web.json_response({"setup_code": code,
                              "bootstrap_snippet": f'<add key="HaTunnelBootstrapCodeHash" value="{code_hash}" />',
                              "expires_in": PAIR_TIMEOUT}, headers={"Cache-Control": "no-store"})


async def begin_pairing(request):
    if CONNECTION.exists() or TOKEN.exists():
        raise web.HTTPConflict(text="Home Tunnel is already paired")
    data = await request.json()
    if not isinstance(data, dict):
        raise web.HTTPBadRequest(text="Invalid setup request")
    try:
        origin, relay_url = public_urls(data.get("public_url"))
    except ValueError as error:
        raise web.HTTPBadRequest(text=str(error))
    existing = read_json(PAIRING)
    if not existing or not CODE_PATTERN.fullmatch(existing.get("setup_code", "")) or existing.get("expires_at", 0) <= time.time():
        raise web.HTTPConflict(text="Generate a new setup code first")
    if existing.get("started") and existing.get("public_url") != origin:
        raise web.HTTPConflict(text="Pairing is already in progress for another URL")

    STATUS.unlink(missing_ok=True)
    existing.update({"origin": origin, "relay_url": relay_url, "public_url": origin, "started": True})
    save_json(PAIRING, existing)
    return web.json_response({"pairing_pending": True}, headers={"Cache-Control": "no-store"})


async def relay_request(connection, action, payload=None, authenticate=True, token=None):
    public_url = connection.get("public_url")
    if token is None:
        token = TOKEN.read_text(encoding="ascii").strip() if authenticate and TOKEN.exists() else None
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    url = public_url + f"/_pair.ashx?action={action}"
    timeout = aiohttp.ClientTimeout(total=8)
    async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as session:
        async with session.post(url, json=payload or {}, headers=headers, allow_redirects=False) as response:
            text = await response.text()
            try:
                body = json.loads(text) if text else {}
            except ValueError:
                body = {}
            return response.status, body


def pair_proof(key, purpose, origin, client_nonce, server_nonce, value=""):
    transcript = "\n".join((PAIR_LABEL, purpose, origin, client_nonce, server_nonce, value))
    return hmac.new(key, transcript.encode("utf-8"), hashlib.sha256).hexdigest()


class PairRejected(Exception):
    pass


async def secure_pairing(pairing):
    origin = pairing["origin"]
    code = pairing["setup_code"]
    key = hashlib.sha256(code.encode("ascii")).digest()
    client_nonce = pairing.get("client_nonce") or secrets.token_hex(32)
    if pairing.get("client_nonce") != client_nonce:
        pairing["client_nonce"] = client_nonce
        pairing.pop("server_nonce", None)
        save_json(PAIRING, pairing)

    status_code, challenge = await relay_request(pairing, "challenge", {
        "client_nonce": client_nonce, "origin": origin,
    }, authenticate=False)
    if status_code == 409:
        raise PairRejected("Relay rejected the setup code hash. Check web.config and try again.")
    if status_code != 200:
        raise aiohttp.ClientError(f"Relay challenge failed with HTTP {status_code}")
    server_nonce = challenge.get("server_nonce", "")
    server_proof = challenge.get("server_proof", "")
    if not CODE_PATTERN.fullmatch(server_nonce) or not CODE_PATTERN.fullmatch(server_proof):
        raise ValueError("Relay returned an invalid challenge")
    expected = pair_proof(key, "server", origin, client_nonce, server_nonce)
    if not hmac.compare_digest(expected, server_proof):
        raise PairRejected("Relay identity check failed. Verify the HTTPS URL and web.config hash.")
    pairing["server_nonce"] = server_nonce
    pairing["server_proof"] = server_proof
    save_json(PAIRING, pairing)

    client_proof = pair_proof(key, "client", origin, client_nonce, server_nonce)
    status_code, result = await relay_request(pairing, "claim", {
        "client_nonce": client_nonce, "server_nonce": server_nonce,
        "origin": origin, "server_proof": server_proof, "client_proof": client_proof,
    }, authenticate=False)
    if status_code == 409:
        raise PairRejected("Relay rejected pairing. Check that its setup hash matches the code.")
    if status_code != 200:
        raise aiohttp.ClientError(f"Relay claim failed with HTTP {status_code}")
    token = result.get("connector_token", "")
    issued_proof = result.get("server_proof", "")
    if not CODE_PATTERN.fullmatch(token) or not CODE_PATTERN.fullmatch(issued_proof):
        raise ValueError("Relay returned an invalid connector credential")
    expected = pair_proof(key, "issued", origin, client_nonce, server_nonce, token)
    if not hmac.compare_digest(expected, issued_proof):
        raise PairRejected("Relay did not authenticate the issued connector key")
    return token


async def pair_worker():
    retry_delay = 3
    while True:
        await reconcile_rotation()
        finalize = read_json(FINALIZE)
        if finalize:
            try:
                status_code, _ = await relay_request(finalize, "finalize")
                if status_code == 200:
                    FINALIZE.unlink(missing_ok=True)
                else:
                    save_json(STATUS, {"connection": "setup_error", "error": f"Relay finalization failed with HTTP {status_code}", "updated_at": time.time()})
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass
        pairing = read_json(PAIRING)
        if pairing and CONNECTION.exists() and TOKEN.exists():
            PAIRING.unlink(missing_ok=True)
            pairing = None
        if pairing:
            if pairing.get("expires_at", 0) <= time.time():
                PAIRING.unlink(missing_ok=True)
                save_json(STATUS, {"connection": "setup_error", "error": "Setup code expired. Generate a new code and update the web.config hash.", "updated_at": time.time()})
                await asyncio.sleep(3)
                continue
            if not pairing.get("started"):
                await asyncio.sleep(3)
                continue
            try:
                token = await secure_pairing(pairing)
                if CODE_PATTERN.fullmatch(token):
                    write_private(TOKEN, token + "\n")
                    save_json(CONNECTION, {"public_url": pairing["public_url"],
                                           "public_origin": pairing["origin"],
                                           "relay_url": pairing["relay_url"]})
                    save_json(FINALIZE, {"public_url": pairing["public_url"]})
                    PAIRING.unlink(missing_ok=True)
                    status_code, _ = await relay_request({"public_url": pairing["public_url"]}, "finalize")
                    if status_code == 200:
                        FINALIZE.unlink(missing_ok=True)
                    else:
                        save_json(STATUS, {"connection": "setup_error", "error": f"Relay finalization failed with HTTP {status_code}", "updated_at": time.time()})
                    LOG.info("Home Tunnel relay pairing completed")
                    retry_delay = 3
            except PairRejected as error:
                save_json(STATUS, {"connection": "setup_error", "error": str(error), "updated_at": time.time()})
                LOG.warning("Pairing rejected: %s", error)
                await asyncio.sleep(60)
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, KeyError) as error:
                LOG.warning("Waiting for relay pairing (%s)", type(error).__name__)
                await asyncio.sleep(retry_delay)
                retry_delay = min(30, retry_delay * 2)
        else:
            retry_delay = 3
        await asyncio.sleep(3)


async def set_forwarding(request, enabled):
    connection = read_json(CONNECTION)
    if not connection or not TOKEN.exists():
        raise web.HTTPConflict(text="Pair Home Tunnel before changing forwarding")
    live = read_json(STATUS) or {}
    if enabled and (live.get("connection") != "connected" or time.time() - live.get("updated_at", 0) >= 20):
        raise web.HTTPConflict(text="Wait for the connector to connect before enabling forwarding")
    try:
        status_code, _ = await relay_request(connection, "enable" if enabled else "disable")
    except (aiohttp.ClientError, asyncio.TimeoutError) as error:
        raise web.HTTPBadGateway(text="Could not reach the paired relay") from error
    if status_code != 200:
        raise web.HTTPBadGateway(text="The relay rejected the forwarding change")
    return web.json_response({"forwarding_enabled": enabled}, headers={"Cache-Control": "no-store"})


async def enable(request):
    return await set_forwarding(request, True)


async def disable(request):
    return await set_forwarding(request, False)


async def connector_supervisor():
    global child
    delay = 2
    while True:
        if CONNECTION.exists() and TOKEN.exists() and (child is None or child.returncode is not None):
            connection = read_json(CONNECTION)
            if connection:
                env = {key: value for key, value in os.environ.items()
                       if key not in ("HOME_TUNNEL_SUPERVISOR_TOKEN", "SUPERVISOR_TOKEN", "HASSIO_TOKEN")}
                env["HOME_TUNNEL_RELAY_URL"] = connection["relay_url"]
                env["HOME_TUNNEL_PUBLIC_ORIGIN"] = connection["public_origin"]
                env["HOME_TUNNEL_TOKEN_FILE"] = str(TOKEN)
                env["HOME_TUNNEL_METRICS_TOKEN"] = ensure_metrics_token()
                child = await asyncio.create_subprocess_exec(sys.executable, "-u", "/app/connector.py", env=env)
                LOG.info("Home Tunnel connector process started")
                await child.wait()
                LOG.warning("Home Tunnel connector process stopped; restarting")
                child = None
                await asyncio.sleep(delay)
                delay = min(30, delay * 2)
        else:
            await asyncio.sleep(1)


async def on_shutdown(app):
    for task in app["tasks"]:
        task.cancel()
    await asyncio.gather(*app["tasks"], return_exceptions=True)
    if child is not None and child.returncode is None:
        child.terminate()
        try:
            await asyncio.wait_for(child.wait(), 10)
        except asyncio.TimeoutError:
            child.kill()
            await child.wait()


# ---------- Home Assistant API (notifications only) ----------
# Supervisor gives this app a token because config.yaml sets homeassistant_api. start.sh
# passes it only to this service; main() takes it out of the environment so the connector
# never inherits it, and marks this process non-dumpable so the connector (same UID) can't
# read it from /proc either.
SUPERVISOR_TOKEN = ""


def take_supervisor_token():
    global SUPERVISOR_TOKEN
    SUPERVISOR_TOKEN = os.environ.pop("HOME_TUNNEL_SUPERVISOR_TOKEN", "").strip()
    os.environ.pop("SUPERVISOR_TOKEN", None)
    os.environ.pop("HASSIO_TOKEN", None)
    try:
        import ctypes
        ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE, 0
    except (OSError, AttributeError):
        LOG.warning("Could not mark the setup service non-dumpable")


async def ha_api(method, path, payload=None):
    if not SUPERVISOR_TOKEN:
        raise PermissionError("Home Assistant API access is unavailable")
    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as session:
        async with session.request(method, SUPERVISOR_API + path, json=payload, allow_redirects=False,
                                   headers={"Authorization": f"Bearer {SUPERVISOR_TOKEN}"}) as response:
            if response.status >= 400:
                raise aiohttp.ClientResponseError(response.request_info, (), status=response.status)
            # The services list of a large install runs to megabytes.
            raw = await read_limited(response, 8 * 1024 * 1024)
            return json.loads(raw) if raw else None


async def notify(event, title, message, target=None):
    """Send one notification if this event type is turned on. Never raises."""
    settings = app_settings()["notifications"]
    target = target or settings["target"]
    if not target or (event != "test" and not settings["events"].get(event)):
        return False
    try:
        if target == "persistent_notification":
            await ha_api("POST", "/services/persistent_notification/create",
                         {"title": title, "message": message, "notification_id": f"home_tunnel_{event}"})
        else:
            await ha_api("POST", f"/services/notify/{target.split('.', 1)[1]}", {"title": title, "message": message})
        return True
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, PermissionError, OSError):
        LOG.warning("Notification %s could not be sent", event)
        return False


async def notify_targets(request):
    targets = ["persistent_notification"]
    error = None
    try:
        services = await ha_api("GET", "/services")
        for domain in services if isinstance(services, list) else []:
            if isinstance(domain, dict) and domain.get("domain") == "notify" and isinstance(domain.get("services"), dict):
                targets += sorted(f"notify.{name}" for name in domain["services"]
                                  if NOTIFY_TARGET_PATTERN.fullmatch(f"notify.{name}") and name not in ("send_message", "persistent_notification"))
    except PermissionError:
        error = "unavailable"
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, OSError) as failure:
        LOG.warning("Could not list notify services (%s%s)", type(failure).__name__,
                    f" {failure.status}" if isinstance(failure, aiohttp.ClientResponseError) else "")
        error = "unreachable"
    return web.json_response({"targets": targets, "error": error}, headers={"Cache-Control": "no-store"})


async def notify_test(request):
    data = await request.json()
    target = data.get("target") if isinstance(data, dict) else None
    if not isinstance(target, str) or not NOTIFY_TARGET_PATTERN.fullmatch(target):
        raise web.HTTPBadRequest(text="Pick where notifications go first")
    if not await notify("test", "Home Tunnel", "Test notification: Home Tunnel alerts will arrive here.", target):
        raise web.HTTPBadGateway(text="Home Assistant did not accept the notification")
    return web.json_response({"sent": True}, headers={"Cache-Control": "no-store"})


# ---------- unpair and key rotation ----------
def stop_connector():
    if child is not None and child.returncode is None:
        child.terminate()


async def unpair(request):
    data = await request.json()
    force = isinstance(data, dict) and data.get("force") is True
    connection = read_json(CONNECTION)
    if not connection or not TOKEN.exists():
        raise web.HTTPConflict(text="Home Tunnel is not paired")
    relay_reset = False
    try:
        status_code, _ = await relay_request(connection, "unpair")
        if status_code == 200:
            relay_reset = True
        elif not force:
            reason = ("This relay is too old to unpair remotely. Update it, or unpair only here."
                      if status_code == 404 else f"The relay refused to unpair (HTTP {status_code}).")
            raise web.HTTPBadGateway(text=reason)
    except (aiohttp.ClientError, asyncio.TimeoutError) as error:
        if not force:
            raise web.HTTPBadGateway(text="Could not reach the relay. Try again, or unpair only here.") from error
    for path in (TOKEN, TOKEN_NEXT, CONNECTION, FINALIZE, PAIRING, STATUS, RELAY_VERSION, RELAY_HEALTH):
        path.unlink(missing_ok=True)
    BLOCK_SYNC.update({"ok": None, "at": None, "error": None, "count": 0})
    REFUSED.update({"items": [], "at": None})
    stop_connector()
    LOG.info("Home Tunnel unpaired%s", "" if relay_reset else " locally only")
    return web.json_response({"unpaired": True, "relay_reset": relay_reset}, headers={"Cache-Control": "no-store"})


async def confirm_rotation(connection, token):
    status_code, _ = await relay_request(connection, "confirm_rotation", token=token)
    if status_code == 200:
        os.replace(TOKEN_NEXT, TOKEN)
        stop_connector()
        LOG.info("Connector key rotated")
        return True
    if status_code == 403:
        # The relay no longer knows this key: it was replaced or the relay was reset.
        TOKEN_NEXT.unlink(missing_ok=True)
    return False


async def reconcile_rotation():
    """Finish a rotation whose confirmation was interrupted."""
    if not TOKEN_NEXT.exists():
        return
    connection = read_json(CONNECTION)
    try:
        token = TOKEN_NEXT.read_text(encoding="ascii").strip()
        if not connection or not CODE_PATTERN.fullmatch(token):
            TOKEN_NEXT.unlink(missing_ok=True)
            return
        await confirm_rotation(connection, token)
    except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
        pass


async def rotate_key(request):
    connection = read_json(CONNECTION)
    if not connection or not TOKEN.exists():
        raise web.HTTPConflict(text="Pair Home Tunnel before rotating its key")
    if TOKEN_NEXT.exists():
        await reconcile_rotation()
        if TOKEN_NEXT.exists():
            raise web.HTTPConflict(text="A key rotation is still finishing. Try again in a minute.")
    try:
        status_code, body = await relay_request(connection, "rotate")
        if status_code == 404:
            raise web.HTTPConflict(text="Update the relay to 0.5.0 or newer to rotate the key from here.")
        if status_code != 200 or not CODE_PATTERN.fullmatch(str(body.get("connector_token", ""))):
            raise web.HTTPBadGateway(text=f"The relay refused to rotate the key (HTTP {status_code}).")
        write_private(TOKEN_NEXT, body["connector_token"] + "\n")
        for attempt in range(3):
            try:
                if await confirm_rotation(connection, body["connector_token"]):
                    return web.json_response({"rotated": True}, headers={"Cache-Control": "no-store"})
                break
            except (aiohttp.ClientError, asyncio.TimeoutError):
                await asyncio.sleep(1 + attempt)
    except (aiohttp.ClientError, asyncio.TimeoutError) as error:
        raise web.HTTPBadGateway(text="Could not reach the relay") from error
    if TOKEN_NEXT.exists():
        return web.json_response({"rotated": False, "pending": True}, headers={"Cache-Control": "no-store"})
    raise web.HTTPBadGateway(text="The relay did not confirm the new key; the old key stays in use.")


# ---------- blocked addresses ----------
BLOCK_SYNC = {"ok": None, "at": None, "error": None, "count": 0}
LAST_BLOCK_PUSH = 0.0


def normalize_cidr(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 64:
        raise ValueError("Enter an IP address or range, like 203.0.113.7 or 203.0.113.0/24")
    try:
        network = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as error:
        raise ValueError("Enter an IP address or range, like 203.0.113.7 or 203.0.113.0/24") from error
    if network.version == 6 and network.network_address.ipv4_mapped:
        network = ipaddress.ip_network(f"{network.network_address.ipv4_mapped}/{max(8, network.prefixlen - 96)}", strict=False)
    if network.prefixlen < (8 if network.version == 4 else 16):
        raise ValueError("That range is too broad to block")
    return str(network.network_address) if network.num_addresses == 1 else network.with_prefixlen


def read_blocks(now=None):
    now = time.time() if now is None else now
    raw = read_json(BLOCKS, 128 * 1024)
    rows = []
    for row in raw if isinstance(raw, list) else []:
        try:
            cidr = normalize_cidr(row.get("cidr"))
        except (ValueError, AttributeError):
            continue
        until = row.get("until")
        if until is not None and (type(until) not in (int, float) or until <= now):
            continue
        rows.append({"cidr": cidr, "until": until, "reason": str(row.get("reason") or "")[:120],
                     "source": row.get("source") if row.get("source") in ("auto", "country") else "manual",
                     "created": row.get("created") if type(row.get("created")) in (int, float) else now})
    return rows[:BLOCK_LIMIT]


def blocked(rows, ip):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in ipaddress.ip_network(row["cidr"], strict=False) for row in rows
               if ipaddress.ip_network(row["cidr"], strict=False).version == address.version)


def relay_supports(feature):
    version = read_json(RELAY_VERSION) or {}
    return feature in (version.get("features") or [])


async def push_blocks(rows):
    global LAST_BLOCK_PUSH
    LAST_BLOCK_PUSH = time.monotonic()
    connection = read_json(CONNECTION)
    if not connection or not TOKEN.exists():
        return
    payload = {"blocks": [{"cidr": row["cidr"], "until": (datetime.fromtimestamp(row["until"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                                                         if row["until"] else None)} for row in rows]}
    try:
        status_code, _ = await relay_request(connection, "blocks", payload)
        BLOCK_SYNC.update({"ok": status_code == 200, "at": time.time(), "count": len(rows),
                           "error": None if status_code == 200 else "relay_too_old" if status_code == 404 else f"http_{status_code}"})
    except (aiohttp.ClientError, asyncio.TimeoutError):
        BLOCK_SYNC.update({"ok": False, "at": time.time(), "error": "unreachable"})


def save_blocks(rows):
    save_json(BLOCKS, rows[:BLOCK_LIMIT])


def blocks_response(rows=None):
    return web.json_response({"blocks": read_blocks() if rows is None else rows, "sync": BLOCK_SYNC, "limit": BLOCK_LIMIT},
                             headers={"Cache-Control": "no-store"})


async def list_blocks(request):
    return blocks_response()


async def add_block(request):
    data = await request.json()
    if not isinstance(data, dict) or not set(data) <= {"cidr", "minutes", "reason"}:
        raise web.HTTPBadRequest(text="Invalid block")
    try:
        cidr = normalize_cidr(data.get("cidr"))
    except ValueError as error:
        raise web.HTTPBadRequest(text=str(error))
    minutes = data.get("minutes")
    if minutes is not None and (type(minutes) is not int or not 1 <= minutes <= 366 * 24 * 60):
        raise web.HTTPBadRequest(text="Pick how long to block for")
    rows = [row for row in read_blocks() if row["cidr"] != cidr]
    if len(rows) >= BLOCK_LIMIT:
        raise web.HTTPConflict(text=f"You can block up to {BLOCK_LIMIT} addresses")
    now = time.time()
    rows.insert(0, {"cidr": cidr, "until": now + minutes * 60 if minutes else None, "reason": str(data.get("reason") or "Blocked by you")[:120],
                    "source": "manual", "created": now})
    save_blocks(rows)
    await push_blocks(rows)
    return blocks_response(rows)


async def remove_block(request):
    data = await request.json()
    cidr = data.get("cidr") if isinstance(data, dict) else None
    rows = read_blocks()
    remaining = [row for row in rows if row["cidr"] != cidr]
    if len(remaining) == len(rows):
        raise web.HTTPNotFound(text="That address isn't blocked")
    save_blocks(remaining)
    await push_blocks(remaining)
    return blocks_response(remaining)


# ---------- background watcher: lockdowns, relay sync and alerts ----------
async def fetch_metrics():
    token = ensure_metrics_token()
    if not CODE_PATTERN.fullmatch(token):
        return None
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3), trust_env=False) as session:
            async with session.get(METRICS_URL, headers={"Authorization": f"Bearer {token}"}) as response:
                if response.status != 200:
                    return None
                data = await response.json()
                return data if isinstance(data, dict) else None
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, OSError):
        return None


def apply_lockdown(metrics, rows, settings, now=None):
    """Block callers over the thresholds. Returns the new blocks."""
    now = time.time() if now is None else now
    if not settings["enabled"] or not metrics:
        return []
    trusted = {row.get("ip") for row in metrics.get("caller_ips") or [] if isinstance(row, dict) and row.get("status") == "authenticated"}
    added = []
    for candidate in metrics.get("lockdown_candidates") or []:
        if not isinstance(candidate, dict):
            continue
        ip, denied, logins = candidate.get("ip"), candidate.get("denied_10m"), candidate.get("logins_10m")
        if type(denied) is not int or type(logins) is not int:
            continue
        if denied < settings["denied"] and logins < settings["logins"]:
            continue
        try:
            cidr = normalize_cidr(ip)
        except ValueError:
            continue
        # Never lock out an address that has signed in to Home Assistant.
        if ip in trusted or blocked(rows, ip) or len(rows) >= BLOCK_LIMIT:
            continue
        reason = f"{denied} denied answers" if denied >= settings["denied"] else f"{logins} login attempts"
        row = {"cidr": cidr, "until": now + settings["minutes"] * 60, "reason": f"Automatic: {reason} in 10 minutes",
               "source": "auto", "created": now}
        rows.insert(0, row)
        added.append(row)
    return added


def connector_offline_for(now=None):
    now = time.time() if now is None else now
    if not (read_json(CONNECTION) and TOKEN.exists()):
        return 0
    live = read_json(STATUS) or {}
    if live.get("connection") == "connected" and now - live.get("updated_at", 0) < 20:
        return 0
    return now - (live.get("updated_at") or now)


async def evaluate_alerts(metrics, now=None):
    now = time.time() if now is None else now
    alerts = read_json(ALERTS, 64 * 1024) or {}
    changed = False
    # Tunnel offline / back online.
    offline = connector_offline_for(now)
    if offline >= OFFLINE_ALERT_AFTER and not alerts.get("offline_notified"):
        await notify("offline", "Home Tunnel is offline", "The connector has not reached the relay for a few minutes. Home Assistant is not reachable from outside.")
        alerts["offline_notified"] = True
        changed = True
    elif offline == 0 and alerts.get("offline_notified"):
        await notify("offline", "Home Tunnel is back online", "The connector reached the relay again.")
        alerts["offline_notified"] = False
        changed = True
    if metrics:
        # Sign-ins from an address that never signed in before.
        signed = {row["ip"] for row in metrics.get("caller_ips") or []
                  if isinstance(row, dict) and row.get("status") == "authenticated" and isinstance(row.get("ip"), str)}
        device_of = {row["ip"]: (row.get("devices") or [None])[0] for row in metrics.get("caller_ips") or []
                     if isinstance(row, dict) and isinstance(row.get("ip"), str)}
        known = alerts.get("signin_ips")
        if not isinstance(known, list):
            known = sorted(signed)  # first run: remember, don't flood
            changed = True
        fresh = sorted(signed - set(known))
        for ip in fresh[:5]:
            device = device_of.get(ip)
            await notify("signin", "New Home Assistant sign-in",
                         f"Someone signed in to Home Assistant through Home Tunnel from {ip}{f' ({device})' if isinstance(device, str) else ''}, an address not seen signing in before.")
        if fresh:
            known = (known + fresh)[-512:]
            changed = True
        alerts["signin_ips"] = known
        issues = [issue for issue in metrics.get("risk_issues") or [] if isinstance(issue, str)]
        if issues and now - alerts.get("attention_at", 0) > 30 * 60:
            await notify("attention", "Home Tunnel needs attention", " ".join(issues))
            alerts["attention_at"] = now
            changed = True
    # Relay update.
    release = read_json(RELAY_RELEASE) or {}
    installed = (read_json(RELAY_VERSION) or {}).get("version")
    latest = release.get("latest_relay_version")
    if (installed and latest and compare_versions(latest, installed) == 1 and alerts.get("relay_update") != latest
            and not re.search(r"-dev(?:\.|$)", latest)):
        await notify("relay_update", "Home Tunnel relay update", f"Relay {latest} is available; yours runs {installed}. Update it by hand on the IIS host.")
        alerts["relay_update"] = latest
        changed = True
    # Certificate expiry.
    health = read_json(RELAY_HEALTH) or {}
    days = health.get("certificate_days_left")
    today = int(now // 86400)
    if type(days) is int and days < 14 and alerts.get("certificate_day") != today:
        await notify("certificate", "Relay certificate expires soon",
                     f"The relay's HTTPS certificate expires in {days} day{'s' if days != 1 else ''}. Renew it on the IIS host.")
        alerts["certificate_day"] = today
        changed = True
    if changed:
        save_json(ALERTS, alerts)


# WebSocket connections the relay refused (path outside the allowed rule, or a foreign origin).
REFUSED = {"items": [], "at": None, "checked": 0.0}


def clean_refusals(items):
    rows = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        at, ip, route, reason = item.get("at"), item.get("ip"), item.get("route"), item.get("reason")
        if (isinstance(at, str) and len(at) <= 40 and isinstance(ip, str) and len(ip) <= 45 and reason in REFUSED_REASONS
                and isinstance(route, str) and route.startswith("/") and len(route) <= 512
                and not any(ord(c) < 32 or ord(c) == 127 for c in route)):
            rows.append({"at": at, "ip": ip, "route": route, "reason": reason})
    return rows[-20:][::-1]  # newest first


async def refresh_refused():
    REFUSED["checked"] = time.monotonic()
    connection = read_json(CONNECTION)
    if not connection:
        return
    try:
        status_code, body = await relay_request(connection, "refused")
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return
    if status_code == 200:
        REFUSED.update({"items": clean_refusals(body.get("refused")), "at": time.time()})


async def watcher():
    await asyncio.sleep(10)
    while True:
        try:
            now = time.time()
            stored = read_json(BLOCKS, 128 * 1024)
            rows = read_blocks(now)
            changed = isinstance(stored, list) and len(stored) != len(rows)  # expired entries dropped
            metrics = await fetch_metrics()
            settings = app_settings()
            added = apply_lockdown(metrics, rows, settings["lockdown"], now)
            # Country rules only work while caller locations are on: they need ipapi.co lookups.
            if metrics and settings["geolocation_enabled"] and settings["countries"]["mode"] != "off":
                trusted = {row.get("ip") for row in metrics.get("caller_ips") or [] if isinstance(row, dict) and row.get("status") == "authenticated"}
                recent = [event.get("ip") for event in reversed(metrics.get("recent_requests") or []) if isinstance(event, dict)]
                callers = [row.get("ip") for row in metrics.get("caller_ips") or [] if isinstance(row, dict)]
                fresh = [ip for ip in dict.fromkeys(recent + callers) if isinstance(ip, str) and ip not in trusted and not blocked(rows, ip)]
                found = await lookup_locations(fresh[:100])
                added += apply_country_rules(found, rows, settings["countries"], trusted, now)
            if added or changed:
                save_blocks(rows)
            paired = bool(read_json(CONNECTION) and TOKEN.exists())
            retry_soon = BLOCK_SYNC["ok"] is False and BLOCK_SYNC.get("error") != "relay_too_old"
            due = time.monotonic() - LAST_BLOCK_PUSH >= (60 if retry_soon else BLOCK_PUSH_INTERVAL)
            if paired and (added or changed or due):
                await push_blocks(rows)
            for row in added:
                LOG.warning("Blocked a caller automatically")
            if len(added) > 3:
                await notify("blocked", "Home Tunnel blocked addresses",
                             f"{len(added)} addresses were blocked automatically, including {', '.join(row['cidr'] for row in added[:3])}.")
            else:
                for row in added:
                    length = f"for {round((row['until'] - now) / 60)} minutes" if row["until"] else "until you unblock it"
                    await notify("blocked", "Home Tunnel blocked an address", f"{row['cidr']} was blocked {length}. {row['reason']}.")
            if paired and relay_supports("refused") and time.monotonic() - REFUSED["checked"] >= REFUSED_CHECK_INTERVAL:
                await refresh_refused()
            await evaluate_alerts(metrics, now)
        except Exception as error:  # the watcher must keep running
            LOG.warning("Background check failed (%s)", type(error).__name__)
        await asyncio.sleep(WATCH_INTERVAL)


# ---------- relay certificate ----------
def certificate_facts(host, port, timeout=8):
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            cert = tls.getpeercert()
    expires = ssl.cert_time_to_seconds(cert["notAfter"])
    issuer = dict(item[0] for item in cert.get("issuer", ()) if item)
    return {"certificate_expires_at": expires, "certificate_days_left": int((expires - time.time()) // 86400),
            "certificate_issuer": str(issuer.get("organizationName") or issuer.get("commonName") or "")[:120]}


async def certificate_checker():
    await asyncio.sleep(20)
    while True:
        connection = read_json(CONNECTION)
        if connection and connection.get("public_url"):
            parsed = urlsplit(connection["public_url"])
            try:
                facts = await asyncio.to_thread(certificate_facts, parsed.hostname, parsed.port or 443)
                facts.update({"checked_at": time.time(), "certificate_error": None})
            except ssl.SSLCertVerificationError:
                facts = {"checked_at": time.time(), "certificate_error": "not_trusted"}
            except (OSError, ValueError, KeyError):
                facts = {"checked_at": time.time(), "certificate_error": "unreachable"}
            save_json(RELAY_HEALTH, facts)
        await asyncio.sleep(CERT_CHECK_INTERVAL if connection else 60)


async def history(request):
    token = ensure_metrics_token()
    try:
        minutes = max(5, min(1440, int(request.query.get("minutes", "1440"))))
    except ValueError:
        raise web.HTTPBadRequest(text="minutes must be a number")
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3), trust_env=False) as session:
            async with session.get(HISTORY_URL, params={"minutes": str(minutes)}, headers={"Authorization": f"Bearer {token}"}) as response:
                if response.status != 200:
                    raise ValueError("history unavailable")
                data = await response.json()
        if not isinstance(data, dict) or not isinstance(data.get("minutes"), list):
            raise ValueError("history invalid")
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError, OSError):
        return web.json_response({"available": False, "fields": [], "minutes": []}, headers={"Cache-Control": "no-store"})
    return web.json_response({"available": True, "fields": data.get("fields", []), "minutes": data["minutes"]},
                             headers={"Cache-Control": "no-store"})


def make_app():
    app = web.Application(middlewares=[restrict_to_ingress], client_max_size=4096)
    app.router.add_get("/", setup_page)
    app.router.add_get("/api/status", status)
    app.router.add_get("/api/telemetry", telemetry)
    app.router.add_post("/api/caller-ips/clear", clear_caller_ips)
    app.router.add_get("/api/geolocation", geolocation)
    app.router.add_post("/api/settings", update_settings)
    app.router.add_post("/api/claim-code", generate_claim_code)
    app.router.add_post("/api/pair", begin_pairing)
    app.router.add_post("/api/enable", enable)
    app.router.add_post("/api/disable", disable)
    app.router.add_post("/api/unpair", unpair)
    app.router.add_post("/api/rotate-key", rotate_key)
    app.router.add_get("/api/blocks", list_blocks)
    app.router.add_post("/api/blocks", add_block)
    app.router.add_post("/api/blocks/remove", remove_block)
    app.router.add_get("/api/history", history)
    app.router.add_get("/api/notify/targets", notify_targets)
    app.router.add_post("/api/notify/test", notify_test)
    return app


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    take_supervisor_token()
    ensure_settings()
    ensure_metrics_token()
    app = make_app()
    app["tasks"] = []
    app.on_shutdown.append(on_shutdown)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", 8099).start()
    app["tasks"].extend([asyncio.create_task(pair_worker()), asyncio.create_task(connector_supervisor()),
                         asyncio.create_task(release_checker()), asyncio.create_task(relay_version_checker()),
                         asyncio.create_task(watcher()), asyncio.create_task(certificate_checker())])
    LOG.info("Home Tunnel setup UI is available through Home Assistant ingress")
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGTERM, stop.set)
    loop.add_signal_handler(signal.SIGINT, stop.set)
    try:
        await stop.wait()
    finally:
        loop.remove_signal_handler(signal.SIGTERM)
        loop.remove_signal_handler(signal.SIGINT)
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
