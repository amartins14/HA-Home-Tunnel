"""Home Assistant ingress setup UI and connector process supervisor."""
import asyncio
import hashlib
import hmac
import html
import json
import logging
import os
from pathlib import Path
import re
import secrets
import signal
import sys
import time
from urllib.parse import urlsplit

import aiohttp
from aiohttp import web
import policy

STATE = Path("/data/state")
PAIRING = STATE / "pairing.json"
CONNECTION = STATE / "connection.json"
FINALIZE = STATE / "finalize.json"
TOKEN = STATE / "tunnel-token.txt"
STATUS = STATE / "status.json"
SETTINGS = STATE / "settings.json"
METRICS_TOKEN = Path("/secrets/metrics-token.txt")
METRICS_TOKEN_STATE = STATE / "metrics-token.txt"
RELAY_RELEASE = STATE / "relay-release.json"
RELAY_VERSION = STATE / "relay-version.json"
SETUP_PAGE = Path("/app/setup.html")
APP_CONFIG = Path("/app/app-config.yaml")
METRICS_URL = "http://127.0.0.1:8100/metrics"
RELEASE_MANIFEST_URL = "https://raw.githubusercontent.com/amartins14/HA-Home-Tunnel/main/release-manifest.json"
RELEASE_CHECK_INTERVAL = 6 * 60 * 60
RELAY_VERSION_CHECK_INTERVAL = 5 * 60
PAIR_TIMEOUT = 86400
CODE_PATTERN = re.compile(r"\A[0-9a-f]{64}\Z")
VERSION_PATTERN = re.compile(r"\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?\Z")
PAIR_LABEL = "home-tunnel-pair-v1"
LOG = logging.getLogger("home-tunnel-service")
child = None


def read_json(path):
    try:
        if path.stat().st_size > 8192:
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
    settings = read_json(SETTINGS)
    if settings is None:
        if SETTINGS.exists():
            raise ValueError("Home Tunnel settings file is unreadable")
        save_json(SETTINGS, {"homeassistant_url": configured_url, "app_option_url": configured_url})
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
                    raw = await response.content.read(16385)
                    if len(raw) > 16384:
                        raise ValueError("release metadata too large")
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
                status_code, body = await relay_request(connection, "version")
                if status_code == 200 and isinstance(body.get("version"), str) and version_key(body["version"]):
                    save_json(RELAY_VERSION, {"version": body["version"], "checked_at": time.time()})
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
    result = {
        "homeassistant_url": ensure_settings(),
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
    }
    safe = {key: value for key, value in data.items() if key in fields}
    events = safe.get("recent_requests")
    if isinstance(events, list):
        safe["recent_requests"] = [
            {key: event[key] for key in ("method", "route", "status", "duration_ms", "request_bytes", "response_bytes", "observed_at") if key in event}
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


async def update_settings(request):
    data = await request.json()
    if not isinstance(data, dict) or set(data) != {"homeassistant_url"}:
        raise web.HTTPBadRequest(text="Set only the Home Assistant URL")
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


async def relay_request(connection, action, payload=None, authenticate=True):
    public_url = connection.get("public_url")
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
                env = dict(os.environ)
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


def make_app():
    app = web.Application(middlewares=[restrict_to_ingress], client_max_size=4096)
    app.router.add_get("/", setup_page)
    app.router.add_get("/api/status", status)
    app.router.add_get("/api/telemetry", telemetry)
    app.router.add_post("/api/settings", update_settings)
    app.router.add_post("/api/claim-code", generate_claim_code)
    app.router.add_post("/api/pair", begin_pairing)
    app.router.add_post("/api/enable", enable)
    app.router.add_post("/api/disable", disable)
    return app


async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    ensure_settings()
    ensure_metrics_token()
    app = make_app()
    app["tasks"] = []
    app.on_shutdown.append(on_shutdown)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", 8099).start()
    app["tasks"].extend([asyncio.create_task(pair_worker()), asyncio.create_task(connector_supervisor()),
                         asyncio.create_task(release_checker()), asyncio.create_task(relay_version_checker())])
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
