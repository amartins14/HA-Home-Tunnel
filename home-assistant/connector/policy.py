"""Validation for a relay with one explicitly configured HA destination."""
import base64
import json
import re
import ipaddress
import os
from pathlib import Path
from urllib.parse import unquote, urlsplit

def _settings():
    try:
        options = json.loads(Path('/data/options.json').read_text(encoding='utf-8'))
    except (FileNotFoundError, PermissionError):
        options = {
            'homeassistant_url': os.environ.get('HOMEASSISTANT_URL', 'http://homeassistant:8123'),
        }
    try:
        settings = json.loads(Path('/data/state/settings.json').read_text(encoding='utf-8'))
    except FileNotFoundError:
        settings = {}
    configured_url = options.get('homeassistant_url', os.environ.get('HOMEASSISTANT_URL', 'http://homeassistant:8123'))
    configured_url = _origin(configured_url, {'http', 'https'}, 'homeassistant_url')
    if settings and 'app_option_url' in settings and settings['app_option_url'] != configured_url:
        settings = {'homeassistant_url': configured_url}
    try:
        connection = json.loads(Path('/data/state/connection.json').read_text(encoding='utf-8'))
    except FileNotFoundError:
        connection = {}
    return {**options, **settings, **connection}

def _origin(value, schemes, name):
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError(f'{name} is required')
    parts = urlsplit(value)
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError(f'{name} has an invalid port') from exc
    if (parts.scheme not in schemes or not parts.hostname or parts.username or parts.password
            or parts.path not in ('', '/') or parts.query or parts.fragment
            or port is not None and not 1 <= port <= 65535):
        raise ValueError(f'{name} must be an origin URL without credentials, path, query, or fragment')
    hostname = parts.hostname.lower()
    host = f'[{hostname}]' if ':' in hostname else hostname
    default_port = 80 if parts.scheme == 'http' else 443
    netloc = host if port in (None, default_port) else f'{host}:{port}'
    return f'{parts.scheme}://{netloc}'

_OPTIONS = _settings()
OPTIONS = _OPTIONS
def homeassistant_origin(value):
    return _origin(value, {'http', 'https'}, 'homeassistant_url')

LOCAL = homeassistant_origin(_OPTIONS.get('homeassistant_url'))
ORIGIN = _origin(_OPTIONS.get('public_origin'), {'https'}, 'public_origin') if _OPTIONS.get('public_origin') else None
REMOTE = _OPTIONS.get('relay_url')
_remote = urlsplit(REMOTE) if isinstance(REMOTE, str) else None
if REMOTE is not None and (_remote is None or _remote.scheme != 'wss' or not _remote.hostname or _remote.username or _remote.password
        or _remote.path != '/_connect.ashx' or _remote.query or _remote.fragment):
    raise ValueError('relay_url must be wss://host/_connect.ashx')
MAX_HTTP = 4 * 1024 * 1024
MAX_RESPONSE = 64 * 1024 * 1024
HTTP_CHUNK = 64 * 1024
MAX_WS = 8 * 1024 * 1024
MAX_FRAME = 12 * 1024 * 1024  # must exceed base64(MAX_WS) + protocol overhead (~10.7 MiB for 8 MiB)
MAX_HEADERS = 16 * 1024
METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
HEADERS = frozenset({"accept", "accept-language", "authorization", "cookie", "content-type", "origin", "if-none-match", "if-modified-since", "range", "if-range", "user-agent"})
RESPONSE_HEADERS = frozenset({"content-type", "content-encoding", "cache-control", "etag", "last-modified", "vary", "content-range", "accept-ranges", "expires", "content-disposition", "set-cookie"})
ID = re.compile(r"^[0-9a-f]{32}$")
# Any WebSocket inside an app's web UI. Home Assistant checks the ingress session for
# these, so allowing every path below the session token lets any app's UI work.
INGRESS_WS = re.compile(r"^/api/hassio_ingress/[A-Za-z0-9_-]{32,256}(?:/[A-Za-z0-9._~!$&'()*+,;=:@-]*)*$")

class ProtocolError(ValueError):
    pass

def local_url(path):
    if not isinstance(path, str) or len(path) > 8192:
        raise ProtocolError("invalid path")
    decoded = path
    for _ in range(4):
        if not decoded.startswith("/") or decoded.startswith("//") or any(ord(c) < 32 or ord(c) == 127 for c in decoded) or "\\" in decoded or "#" in decoded:
            raise ProtocolError("invalid path")
        parts = urlsplit(decoded)
        if parts.scheme or parts.netloc or any(segment in {".", ".."} for segment in parts.path.split("/")):
            raise ProtocolError("invalid path")
        next_decoded = unquote(decoded, errors="strict")
        if next_decoded == decoded:
            return LOCAL + path
        decoded = next_decoded
    raise ProtocolError("nested path encoding")

def allowed_websocket_path(path):
    # Home Assistant's own socket, or any socket below an app's authenticated
    # ingress base (Zigbee2MQTT, Node-RED, ESPHome...). Percent-encoding and dot
    # segments are refused so the path can't step outside that base.
    if path == "/api/websocket":
        return True
    route = path.split("?", 1)[0]
    return INGRESS_WS.fullmatch(route) is not None and not any(segment in {".", ".."} for segment in route.split("/"))

def headers(values):
    if not isinstance(values, dict) or len(values) > 32:
        raise ProtocolError("invalid headers")
    result, total = {}, 0
    for name, value in values.items():
        if not isinstance(name, str) or not isinstance(value, str) or name.lower() not in HEADERS or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ProtocolError("invalid headers")
        total += len(name.encode()) + len(value.encode())
        if total > MAX_HEADERS or name.lower() in result:
            raise ProtocolError("headers too large or duplicated")
        result[name.lower()] = value
    return result

def payload(value, limit):
    if not isinstance(value, str) or len(value) > 4 * ((limit + 2) // 3):
        raise ProtocolError("payload too large")
    try:
        data = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ProtocolError("invalid payload") from exc
    if len(data) > limit:
        raise ProtocolError("payload too large")
    return data

def parse(raw):
    if not isinstance(raw, str) or len(raw.encode()) > MAX_FRAME:
        raise ProtocolError("frame too large")
    try:
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ProtocolError("duplicate field")
                result[key] = value
            return result
        message = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, RecursionError) as exc:
        raise ProtocolError("invalid JSON") from exc
    if not isinstance(message, dict):
        raise ProtocolError("invalid message")
    kind = message.get("type")
    fields = {"telemetry": {"type", "events", "stats"}, "pong": {"type"}, "http_ack": {"type", "id", "sequence"}, "http": {"type", "id", "method", "path", "headers", "body"}, "ws_open": {"type", "id", "path", "headers"}, "ws_data": {"type", "id", "kind", "data"}, "ws_close": {"type", "id"}}
    valid_fields = fields.get(kind) if isinstance(kind, str) else None
    if kind in ("ws_open", "http"):
        # The relay adds the visitor's socket address (never a header they sent); see forwarded().
        valid_fields = fields[kind] | ({"client_ip", "native_client"} & message.keys() if kind == "ws_open" else {"client_ip"} & message.keys())
        if "client_ip" in message:
            try:
                ipaddress.ip_address(message["client_ip"])
            except (TypeError, ValueError) as exc:
                raise ProtocolError("invalid client IP") from exc
        if "native_client" in message and message["native_client"] is not True:
            raise ProtocolError("invalid native client marker")
    if valid_fields is None or set(message) != valid_fields:
        raise ProtocolError("invalid message fields")
    if kind == "telemetry":
        validate_telemetry(message)
        return message
    if kind != "pong" and (not isinstance(message["id"], str) or not ID.fullmatch(message["id"])):
        raise ProtocolError("invalid request id")
    if kind in {"http", "ws_open"}:
        local_url(message["path"])
        message["headers"] = headers(message["headers"])
    if kind == "http":
        if not isinstance(message["method"], str) or message["method"] not in METHODS:
            raise ProtocolError("invalid method")
        payload(message["body"], MAX_HTTP)
    elif kind == "http_ack":
        if type(message["sequence"]) is not int or not 0 <= message["sequence"] <= MAX_RESPONSE:
            raise ProtocolError("invalid HTTP acknowledgment")
    elif kind == "ws_open":
        # Only the authenticated relay can mark an explicitly enabled native session.
        # A supplied Origin is never erased or reclassified as native.
        native_client = message.get("native_client")
        origin_allowed = ((message["path"] == "/api/websocket" and "origin" not in message["headers"]
                          and native_client) if native_client else message["headers"].get("origin") == ORIGIN)
        if not allowed_websocket_path(message["path"]) or not origin_allowed:
            raise ProtocolError("invalid WebSocket target or origin")
    elif kind == "ws_data":
        if message["kind"] not in ("text", "binary"):
            raise ProtocolError("invalid WebSocket kind")
        data = payload(message["data"], MAX_WS)
        if message["kind"] == "text":
            try:
                data.decode("utf-8", errors="strict")
            except UnicodeError as exc:
                raise ProtocolError("invalid text") from exc
    return message

def validate_telemetry(message):
    stats = message["stats"]
    names = {"requests", "errors_4xx", "errors_5xx", "response_bytes", "active_http", "active_ws", "queued_http", "events_dropped", "uptime_seconds", "forwarding_enabled"}
    if not isinstance(stats, dict) or set(stats) != names or any(type(v) is not int or not 0 <= v <= 2**63-1 for v in stats.values()):
        raise ProtocolError("invalid telemetry counters")
    events = message["events"]
    if not isinstance(events, list) or len(events) > 64:
        raise ProtocolError("invalid telemetry events")
    for event in events:
        if not isinstance(event, dict) or set(event) != {"ip", "method", "route", "status", "duration_ms", "request_bytes", "response_bytes"}:
            raise ProtocolError("invalid telemetry fields")
        if not isinstance(event["ip"], str) or len(event["ip"]) > 45:
            raise ProtocolError("invalid telemetry IP")
        if event["ip"] != "unknown":
            try:
                ipaddress.ip_address(event["ip"])
            except ValueError as exc:
                raise ProtocolError("invalid telemetry IP") from exc
        route = event["route"]
        legacy_route = isinstance(route, str) and route in {"frontend", "auth", "api", "media", "root", "other", "websocket"}
        display_route = isinstance(route, str) and len(route) <= 512 and route.startswith("/") and "?" not in route and "#" not in route and not any(ord(c) < 32 or ord(c) == 127 for c in route)
        if event["method"] not in METHODS | {"OTHER"} or not (legacy_route or display_route):
            raise ProtocolError("invalid telemetry route")
        if any(type(event[name]) is not int or not 0 <= event[name] <= 2**63-1 for name in ("status", "duration_ms", "request_bytes", "response_bytes")) or not 100 <= event["status"] <= 599:
            raise ProtocolError("invalid telemetry measurements")

def token_from_file(path):
    value = path.read_text().strip()
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ProtocolError("missing or invalid connector key")
    return value
