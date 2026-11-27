"""Read-only dashboard telemetry on the private HA app network."""
from collections import deque
from datetime import datetime, timezone
import hmac
import ipaddress
import json
import os
import re
from pathlib import Path
import time
import logging
from aiohttp import web

VERSION = "0.7.4"
PUBLIC_HEALTH_MAX_AGE = 90
IP_HISTORY_PATH = Path("/data/state/caller-ips.json")
IP_HISTORY_TTL = 30 * 24 * 60 * 60
IP_HISTORY_LIMIT = 2048
TRAFFIC_HISTORY_PATH = Path("/data/state/traffic-history.json")
TRAFFIC_MINUTES = 24 * 60
TRAFFIC_SAVE_INTERVAL = 300
# One row per minute: minute (epoch // 60), requests, response bytes, latency sum (ms),
# latency samples, denied (401/403), server errors (5xx), new HA sign-ins.
TRAFFIC_FIELDS = ("minute", "requests", "bytes", "latency_sum", "latency_count", "denied", "errors", "signins")
LOCKDOWN_WINDOW = 600
LOCKDOWN_REPORT_MIN = 3
LOCKDOWN_IPS = 1024
LOGIN_ROUTES = ("/auth/login_flow", "/auth/login_flow/[flow-id]")
DEVICES_PER_CALLER = 4
DEVICE_LABEL = re.compile(r"\A[\w .,()/+·-]{1,60}\Z")


def device_label(agent):
    """A short, non-identifying label for a User-Agent, such as "Safari · iPhone"."""
    if not isinstance(agent, str) or not agent.strip():
        return None
    agent = agent[:512]
    app = re.search(r"Home ?Assistant/[\d.]+.*?\b(iOS|iPadOS|macOS|Android|watchOS)\s?([\d]+)?", agent)
    if app:
        return f"Home Assistant app · {app.group(1)}" + (f" {app.group(2)}" if app.group(2) else "")
    if re.match(r"Home ?Assistant/", agent):
        return "Home Assistant app"
    if "iPhone" in agent:
        system = "iPhone"
    elif "iPad" in agent:
        system = "iPad"
    elif "Android" in agent:
        version = re.search(r"Android (\d+)", agent)
        system = "Android" + (f" {version.group(1)}" if version else "")
    elif "CrOS" in agent:
        system = "ChromeOS"
    elif "Windows" in agent:
        system = "Windows"
    elif "Macintosh" in agent or "Mac OS X" in agent:
        system = "macOS"
    elif "Linux" in agent:
        system = "Linux"
    else:
        system = None
    for pattern, name in ((r"Edg(A|iOS)?/", "Edge"), (r"OPR/|Opera", "Opera"), (r"SamsungBrowser/", "Samsung Internet"),
                          (r"Firefox/|FxiOS/", "Firefox"), (r"Chrome/|CriOS/", "Chrome"), (r"Version/[\d.]+.*Safari/", "Safari")):
        if re.search(pattern, agent):
            return f"{name} · {system}" if system else name
    if system:
        return f"Browser · {system}"
    tool = re.match(r"([A-Za-z][\w.-]{0,30})/", agent)
    return tool.group(1) if tool else "Unknown device"
LOG = logging.getLogger("amdeploy-tunnel")

class Metrics:
    def __init__(self, history_path=IP_HISTORY_PATH, traffic_path=TRAFFIC_HISTORY_PATH):
        self.connected = False
        self.updated = None
        self.stats = {}
        self.events = deque(maxlen=20)
        self.request_rate = self.byte_rate = 0
        self.previous = None
        self.clients = {}
        self.sessions = {}
        self.security_events = deque(maxlen=5000)
        self.loss_observed = None
        self.audit_ok = False
        self.public_verified_at = None
        self.public_check_failures = 0
        self.automatic_reconnects = 0
        self.ip_history = {}
        self.ip_history_ok = True
        self.ip_history_path = Path(history_path)
        self.load_ip_history()
        self.traffic = deque(maxlen=TRAFFIC_MINUTES)
        self.traffic_path = Path(traffic_path)
        self.traffic_saved = time.monotonic()
        self.load_traffic()
        # Per-caller denied answers and login attempts over the last 10 minutes, for lockdowns.
        self.suspects = {}

    @staticmethod
    def ip_value(value):
        try:
            address = ipaddress.ip_address(value)
            return address.compressed
        except (ValueError, TypeError):
            return None

    def load_ip_history(self):
        try:
            if self.ip_history_path.stat().st_size > 512 * 1024:
                raise ValueError("IP history exceeds its storage limit")
            raw = json.loads(self.ip_history_path.read_text(encoding="utf-8"))
            if not isinstance(raw, list):
                raise ValueError("IP history is invalid")
            now = time.time()
            for row in raw:
                if not isinstance(row, dict):
                    continue
                ip = self.ip_value(row.get("ip"))
                first = row.get("first_seen")
                last = row.get("last_seen")
                auth = row.get("authenticated_at")
                calls = row.get("requests")
                if (ip is None or type(first) not in (int, float) or type(last) not in (int, float)
                        or (auth is not None and type(auth) not in (int, float)) or type(calls) is not int):
                    continue
                if (0 < first <= last <= now + 300 and (auth is None or 0 < auth <= now + 300)
                        and 0 <= now - last <= IP_HISTORY_TTL):
                    devices = [device for device in row.get("devices") or []
                               if isinstance(device, dict) and isinstance(device.get("label"), str)
                               and DEVICE_LABEL.fullmatch(device["label"]) and type(device.get("last_seen")) in (int, float)]
                    self.ip_history[ip] = {"ip": ip, "first_seen": first, "last_seen": last,
                                           "authenticated_at": auth, "requests": max(0, calls),
                                           "devices": devices[:DEVICES_PER_CALLER]}
            self.prune_ip_history(now)
        except FileNotFoundError:
            return
        except (OSError, ValueError, TypeError):
            self.ip_history_ok = False
            LOG.warning("Could not read caller IP history")

    def prune_ip_history(self, now):
        expired = [ip for ip, row in self.ip_history.items() if now-row["last_seen"] > IP_HISTORY_TTL]
        for ip in expired:
            self.ip_history.pop(ip, None)
        if len(self.ip_history) > IP_HISTORY_LIMIT:
            oldest = sorted(self.ip_history, key=lambda ip: self.ip_history[ip]["last_seen"])
            for ip in oldest[:len(self.ip_history)-IP_HISTORY_LIMIT]:
                self.ip_history.pop(ip, None)

    def save_ip_history(self):
        try:
            self.ip_history_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            rows = sorted(self.ip_history.values(), key=lambda row: row["last_seen"], reverse=True)
            temporary = self.ip_history_path.with_suffix(".tmp")
            temporary.write_text(json.dumps(rows, separators=(",", ":")), encoding="utf-8")
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.ip_history_path)
            self.ip_history_ok = True
        except OSError:
            self.ip_history_ok = False
            LOG.warning("Could not save caller IP history")

    def observe_ip(self, ip, now=None, authenticated=False, persist=True):
        ip = self.ip_value(ip)
        if ip is None:
            return False
        now = time.time() if now is None else now
        self.prune_ip_history(now)
        row = self.ip_history.get(ip)
        if row is None:
            if len(self.ip_history) >= IP_HISTORY_LIMIT:
                oldest = min(self.ip_history, key=lambda value: self.ip_history[value]["last_seen"])
                self.ip_history.pop(oldest, None)
            row = {"ip": ip, "first_seen": now, "last_seen": now, "authenticated_at": None, "requests": 0, "devices": []}
            self.ip_history[ip] = row
        row["last_seen"] = max(now, row["last_seen"])
        if authenticated:
            row["authenticated_at"] = now
        else:
            row["requests"] += 1
        if persist:
            self.save_ip_history()
        return True

    def load_traffic(self):
        try:
            if self.traffic_path.stat().st_size > 1024 * 1024:
                raise ValueError("traffic history exceeds its storage limit")
            rows = json.loads(self.traffic_path.read_text(encoding="utf-8"))
            if not isinstance(rows, list):
                raise ValueError("traffic history is invalid")
            oldest = int(time.time() // 60) - TRAFFIC_MINUTES
            previous = None
            for row in rows:
                if (isinstance(row, list) and len(row) == len(TRAFFIC_FIELDS)
                        and all(type(value) is int and value >= 0 for value in row)
                        and row[0] > oldest and (previous is None or row[0] > previous)):
                    self.traffic.append(row)
                    previous = row[0]
        except FileNotFoundError:
            return
        except (OSError, ValueError, TypeError):
            LOG.warning("Could not read traffic history")

    def save_traffic(self):
        try:
            self.traffic_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            temporary = self.traffic_path.with_suffix(".tmp")
            temporary.write_text(json.dumps(list(self.traffic), separators=(",", ":")), encoding="utf-8")
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.traffic_path)
        except OSError:
            LOG.warning("Could not save traffic history")

    def traffic_row(self, wall=None):
        minute = int((time.time() if wall is None else wall) // 60)
        if not self.traffic or self.traffic[-1][0] < minute:
            self.traffic.append([minute] + [0] * (len(TRAFFIC_FIELDS) - 1))
        return self.traffic[-1]

    def traffic_history(self, minutes=TRAFFIC_MINUTES, wall=None):
        newest = int((time.time() if wall is None else wall) // 60)
        oldest = newest - max(1, min(TRAFFIC_MINUTES, int(minutes)))
        return {"fields": list(TRAFFIC_FIELDS), "minutes": [row for row in self.traffic if row[0] > oldest]}

    def note_suspect(self, ip, event, now):
        if ip == "unknown":
            return
        denied = event["status"] in (401, 403)
        login = event["method"] == "POST" and event["route"] in LOGIN_ROUTES
        if not denied and not login:
            return
        if ip not in self.suspects:
            if len(self.suspects) >= LOCKDOWN_IPS:
                self.prune_suspects(now)
                if len(self.suspects) >= LOCKDOWN_IPS:
                    return
            self.suspects[ip] = deque(maxlen=500)
        self.suspects[ip].append((now, "denied" if denied else "login"))

    def prune_suspects(self, now):
        for ip in list(self.suspects):
            marks = self.suspects[ip]
            while marks and now - marks[0][0] > LOCKDOWN_WINDOW:
                marks.popleft()
            if not marks:
                del self.suspects[ip]

    def lockdown_candidates(self, now):
        self.prune_suspects(now)
        rows = []
        for ip, marks in self.suspects.items():
            denied = sum(kind == "denied" for _, kind in marks)
            logins = len(marks) - denied
            if denied >= LOCKDOWN_REPORT_MIN or logins >= LOCKDOWN_REPORT_MIN:
                rows.append({"ip": ip, "denied_10m": denied, "logins_10m": logins})
        rows.sort(key=lambda row: row["denied_10m"] + row["logins_10m"], reverse=True)
        return rows[:50]

    def observe_device(self, ip, agent, now=None):
        """Remember which kind of device used an address (from its WebSocket's User-Agent)."""
        label = device_label(agent)
        ip = self.ip_value(ip)
        if label is None or ip is None or not DEVICE_LABEL.fullmatch(label):
            return None
        now = time.time() if now is None else now
        self.observe_ip(ip, now=now, persist=False)
        row = self.ip_history[ip]
        row["requests"] = max(0, row["requests"] - 1)  # observe_ip counted a request; this isn't one
        devices = [device for device in row.setdefault("devices", []) if device["label"] != label]
        row["devices"] = [{"label": label, "last_seen": now}] + devices[:DEVICES_PER_CALLER - 1]
        self.save_ip_history()
        return label

    def clear_ip_history(self):
        self.ip_history.clear()
        self.save_ip_history()

    def forwarding_ready(self, now=None):
        now = time.monotonic() if now is None else now
        return (self.connected and self.updated is not None and 0 <= now-self.updated < 45
                and self.audit_ok and self.stats.get("forwarding_enabled") == 1)

    def public_checked(self, healthy, now=None):
        if healthy:
            self.public_verified_at = time.monotonic() if now is None else now
            self.public_check_failures = 0
        else:
            self.public_check_failures += 1

    def authenticated(self, connection_id, ip):
        self.sessions[connection_id] = {"ip":ip, "authenticated_at":datetime.now(timezone.utc).isoformat()}
        # The device was recorded when its socket opened; keep that address's history current.
        self.observe_ip(ip, authenticated=True)
        self.traffic_row()[7] += 1

    def closed(self, connection_id):
        self.sessions.pop(connection_id, None)

    def update(self, message, counters, now=None):
        now = time.monotonic() if now is None else now
        current = message["stats"]
        if self.previous:
            old, old_time = self.previous
            elapsed = now - old_time
            same_worker = current["uptime_seconds"] >= old["uptime_seconds"] and current["requests"] >= old["requests"] and current["response_bytes"] >= old["response_bytes"]
            self.request_rate = (current["requests"]-old["requests"])*60/elapsed if same_worker and elapsed > 0 else 0
            self.byte_rate = (current["response_bytes"]-old["response_bytes"])/1024/elapsed if same_worker and elapsed > 0 else 0
        delta_requests = delta_bytes = 0
        if self.previous:
            delta_requests = current["requests"]-old["requests"] if same_worker else current["requests"]
            delta_bytes = current["response_bytes"]-old["response_bytes"] if same_worker else current["response_bytes"]
        self.previous = (dict(current), now)
        row = self.traffic_row()
        row[1] += max(0, delta_requests)
        row[2] += max(0, delta_bytes)
        if current.get("events_dropped", 0) > self.stats.get("events_dropped", 0):
            self.loss_observed = now
        self.stats = {**current, **counters}
        timestamp = datetime.now(timezone.utc).isoformat()
        self.clients = {ip: row for ip, row in self.clients.items() if now-row["seen"] <= 900}
        history_changed = False
        for event in message["events"]:
            self.events.append({**event, "observed_at": timestamp})
            self.security_events.append((now, event["status"]))
            row[3] += event["duration_ms"]
            row[4] += 1
            row[5] += event["status"] in (401, 403)
            row[6] += event["status"] >= 500
            ip = event["ip"]
            self.note_suspect(ip, event, now)
            history_changed = self.observe_ip(ip, persist=False) or history_changed
            if ip != "unknown" and (ip in self.clients or len(self.clients) < 1024):
                old = self.clients.get(ip, {"calls":0})
                self.clients[ip] = {"ip":ip, "seen":now, "last_seen":timestamp, "calls":old["calls"]+1}
        if history_changed:
            self.save_ip_history()
        if now - self.traffic_saved >= TRAFFIC_SAVE_INTERVAL:
            self.traffic_saved = now
            self.save_traffic()
        self.updated = now

    def snapshot(self, now=None):
        now = time.monotonic() if now is None else now
        age = round(now-self.updated, 1) if self.updated is not None else None
        public_age = now-self.public_verified_at if self.public_verified_at is not None else None
        public_reachable = (self.connected and self.public_check_failures == 0 and public_age is not None
                            and 0 <= public_age < PUBLIC_HEALTH_MAX_AGE)
        healthy = self.forwarding_ready(now) and public_reachable
        recent = list(self.events)
        clients = [{k:v for k,v in row.items() if k != "seen"} for row in self.clients.values() if now-row["seen"] <= 900]
        clients.sort(key=lambda r:r["last_seen"], reverse=True)
        sessions = list(self.sessions.values()) if self.connected else []
        callers = []
        for row in self.ip_history.values():
            callers.append({"ip": row["ip"], "status": "authenticated" if row["authenticated_at"] is not None else "unknown",
                            "first_seen": datetime.fromtimestamp(row["first_seen"], timezone.utc).isoformat(),
                            "last_seen": datetime.fromtimestamp(row["last_seen"], timezone.utc).isoformat(),
                            "authenticated_at": datetime.fromtimestamp(row["authenticated_at"], timezone.utc).isoformat() if row["authenticated_at"] is not None else None,
                            "requests": row["requests"],
                            "devices": [device["label"] for device in row.get("devices") or []]})
        callers.sort(key=lambda row: row["last_seen"], reverse=True)
        status = "online" if healthy else ("disabled" if self.connected and self.stats.get("forwarding_enabled") == 0 else "waiting" if self.connected and age is None else "stale" if self.connected else "offline")
        window = [status for observed, status in self.security_events if now-observed <= 300]
        rejected = sum(status in (401,403) for status in window)
        failures = sum(status >= 500 for status in window)
        issues = []
        if rejected >= 10: issues.append("At least 10 access-denied responses in 5 minutes; inspect clients")
        if failures >= 5: issues.append("At least 5 server failures in 5 minutes")
        if self.loss_observed is not None and now-self.loss_observed <= 300: issues.append("Relay dropped audit events in the last 5 minutes")
        if len(window) == self.security_events.maxlen: issues.append("Security sample window reached its 5000-event limit")
        return {**self.stats, "version": VERSION,
            "risk_status": "unknown" if not healthy else "attention" if issues else "normal",
            "risk_issues": issues, "denied_5m": rejected, "failures_5m": failures,
            "audit_healthy": self.audit_ok, "status": status, "healthy": healthy,
            "public_reachable": public_reachable, "public_check_age_seconds": round(public_age, 1) if public_age is not None else None,
            "public_check_failures": self.public_check_failures, "automatic_reconnects": self.automatic_reconnects,
            "telemetry_age_seconds": age, "requests_per_minute": round(self.request_rate, 2) if healthy else 0,
            "http_kib_per_second": round(self.byte_rate, 2) if healthy else 0,
            "recent_latency_ms": round(sum(e["duration_ms"] for e in recent)/len(recent), 1) if recent else 0,
            "recent_requests": recent, "recent_request_count": len(recent),
            "caller_ips": callers, "caller_ip_retention_days": 30, "caller_ip_history_ok": self.ip_history_ok,
            "unique_ips_15m":len(clients), "clients":clients[:100],
            "lockdown_candidates": self.lockdown_candidates(now),
            "authenticated_connections":len(sessions), "authenticated_ips":len({s["ip"] for s in sessions if s["ip"] != "unknown"}), "authenticated_sessions":sessions,
            "last_client_ip": recent[-1]["ip"] if recent else "none"}

def application(metrics, token):
    app = web.Application(client_max_size=1024)
    async def read(request):
        value = request.headers.get("Authorization", "")
        if not hmac.compare_digest(value.encode("utf-8"), ("Bearer " + token).encode("ascii")):
            return web.json_response({"error":"unauthorized"}, status=401, headers={"Cache-Control":"no-store"})
        return web.json_response(metrics.snapshot(), headers={"Cache-Control":"no-store", "X-Content-Type-Options":"nosniff"})
    async def clear_ip_history(request):
        value = request.headers.get("Authorization", "")
        if not hmac.compare_digest(value.encode("utf-8"), ("Bearer " + token).encode("ascii")):
            return web.json_response({"error":"unauthorized"}, status=401, headers={"Cache-Control":"no-store"})
        metrics.clear_ip_history()
        if not metrics.ip_history_ok:
            return web.json_response({"error":"storage_unavailable"}, status=503, headers={"Cache-Control":"no-store"})
        return web.json_response({"cleared":True}, headers={"Cache-Control":"no-store", "X-Content-Type-Options":"nosniff"})
    async def history(request):
        value = request.headers.get("Authorization", "")
        if not hmac.compare_digest(value.encode("utf-8"), ("Bearer " + token).encode("ascii")):
            return web.json_response({"error":"unauthorized"}, status=401, headers={"Cache-Control":"no-store"})
        try:
            minutes = int(request.query.get("minutes", TRAFFIC_MINUTES))
        except ValueError:
            minutes = TRAFFIC_MINUTES
        return web.json_response(metrics.traffic_history(minutes), headers={"Cache-Control":"no-store", "X-Content-Type-Options":"nosniff"})
    app.router.add_get("/metrics", read)
    app.router.add_get("/history", history)
    app.router.add_post("/ip-history/clear", clear_ip_history)
    return app
