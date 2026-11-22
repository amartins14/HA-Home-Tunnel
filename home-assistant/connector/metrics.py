"""Read-only dashboard telemetry on the private HA app network."""
from collections import deque
from datetime import datetime, timezone
import hmac
import time
from aiohttp import web

VERSION = "0.4.0-dev"
PUBLIC_HEALTH_MAX_AGE = 90

class Metrics:
    def __init__(self):
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
        self.previous = (dict(current), now)
        if current.get("events_dropped", 0) > self.stats.get("events_dropped", 0):
            self.loss_observed = now
        self.stats = {**current, **counters}
        timestamp = datetime.now(timezone.utc).isoformat()
        self.clients = {ip: row for ip, row in self.clients.items() if now-row["seen"] <= 900}
        for event in message["events"]:
            self.events.append({**event, "observed_at": timestamp})
            self.security_events.append((now, event["status"]))
            ip = event["ip"]
            if ip != "unknown" and (ip in self.clients or len(self.clients) < 1024):
                old = self.clients.get(ip, {"calls":0})
                self.clients[ip] = {"ip":ip, "seen":now, "last_seen":timestamp, "calls":old["calls"]+1}
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
            "unique_ips_15m":len(clients), "clients":clients[:100],
            "authenticated_connections":len(sessions), "authenticated_ips":len({s["ip"] for s in sessions if s["ip"] != "unknown"}), "authenticated_sessions":sessions,
            "last_client_ip": recent[-1]["ip"] if recent else "none"}

def application(metrics, token):
    app = web.Application(client_max_size=1024)
    async def read(request):
        value = request.headers.get("Authorization", "")
        if not hmac.compare_digest(value.encode("utf-8"), ("Bearer " + token).encode("ascii")):
            return web.json_response({"error":"unauthorized"}, status=401, headers={"Cache-Control":"no-store"})
        return web.json_response(metrics.snapshot(), headers={"Cache-Control":"no-store", "X-Content-Type-Options":"nosniff"})
    app.router.add_get("/metrics", read)
    return app
