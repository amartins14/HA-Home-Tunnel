"""Checks for traffic history, lockdowns, blocked addresses, key rotation, unpairing and alerts."""
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "home-assistant" / "connector")]
from aiohttp import web
import service
from metrics import Metrics


def telemetry(requests, events, uptime=100, response_bytes=0):
    stats = {"requests": requests, "errors_4xx": 0, "errors_5xx": 0, "response_bytes": response_bytes, "active_http": 0,
             "active_ws": 0, "queued_http": 0, "events_dropped": 0, "uptime_seconds": uptime, "forwarding_enabled": 1}
    return {"type": "telemetry", "stats": stats, "events": events}


def event(ip="203.0.113.9", status=200, method="GET", route="/api/states", duration=10):
    return {"ip": ip, "method": method, "route": route, "status": status, "duration_ms": duration,
            "request_bytes": 0, "response_bytes": 0}


class Request:
    def __init__(self, body):
        self.body = body

    async def json(self):
        return self.body


class TrafficAndLockdownMetricsTests(unittest.TestCase):
    def test_traffic_history_counts_minutes_and_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "traffic.json"
            metrics = Metrics(Path(directory) / "ips.json", path)
            metrics.update(telemetry(10, []), {}, now=0)
            metrics.update(telemetry(25, [event(status=401, duration=30), event(status=502, duration=50)], response_bytes=4096), {}, now=10)
            row = metrics.traffic[-1]
            # The first sample only sets the baseline: relay counters run since the relay started.
            self.assertEqual(row[1:7], [15, 4096, 80, 2, 1, 1])
            metrics.save_traffic()
            restored = Metrics(Path(directory) / "ips.json", path)
            self.assertEqual(restored.traffic_history()["minutes"][-1], row)
            self.assertEqual(restored.traffic_history()["fields"][0], "minute")

    def test_traffic_history_drops_old_or_malformed_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "traffic.json"
            minute = int(time.time() // 60)
            path.write_text(json.dumps([[minute - 3000, 1, 0, 0, 0, 0, 0, 0], ["x"], [minute - 5, 2, 0, 0, 0, 0, 0, 0],
                                        [minute - 6, 3, 0, 0, 0, 0, 0, 0]]))
            metrics = Metrics(Path(directory) / "ips.json", path)
            self.assertEqual([row[0] for row in metrics.traffic], [minute - 5])

    def test_lockdown_candidates_count_denied_answers_and_login_posts_per_caller(self):
        with tempfile.TemporaryDirectory() as directory:
            metrics = Metrics(Path(directory) / "ips.json", Path(directory) / "traffic.json")
            events = [event(status=401) for _ in range(4)]
            events += [event(ip="198.51.100.2", method="POST", route="/auth/login_flow/[flow-id]") for _ in range(3)]
            events += [event(ip="192.0.2.5", status=200), event(ip="unknown", status=403)]
            metrics.update(telemetry(9, events), {}, now=1000)
            rows = {row["ip"]: row for row in metrics.snapshot(now=1000)["lockdown_candidates"]}
            self.assertEqual(rows["203.0.113.9"]["denied_10m"], 4)
            self.assertEqual(rows["198.51.100.2"]["logins_10m"], 3)
            self.assertNotIn("192.0.2.5", rows)
            self.assertNotIn("unknown", rows)
            self.assertEqual(metrics.lockdown_candidates(now=1000 + 601), [])


class DeviceTests(unittest.TestCase):
    def test_user_agents_become_short_labels(self):
        from metrics import device_label
        cases = {
            "Home Assistant/2025.11.2 (io.robbie.HomeAssistant; build:2025.1489; iOS 18.1.0) Alamofire/5.10.2": "Home Assistant app · iOS 18",
            "Home Assistant/2025.11.1-full (Android 14; Pixel 8)": "Home Assistant app · Android 14",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1": "Safari · iPhone",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0 Mobile/15E148 Safari/604.1": "Chrome · iPhone",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36 Edg/131.0": "Edge · Windows",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15": "Safari · macOS",
            "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0": "Firefox · Linux",
            "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0 Mobile Safari/537.36": "Samsung Internet · Android 14",
            "curl/8.5.0": "curl",
            "": None,
            None: None,
        }
        for agent, label in cases.items():
            with self.subTest(agent=agent):
                self.assertEqual(device_label(agent), label)

    def test_devices_are_kept_per_caller_and_survive_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ips.json"
            metrics = Metrics(path, Path(directory) / "traffic.json")
            iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"
            app = "Home Assistant/2025.11.2 (io.robbie.HomeAssistant; build:1; iOS 18.1.0)"
            start = time.time() - 60
            metrics.observe_device("203.0.113.7", iphone, now=start)
            metrics.observe_device("203.0.113.7", app, now=start + 1)
            metrics.observe_device("203.0.113.7", iphone, now=start + 2)
            for n in range(6):
                metrics.observe_device("203.0.113.7", f"tool{n}/1.0", now=start + 3 + n)
            callers = {row["ip"]: row for row in metrics.snapshot()["caller_ips"]}
            self.assertEqual(len(callers["203.0.113.7"]["devices"]), 4, "only the latest four devices are kept")
            self.assertEqual(callers["203.0.113.7"]["requests"], 0, "opening a socket isn't counted as a request")
            restored = Metrics(path, Path(directory) / "traffic.json")
            self.assertEqual(restored.snapshot()["caller_ips"][0]["devices"], callers["203.0.113.7"]["devices"])
            self.assertIsNone(metrics.observe_device("not-an-ip", iphone))

    def test_history_without_devices_still_loads(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ips.json"
            now = time.time()
            path.write_text(json.dumps([{"ip": "203.0.113.7", "first_seen": now - 10, "last_seen": now, "authenticated_at": None, "requests": 3}]))
            row = Metrics(path, Path(directory) / "traffic.json").snapshot()["caller_ips"][0]
            self.assertEqual((row["requests"], row["devices"]), (3, []))


class ServiceFeatureTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Keep the event log and uptime out of /data during tests.
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.logs = Path(directory.name)
        for name, file in (("EVENTS", "events.json"), ("UPTIME", "uptime.json")):
            patcher = patch.object(service, name, self.logs / file)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_block_ranges_are_normalized_and_bounded(self):
        self.assertEqual(service.normalize_cidr("203.0.113.7"), "203.0.113.7")
        self.assertEqual(service.normalize_cidr("203.0.113.9/24"), "203.0.113.0/24")
        self.assertEqual(service.normalize_cidr("::ffff:203.0.113.7"), "203.0.113.7")
        self.assertEqual(service.normalize_cidr("2001:db8::1/32"), "2001:db8::/32")
        for value in ("", "nope", "10.0.0.0/7", "::/0", "1.2.3.4/33", None, "1" * 80):
            with self.assertRaises(ValueError):
                service.normalize_cidr(value)

    def test_lockdown_blocks_noisy_callers_but_never_signed_in_ones(self):
        settings = {"enabled": True, "denied": 20, "logins": 15, "minutes": 60}
        metrics = {"caller_ips": [{"ip": "198.51.100.2", "status": "authenticated"}],
                   "lockdown_candidates": [{"ip": "203.0.113.9", "denied_10m": 25, "logins_10m": 0},
                                           {"ip": "198.51.100.2", "denied_10m": 50, "logins_10m": 0},
                                           {"ip": "192.0.2.5", "denied_10m": 3, "logins_10m": 15},
                                           {"ip": "192.0.2.6", "denied_10m": 3, "logins_10m": 4}]}
        rows = []
        added = service.apply_lockdown(metrics, rows, settings, now=1000)
        self.assertEqual([row["cidr"] for row in added], ["203.0.113.9", "192.0.2.5"])
        self.assertTrue(all(row["until"] == 1000 + 3600 and row["source"] == "auto" for row in added))
        self.assertEqual(service.apply_lockdown(metrics, rows, settings, now=1001), [], "blocked callers are not added twice")
        self.assertEqual(service.apply_lockdown(metrics, [], {**settings, "enabled": False}), [])

    def test_expired_blocks_are_dropped_and_ranges_match(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "blocks.json"
            path.write_text(json.dumps([{"cidr": "203.0.113.0/24", "until": None}, {"cidr": "192.0.2.1", "until": 10}, {"cidr": "bad"}]))
            with patch.object(service, "BLOCKS", path):
                rows = service.read_blocks(now=100)
            self.assertEqual([row["cidr"] for row in rows], ["203.0.113.0/24"])
            self.assertTrue(service.blocked(rows, "203.0.113.200"))
            self.assertFalse(service.blocked(rows, "2001:db8::1"))

    def test_settings_validate_lockdown_and_notifications(self):
        events = {name: True for name in service.NOTIFY_EVENTS}
        service.valid_lockdown({"enabled": True, "denied": 20, "logins": 15, "minutes": 60})
        service.valid_notifications({"target": "notify.mobile_app_phone", "events": events})
        service.valid_notifications({"target": "", "events": events})
        for bad in ({"enabled": True, "denied": 1, "logins": 15, "minutes": 60},
                    {"enabled": "yes", "denied": 20, "logins": 15, "minutes": 60}, {}):
            with self.assertRaises(ValueError):
                service.valid_lockdown(bad)
        for target in ("notify.Bad", "light.kitchen", "notify.a/b", "persistent_notification.create"):
            with self.assertRaises(ValueError):
                service.valid_notifications({"target": target, "events": events})

    def test_country_settings_are_validated(self):
        self.assertEqual(service.valid_countries({"mode": "block", "codes": ["RU", "CN", "RU"], "minutes": None}),
                         {"mode": "block", "codes": ["CN", "RU"], "minutes": None})
        for bad in ({"mode": "allow", "codes": [], "minutes": 60}, {"mode": "block", "codes": ["usa"], "minutes": 60},
                    {"mode": "block", "codes": ["us"], "minutes": 60}, {"mode": "deny", "codes": [], "minutes": 60},
                    {"mode": "block", "codes": [], "minutes": 5}, {"mode": "block", "codes": []}):
            with self.assertRaises(ValueError):
                service.valid_countries(bad)

    def test_location_answer_gives_label_and_country_code(self):
        self.assertEqual(service.parse_location({"city": "Porto", "region": "Porto", "country_name": "Portugal", "country_code": "pt"}),
                         ("Porto, Portugal", "PT"))
        self.assertEqual(service.parse_location({"error": True}), ("", ""))
        self.assertEqual(service.parse_location({"country_code": "XYZ"}), ("", ""))

    def test_country_rules_block_on_first_sight(self):
        found = {"203.0.113.7": ("Moscow, Russia", "RU"), "198.51.100.2": ("Porto, Portugal", "PT"),
                 "192.0.2.5": ("", ""), "192.0.2.9": ("Berlin, Germany", "DE")}
        rows = []
        added = service.apply_country_rules(found, rows, {"mode": "block", "codes": ["RU", "DE"], "minutes": 60}, now=1000)
        # Signed-in addresses are blocked too (192.0.2.9 stands for one); unknown countries are not.
        self.assertEqual([row["cidr"] for row in added], ["203.0.113.7", "192.0.2.9"])
        self.assertEqual((added[0]["source"], added[0]["until"]), ("country", 1000 + 3600))
        self.assertIn("Russia (RU)", added[0]["reason"])
        allow = service.apply_country_rules(found, [], {"mode": "allow", "codes": ["PT"], "minutes": None}, now=1000)
        self.assertEqual(sorted(row["cidr"] for row in allow), ["192.0.2.9", "203.0.113.7"])
        self.assertIsNone(allow[0]["until"])
        self.assertEqual(service.apply_country_rules(found, [], {"mode": "off", "codes": ["RU"], "minutes": 60}), [])

    async def test_location_lookups_share_the_daily_cap_and_cache(self):
        with patch.object(service, "GEOLOCATION_CACHE", {"8.8.8.8": (time.monotonic(), "Porto, Portugal", "PT")}), \
                patch.object(service, "GEOLOCATION_LOOKUP_COUNT", service.GEOLOCATION_LOOKUP_LIMIT), \
                patch.object(service, "GEOLOCATION_WINDOW_STARTED", time.monotonic()):
            found = await service.lookup_locations(["8.8.8.8", "1.1.1.1", "10.0.0.1"])
        self.assertEqual(found, {"8.8.8.8": ("Porto, Portugal", "PT")}, "cached answers are free; the cap stops new lookups")

    def test_refused_sockets_from_the_relay_are_checked_and_newest_first(self):
        rows = service.clean_refusals([
            {"at": "2026-11-27T18:00:00Z", "ip": "203.0.113.7", "route": "/api/events/websocket", "reason": "path"},
            {"at": "2026-11-27T18:01:00Z", "ip": "198.51.100.2", "route": "/api/websocket", "reason": "origin"},
            {"at": "x", "ip": "1.2.3.4", "route": "no-slash", "reason": "path"},
            {"at": "x", "ip": "1.2.3.4", "route": "/ok", "reason": "other"},
            {"at": "x", "ip": "1.2.3.4", "route": "/bad\nline", "reason": "path"},
            "junk",
        ])
        self.assertEqual([row["reason"] for row in rows], ["origin", "path"])
        self.assertEqual(service.clean_refusals(None), [])
        self.assertEqual(len(service.clean_refusals([{"at": "t", "ip": "1.1.1.1", "route": "/x", "reason": "path"}] * 50)), 20)

    async def test_refused_sockets_are_fetched_from_the_relay(self):
        with tempfile.TemporaryDirectory() as directory:
            self.paired_state(directory)

            async def relay(connection, action, payload=None, authenticate=True, token=None):
                self.assertEqual(action, "refused")
                return 200, {"refused": [{"at": "t", "ip": "203.0.113.7", "route": "/api/events/websocket", "reason": "path"}], "native_clients": False}
            with patch.object(service, "relay_request", relay):
                await service.refresh_refused()
            self.assertEqual(service.REFUSED["items"][0]["route"], "/api/events/websocket")
            service.REFUSED.update({"items": [], "at": None, "checked": 0.0})

    async def fake_ipapi(self, answers):
        """A local stand-in for ipapi.co; answers maps IP -> (status, json)."""
        seen = []

        async def handler(request):
            ip = request.match_info["ip"]
            seen.append(ip)
            status, body = answers.get(ip, (200, {"country_code": "PT", "country_name": "Portugal", "city": "Porto"}))
            return web.json_response(body, status=status)
        app = web.Application()
        app.router.add_get("/{ip}/json/", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        self.addAsyncCleanup(runner.cleanup)
        port = site._server.sockets[0].getsockname()[1]
        return f"http://127.0.0.1:{port}/{{}}/json/", seen

    async def test_lookups_run_one_at_a_time_and_pause_when_rate_limited(self):
        url, seen = await self.fake_ipapi({"1.1.1.1": (429, {"error": True, "reason": "RateLimited"})})
        state = {"GEOLOCATION_URL": url, "GEOLOCATION_CACHE": {}, "GEOLOCATION_LOOKUP_COUNT": 0,
                 "GEOLOCATION_WINDOW_STARTED": time.monotonic(),
                 "GEOLOCATION_STATUS": {"error": None, "at": None, "paused_until": 0.0}}
        with patch.multiple(service, **state):
            found = await service.lookup_locations(["8.8.8.8", "1.1.1.1", "9.9.9.9"])
            self.assertEqual(found, {"8.8.8.8": ("Porto, Portugal", "PT")})
            self.assertEqual(seen, ["8.8.8.8", "1.1.1.1"], "lookups stop at the first rate-limit answer")
            self.assertNotIn("1.1.1.1", service.GEOLOCATION_CACHE, "a rate-limited address is retried, not cached empty")
            self.assertEqual(service.GEOLOCATION_LOOKUP_COUNT, 1, "unused lookups go back to the daily budget")
            self.assertEqual(service.GEOLOCATION_STATUS["error"], "rate_limited")
            self.assertEqual(await service.lookup_locations(["9.9.9.9"]), {}, "no new lookups while paused")
            self.assertEqual(len(seen), 2)

    async def test_geolocation_endpoint_accepts_repeated_parameters(self):
        url, _ = await self.fake_ipapi({})
        with tempfile.TemporaryDirectory() as directory:
            settings = Path(directory) / "settings.json"
            settings.write_text(json.dumps({"geolocation_enabled": True}))
            state = {"GEOLOCATION_URL": url, "GEOLOCATION_CACHE": {}, "GEOLOCATION_LOOKUP_COUNT": 0, "SETTINGS": settings,
                     "GEOLOCATION_WINDOW_STARTED": time.monotonic(), "GEOLOCATION_STATUS": {"error": None, "at": None, "paused_until": 0.0}}
            from aiohttp.test_utils import make_mocked_request
            with patch.multiple(service, **state):
                response = await service.geolocation(make_mocked_request("GET", "/api/geolocation?ips=8.8.8.8&ips=1.1.1.1,9.9.9.9"))
            self.assertEqual(json.loads(response.text)["countries"], {"8.8.8.8": "PT", "1.1.1.1": "PT", "9.9.9.9": "PT"})

    async def test_large_home_assistant_answers_are_read_whole(self):
        services = [{"domain": f"domain_{n}", "services": {f"service_{m}": {"description": "x" * 200} for m in range(40)}} for n in range(60)]
        services.append({"domain": "notify", "services": {"mobile_app_phone": {}, "send_message": {}}})

        async def handler(request):
            return web.json_response(services)
        app = web.Application()
        app.router.add_get("/core/api/services", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        self.addAsyncCleanup(runner.cleanup)
        port = site._server.sockets[0].getsockname()[1]
        with patch.object(service, "SUPERVISOR_API", f"http://127.0.0.1:{port}/core/api"), patch.object(service, "SUPERVISOR_TOKEN", "t"):
            data = json.loads((await service.notify_targets(None)).text)
        self.assertGreater(len(json.dumps(services)), 300000)
        self.assertEqual(data, {"targets": ["persistent_notification", "notify.mobile_app_phone"], "error": None})

    def test_supervisor_token_is_taken_out_of_the_environment(self):
        with patch.dict(os.environ, {"HOME_TUNNEL_SUPERVISOR_TOKEN": "secret", "SUPERVISOR_TOKEN": "x"}):
            service.take_supervisor_token()
            self.assertEqual(service.SUPERVISOR_TOKEN, "secret")
            self.assertNotIn("HOME_TUNNEL_SUPERVISOR_TOKEN", os.environ)
            self.assertNotIn("SUPERVISOR_TOKEN", os.environ)
        service.SUPERVISOR_TOKEN = ""

    def test_connector_environment_never_gets_the_supervisor_token(self):
        source = (ROOT / "home-assistant" / "connector" / "service.py").read_text()
        self.assertIn('if key not in ("HOME_TUNNEL_SUPERVISOR_TOKEN", "SUPERVISOR_TOKEN", "HASSIO_TOKEN")', source)
        self.assertIn("HOME_TUNNEL_SUPERVISOR_TOKEN", (ROOT / "home-assistant" / "connector" / "connector.py").read_text())

    def paired_state(self, directory):
        state = Path(directory)
        (state / "tunnel-token.txt").write_text("a" * 64 + "\n")
        (state / "connection.json").write_text(json.dumps({"public_url": "https://tunnel.example.test"}))
        names = {"TOKEN": "tunnel-token.txt", "TOKEN_NEXT": "tunnel-token.next", "CONNECTION": "connection.json",
                 "FINALIZE": "finalize.json", "PAIRING": "pairing.json", "STATUS": "status.json",
                 "RELAY_VERSION": "relay-version.json", "RELAY_HEALTH": "relay-health.json"}
        patches = [patch.object(service, key, state / name) for key, name in names.items()] + [patch.object(service, "child", None)]
        for item in patches:
            item.start()
        self.addCleanup(lambda: [item.stop() for item in patches])
        return state

    async def test_dashboard_read_endpoints_answer_on_a_paired_install(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.paired_state(directory)
            extra = {name: state / f"{name.lower()}.json" for name in ("SETTINGS", "RELAY_RELEASE", "BLOCKS", "ALERTS")}
            patches = [patch.object(service, name, path) for name, path in extra.items()]
            patches.append(patch.object(service, "APP_CONFIG", state / "missing-config.yaml"))
            patches.append(patch.dict(os.environ, {"HOMEASSISTANT_URL": "http://homeassistant:8123"}))
            for item in patches:
                item.start()
            self.addCleanup(lambda: [item.stop() for item in patches])
            (state / "settings.json").write_text(json.dumps({"homeassistant_url": "http://homeassistant:8123", "app_option_url": "http://homeassistant:8123", "geolocation_enabled": True, "app_option_geolocation": False,
                                                              "countries": {"mode": "block", "codes": ["RU"], "minutes": 60}}))
            data = json.loads((await service.status(None)).text)
            self.assertTrue(data["paired"])
            self.assertTrue(data["geolocation_enabled"])
            self.assertEqual(data["countries"]["codes"], ["RU"])
            self.assertEqual(set(data["lockdown"]), {"enabled", "denied", "logins", "minutes"})
            self.assertIn("notifications_available", data)
            blocks = json.loads((await service.list_blocks(None)).text)
            self.assertEqual(blocks["blocks"], [])

    async def test_rotation_confirms_new_key_before_using_it(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.paired_state(directory)
            new = "b" * 64
            calls = []

            async def relay(connection, action, payload=None, authenticate=True, token=None):
                calls.append((action, token))
                return (200, {"connector_token": new}) if action == "rotate" else (200, {})
            with patch.object(service, "relay_request", relay):
                response = await service.rotate_key(None)
            self.assertEqual(json.loads(response.text), {"rotated": True})
            self.assertEqual(calls, [("rotate", None), ("confirm_rotation", new)])
            self.assertEqual((state / "tunnel-token.txt").read_text().strip(), new)
            self.assertFalse((state / "tunnel-token.next").exists())

    async def test_refused_confirmation_keeps_the_old_key(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.paired_state(directory)

            async def relay(connection, action, payload=None, authenticate=True, token=None):
                return (200, {"connector_token": "b" * 64}) if action == "rotate" else (403, {})
            with patch.object(service, "relay_request", relay):
                with self.assertRaises(web.HTTPBadGateway):
                    await service.rotate_key(None)
            self.assertEqual((state / "tunnel-token.txt").read_text().strip(), "a" * 64)
            self.assertFalse((state / "tunnel-token.next").exists())

    async def test_interrupted_rotation_is_finished_later(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.paired_state(directory)
            (state / "tunnel-token.next").write_text("c" * 64)

            async def relay(connection, action, payload=None, authenticate=True, token=None):
                return (200, {}) if action == "confirm_rotation" and token == "c" * 64 else (500, {})
            with patch.object(service, "relay_request", relay):
                await service.reconcile_rotation()
            self.assertEqual((state / "tunnel-token.txt").read_text().strip(), "c" * 64)

    async def test_old_relay_rotation_is_explained(self):
        with tempfile.TemporaryDirectory() as directory:
            self.paired_state(directory)

            async def relay(connection, action, payload=None, authenticate=True, token=None):
                return 404, {}
            with patch.object(service, "relay_request", relay):
                with self.assertRaises(web.HTTPConflict) as raised:
                    await service.rotate_key(None)
            self.assertIn("0.5.0", raised.exception.text)

    async def test_unpair_clears_local_pairing_only_after_relay_agrees_or_when_forced(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.paired_state(directory)

            async def refuses(connection, action, payload=None, authenticate=True, token=None):
                return 404, {}

            async def agrees(connection, action, payload=None, authenticate=True, token=None):
                return 200, {}
            with patch.object(service, "relay_request", refuses):
                with self.assertRaises(web.HTTPBadGateway):
                    await service.unpair(Request({}))
                self.assertTrue((state / "tunnel-token.txt").exists())
                response = await service.unpair(Request({"force": True}))
                self.assertEqual(json.loads(response.text), {"unpaired": True, "relay_reset": False})
            self.assertFalse((state / "tunnel-token.txt").exists() or (state / "connection.json").exists())
            (state / "tunnel-token.txt").write_text("a" * 64)
            (state / "connection.json").write_text(json.dumps({"public_url": "https://tunnel.example.test"}))
            with patch.object(service, "relay_request", agrees):
                response = await service.unpair(Request({}))
            self.assertTrue(json.loads(response.text)["relay_reset"])

    async def test_blocks_are_sent_to_the_relay_with_utc_expiry(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.paired_state(directory)
            sent = []

            async def relay(connection, action, payload=None, authenticate=True, token=None):
                sent.append((action, payload))
                return 200, {}
            with patch.object(service, "BLOCKS", state / "blocks.json"), patch.object(service, "relay_request", relay):
                await service.add_block(Request({"cidr": "203.0.113.7", "minutes": 60}))
                await service.add_block(Request({"cidr": "198.51.100.0/24", "minutes": None, "reason": "scanner"}))
                with self.assertRaises(web.HTTPBadRequest):
                    await service.add_block(Request({"cidr": "0.0.0.0/0"}))
                await service.remove_block(Request({"cidr": "203.0.113.7"}))
            self.assertEqual(sent[0][0], "blocks")
            self.assertRegex(sent[0][1]["blocks"][0]["until"], r"\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\Z")
            self.assertEqual(sent[-1][1], {"blocks": [{"cidr": "198.51.100.0/24", "until": None}]})
            self.assertTrue(service.BLOCK_SYNC["ok"])

    async def test_alerts_notify_once_for_new_sign_ins_and_offline(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.paired_state(directory)
            sent = []

            async def notify(event, title, message, target=None, kind=None):
                sent.append(event)
                return True
            metrics = {"caller_ips": [{"ip": "203.0.113.7", "status": "authenticated"}], "risk_issues": []}
            with patch.object(service, "ALERTS", state / "alerts.json"), patch.object(service, "RELAY_RELEASE", state / "release.json"), \
                    patch.object(service, "notify", notify):
                (state / "status.json").write_text(json.dumps({"connection": "disconnected", "updated_at": 1000}))
                await service.evaluate_alerts(metrics, now=1100)
                self.assertEqual(sent, [], "first run remembers existing sign-ins; offline not yet long enough")
                metrics["caller_ips"].append({"ip": "198.51.100.2", "status": "authenticated"})
                await service.evaluate_alerts(metrics, now=1300)
                await service.evaluate_alerts(metrics, now=1310)
                self.assertEqual(sent, ["offline", "signin"])
                (state / "status.json").write_text(json.dumps({"connection": "connected", "updated_at": 1400}))
                await service.evaluate_alerts(metrics, now=1405)
                self.assertEqual(sent, ["offline", "signin", "offline"])


    def test_travel_entries_are_validated_and_expired_ones_dropped(self):
        now = 1_000_000
        travel = service.valid_travel([{"code": "ES", "until": now + 86400}, {"code": "ES", "until": now + 2 * 86400},
                                       {"code": "FR", "until": now - 1}], now)
        self.assertEqual(travel, [{"code": "ES", "until": now + 2 * 86400}])
        for bad in ([{"code": "es", "until": now + 60}], [{"code": "ES", "until": now + 91 * 86400}],
                    [{"code": "ES"}], "ES", [{"code": "ES", "until": "soon"}]):
            with self.assertRaises(ValueError):
                service.valid_travel(bad, now)

    def test_travel_mode_lets_a_blocked_country_through_until_it_ends(self):
        found = {"203.0.113.7": ("", "ES"), "198.51.100.2": ("", "RU")}
        policy = {"mode": "block", "codes": ["ES", "RU"], "minutes": 60}
        travel = [{"code": "ES", "until": 2000}]
        added = service.apply_country_rules(found, [], policy, now=1000, travel=travel)
        self.assertEqual([row["cidr"] for row in added], ["198.51.100.2"])
        later = service.apply_country_rules(found, [], policy, now=2001, travel=travel)
        self.assertEqual(sorted(row["cidr"] for row in later), ["198.51.100.2", "203.0.113.7"])
        allow = service.apply_country_rules(found, [], {"mode": "allow", "codes": ["PT"], "minutes": 60}, now=1000, travel=travel)
        self.assertEqual([row["cidr"] for row in allow], ["198.51.100.2"])

    def test_country_blocks_know_their_country(self):
        self.assertEqual(service.block_country({"source": "country", "reason": "Country: ES is blocked"}), "ES")
        self.assertEqual(service.block_country({"source": "country", "reason": "Country: Madrid, Spain (ES) is not on the allowed list"}), "ES")
        self.assertIsNone(service.block_country({"source": "manual", "reason": "Country: ES is blocked"}))
        self.assertIsNone(service.block_country({"source": "country", "reason": "scanner"}))

    async def test_turning_on_travel_mode_lifts_country_blocks_and_is_logged(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.paired_state(directory)
            sent = []

            async def relay(connection, action, payload=None, authenticate=True, token=None):
                sent.append(payload)
                return 200, {}
            now = time.time()
            (state / "blocks.json").write_text(json.dumps([
                {"cidr": "203.0.113.7", "until": None, "reason": "Country: ES is blocked", "source": "country", "created": now},
                {"cidr": "198.51.100.2", "until": None, "reason": "Country: RU is blocked", "source": "country", "created": now},
                {"cidr": "192.0.2.1", "until": None, "reason": "Blocked by you", "source": "manual", "created": now}]))
            (state / "settings.json").write_text(json.dumps({"homeassistant_url": "http://homeassistant:8123", "app_option_url": "http://homeassistant:8123",
                                                              "countries": {"mode": "block", "codes": ["ES", "RU"], "minutes": 60}}))
            with patch.object(service, "BLOCKS", state / "blocks.json"), patch.object(service, "SETTINGS", state / "settings.json"),                     patch.object(service, "APP_CONFIG", state / "missing-config.yaml"), patch.object(service, "relay_request", relay),                     patch.dict(os.environ, {"HOMEASSISTANT_URL": "http://homeassistant:8123"}):
                response = await service.update_settings(Request({"travel": [{"code": "ES", "until": now + 7 * 86400}]}))
                self.assertEqual(json.loads(response.text)["travel"][0]["code"], "ES")
                self.assertEqual([row["cidr"] for row in service.read_blocks()], ["198.51.100.2", "192.0.2.1"])
                self.assertEqual(len(sent[-1]["blocks"]), 2)
                titles = [row["title"] for row in service.read_events()]
                self.assertEqual(titles, ["Lifted 1 country block", "Travel mode: ES allowed"])
                # Taking RU off the rule lifts its block too; the manual block stays.
                response = await service.update_settings(Request({"countries": {"mode": "block", "codes": ["ES"], "minutes": 60}}))
                self.assertEqual(json.loads(response.text)["lifted"], 1)
                self.assertEqual([row["cidr"] for row in service.read_blocks()], ["192.0.2.1"])
                self.assertEqual(service.read_events()[0]["title"], "Lifted 1 country block")
                service.expire_travel(now + 8 * 86400)
                self.assertEqual(service.app_settings()["travel"], [])
                self.assertEqual(service.read_events()[0]["title"], "Travel mode for ES ended")

    async def test_events_are_logged_newest_first_even_with_notifications_off(self):
        with patch.object(service, "SETTINGS", self.logs / "settings.json"):
            self.assertFalse(await service.notify("blocked", "Home Tunnel blocked an address", "203.0.113.7 was blocked."))
            await service.notify("offline", "Home Tunnel is back online", "Reached the relay.", kind="online")
            await service.notify("test", "Test", "Not logged")
        events = service.read_events()
        self.assertEqual([row["kind"] for row in events], ["online", "blocked"])
        for n in range(service.EVENT_LIMIT + 5):
            service.log_event("forwarding", f"Event {n}")
        self.assertEqual(len(service.read_events()), service.EVENT_LIMIT)
        self.assertEqual(service.read_events()[0]["title"], f"Event {service.EVENT_LIMIT + 4}")

    def test_uptime_is_kept_as_runs_with_the_worst_state_per_minute(self):
        with tempfile.TemporaryDirectory() as directory:
            state = self.paired_state(directory)
            base = int(time.time() // 60) * 60

            def at(minute, connected=True, forwarding=True, second=0):
                now = base + minute * 60 + second
                (state / "status.json").write_text(json.dumps({"connection": "connected" if connected else "disconnected",
                                                               "updated_at": now, "forwarding_enabled": forwarding}))
                service.record_uptime(now)
            at(0); at(0, second=30); at(1); at(2, connected=False); at(2, second=30); at(3, forwarding=False); at(6)
            m = base // 60
            self.assertEqual(service.read_uptime(base + 400), [[m, m + 1, 2], [m + 2, m + 2, 0], [m + 3, m + 3, 1], [m + 6, m + 6, 2]])


if __name__ == "__main__":
    unittest.main(verbosity=2)
