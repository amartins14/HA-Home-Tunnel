import asyncio
import base64
import importlib.util
import json
import gzip
import random
import logging
from pathlib import Path
import ssl
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "home-assistant" / "connector")]
import aiohttp
from aiohttp import web
from yarl import URL
from yarl import URL
import connector
import policy
import service
from metrics import Metrics, application
spec = importlib.util.spec_from_file_location("rotate_key", ROOT / "tools" / "rotate_key.py")
rotation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rotation)

RID = "a" * 32

def request(**changes):
    message = {"type": "http", "id": RID, "method": "GET", "path": "/api/", "headers": {}, "body": ""}
    message.update(changes)
    return message

class SecurityPolicyTests(unittest.TestCase):
    def test_root_only_options_use_the_explicit_url_environment(self):
        original_read_text = Path.read_text
        def read_text(path, *args, **kwargs):
            if path.name == "options.json" and path.parent.name == "data":
                raise PermissionError("root-only supervisor options")
            return original_read_text(path, *args, **kwargs)
        with patch.dict("os.environ", {"HOMEASSISTANT_URL": "http://ha.example.test:8123"}):
            with patch.object(Path, "read_text", read_text):
                self.assertEqual(policy._settings()["homeassistant_url"], "http://ha.example.test:8123")
    def test_web_ui_setting_overrides_initial_option(self):
        original_read_text = Path.read_text
        def read_text(path, *args, **kwargs):
            if path.name == "options.json" and path.parent.name == "data":
                raise PermissionError("root-only supervisor options")
            if path.name == "settings.json" and path.parent.name == "state":
                return '{"homeassistant_url":"https://ha.example.test:8443"}'
            return original_read_text(path, *args, **kwargs)
        with patch.dict("os.environ", {"HOMEASSISTANT_URL": "http://legacy.example.test:8123"}):
            with patch.object(Path, "read_text", read_text):
                self.assertEqual(policy._settings()["homeassistant_url"], "https://ha.example.test:8443")
    def test_updated_app_option_overrides_saved_dashboard_value(self):
        original_read_text = Path.read_text
        def read_text(path, *args, **kwargs):
            if path.name == "options.json" and path.parent.name == "data":
                return '{"homeassistant_url":"http://new-option.example.test:8123"}'
            if path.name == "settings.json" and path.parent.name == "state":
                return '{"homeassistant_url":"http://dashboard.example.test:8123","app_option_url":"http://old-option.example.test:8123"}'
            if path.name == "connection.json" and path.parent.name == "state":
                return "{}"
            return original_read_text(path, *args, **kwargs)
        with patch.object(Path, "read_text", read_text):
            self.assertEqual(policy._settings()["homeassistant_url"], "http://new-option.example.test:8123")
    def test_no_alternate_destinations_or_traversal(self):
        paths = ["http://evil/", "//evil/", "/\\evil", "/%2fexample.com", "/%252fexample.com", "/../api/", "/%2e%2e/api/", "/api\r\nHost: evil", "/api#fragment", "/%00", "/%25252e%25252e/api/"]
        for value in paths:
            with self.subTest(path=value), self.assertRaises((policy.ProtocolError, UnicodeError)):
                policy.local_url(value)
        self.assertEqual(policy.local_url("/api/?next=https%3A%2F%2Fexample.org"), policy.LOCAL + "/api/?next=https%3A%2F%2Fexample.org")

    def test_destination_never_comes_from_message(self):
        self.assertEqual(policy.local_url("/api/"), policy.LOCAL + "/api/")
        with self.assertRaises(policy.ProtocolError):
            policy.parse(json.dumps(request(destination="https://untrusted.example.test/")))

    def test_malformed_protocol(self):
        invalid = ["{", "[]", "null", '{"type":"pong","type":"http"}', json.dumps(request(id="bad")), json.dumps(request(method="CONNECT")), json.dumps(request(body="!!!!")), json.dumps(request(headers={"Host": "evil"})), json.dumps(request(headers={"X-Forwarded-For": "127.0.0.1"})), json.dumps(request(headers={"Authorization": "token\r\ninjected"})), '{"type":[]}', '{"type":"http"}']
        for raw in invalid:
            with self.subTest(raw=raw), self.assertRaises(policy.ProtocolError):
                policy.parse(raw)

    @patch.object(policy, "ORIGIN", "https://tunnel.example.test")
    def test_websocket_origin_and_target(self):
        value = {"type": "ws_open", "id": RID, "path": "/api/websocket", "headers": {"Origin": policy.ORIGIN}}
        self.assertEqual(policy.parse(json.dumps(value))["path"], "/api/websocket")
        ingress_token = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v"
        value.update(path=f"/api/hassio_ingress/{ingress_token}/api/?EIO=4&transport=websocket")
        self.assertEqual(policy.parse(json.dumps(value))["path"], value["path"])
        for path in [
            "/api/hassio_ingress/short/api",
            f"/api/hassio_ingress/{ingress_token}/api/extra",
            f"/api/hassio_ingress/{ingress_token}/other",
            f"/api/hassio_ingress/{ingress_token}/api/%2e%2e/websocket",
        ]:
            value["path"] = path
            with self.subTest(path=path), self.assertRaises(policy.ProtocolError):
                policy.parse(json.dumps(value))
        value["path"] = "/api/websocket"
        for origin in [None, "null", "https://evil.example", "https://tunnel.example.test.evil.example", "http://tunnel.example.test"]:
            value["headers"] = {} if origin is None else {"Origin": origin}
            with self.assertRaises(policy.ProtocolError):
                policy.parse(json.dumps(value))
        value.update(path="/api/hassio", headers={"Origin": policy.ORIGIN})
        with self.assertRaises(policy.ProtocolError):
            policy.parse(json.dumps(value))
        value.update(path=f"/api/hassio_ingress/{ingress_token}/api", headers={}, native_client=True)
        with self.assertRaises(policy.ProtocolError):
            policy.parse(json.dumps(value))

    def test_explicit_native_websocket_marker(self):
        value = {"type": "ws_open", "id": RID, "path": "/api/websocket", "headers": {}, "native_client": True}
        self.assertTrue(policy.parse(json.dumps(value))["native_client"])
        value["client_ip"] = "203.0.113.1"
        self.assertEqual(policy.parse(json.dumps(value))["client_ip"], "203.0.113.1")
        for marker in (False, 1, "true", None):
            with self.subTest(marker=marker), self.assertRaises(policy.ProtocolError):
                policy.parse(json.dumps({**value, "native_client": marker}))
        for origin in ("", "null", policy.ORIGIN, "https://evil.example", "http://tunnel.example.test"):
            with self.subTest(origin=origin), self.assertRaises(policy.ProtocolError):
                policy.parse(json.dumps({**value, "headers": {"Origin": origin}}))
        with self.assertRaises(policy.ProtocolError):
            policy.parse(json.dumps({**value, "path": "/api/states"}))
        with self.assertRaises(policy.ProtocolError):
            policy.parse(json.dumps({**value, "client_ip": "not-an-IP"}))

    def test_message_payload_limits_and_utf8(self):
        self.assertEqual(policy.payload(base64.b64encode(b"a" * 8).decode(), 8), b"a" * 8)
        with self.assertRaises(policy.ProtocolError):
            policy.payload(base64.b64encode(b"a" * 9).decode(), 8)
        with self.assertRaises(policy.ProtocolError):
            policy.parse("x" * (policy.MAX_FRAME + 1))
        with self.assertRaises(policy.ProtocolError):
            policy.parse(json.dumps({"type": "ws_data", "id": RID, "kind": "text", "data": "/w=="}))

    def test_runtime_key_missing_and_rotation(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            with self.assertRaises(FileNotFoundError):
                policy.token_from_file(directory / "tunnel-token.txt")
            rotation.rotate(directory)
            old = policy.token_from_file(directory / "tunnel-token.txt")
            self.assertEqual(len(old), 64)
            rotation.rotate(directory)
            keys = json.loads((directory / "tunnel-keys.json").read_text())
            self.assertNotEqual(keys["active"], old)
            self.assertEqual(keys["previous"], old)
            rotation.rotate(directory, 0)
            self.assertNotIn("previous", json.loads((directory / "tunnel-keys.json").read_text()))

    def test_tls_validation_and_container_restrictions(self):
        self.assertTrue(connector.TLS.check_hostname)
        self.assertEqual(connector.TLS.verify_mode, ssl.CERT_REQUIRED)
        config = (ROOT / "home-assistant/config.yaml").read_text()
        for item in ["hassio_api: false", "docker_api: false", "full_access: false", "host_network: false", "host_pid: false", "read_only: true"]:
            self.assertIn(item, config)
        self.assertNotIn("homeassistant_config", config)
        docker = (ROOT / "home-assistant/Dockerfile").read_text()
        # Effective UID/capabilities and writable fresh storage are checked by
        # the network-isolated container CI step after its setup entrypoint.
        self.assertNotIn("COPY tunnel-token", docker)

    def test_runtime_checks_fail_closed(self):
        status = dict.fromkeys(('non_root', 'no_capabilities', 'no_ha_config', 'no_supervisor_token', 'no_docker_socket', 'secrets_readonly', 'key_private'), True)
        connector.verify_runtime(status)
        for name in status:
            with self.subTest(control=name), self.assertRaises(policy.ProtocolError):
                connector.verify_runtime({**status, name: False})

class FakeTunnel:
    def __init__(self): self.sent = []; self.closed = False
    async def send_json(self, value): self.sent.append(value)
    async def close(self): self.closed = True

class FakeContent:
    def __init__(self, blocks): self.blocks = blocks
    async def iter_chunked(self, size):
        for block in self.blocks:
            for start in range(0,len(block),size): yield block[start:start+size]

class Response:
    def __init__(self, status=200, blocks=None, headers=None):
        self.status = status; self.content = FakeContent(blocks or [b"ok"]); self.headers = headers or {"Content-Type": "text/plain"}
    async def __aenter__(self): return self
    async def __aexit__(self, *args): pass

class FakeLocal:
    def __init__(self, response=None, failure=None): self.response = response; self.failure = failure; self.calls = []
    def request(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.failure: raise self.failure
        return self.response

class ConnectorAsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_app_configuration_and_dashboard_settings_reconcile(self):
        with tempfile.TemporaryDirectory() as temporary:
            settings_path = Path(temporary) / "settings.json"
            settings_path.write_text(json.dumps({
                "homeassistant_url": "http://dashboard.example.test:8123",
                "app_option_url": "http://option.example.test:8123",
            }))
            with patch.object(service, "SETTINGS", settings_path), patch.dict("os.environ", {"HOMEASSISTANT_URL": "http://option.example.test:8123"}):
                self.assertEqual(service.ensure_settings(), "http://dashboard.example.test:8123")
            with patch.object(service, "SETTINGS", settings_path), patch.dict("os.environ", {"HOMEASSISTANT_URL": "http://new-option.example.test:8123"}):
                self.assertEqual(service.ensure_settings(), "http://new-option.example.test:8123")
                saved = json.loads(settings_path.read_text())
                self.assertEqual(saved["app_option_url"], "http://new-option.example.test:8123")

    def test_dashboard_telemetry_strips_client_identity(self):
        result = service.sanitize_telemetry({
            "status": "online", "clients": [{"ip": "203.0.113.1"}],
            "authenticated_sessions": [{"ip": "203.0.113.2"}], "authenticated_ips": 2,
            "last_client_ip": "203.0.113.1",
            "recent_requests": [{"ip": "203.0.113.3", "url": "/private?q=secret", "method": "GET", "route": "api", "status": 200}],
        })
        self.assertEqual(result["recent_requests"], [{"method": "GET", "route": "api", "status": 200}])
        self.assertFalse({"clients", "authenticated_sessions", "authenticated_ips", "last_client_ip"} & result.keys())

    async def test_ingress_settings_save_url_and_restart_connector(self):
        class Request:
            async def json(self):
                return {"homeassistant_url": "http://new-ha.example.test:8123/"}
        class Child:
            returncode = None
            def __init__(self): self.terminated = False
            def terminate(self): self.terminated = True
        with tempfile.TemporaryDirectory() as temporary:
            settings_path = Path(temporary) / "settings.json"
            child = Child()
            with patch.object(service, "SETTINGS", settings_path), patch.object(service, "child", child), patch.dict("os.environ", {"HOMEASSISTANT_URL": "http://legacy.example.test:8123"}):
                response = await service.update_settings(Request())
                self.assertEqual(response.status, 200)
                self.assertEqual(json.loads(response.text), {"homeassistant_url": "http://new-ha.example.test:8123", "restarting": True})
                self.assertTrue(child.terminated)
                self.assertEqual(json.loads(settings_path.read_text()), {
                    "homeassistant_url": "http://new-ha.example.test:8123",
                    "app_option_url": "http://legacy.example.test:8123",
                })
                class InvalidRequest:
                    async def json(self):
                        return {"homeassistant_url": "https://user:pass@ha.example.test/path"}
                with self.assertRaises(web.HTTPBadRequest):
                    await service.update_settings(InvalidRequest())
    async def test_large_model_streams_in_bounded_acknowledged_chunks(self):
        # A standalone fixture keeps tunnel tests independent of the 3D app.
        data = gzip.compress(random.Random(42).randbytes(5 * 1024 * 1024), mtime=0)
        class AcknowledgingTunnel(FakeTunnel):
            async def send_json(self, value):
                await super().send_json(value)
                if value['type']=='http_chunk':
                    await relay.dispatch(json.dumps({'type':'http_ack','id':RID,'sequence':value['sequence']}))
        tunnel = AcknowledgingTunnel()
        local = FakeLocal(Response(blocks=[data],headers={'Content-Type':'application/octet-stream','Content-Encoding':'gzip','Content-Length':str(len(data))}))
        relay = connector.Connector(tunnel,local)
        await relay.http(request(path='/local/floorplan3d/model-193.bin'))
        self.assertEqual(tunnel.sent[0]['type'],'http_start')
        self.assertEqual(tunnel.sent[0]['headers']['Content-Encoding'],'gzip')
        chunks=[base64.b64decode(x['body']) for x in tunnel.sent if x['type']=='http_chunk']
        self.assertTrue(all(len(x)<=policy.HTTP_CHUNK for x in chunks))
        self.assertEqual(b''.join(chunks),data)
        self.assertEqual(tunnel.sent[-1]['type'],'http_end')
        self.assertEqual(local.calls[0][1]['headers']['Accept-Encoding'],'gzip')
        self.assertFalse(relay.http_acks)

    async def test_gzip_expansion_is_bounded_and_truncation_aborts(self):
        class AcknowledgingTunnel(FakeTunnel):
            async def send_json(self,value):
                await super().send_json(value)
                if value['type']=='http_chunk': relay.http_acks[RID][1].set()
        for data,limit in [(gzip.compress(b'x'*20000),4096),(gzip.compress(b'hello')[:-3],policy.MAX_RESPONSE)]:
            tunnel=AcknowledgingTunnel();relay=connector.Connector(tunnel,FakeLocal(Response(blocks=[data],headers={'Content-Encoding':'gzip'})))
            with patch.object(connector,'MAX_RESPONSE',limit),self.assertLogs('amdeploy-tunnel',logging.WARNING):
                await relay.http(request())
            self.assertEqual(tunnel.sent[-1]['type'],'http_abort')
            self.assertFalse(relay.http_acks)
    async def test_session_requires_real_ha_auth_ok_and_cleans_up(self):
        for result_type in ("auth_ok","auth_invalid"):
            store = Metrics(); observed = []
            class Socket:
                async def __aenter__(self): return self
                async def __aexit__(self,*args): pass
                def __aiter__(self): return self.frames()
                async def frames(self):
                    yield types.SimpleNamespace(type=aiohttp.WSMsgType.TEXT,data=json.dumps({"type":"auth_required"}))
                    observed.append(RID in store.sessions)
                    yield types.SimpleNamespace(type=aiohttp.WSMsgType.TEXT,data=json.dumps({"type":result_type}))
                    observed.append(RID in store.sessions)
            class Local:
                async def ws_connect(self,*args,**kwargs): return Socket()
            with patch.object(connector,"METRICS",store):
                await connector.Connector(FakeTunnel(),Local()).websocket({"id":RID,"path":"/api/websocket","headers":{},"client_ip":"203.0.113.1"})
            self.assertEqual(observed,[False,result_type=="auth_ok"])
            self.assertFalse(store.sessions)

    async def test_client_summary_deduplicates_expires_and_tracks_confirmed_sessions(self):
        store = Metrics()
        event = {"ip":"203.0.113.1", "method":"GET", "route":"api", "status":200, "duration_ms":20, "request_bytes":0, "response_bytes":10}
        store.connected = True
        store.audit_ok = True
        store.update({"stats":{"requests":2,"response_bytes":20,"uptime_seconds":1},"events":[event,event]}, {}, now=100)
        self.assertEqual(store.snapshot(now=101)["unique_ips_15m"],1)
        self.assertEqual(store.snapshot(now=101)["clients"][0]["calls"],2)
        self.assertEqual(store.snapshot(now=101)["authenticated_ips"],0)
        store.authenticated(RID,event["ip"])
        store.authenticated("b"*32,event["ip"])
        self.assertEqual(store.snapshot(now=101)["authenticated_connections"],2)
        self.assertEqual(store.snapshot(now=101)["authenticated_ips"],1)
        store.closed(RID)
        self.assertEqual(store.snapshot(now=101)["authenticated_connections"],1)
        store.closed("b"*32)
        self.assertEqual(store.snapshot(now=101)["authenticated_ips"],0)
        self.assertEqual(store.snapshot(now=1001)["unique_ips_15m"],0)
    async def test_private_metrics_requires_key_and_is_read_only(self):
        store = Metrics()
        runner = web.AppRunner(application(store, "a"*64))
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://127.0.0.1:{port}/metrics"
                for headers in [{}, {"Authorization":"Bearer wrong"}]:
                    async with session.get(url, headers=headers) as response:
                        self.assertEqual(response.status, 401)
                async with session.get(url, headers={"Authorization":"Bearer " + "a"*64}) as response:
                    self.assertEqual(response.status, 200)
                    data = await response.json()
                    self.assertEqual(data["status"], "offline")
                    self.assertNotIn("a"*64, json.dumps(data))
                async with session.post(url, headers={"Authorization":"Bearer " + "a"*64}) as response:
                    self.assertEqual(response.status, 405)
                async with session.get(f"http://127.0.0.1:{port}/api/states") as response:
                    self.assertEqual(response.status, 404)
        finally:
            await runner.cleanup()

    async def test_metrics_staleness_rates_reset_and_bounded_history(self):
        store = Metrics()
        event = {"ip":"203.0.113.1", "method":"GET", "route":"api", "status":200, "duration_ms":20, "request_bytes":0, "response_bytes":10}
        store.connected = True
        store.audit_ok = True
        store.public_checked(True, now=115)
        store.update({"stats":{"requests":100, "response_bytes":10240, "uptime_seconds":100}, "events":[event]*64}, {}, now=100)
        store.update({"stats":{"requests":130, "response_bytes":25600, "uptime_seconds":115, "forwarding_enabled":1}, "events":[]}, {}, now=115)
        data = store.snapshot(now=116)
        self.assertTrue(data["healthy"])
        self.assertEqual(data["requests_per_minute"], 120)
        self.assertEqual(data["http_kib_per_second"], 1)
        self.assertEqual(len(data["recent_requests"]), 20)
        self.assertEqual(store.snapshot(now=161)["status"], "stale")
        store.connected = False
        self.assertEqual(store.snapshot(now=116)["status"], "offline")
        store.update({"stats":{"requests":1, "response_bytes":10, "uptime_seconds":1}, "events":[]}, {}, now=130)
        self.assertEqual(store.request_rate, 0)

    async def test_telemetry_logs_only_validated_metadata(self):
        relay = connector.Connector(FakeTunnel(), None)
        message = {"type":"telemetry", "events":[{"ip":"203.0.113.7", "method":"POST", "route":"auth", "status":401, "duration_ms":35, "request_bytes":100, "response_bytes":20}],
            "stats":dict.fromkeys(("requests", "errors_4xx", "errors_5xx", "response_bytes", "active_http", "active_ws", "queued_http", "events_dropped", "uptime_seconds", "forwarding_enabled"), 0)}
        with self.assertLogs("amdeploy-tunnel", logging.INFO) as logs:
            await relay.dispatch(json.dumps(message))
        output = " ".join(logs.output)
        self.assertIn("203.0.113.7", output)
        self.assertIn("STATS", output)
        for field, value in [("route", "auth?token=SUPERSECRET"), ("ip", "203.0.113.7\\r\\nSUPERSECRET"), ("Authorization", "Bearer SUPERSECRET")]:
            poisoned = json.loads(json.dumps(message))
            poisoned["events"][0][field] = value
            with self.assertRaises(policy.ProtocolError):
                await relay.dispatch(json.dumps(poisoned))

    async def test_closed_browser_socket_does_not_disconnect_tunnel(self):
        class ClosedSocket:
            async def send_str(self, data):
                raise ConnectionError("closed socket")
        tunnel = FakeTunnel()
        relay = connector.Connector(tunnel, None)
        relay.sockets[RID] = ClosedSocket()
        await relay.dispatch(json.dumps({"type": "ws_data", "id": RID, "kind": "text", "data": base64.b64encode(b"hello").decode()}))
        self.assertNotIn(RID, relay.sockets)
        self.assertFalse(tunnel.closed)
        await relay.dispatch(json.dumps({"type": "pong"}))

    async def test_stream_read_is_complete_and_bounded(self):
        self.assertEqual(await connector.bounded_read(FakeContent([b"a", b"bc"]), 3), b"abc")
        with self.assertRaises(policy.ProtocolError):
            await connector.bounded_read(FakeContent([b"abc", b"d"]), 3)

    async def test_redirects_and_upstream_failures_return_safe_errors(self):
        for local in [FakeLocal(Response(status=302, headers={"Location": "https://untrusted.example.test/"})), FakeLocal(failure=TimeoutError("Bearer SUPERSECRET password")), FakeLocal(failure=ConnectionError("secret")), FakeLocal(Response(blocks=[b"a" * (policy.MAX_HTTP + 1)]))]:
            tunnel = FakeTunnel(); relay = connector.Connector(tunnel, local)
            with self.assertLogs("amdeploy-tunnel", logging.WARNING) as logs:
                await relay.http(request())
            self.assertEqual(tunnel.sent[0]["status"], 502)
            self.assertNotIn("SUPERSECRET", " ".join(logs.output))
            self.assertNotIn("password", " ".join(logs.output))

    async def test_http_fixed_target_no_redirects_or_cookie_jar(self):
        local = FakeLocal(Response(blocks=[b"a", b"bc"]))
        tunnel = FakeTunnel()
        await connector.Connector(tunnel, local).http(request())
        args, kwargs = local.calls[0]
        self.assertEqual(args[1].host, URL(policy.LOCAL).host)
        self.assertEqual(args[1].port, URL(policy.LOCAL).port or (443 if URL(policy.LOCAL).scheme == "https" else 80))
        self.assertEqual(args[1].path, "/api/")
        self.assertFalse(kwargs["allow_redirects"])
        self.assertFalse(kwargs["auto_decompress"])
        self.assertEqual(base64.b64decode(tunnel.sent[0]["body"]), b"abc")

    async def test_http_job_limit_and_duplicate_ids(self):
        tunnel = FakeTunnel(); relay = connector.Connector(tunnel, None)
        blocker = asyncio.create_task(asyncio.sleep(30))
        try:
            relay.jobs = {str(i): ("http", blocker) for i in range(8)}
            await relay.dispatch(json.dumps(request()))
            self.assertEqual(tunnel.sent[0]["status"], 503)
            relay.jobs = {RID: ("http", blocker)}
            with self.assertRaises(policy.ProtocolError):
                relay.spawn(request(), asyncio.sleep(0))
        finally:
            blocker.cancel(); await asyncio.gather(blocker, return_exceptions=True)

    async def test_message_burst_does_not_disconnect_transport(self):
        relay = connector.Connector(FakeTunnel(), None)
        for _ in range(2000): await relay.dispatch('{"type":"pong"}')
        self.assertFalse(relay.tunnel.closed)

    async def test_transport_disconnect_cancels_pending_work(self):
        class ClosedTunnel(FakeTunnel):
            def __aiter__(self): return self
            async def __anext__(self): raise StopAsyncIteration
        relay = connector.Connector(ClosedTunnel(), None)
        task = asyncio.create_task(asyncio.sleep(30))
        relay.jobs[RID] = ("http", task)
        await relay.run()
        self.assertTrue(task.cancelled())
        self.assertFalse(relay.sockets)

    async def test_redirect_trace_rejects_websocket_redirects(self):
        trace = connector.traces("local")
        with self.assertRaises(policy.ProtocolError):
            await trace.on_request_redirect[0](None, None, None)
        from yarl import URL
        for url in ["http://unconfigured.example.test:8123/", "http://different-ha.example.test:8123/", "https://different-ha.example.test:80/", "http://user@different-ha.example.test:80/"]:
            with self.assertRaises(policy.ProtocolError):
                await trace.on_request_start[0](None, None, types.SimpleNamespace(url=URL(url)))

    async def test_real_websocket_redirect_never_reaches_second_endpoint(self):
        redirected_hits = []
        app = web.Application()
        async def redirect(request):
            return web.Response(status=302, headers={"Location": "/unexpected"})
        async def unexpected(request):
            redirected_hits.append(1)
            return web.Response(text="should never be requested")
        app.router.add_get("/api/websocket", redirect)
        app.router.add_get("/unexpected", unexpected)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        trace = connector.traces("local")
        # Only the test fixture substitutes the HA destination with loopback.
        # Keep the production redirect rejection hook unchanged.
        trace.on_request_start.clear()
        try:
            async with aiohttp.ClientSession(trace_configs=[trace]) as session:
                with self.assertRaises(policy.ProtocolError):
                    await session.ws_connect(f"http://127.0.0.1:{port}/api/websocket")
            self.assertEqual(redirected_hits, [])
        finally:
            await runner.cleanup()

if __name__ == "__main__": unittest.main(verbosity=2)
