import asyncio
import base64
import logging
import json
import os
import random
import re
import secrets
import signal
import ssl
import time
import zlib
from pathlib import Path
import aiohttp
from yarl import URL
from aiohttp import web
from metrics import Metrics, application
from audit import AuditLog
from policy import LOCAL, REMOTE, ORIGIN, MAX_HTTP, MAX_RESPONSE, HTTP_CHUNK, MAX_WS, MAX_FRAME, RESPONSE_HEADERS, OPTIONS, ProtocolError, local_url, parse, payload, token_from_file

TOKEN_PATH = Path(os.environ.get("HOME_TUNNEL_TOKEN_FILE", "/data/state/tunnel-token.txt"))
METRICS_TOKEN_PATH = Path(os.environ.get("HOME_TUNNEL_METRICS_TOKEN_FILE", "/secrets/metrics-token.txt"))
TLS = ssl.create_default_context()
LOG = logging.getLogger("amdeploy-tunnel")
MAX_HTTP_JOBS, MAX_WEBSOCKETS = 8, 8
METRICS = Metrics()
AUDIT = None
STATUS_PATH = Path("/data/state/status.json")
PUBLIC_CHECK_INTERVAL = 30
PUBLIC_CHECK_TIMEOUT = 15
PUBLIC_CHECK_FAILURES = 2
PUBLIC_CHECK_START_DELAY = 15
HEARTBEAT_INTERVAL = 5

def write_runtime_status(connection, forwarding_enabled=False, error=None):
    try:
        value = {"connection": connection, "forwarding_enabled": bool(forwarding_enabled), "updated_at": time.time()}
        if error:
            value["error"] = error
        temporary = STATUS_PATH.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, STATUS_PATH)
    except OSError:
        LOG.warning("Could not update local connection status")

def runtime_status():
    capabilities = next(line.split()[1] for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('CapEff:'))
    mounts = [line.split(' - ')[0].split() for line in Path('/proc/self/mountinfo').read_text().splitlines()]
    key_stat = TOKEN_PATH.stat()
    return {
        'non_root': os.getuid() == 10001,
        'no_capabilities': int(capabilities, 16) == 0,
        'no_ha_config': not any(Path(path).exists() for path in ('/homeassistant', '/config', '/host')),
        'no_supervisor_token': not os.environ.get('SUPERVISOR_TOKEN') and not os.environ.get('HASSIO_TOKEN'),
        'no_docker_socket': not Path('/var/run/docker.sock').exists(),
        'secrets_readonly': any(fields[4] == '/secrets' and 'ro' in fields[5].split(',') for fields in mounts),
        'key_private': key_stat.st_uid == 10001 and key_stat.st_mode & 0o777 == 0o600,
    }

def verify_runtime(status):
    if not status or not all(status.values()):
        raise ProtocolError('runtime isolation check failed')

def traces(target):
    trace = aiohttp.TraceConfig()
    async def start(session, context, params):
        value = params.url
        if target == "local":
            if value.origin() != URL(LOCAL).origin() or value.user or value.password:
                raise ProtocolError("destination rejected")
        elif target == "probe":
            if (value.origin() != URL(ORIGIN).origin() or value.user or value.password
                    or value.path != "/" or value.fragment
                    or not re.fullmatch(r"amdeploy_probe=[0-9a-f]{32}", value.raw_query_string)):
                raise ProtocolError("public check destination rejected")
        elif str(value) != REMOTE:
            raise ProtocolError("relay destination rejected")
    async def redirect(session, context, params):
        raise ProtocolError("redirect rejected")
    trace.on_request_start.append(start)
    trace.on_request_redirect.append(redirect)
    return trace

async def bounded_read(content, maximum):
    body = bytearray()
    async for block in content.iter_chunked(65536):
        if len(body) + len(block) > maximum:
            raise ProtocolError("response too large")
        body.extend(block)
    return bytes(body)

class Connector:
    def __init__(self, tunnel, local):
        self.tunnel, self.local = tunnel, local
        self.sockets, self.jobs = {}, {}
        self.send_lock = asyncio.Lock()
        self.http_acks = {}
        self.last_pong = time.monotonic()
        self.started = self.last_pong
        self.frames_in = self.frames_out = self.bytes_in = self.bytes_out = 0
        self.probe_path = None
        self.probe_seen = False

    async def send(self, message):
        async with asyncio.timeout(10):
            async with self.send_lock:
                await self.tunnel.send_json(message)
            self.frames_out += 1
            if message.get("type") == "ws_data":
                self.bytes_out += len(payload(message["data"], MAX_WS))

    async def http(self, message):
        streaming = False
        try:
            headers = dict(message["headers"])
            if message["method"] in {"GET", "HEAD"} and message["path"].startswith(("/local/", "/static/", "/frontend_")):
                headers["Accept-Encoding"] = "gzip"
            async with self.local.request(message["method"], URL(local_url(message["path"]), encoded=True), headers=headers, data=payload(message["body"], MAX_HTTP), allow_redirects=False, auto_decompress=False) as response:
                encoding = response.headers.get("Content-Encoding", "identity").lower()
                length = int(response.headers.get("Content-Length", "0"))
                if response.status in {301, 302, 303, 307, 308} or encoding not in {"identity", "gzip"} or length > MAX_RESPONSE:
                    raise ProtocolError("upstream response rejected")
                if encoding == "gzip" or length > MAX_HTTP:
                    streaming = True
                    await self.send({"type":"http_start", "id":message["id"], "status":response.status, "headers":{k:v for k,v in response.headers.items() if k.lower() in RESPONSE_HEADERS}})
                    total = decoded = sequence = 0
                    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS) if encoding == "gzip" and message["method"] != "HEAD" and response.status not in {204,304} else None
                    async for block in response.content.iter_chunked(HTTP_CHUNK):
                        total += len(block)
                        if total > MAX_RESPONSE: raise ProtocolError("response too large")
                        if inflater:
                            remaining = block
                            while remaining:
                                decoded += len(inflater.decompress(remaining, min(1024*1024, MAX_RESPONSE-decoded+1)))
                                if decoded > MAX_RESPONSE: raise ProtocolError("decoded response too large")
                                remaining = inflater.unconsumed_tail
                            if inflater.unused_data: raise ProtocolError("trailing gzip data")
                        event = asyncio.Event(); self.http_acks[message["id"]] = (sequence,event)
                        await self.send({"type":"http_chunk", "id":message["id"], "sequence":sequence, "body":base64.b64encode(block).decode()})
                        async with asyncio.timeout(10): await event.wait()
                        sequence += 1
                    if inflater and not inflater.eof: raise ProtocolError("incomplete gzip response")
                    await self.send({"type":"http_end", "id":message["id"], "sequence":sequence})
                    return
                body = await bounded_read(response.content, MAX_HTTP)
                reply = {"type": "http_response", "id": message["id"], "status": response.status, "headers": {key: value for key, value in response.headers.items() if key.lower() in RESPONSE_HEADERS}, "body": base64.b64encode(body).decode()}
        except Exception:
            LOG.warning("HTTP relay failed")
            if streaming:
                await self.send({"type":"http_abort", "id":message["id"]})
                return
            reply = {"type": "http_response", "id": message["id"], "status": 502, "headers": {}, "body": ""}
        finally:
            self.http_acks.pop(message["id"], None)
        await self.send(reply)

    async def websocket(self, message):
        connection_id = message["id"]
        try:
            async with asyncio.timeout(10):
                socket = await self.local.ws_connect(URL(local_url(message["path"]), encoded=True), headers=message["headers"], max_msg_size=MAX_WS, heartbeat=30, compress=0, timeout=aiohttp.ClientWSTimeout(ws_receive=90, ws_close=5))
            async with socket:
                auth_observed = False
                self.sockets[connection_id] = socket
                await self.send({"type": "ws_ready", "id": connection_id})
                async for frame in socket:
                    if frame.type in (aiohttp.WSMsgType.TEXT, aiohttp.WSMsgType.BINARY):
                        data = frame.data.encode() if isinstance(frame.data, str) else frame.data
                        if len(data) > MAX_WS:
                            raise ProtocolError("WebSocket response too large")
                        # Display HA's existing authentication result, never inspect credentials.
                        if not auth_observed and frame.type == aiohttp.WSMsgType.TEXT and len(data) < 4096:
                            try:
                                result = json.loads(frame.data)
                            except (ValueError, TypeError):
                                result = None
                            if isinstance(result, dict) and result.get("type") in {"auth_ok", "auth_invalid"}:
                                auth_observed = True
                                if result["type"] == "auth_ok":
                                    METRICS.authenticated(connection_id, message.get("client_ip", "unknown"))
                        await self.send({"type": "ws_data", "id": connection_id, "kind": "text" if frame.type == aiohttp.WSMsgType.TEXT else "binary", "data": base64.b64encode(data).decode()})
                    elif frame.type == aiohttp.WSMsgType.ERROR:
                        raise ProtocolError("WebSocket failed")
        except Exception:
            LOG.warning("WebSocket relay closed")
        finally:
            METRICS.closed(connection_id)
            self.sockets.pop(connection_id, None)
            try:
                await self.send({"type": "ws_close", "id": connection_id})
            except Exception:
                pass

    def spawn(self, message, coroutine):
        request_id = message["id"]
        if request_id in self.jobs:
            coroutine.close()
            raise ProtocolError("duplicate request id")
        task = asyncio.create_task(coroutine)
        self.jobs[request_id] = (message["type"], task)
        def done(task):
            self.jobs.pop(request_id, None)
            if not task.cancelled() and task.exception():
                LOG.warning("Relay task ended")
                asyncio.create_task(self.tunnel.close())
        task.add_done_callback(done)

    async def dispatch(self, raw):
        message = parse(raw)
        now = time.monotonic()
        kind = message["type"]
        if kind == "http_ack":
            pending = self.http_acks.get(message["id"])
            if pending and pending[0] == message["sequence"]: pending[1].set()
            return
        self.frames_in += 1
        if kind == "ws_data":
            self.bytes_in += len(payload(message["data"], MAX_WS))
        if kind == "telemetry":
            write_runtime_status("connected", message["stats"].get("forwarding_enabled") == 1)
            for event in message["events"]:
                LOG.info("HTTP %s", json.dumps(event, separators=(",", ":")))
            stats = {**message["stats"], "connector_uptime_seconds": int(now-self.started), "local_http_jobs": sum(kind == "http" for kind, _ in self.jobs.values()),
                "local_websockets": len(self.sockets), "tunnel_frames_in": self.frames_in, "tunnel_frames_out": self.frames_out,
                "websocket_bytes_to_ha": self.bytes_in, "websocket_bytes_from_ha": self.bytes_out}
            LOG.info("STATS %s", json.dumps(stats, separators=(",", ":")))
            if AUDIT is not None:
                try:
                    for event in message["events"]:
                        AUDIT.write({"time": time.time(), "event": "request", **event})
                    AUDIT.write({"time": time.time(), "event": "health", "stats": stats})
                    METRICS.audit_ok = True
                except (OSError, ValueError):
                    METRICS.audit_ok = False
                    raise ProtocolError("audit storage unavailable")
            METRICS.update(message, stats)
            return
        if kind in {"http", "ws_open"}:
            if kind == "http" and message["method"] == "GET" and message["path"] == self.probe_path:
                self.probe_seen = True
            count = sum(job_kind == kind for job_kind, _ in self.jobs.values())
            maximum = MAX_HTTP_JOBS if kind == "http" else MAX_WEBSOCKETS
            if count >= maximum:
                await self.send({"type": "http_response", "id": message["id"], "status": 503, "headers": {}, "body": ""} if kind == "http" else {"type": "ws_close", "id": message["id"]})
                return
            self.spawn(message, self.http(message) if kind == "http" else self.websocket(message))
        elif kind == "pong":
            self.last_pong = now
        elif kind in {"ws_data", "ws_close"}:
            socket = self.sockets.get(message["id"])
            if socket is None:
                return
            # Validate data before isolating transport failures, so malformed protocol
            # still fails closed. A stale browser frame is only a socket failure.
            data = payload(message["data"], MAX_WS) if kind == "ws_data" else None
            text = data.decode() if kind == "ws_data" and message["kind"] != "binary" else None
            try:
                async with asyncio.timeout(10):
                    if kind == "ws_close":
                        await socket.close()
                    elif message["kind"] == "binary":
                        await socket.send_bytes(data)
                    else:
                        await socket.send_str(text)
            except (aiohttp.ClientError, ConnectionError, RuntimeError, TimeoutError):
                LOG.info("Browser socket unavailable; closing only its session")
                job = self.jobs.get(message["id"])
                if job:
                    job[1].cancel()
                self.sockets.pop(message["id"], None)

    async def heartbeat(self):
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            if not METRICS.audit_ok or time.monotonic() - self.last_pong > 45:
                await self.tunnel.close()
                return
            try:
                await self.send({"type": "ping"})
                # Renew relay readiness after live telemetry and audit storage are healthy.
                if METRICS.forwarding_ready():
                    await self.send({"type": "connector_ready"})
            except Exception:
                await self.tunnel.close()
                return

    async def check_public(self, session):
        # A fresh request must return through THIS transport. A 200 from another
        # IIS worker (or a cache) cannot validate a stranded WebSocket connection.
        self.probe_path = "/?amdeploy_probe=" + secrets.token_hex(16)
        self.probe_seen = False
        try:
            async with session.get(ORIGIN + self.probe_path, ssl=TLS, allow_redirects=False,
                                   headers={"Cache-Control": "no-cache, no-store", "Accept-Encoding": "identity"}) as response:
                await bounded_read(response.content, 65536)
                return response.status == 200 and self.probe_seen
        except (aiohttp.ClientError, TimeoutError, ProtocolError):
            return False
        finally:
            self.probe_path = None
            self.probe_seen = False

    async def watch_public(self):
        try:
            await asyncio.sleep(PUBLIC_CHECK_START_DELAY)
            # Never reuse the transport's HTTP connection or cached DNS: the
            # check must exercise the hosting instance receiving new visitors.
            async with aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(force_close=True, use_dns_cache=False, limit=1),
                timeout=aiohttp.ClientTimeout(total=PUBLIC_CHECK_TIMEOUT, connect=5),
                cookie_jar=aiohttp.DummyCookieJar(), trust_env=False,
                trace_configs=[traces("probe")], auto_decompress=False,
            ) as session:
                while True:
                    if METRICS.forwarding_ready():
                        healthy = await self.check_public(session)
                        METRICS.public_checked(healthy)
                        if not healthy:
                            LOG.warning("Public tunnel check failed (%s/%s)", METRICS.public_check_failures, PUBLIC_CHECK_FAILURES)
                        if METRICS.public_check_failures >= PUBLIC_CHECK_FAILURES:
                            METRICS.automatic_reconnects += 1
                            if AUDIT is not None:
                                AUDIT.write({"time": time.time(), "event": "public_path_reconnect"})
                            LOG.warning("Public tunnel unavailable; reconnecting transport")
                            await self.tunnel.close()
                            return
                    await asyncio.sleep(PUBLIC_CHECK_INTERVAL)
        except Exception as error:
            # An unexpected checker/audit failure must not leave a permanently
            # unverified connection running. Never log URLs or exception text.
            LOG.warning("Public tunnel checker unavailable (%s); reconnecting", type(error).__name__)
            await self.tunnel.close()

    async def run(self):
        heartbeat = asyncio.create_task(self.heartbeat())
        public_check = asyncio.create_task(self.watch_public())
        try:
            async for frame in self.tunnel:
                if frame.type != aiohttp.WSMsgType.TEXT:
                    raise ProtocolError("invalid transport frame")
                await self.dispatch(frame.data)
        finally:
            heartbeat.cancel()
            public_check.cancel()
            pending = [task for _, task in list(self.jobs.values())]
            for task in pending:
                task.cancel()
            await asyncio.gather(heartbeat, public_check, *pending, return_exceptions=True)
            self.sockets.clear()

async def connect():
    if AUDIT is None:
        raise ProtocolError("audit storage not initialized")
    try:
        AUDIT.write({"time": time.time(), "event": "connection_check"})
        METRICS.audit_ok = True
    except (OSError, ValueError):
        METRICS.audit_ok = False
        raise ProtocolError("audit storage unavailable")
    token = token_from_file(TOKEN_PATH)
    write_runtime_status("connecting")
    METRICS.updated = None
    METRICS.public_verified_at = None
    METRICS.public_check_failures = 0
    timeout = aiohttp.ClientTimeout(total=45, connect=10, sock_read=30)
    async with aiohttp.ClientSession(timeout=timeout, cookie_jar=aiohttp.DummyCookieJar(), trust_env=False, trace_configs=[traces("local")], skip_auto_headers={"Accept-Encoding"}) as local:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30, connect=10), cookie_jar=aiohttp.DummyCookieJar(), trust_env=False, trace_configs=[traces("remote")]) as remote:
            async with remote.ws_connect(REMOTE, headers={"Authorization": f"Bearer {token}"}, ssl=TLS, heartbeat=20, max_msg_size=MAX_FRAME, compress=0, timeout=aiohttp.ClientWSTimeout(ws_receive=90, ws_close=5)) as tunnel:
                LOG.info("Tunnel connected")
                METRICS.connected = True
                try:
                    await Connector(tunnel, local).run()
                finally:
                    METRICS.connected = False
                    METRICS.sessions.clear()
                    write_runtime_status("disconnected")

async def main():
    global AUDIT
    AUDIT = AuditLog()
    runner = None
    try:
        metrics_token = token_from_file(METRICS_TOKEN_PATH)
    except (OSError, ProtocolError):
        LOG.warning("Metrics endpoint disabled; add its private key file to enable the HA dashboard")
    else:
        runner = web.AppRunner(application(METRICS, metrics_token), access_log=None)
        await runner.setup()
        await web.TCPSite(runner, "0.0.0.0", 8100).start()
        LOG.info("Read-only metrics endpoint ready on the app network")
    try:
        await reconnect()
    finally:
        if runner is not None:
            await runner.cleanup()
        AUDIT.close()

async def reconnect():
    delay = 2
    while True:
        try:
            await connect()
            delay = 2
        except Exception as error:
            LOG.warning("Tunnel unavailable (%s); retrying", type(error).__name__)
        await asyncio.sleep(delay + random.uniform(0, 1))
        delay = min(30, delay * 2)

async def run_until_stopped():
    """Handle HA's Stop signal even when Python is the container's PID 1."""
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    loop.add_signal_handler(signal.SIGTERM, task.cancel)
    try:
        await main()
    except asyncio.CancelledError:
        LOG.info("Tunnel stopped; connections and readiness closed")
    finally:
        loop.remove_signal_handler(signal.SIGTERM)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    try:
        checks = runtime_status()
        verify_runtime(checks)
    except Exception as error:
        if 'checks' in globals():
            LOG.error('Runtime check results: %s', checks)
        else:
            LOG.error('Runtime check could not complete: %s', type(error).__name__)
        LOG.error('Runtime isolation verification failed; connector will not start')
        raise SystemExit(1)
    LOG.info('Runtime isolation verified: non-root, no capabilities or HA config mounts, private connector key')
    asyncio.run(run_until_stopped())
