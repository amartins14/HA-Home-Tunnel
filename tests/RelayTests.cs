using System;
using System.Collections.Generic;
using System.IO;
using System.Net.WebSockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public class FakeSocket : WebSocket
{
    public bool Aborted; public byte[] Data = new byte[0]; public WebSocketMessageType Kind = WebSocketMessageType.Text; public bool Hang;
    public override WebSocketCloseStatus? CloseStatus { get { return null; } }
    public override string CloseStatusDescription { get { return null; } }
    public override WebSocketState State { get { return Aborted ? WebSocketState.Aborted : WebSocketState.Open; } }
    public override string SubProtocol { get { return null; } }
    public override void Abort() { Aborted = true; }
    public override void Dispose() { Abort(); }
    public override Task CloseAsync(WebSocketCloseStatus status, string text, CancellationToken token) { Abort(); return Task.FromResult(0); }
    public override Task CloseOutputAsync(WebSocketCloseStatus status, string text, CancellationToken token) { return CloseAsync(status, text, token); }
    public override async Task<WebSocketReceiveResult> ReceiveAsync(ArraySegment<byte> buffer, CancellationToken token) {
        if (Hang) await Task.Delay(10000, token);
        int count = Math.Min(buffer.Count, Data.Length); Array.Copy(Data, 0, buffer.Array, buffer.Offset, count);
        return new WebSocketReceiveResult(count, Kind, true);
    }
    public override Task SendAsync(ArraySegment<byte> data, WebSocketMessageType type, bool end, CancellationToken token) { return Task.FromResult(0); }
}

public static class RelayTests
{
    static int tests;
    static void Check(bool value, string label) { if (!value) throw new Exception(label); tests++; Console.WriteLine("PASS " + label); }
    static void Reject(Action action, string label) { bool rejected = false; try { action(); } catch { rejected = true; } Check(rejected, label); }
    public static void Main() { Run().GetAwaiter().GetResult(); }
    static async Task Run()
    {
        Check(HaTunnel.Connector == null && HaTunnel.Requests.IsEmpty && HaTunnel.Browsers.IsEmpty, "fresh worker starts with no connector or pending state");
        Check(HaTunnel.Route("/auth/login_flow?token=SECRET") == "auth", "audit route category ignores query credentials");
        Check(HaTunnel.Route("/api/states/private_entity?password=SECRET") == "api", "audit logs route category without private identifiers");
        Check(HaTunnel.Route("/SECRET/private_path") == "other", "audit does not expose arbitrary path content");
        Check(HaTunnel.DisplayRoute("/api/states/lamp?token=SECRET") == "/api/states/lamp", "display route keeps path and removes query values");
        Check(HaTunnel.DisplayRoute("/api/hassio_ingress/" + new string('a', 40) + "/api") == "/api/hassio_ingress/[ingress-token]/api", "display route hides ingress token");
        var html = Encoding.UTF8.GetBytes("<html><head></head><body>HA</body></html>");
        Check(Encoding.UTF8.GetString(RelayPolicy.LoginPage("/auth/authorize?client_id=x", 200, "text/html", html)).Contains("application/json"), "login page declares JSON auth requests");
        Check(Object.ReferenceEquals(html, RelayPolicy.LoginPage("/api/", 200, "text/html", html)), "API response is unchanged");
        Check(Object.ReferenceEquals(html, RelayPolicy.LoginPage("/auth/authorize", 403, "text/html", html)), "failed login document is unchanged");
        string key = new string('a', 64), old = new string('b', 64);
        string keys = "{\"active\":\"" + key + "\",\"previous\":\"" + old + "\",\"previous_expires_utc\":\"2030-01-01T00:00:00Z\"}";
        Check(RelayPolicy.Authorized("Bearer " + key, keys, DateTime.UtcNow), "active key accepted");
        Check(RelayPolicy.Authorized("Bearer " + old, keys, new DateTime(2029, 1, 1)), "previous key allowed during rotation");
        Check(!RelayPolicy.Authorized("Bearer " + old, keys, new DateTime(2031, 1, 1)), "expired previous key rejected");
        foreach (var value in new[] { "", "Bearer ", "Bearer wrong", "Basic " + key }) Check(!RelayPolicy.Authorized(value, keys, DateTime.UtcNow), "missing or invalid credential rejected");
        Check(!RelayPolicy.Authorized("Bearer " + key, "{}", DateTime.UtcNow), "missing key file contents fail closed");
        Check(!RelayPolicy.Authorized("Bearer ", "{\"active\":\"\"}", DateTime.UtcNow), "empty configured key rejected");
        Check(!RelayPolicy.GoodOrigin(null) && !RelayPolicy.GoodOrigin("") && !RelayPolicy.GoodOrigin("https://tunnel.example.test.evil") && RelayPolicy.GoodOrigin("https://tunnel.example.test"), "exact configured origin required; empty origin fails closed");
        Check(!RelayPolicy.GoodWebSocketOrigin(null, false, "/api/websocket") && RelayPolicy.GoodWebSocketOrigin(null, true, "/api/websocket"), "native core sockets require explicit opt-in");
        Check(RelayPolicy.GoodWebSocketOrigin(RelayPolicy.Origin, false, "/api/websocket") && RelayPolicy.GoodWebSocketOrigin(RelayPolicy.Origin, true, "/api/websocket"), "browser origin works in both modes");
        string ingressToken = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v";
        Check(RelayPolicy.AllowedWebSocketPath("/api/websocket"), "HA core WebSocket remains allowed");
        Check(RelayPolicy.AllowedWebSocketPath("/api/hassio_ingress/" + ingressToken + "/api/?EIO=4&transport=websocket"), "HA ingress API WebSocket is allowed");
        Check(RelayPolicy.GoodWebSocketOrigin(RelayPolicy.Origin, false, "/api/hassio_ingress/" + ingressToken + "/api") && !RelayPolicy.GoodWebSocketOrigin(null, true, "/api/hassio_ingress/" + ingressToken + "/api"), "ingress sockets require exact browser origin even when native core sockets are enabled");
        foreach (var path in new[] { "/api/hassio_ingress/short/api", "/api/hassio_ingress/" + ingressToken + "/other", "/api/hassio_ingress/" + ingressToken + "/api/extra", "/api/hassio_ingress/" + ingressToken + "/api/%2e%2e/websocket" })
            Check(!RelayPolicy.AllowedWebSocketPath(path), "other ingress WebSocket paths are rejected");
        foreach (var origin in new[] { "", "null", "https://evil.example", "http://tunnel.example.test", "https://tunnel.example.test.evil", RelayPolicy.Origin + "/" })
            Check(!RelayPolicy.GoodWebSocketOrigin(origin, false, "/api/websocket") && !RelayPolicy.GoodWebSocketOrigin(origin, true, "/api/websocket"), "native opt-in never accepts foreign or malformed browser origins");
        foreach (var path in new[] { "http://evil/", "//evil/", "/\\evil", "/%2fexample.com", "/%252fexample.com", "/../api/", "/%2e%2e/api/", "/api\r\nHost: evil", "/api#fragment", "/%00" }) Reject(() => RelayPolicy.ValidPath(path), "unsafe path rejected");
        Check(RelayPolicy.ValidPath("/api/?x=1") == "/api/?x=1", "HA path preserved");
        Reject(() => RelayPolicy.Payload("!!!!", 8), "malformed base64 rejected");
        Reject(() => RelayPolicy.Payload(Convert.ToBase64String(new byte[9]), 8), "decoded payload limit enforced");
        Reject(() => RelayPolicy.ValidateHeaders(new Dictionary<string, object> { { "Content-Type", "a\r\nb" } }, true), "response header injection rejected");
        Reject(() => RelayPolicy.ValidateHeaders(new Dictionary<string, object> { { "X-Forwarded-For", "127.0.0.1" } }, false), "forwarded identity rejected");
        foreach (var raw in new[] { "{", "null", "[]", "{\"type\":\"unknown\"}", "{\"type\":\"ws_close\",\"id\":\"bad\"}", "{\"type\":\"ping\",\"extra\":1}", "{\"type\":\"http_response\",\"id\":\"" + new string('a', 32) + "\",\"status\":302,\"headers\":{},\"body\":\"\"}" }) Reject(() => RelayPolicy.Parse(raw), "malformed protocol rejected");
        Check(RelayPolicy.Parse("{\"type\":\"ping\"}")["type"].ToString() == "ping", "valid heartbeat accepted");
        Reject(() => RelayPolicy.Parse("{\"type\":\"bad\",\"type\":\"ping\"}"), "duplicate protocol keys rejected");
        Reject(() => RelayPolicy.Parse("{\"type\":\"bad\",\"ty\\u0070e\":\"ping\"}"), "escaped duplicate protocol keys rejected");
        var globalBudget = new RelayBudget(); var globalLeases = new List<RelayLease>();
        for (int i = 0; i < 8; i++) { globalBudget.Rate("ip" + i, false, now: DateTime.UtcNow); globalLeases.Add(globalBudget.Acquire("ip" + i, false)); }
        globalBudget.Rate("overflow", false, DateTime.UtcNow);
        Check(globalLeases.TrueForAll(x => x != null) && globalBudget.Acquire("overflow", false) == null, "global HTTP concurrency enforced across clients");
        foreach (var item in globalLeases) item.Dispose();
        var budget = new RelayBudget(); var now = DateTime.UtcNow;
        for (int i = 0; i < 6000; i++) if (!budget.Rate("client", false, now)) throw new Exception("public traffic must not be rate throttled");
        Check(budget.Rate("client", false, now), "public requests have no per-minute quota");
        var leases = new List<RelayLease>();
        for (int i = 0; i < 8; i++) leases.Add(budget.Acquire("client", false));
        Check(leases.TrueForAll(x => x != null) && budget.Acquire("client", false) == null, "per-client concurrency enforced");
        foreach (var lease in leases) { lease.Dispose(); lease.Dispose(); }
        var held = new List<RelayLease>(); for (int i = 0; i < 8; i++) held.Add(budget.Acquire("client", false));
        var waiting = budget.AcquireHttp("client", CancellationToken.None);
        await Task.Delay(50);
        Check(!waiting.IsCompleted, "frontend burst queues instead of immediate rejection");
        held[0].Dispose();
        using (var queued = await waiting) Check(queued != null, "queued request proceeds when slot frees");
        foreach (var item in held) item.Dispose();
        using (var lease = budget.Acquire("client", false)) Check(lease != null, "limits released idempotently");
        var sockets = new List<RelayLease>(); for (int i = 0; i < 8; i++) sockets.Add(budget.Acquire("client", true));
        Check(sockets.TrueForAll(x => x != null) && budget.Acquire("client", true) == null, "eight household WebSockets allowed with bounded capacity");
        foreach (var socket in sockets) socket.Dispose();
        for (int i = 0; i < 10; i++) budget.Rate("connector", true, now);
        Check(!budget.Rate("connector", true, now), "connector login rate enforced");
        var peer = new ConnectorPeer { Socket = new FakeSocket() };
        Check(HaTunnel.Register(peer), "connector registered");
        Check(!HaTunnel.Register(new ConnectorPeer { Socket = new FakeSocket() }), "duplicate connector refused");
        var pending = new PendingReply { Connector = peer }; HaTunnel.Requests["pending"] = pending;
        var browser = new BrowserPeer { Connector = peer, Socket = new FakeSocket() }; HaTunnel.Browsers["browser"] = browser;
        HaTunnel.Disconnect(peer);
        Check(HaTunnel.Connector == null && peer.Lifetime.IsCancellationRequested && pending.Completion.Task.IsFaulted, "outage fails pending requests and disables relay");
        Check(((FakeSocket)browser.Socket).Aborted, "outage closes browser sockets");
        var replacement = new ConnectorPeer { Socket = new FakeSocket() }; Check(HaTunnel.Register(replacement), "connector reconnect accepted after outage");
        HaTunnel.Disconnect(peer); Check(HaTunnel.Connector == replacement, "old disconnect cannot remove replacement connector");
        HaTunnel.Disconnect(replacement);
        var small = await RelayPolicy.BoundedRead(new MemoryStream(new byte[8]), 8, CancellationToken.None); Check(small.Length == 8, "bounded stream reads complete body");
        Reject(() => RelayPolicy.BoundedRead(new MemoryStream(new byte[9]), 8, CancellationToken.None).GetAwaiter().GetResult(), "stream cap enforced before growth");
        Reject(() => RelayPolicy.Read(new FakeSocket { Data = new byte[9] }, 8, 500, CancellationToken.None).GetAwaiter().GetResult(), "WebSocket frame size bounded");
        Reject(() => RelayPolicy.Read(new FakeSocket { Hang = true }, 8, 30, CancellationToken.None).GetAwaiter().GetResult(), "WebSocket receive timeout enforced");
        var readinessPeer = new ConnectorPeer { Socket = new FakeSocket() };
        Check(!readinessPeer.IsReady, "new connector cannot forward before its readiness handshake");
        readinessPeer.RenewReadiness();
        Check(readinessPeer.IsReady, "fresh connector readiness permits forwarding");
        typeof(ConnectorPeer).GetField("readinessUntil",System.Reflection.BindingFlags.NonPublic|System.Reflection.BindingFlags.Instance).SetValue(readinessPeer, 1L);
        Check(readinessPeer.ReadinessExpired, "connector readiness lease expires independently of browser traffic");
        await readinessPeer.WatchReadiness();
        Check(readinessPeer.Lifetime.IsCancellationRequested && ((FakeSocket)readinessPeer.Socket).Aborted,"expired readiness closes existing connector");
        Check((string)RelayPolicy.Parse("{\"type\":\"connector_ready\"}")["type"]=="connector_ready","strict readiness protocol accepted");
        Reject(()=>RelayPolicy.Parse("{\"type\":\"connector_ready\",\"extra\":true}"),"readiness rejects extra fields");
        var utc = new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        Check(RelayBlocks.Matches(RelayBlocks.Parse("203.0.113.7", null), "203.0.113.7", utc) && !RelayBlocks.Matches(RelayBlocks.Parse("203.0.113.7", null), "203.0.113.8", utc), "single address block matches only that address");
        Check(RelayBlocks.Matches(RelayBlocks.Parse("203.0.113.0/24", null), "203.0.113.200", utc) && !RelayBlocks.Matches(RelayBlocks.Parse("203.0.113.0/24", null), "203.0.114.1", utc), "IPv4 range block honors prefix");
        Check(RelayBlocks.Matches(RelayBlocks.Parse("203.0.113.9/24", null), "203.0.113.1", utc), "host bits in a range are ignored");
        Check(RelayBlocks.Matches(RelayBlocks.Parse("203.0.113.7", null), "::ffff:203.0.113.7", utc), "IPv4-mapped IPv6 caller is matched as IPv4");
        Check(RelayBlocks.Matches(RelayBlocks.Parse("2001:db8::/32", null), "2001:db8:1::5", utc) && !RelayBlocks.Matches(RelayBlocks.Parse("2001:db8::/32", null), "2001:db9::5", utc), "IPv6 range block honors prefix");
        Check(!RelayBlocks.Matches(RelayBlocks.Parse("203.0.113.7", "2029-12-31T23:00:00Z"), "203.0.113.7", utc) && RelayBlocks.Matches(RelayBlocks.Parse("203.0.113.7", "2030-01-01T01:00:00Z"), "203.0.113.7", utc), "temporary blocks expire");
        foreach (var bad in new[] { "", "not-an-ip", "203.0.113.7/33", "203.0.113.7/-1", "10.0.0.0/7", "::/0", "2001:db8::/15", "1.2.3.4/24/1", "fe80::1%eth0", "203.0.113.7/ 24" }) Check(RelayBlocks.Parse(bad, null) == null, "invalid or too-broad block rejected");
        Check(RelayBlocks.Parse("203.0.113.7", "soon") == null, "invalid block expiry rejected");
        var parsedList = RelayBlocks.FromJson(new System.Web.Script.Serialization.JavaScriptSerializer().Deserialize<Dictionary<string, object>>("{\"blocks\":[{\"cidr\":\"203.0.113.7\",\"until\":null},{\"cidr\":\"198.51.100.0/24\"}]}")["blocks"]);
        Check(parsedList != null && parsedList.Count == 2 && RelayBlocks.Blocked(parsedList, "198.51.100.4", utc) && !RelayBlocks.Blocked(parsedList, "192.0.2.1", utc), "block list parsed from app JSON");
        Check(RelayBlocks.FromJson(new System.Web.Script.Serialization.JavaScriptSerializer().Deserialize<Dictionary<string, object>>("{\"blocks\":[{\"cidr\":\"203.0.113.7\"},{\"cidr\":\"bad\"}]}")["blocks"]) == null, "one invalid entry rejects the whole list");
        Check(RelayBlocks.FromJson(new System.Web.Script.Serialization.JavaScriptSerializer().Deserialize<Dictionary<string, object>>("{\"blocks\":[{\"cidr\":\"203.0.113.7\",\"extra\":1}]}")["blocks"]) == null, "unknown block fields rejected");
        Check(!RelayBlocks.Blocked(null, "203.0.113.7", utc) && !RelayBlocks.IsBlocked(null), "no list or no caller address fails open for blocking only");
        Console.WriteLine(tests + " security checks passed");
        var streamed = new PendingReply();
        streamed.StreamMessage(RelayPolicy.Parse("{\"type\":\"http_start\",\"id\":\""+new string('a',32)+"\",\"status\":200,\"headers\":{\"Content-Encoding\":\"gzip\"}}"));
        Check(streamed.Streaming && streamed.Completion.Task.IsCompleted, "gzip streaming headers accepted");
        var chunk = new Dictionary<string,object>{{"type","http_chunk"},{"sequence",0},{"body",Convert.ToBase64String(new byte[RelayPolicy.HttpChunkLimit])}};
        streamed.StreamMessage(chunk); Check((await streamed.Next(CancellationToken.None)).Length==RelayPolicy.HttpChunkLimit,"stream chunk consumed without full response buffering");
        Reject(()=>streamed.StreamMessage(chunk),"duplicate stream sequence rejected");
        streamed.StreamMessage(new Dictionary<string,object>{{"type","http_end"},{"sequence",1}});
        Check((await streamed.Next(CancellationToken.None)).Length==0,"stream completion delivers EOF");
        Reject(()=>streamed.StreamMessage(chunk),"chunks after EOF rejected");
        Reject(()=>RelayPolicy.ValidateHeaders(new Dictionary<string,object>{{"Content-Encoding","evil"}},true),"unknown content encoding rejected");
        var aborted=new PendingReply();aborted.StreamMessage(new Dictionary<string,object>{{"type","http_start"}});aborted.Fail(new IOException());
        Reject(()=>aborted.Next(CancellationToken.None).GetAwaiter().GetResult(),"stream disconnect unblocks waiting consumer");
    }
}
