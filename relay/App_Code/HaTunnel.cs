using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.WebSockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Hosting;
using System.Web.Script.Serialization;

public static class RelayPolicy
{
    public static string Origin
    {
        get {
            string stored = null;
            try { stored = RelayState.Origin; } catch { }
            if (!String.IsNullOrEmpty(stored)) return stored;
            try {
                var configured = new Uri(ConfigurationManager.AppSettings["HaTunnelPublicOrigin"] ?? "");
                if (configured.Scheme != Uri.UriSchemeHttps || configured.UserInfo.Length != 0 || configured.AbsolutePath != "/" || configured.Query.Length != 0 || configured.Fragment.Length != 0) return "";
                return configured.GetLeftPart(UriPartial.Authority).TrimEnd('/');
            } catch { return ""; }
        }
    }
    public const int HttpLimit = 4 * 1024 * 1024, WsLimit = 1024 * 1024, FrameLimit = 6 * 1024 * 1024;
    public const int ResponseLimit = 64 * 1024 * 1024, HttpChunkLimit = 64 * 1024;
    public static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
    public static readonly HashSet<string> Methods = new HashSet<string> { "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS" };
    public static readonly HashSet<string> RequestHeaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Accept", "Accept-Language", "Authorization", "Cookie", "Content-Type", "Origin", "If-None-Match", "If-Modified-Since", "Range", "If-Range", "User-Agent" };
    public static readonly HashSet<string> ResponseHeaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Content-Type", "Content-Encoding", "Cache-Control", "ETag", "Last-Modified", "Vary", "Content-Range", "Accept-Ranges", "Expires", "Content-Disposition", "Set-Cookie" };
    public static JavaScriptSerializer Json() { return new JavaScriptSerializer { MaxJsonLength = FrameLimit, RecursionLimit = 8 }; }
    public static bool GoodOrigin(string value)
    {
        string expected = Origin;
        return !String.IsNullOrEmpty(expected) && !String.IsNullOrEmpty(value)
            && String.Equals(value, expected, StringComparison.Ordinal);
    }
    public static bool AllowedWebSocketPath(string path)
    {
        if (path == "/api/websocket") return true;
        // Any WebSocket below an app's web UI (Home Assistant ingress), which HA authenticates.
        // Percent-encoding and dot segments are refused so the path can't leave that base.
        string route = path == null ? "" : path.Split('?')[0];
        if (!Regex.IsMatch(route, @"^/api/hassio_ingress/[A-Za-z0-9_-]{32,256}(?:/[A-Za-z0-9._~!$&'()*+,;=:@-]*)*$", RegexOptions.CultureInvariant)) return false;
        return !route.Split('/').Any(segment => segment == "." || segment == "..");
    }
    // Only the core HA socket has native clients; ingress sockets are browser-only.
    public static bool GoodWebSocketOrigin(string value, bool allowNative, string path) { return GoodOrigin(value) || (path == "/api/websocket" && allowNative && value == null); }
    // HA's auth frontend omits Content-Type for JSON, so fetch defaults to text/plain.
    // This host rejects those POSTs before our handler; declare their actual format.
    public static byte[] LoginPage(string path, int status, string contentType, byte[] body)
    {
        if (path.Split('?')[0] != "/auth/authorize" || status != 200 || contentType == null || !contentType.StartsWith("text/html", StringComparison.OrdinalIgnoreCase)) return body;
        string html = Utf8.GetString(body);
        const string script = "<script>(()=>{const original=window.fetch;window.fetch=function(input,init){if(typeof input==='string'&&init&&init.method==='POST'&&typeof init.body==='string'){const url=new URL(input,location.href);if(url.origin===location.origin&&/^\\/auth\\/login_flow(?:\\/[a-f0-9]{32})?$/.test(url.pathname)){const headers=new Headers(init.headers);if(!headers.has('Content-Type'))headers.set('Content-Type','application/json');init={...init,headers};}}return original.call(this,input,init);};})();</script>";
        return Utf8.GetBytes(html.Replace("<head>", "<head>" + script));
    }
    public static string ValidPath(string path)
    {
        if (String.IsNullOrEmpty(path) || path.Length > 8192) throw new InvalidDataException();
        string decoded = path;
        for (int round = 0; round < 4; round++) {
            if (!decoded.StartsWith("/") || decoded.StartsWith("//") || decoded.Contains("\\") || decoded.Contains("#") || decoded.Any(c => c < 32 || c == 127)) throw new InvalidDataException();
            if (decoded.Split('?')[0].Split('/').Any(p => p == "." || p == "..")) throw new InvalidDataException();
            string next = Uri.UnescapeDataString(decoded);
            if (next == decoded) return path;
            decoded = next;
        }
        throw new InvalidDataException();
    }
    public static bool ValidId(string value) { return value != null && Regex.IsMatch(value, "\\A[0-9a-f]{32}\\z"); }
    public static byte[] Payload(object value, int maximum)
    {
        string text = value as string;
        if (text == null || text.Length > 4 * ((maximum + 2) / 3) || !Regex.IsMatch(text, "\\A[A-Za-z0-9+/]*={0,2}\\z")) throw new InvalidDataException();
        byte[] bytes = Convert.FromBase64String(text);
        if (bytes.Length > maximum) throw new InvalidDataException();
        return bytes;
    }
    public static Dictionary<string, string> ValidateHeaders(Dictionary<string, object> values, bool response)
    {
        if (values == null || values.Count > 32) throw new InvalidDataException();
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        int total = 0;
        foreach (var entry in values) {
            string value = entry.Value as string;
            if (!(response ? ResponseHeaders : RequestHeaders).Contains(entry.Key) || value == null || value.Any(c => c < 32 || c == 127) || result.ContainsKey(entry.Key)) throw new InvalidDataException();
            if (entry.Key.Equals("Content-Encoding", StringComparison.OrdinalIgnoreCase) && value != "gzip" && value != "identity") throw new InvalidDataException();
            total += Utf8.GetByteCount(entry.Key) + Utf8.GetByteCount(value);
            if (total > 16384) throw new InvalidDataException();
            result[entry.Key] = value;
        }
        return result;
    }
    public static Dictionary<string, object> Parse(string raw)
    {
        RejectDuplicateFields(raw);
        var msg = Json().Deserialize<Dictionary<string, object>>(raw);
        if (msg == null) throw new InvalidDataException();
        object kindObject;
        if (!msg.TryGetValue("type", out kindObject) || !(kindObject is string)) throw new InvalidDataException();
        string kind = (string)kindObject;
        string[] keys;
        switch (kind) {
            case "connector_ready": case "ping": keys = new[] { "type" }; break;
            case "http_response": keys = new[] { "type", "id", "status", "headers", "body" }; break;
            case "http_start": keys = new[] { "type", "id", "status", "headers" }; break;
            case "http_chunk": keys = new[] { "type", "id", "sequence", "body" }; break;
            case "http_end": keys = new[] { "type", "id", "sequence" }; break;
            case "http_abort": keys = new[] { "type", "id" }; break;
            case "ws_ready": case "ws_close": keys = new[] { "type", "id" }; break;
            case "ws_data": keys = new[] { "type", "id", "kind", "data" }; break;
            default: throw new InvalidDataException();
        }
        if (msg.Count != keys.Length || keys.Any(k => !msg.ContainsKey(k))) throw new InvalidDataException();
        if (kind != "ping" && kind != "connector_ready" && !ValidId(msg["id"] as string)) throw new InvalidDataException();
        if (kind == "http_response" || kind == "http_start") {
            if (!(msg["status"] is int) || (int)msg["status"] < 200 || (int)msg["status"] > 599 || new[] { 301, 302, 303, 307, 308 }.Contains((int)msg["status"])) throw new InvalidDataException();
            ValidateHeaders(msg["headers"] as Dictionary<string, object>, true);
            if (kind == "http_response") Payload(msg["body"], HttpLimit);
        } else if (kind == "http_chunk" || kind == "http_end") {
            if (!(msg["sequence"] is int) || (int)msg["sequence"] < 0 || (int)msg["sequence"] > ResponseLimit) throw new InvalidDataException();
            if (kind == "http_chunk" && Payload(msg["body"], HttpChunkLimit).Length == 0) throw new InvalidDataException();
        } else if (kind == "ws_data") {
            string format = msg["kind"] as string;
            if (format != "text" && format != "binary") throw new InvalidDataException();
            var bytes = Payload(msg["data"], WsLimit);
            if (format == "text") Utf8.GetString(bytes);
        }
        return msg;
    }
    public static void RejectDuplicateFields(string raw)
    {
        var objects = new Stack<HashSet<string>>();
        for (int i = 0; i < raw.Length; i++) {
            if (raw[i] == '{') objects.Push(new HashSet<string>());
            else if (raw[i] == '}') { if (objects.Count == 0) throw new InvalidDataException(); objects.Pop(); }
            else if (raw[i] == '"') {
                int start = i++;
                while (i < raw.Length && raw[i] != '"') { if (raw[i] == '\\') i++; i++; }
                if (i >= raw.Length) throw new InvalidDataException();
                int next = i + 1; while (next < raw.Length && Char.IsWhiteSpace(raw[next])) next++;
                if (next < raw.Length && raw[next] == ':') {
                    string key = Json().Deserialize<string>(raw.Substring(start, i - start + 1));
                    if (objects.Count == 0 || !objects.Peek().Add(key)) throw new InvalidDataException();
                }
            }
        }
        if (objects.Count != 0) throw new InvalidDataException();
    }
    public static async Task<byte[]> BoundedRead(Stream source, int maximum, CancellationToken cancel)
    {
        byte[] buffer = new byte[65536];
        using (var target = new MemoryStream()) {
            int count;
            while ((count = await source.ReadAsync(buffer, 0, buffer.Length, cancel)) > 0) {
                if (target.Length + count > maximum) throw new InvalidDataException();
                target.Write(buffer, 0, count);
            }
            return target.ToArray();
        }
    }
    public static async Task<Tuple<byte[], WebSocketMessageType>> Read(WebSocket socket, int maximum, int timeout, CancellationToken cancel)
    {
        using (var timer = CancellationTokenSource.CreateLinkedTokenSource(cancel)) {
            timer.CancelAfter(timeout);
            byte[] buffer = new byte[65536];
            using (var stream = new MemoryStream()) {
                WebSocketMessageType? kind = null;
                WebSocketReceiveResult part;
                do {
                    part = await socket.ReceiveAsync(new ArraySegment<byte>(buffer), timer.Token);
                    if (part.MessageType == WebSocketMessageType.Close) return null;
                    if (kind.HasValue && kind.Value != part.MessageType) throw new InvalidDataException();
                    kind = part.MessageType;
                    if (stream.Length + part.Count > maximum) throw new InvalidDataException();
                    stream.Write(buffer, 0, part.Count);
                } while (!part.EndOfMessage);
                return Tuple.Create(stream.ToArray(), kind.Value);
            }
        }
    }
    public static bool Matches(string actual, string expected)
    {
        if (expected == null || !Regex.IsMatch(expected, "\\A[0-9a-f]{64}\\z")) return false;
        byte[] a = Encoding.ASCII.GetBytes(actual ?? ""), b = Encoding.ASCII.GetBytes("Bearer " + expected);
        int mismatch = a.Length ^ b.Length;
        for (int i = 0; i < b.Length; i++) mismatch |= b[i] ^ (i < a.Length ? a[i] : 0);
        return mismatch == 0;
    }
    public static bool Authorized(string actual, string json, DateTime utc)
    {
        try {
            RejectDuplicateFields(json);
            var keys = Json().Deserialize<Dictionary<string, object>>(json);
            string active = keys["active"] as string;
            bool current = Matches(actual, active);
            object previous, expires;
            bool old = false;
            if (keys.TryGetValue("previous", out previous) && keys.TryGetValue("previous_expires_utc", out expires)) {
                DateTime end;
                if (DateTime.TryParse(expires as string, null, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out end)) old = Matches(actual, previous as string) & (utc < end);
            }
            return current | old;
        } catch { return false; }
    }
    public static string KeysFile()
    {
        // A sibling of the served domain folder; never a URL-addressable App_Data file.
        string appRoot = HostingEnvironment.ApplicationPhysicalPath;
        if (String.IsNullOrEmpty(appRoot)) throw new InvalidOperationException();
        return System.IO.Path.Combine(Directory.GetParent(appRoot.TrimEnd('\\', '/')).FullName, "_ha-secrets", "tunnel-keys.json");
    }
    public static bool KeyAllowed(string value)
    {
        if (RelayState.IsPaired) return RelayState.KeyAllowed(value != null && value.StartsWith("Bearer ", StringComparison.Ordinal) ? value.Substring(7) : value);
        try {
            string path = KeysFile();
            if (new FileInfo(path).Length > 4096) return false;
            return Authorized(value, File.ReadAllText(path), DateTime.UtcNow);
        }
        catch { return false; }
    }
}

public static class RelayBuild
{
    // Keep this aligned with release-manifest.json when publishing a relay build.
    public const string Version = "0.5.1";
    // Pairing actions this build supports, so the app can tell what an older relay lacks.
    public static readonly string[] Features = { "rotate", "unpair", "blocks", "refused" };
    public static bool NativeClients { get { return ConfigurationManager.AppSettings["HaTunnelNativeClientsEnabled"] == "true"; } }
}

public sealed class RelayLease : IDisposable
{
    private Action release;
    public RelayLease(Action action) { release = action; }
    public void Dispose() { var action = Interlocked.Exchange(ref release, null); if (action != null) action(); }
}
public class ClientBudget { public DateTime Window, Last; public int Connects, Http, Ws, Waiting; }
public sealed class RelayBudget
{
    readonly object gate = new object();
    readonly Dictionary<string, ClientBudget> clients = new Dictionary<string, ClientBudget>();
    int totalHttp, totalWs, totalWaiting;
    public int[] Active() { lock (gate) { return new[] { totalHttp, totalWs, totalWaiting }; } }
    public bool Rate(string ip, bool connector, DateTime now, bool asset = false)
    {
        lock (gate) {
            ClientBudget budget;
            if (!clients.TryGetValue(ip, out budget)) {
                foreach (var stale in clients.Where(p => p.Value.Http == 0 && p.Value.Ws == 0 && p.Value.Waiting == 0 && (now - p.Value.Last).TotalSeconds > 120).Select(p => p.Key).ToArray()) clients.Remove(stale);
                if (clients.Count >= 1024) return false;
                clients[ip] = budget = new ClientBudget { Window = now, Last = now };
            }
            budget.Last = now;
            if ((now - budget.Window).TotalSeconds >= 60) { budget.Window = now; budget.Connects = 0; }
            if (connector) { if (budget.Connects >= 10) return false; budget.Connects++; }
            return true;
        }
    }
    public RelayLease Acquire(string ip, bool websocket)
    {
        lock (gate) {
            ClientBudget budget;
            if (!clients.TryGetValue(ip, out budget)) return null;
            if (websocket) { if (totalWs >= 8 || budget.Ws >= 8) return null; totalWs++; budget.Ws++; }
            else { if (totalHttp >= 8 || budget.Http >= 8) return null; totalHttp++; budget.Http++; }
            return new RelayLease(() => { lock (gate) { if (websocket) { totalWs--; budget.Ws--; } else { totalHttp--; budget.Http--; } } });
        }
    }
    public async Task<RelayLease> AcquireHttp(string ip, CancellationToken cancel)
    {
        var immediate = Acquire(ip, false);
        if (immediate != null) return immediate;
        ClientBudget budget;
        lock (gate) {
            if (!clients.TryGetValue(ip, out budget) || totalWaiting >= 256 || budget.Waiting >= 128) return null;
            totalWaiting++; budget.Waiting++;
        }
        try {
            var end = DateTime.UtcNow.AddSeconds(20);
            while (DateTime.UtcNow < end) {
                cancel.ThrowIfCancellationRequested();
                await Task.Delay(25, cancel);
                var lease = Acquire(ip, false);
                if (lease != null) return lease;
            }
            return null;
        } finally { lock (gate) { totalWaiting--; budget.Waiting--; } }
    }
}

public class ConnectorPeer
{
    private long readinessUntil;
    private readonly long started = Stopwatch.GetTimestamp();
    public void RenewReadiness() { Interlocked.Exchange(ref readinessUntil, Stopwatch.GetTimestamp() + 20 * Stopwatch.Frequency); }
    public bool IsReady { get { return Stopwatch.GetTimestamp() < Interlocked.Read(ref readinessUntil); } }
    public bool ReadinessExpired { get { return !IsReady && (Interlocked.Read(ref readinessUntil) != 0 || Stopwatch.GetTimestamp() - started > 30 * Stopwatch.Frequency); } }
    public async Task WatchReadiness() {
        try {
            while (!Lifetime.IsCancellationRequested) {
                await Task.Delay(1000, Lifetime.Token);
                if (ReadinessExpired) { HaTunnel.Disconnect(this); return; }
            }
        } catch (OperationCanceledException) { }
    }

    public WebSocket Socket;
    public string Credential;
    public CancellationTokenSource Lifetime = new CancellationTokenSource();
    public SemaphoreSlim SendLock = new SemaphoreSlim(1, 1);
}
public class BrowserPeer
{
    public WebSocket Socket;
    public ConnectorPeer Connector;
    public SemaphoreSlim SendLock = new SemaphoreSlim(1, 1);
    public TaskCompletionSource<bool> Ready = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
}
public class PendingReply
{
    public ConnectorPeer Connector;
    public TaskCompletionSource<Dictionary<string, object>> Completion = new TaskCompletionSource<Dictionary<string, object>>(TaskCreationOptions.RunContinuationsAsynchronously);
    public ConcurrentQueue<byte[]> Chunks = new ConcurrentQueue<byte[]>();
    public SemaphoreSlim Available = new SemaphoreSlim(0);
    public int Sequence, Bytes;
    public bool Streaming, Ended;
    public Exception Failure;
    public void StreamMessage(Dictionary<string, object> msg) {
        string kind = (string)msg["type"];
        if (kind == "http_start") {
            if (Streaming || Completion.Task.IsCompleted) throw new InvalidDataException();
            Streaming = true; Completion.TrySetResult(msg); return;
        }
        if (!Streaming || Ended) throw new InvalidDataException();
        if (kind == "http_abort") { Fail(new IOException("Upstream stream failed")); return; }
        if ((int)msg["sequence"] != Sequence) throw new InvalidDataException();
        if (kind == "http_end") { Ended = true; Chunks.Enqueue(new byte[0]); Available.Release(); return; }
        var bytes = RelayPolicy.Payload(msg["body"], RelayPolicy.HttpChunkLimit);
        if (Bytes + bytes.Length > RelayPolicy.ResponseLimit || Chunks.Count >= 2) throw new InvalidDataException();
        Bytes += bytes.Length; Sequence++; Chunks.Enqueue(bytes); Available.Release();
    }
    public void Fail(Exception error) { Failure = error; Ended = true; Completion.TrySetException(error); Available.Release(); }
    public async Task<byte[]> Next(CancellationToken cancel) {
        await Available.WaitAsync(cancel); if (Failure != null) throw Failure;
        byte[] bytes; if (!Chunks.TryDequeue(out bytes)) throw new IOException("Incomplete response stream"); return bytes;
    }
}
public static class HaTunnel
{
    public static readonly ConcurrentDictionary<string, PendingReply> Requests = new ConcurrentDictionary<string, PendingReply>();
    public static readonly ConcurrentDictionary<string, BrowserPeer> Browsers = new ConcurrentDictionary<string, BrowserPeer>();
    public static readonly RelayBudget Budget = new RelayBudget();
    public static readonly object Gate = new object();
    public static ConnectorPeer Connector;
    public static bool ForwardingEnabled { get { return RelayState.IsPaired ? RelayState.ForwardingEnabled : ConfigurationManager.AppSettings["HaTunnelEnabled"] == "true"; } }
    static readonly ConcurrentQueue<object> Audit = new ConcurrentQueue<object>();
    static readonly object AuditGate = new object();
    static readonly DateTime Started = DateTime.UtcNow;
    static long requests, error4xx, error5xx, responseBytes, dropped;
    public static string Route(string path)
    {
        string route = path.Split('?')[0];
        if (RelayPolicy.AllowedWebSocketPath(route)) return "websocket";
        if (route.StartsWith("/auth/")) return "auth";
        if (route.StartsWith("/frontend_") || route.StartsWith("/static/") || route.StartsWith("/local/")) return "frontend";
        if (route.StartsWith("/api/")) return "api";
        if (route.StartsWith("/media/")) return "media";
        return route == "/" ? "root" : "other";
    }
    public static string DisplayRoute(string path)
    {
        string route = (path ?? "/").Split('?')[0];
        route = Regex.Replace(route, @"(?i)%3f.*$", "", RegexOptions.CultureInvariant);
        // App web UI session tokens are hidden wherever they appear, not only on the socket path.
        route = Regex.Replace(route, @"(?i)(/api/hassio_ingress/)[A-Za-z0-9_-]{32,256}(?=/|$)", "$1[ingress-token]", RegexOptions.CultureInvariant);
        route = Regex.Replace(route, @"(?i)(/auth/login_flow/)[a-f0-9]{32}(?=/|$)", "$1[flow-id]", RegexOptions.CultureInvariant);
        if (route.Length > 512) route = route.Substring(0, 512);
        return route;
    }
    public static void Record(HttpContext context, long duration)
    {
        int status = context.Items["HaWsAccepted"] != null ? 101 : context.Response.StatusCode;
        long bytes = context.Items["HaResponseBytes"] == null ? 0 : (long)context.Items["HaResponseBytes"];
        Interlocked.Increment(ref requests); Interlocked.Add(ref responseBytes, bytes);
        if (status >= 500) Interlocked.Increment(ref error5xx);
        else if (status >= 400) Interlocked.Increment(ref error4xx);
        string category = Route(context.Request.RawUrl);
        System.Net.IPAddress address;
        string ip = System.Net.IPAddress.TryParse(context.Request.UserHostAddress, out address) ? address.ToString() : "unknown";
        lock (AuditGate) {
            if (Audit.Count >= 256) { Interlocked.Increment(ref dropped); return; }
            Audit.Enqueue(new { ip = ip, method = RelayPolicy.Methods.Contains(context.Request.HttpMethod) ? context.Request.HttpMethod : "OTHER",
                route = DisplayRoute(context.Request.RawUrl), status = status, duration_ms = Math.Min(duration, 86400000), request_bytes = Math.Max(0, context.Request.ContentLength), response_bytes = bytes });
        }
    }
    public static object Telemetry()
    {
        var events = new List<object>(); object item;
        lock (AuditGate) { while (events.Count < 64 && Audit.TryDequeue(out item)) events.Add(item); }
        var active = Budget.Active();
        return new { type = "telemetry", events = events, stats = new {
            forwarding_enabled = ForwardingEnabled ? 1 : 0,
            requests = Interlocked.Read(ref requests), errors_4xx = Interlocked.Read(ref error4xx), errors_5xx = Interlocked.Read(ref error5xx),
            response_bytes = Interlocked.Read(ref responseBytes), active_http = active[0], active_ws = active[1], queued_http = active[2],
            events_dropped = Interlocked.Read(ref dropped), uptime_seconds = (long)(DateTime.UtcNow - Started).TotalSeconds } };
    }
    // The last WebSocket connections the relay refused, so the app can show why an app's UI fails.
    static readonly ConcurrentQueue<object> RefusedSockets = new ConcurrentQueue<object>();
    public static void RecordRefusal(string ip, string path, string reason)
    {
        System.Net.IPAddress address;
        RefusedSockets.Enqueue(new { at = DateTime.UtcNow.ToString("o"), ip = System.Net.IPAddress.TryParse(ip, out address) ? address.ToString() : "unknown",
            route = DisplayRoute(path), reason = reason });
        object dropped;
        while (RefusedSockets.Count > 20 && RefusedSockets.TryDequeue(out dropped)) { }
    }
    public static object[] Refusals() { return RefusedSockets.ToArray(); }
    public static bool Register(ConnectorPeer peer) { lock (Gate) { if (Connector != null) return false; Connector = peer; return true; } }
    public static void Disconnect(ConnectorPeer peer)
    {
        lock (Gate) { if (Connector == peer) Connector = null; }
        peer.Lifetime.Cancel();
        foreach (var pending in Requests.Values.Where(p => p.Connector == peer)) pending.Fail(new IOException("Connector unavailable"));
        foreach (var browser in Browsers.Values.Where(p => p.Connector == peer)) { browser.Ready.TrySetResult(false); browser.Socket.Abort(); }
        peer.Socket.Abort();
        Trace.TraceInformation("HA relay connector disconnected");
    }
    public static async Task Send(ConnectorPeer peer, object message)
    {
        if (peer == null || peer.Lifetime.IsCancellationRequested) throw new IOException();
        byte[] bytes = RelayPolicy.Utf8.GetBytes(RelayPolicy.Json().Serialize(message));
        if (bytes.Length > RelayPolicy.FrameLimit) throw new InvalidDataException();
        using (var timer = CancellationTokenSource.CreateLinkedTokenSource(peer.Lifetime.Token)) {
            timer.CancelAfter(10000);
            await peer.SendLock.WaitAsync(timer.Token);
            try { await peer.Socket.SendAsync(new ArraySegment<byte>(bytes), WebSocketMessageType.Text, true, timer.Token); }
            finally { peer.SendLock.Release(); }
        }
    }
    public static bool Secure(HttpContext context)
    {
        context.Response.TrySkipIisCustomErrors = true;
        context.Response.Cache.SetCacheability(HttpCacheability.NoCache);
        context.Response.Cache.SetNoStore();
        Uri expected;
        if (!context.Request.IsSecureConnection) { context.Response.StatusCode = 403; return false; }
        if (!String.IsNullOrEmpty(RelayPolicy.Origin) && (!Uri.TryCreate(RelayPolicy.Origin, UriKind.Absolute, out expected)
            || !String.Equals(context.Request.Url.GetLeftPart(UriPartial.Authority), expected.GetLeftPart(UriPartial.Authority), StringComparison.OrdinalIgnoreCase))) {
            context.Response.StatusCode = 403; return false;
        }
        return true;
    }
    public static Dictionary<string, string> Headers(HttpRequest request)
    {
        var values = new Dictionary<string, object>();
        foreach (string key in request.Headers.AllKeys) if (key != null && RelayPolicy.RequestHeaders.Contains(key)) values[key] = request.Headers[key];
        return RelayPolicy.ValidateHeaders(values, false);
    }
    public static string Path(HttpRequest request)
    {
        // IIS owns this variable; never use a client-supplied X-Original-URL header.
        return RelayPolicy.ValidPath(request.ServerVariables["UNENCODED_URL"] ?? request.RawUrl);
    }
}

public class HaConnect : HttpTaskAsyncHandler
{
    public override Task ProcessRequestAsync(HttpContext context)
    {
        if (!HaTunnel.Secure(context)) return Task.FromResult(0);
        if (!HaTunnel.Budget.Rate(context.Request.UserHostAddress ?? "unknown", true, DateTime.UtcNow)) { context.Response.StatusCode = 429; return Task.FromResult(0); }
        string credential = context.Request.Headers["Authorization"] ?? "";
        if (!RelayPolicy.KeyAllowed(credential)) { context.Response.StatusCode = 403; return Task.FromResult(0); }
        if (context.Request.Headers["Origin"] != null && !RelayPolicy.GoodOrigin(context.Request.Headers["Origin"])) { context.Response.StatusCode = 403; return Task.FromResult(0); }
        if (!context.IsWebSocketRequest) { context.Response.StatusCode = 400; return Task.FromResult(0); }
        context.AcceptWebSocketRequest(async ws => {
            var peer = new ConnectorPeer { Socket = ws.WebSocket, Credential = credential };
            if (!HaTunnel.Register(peer)) { peer.Socket.Abort(); return; }
            Trace.TraceInformation("HA relay connector connected");
            Task readinessWatch = peer.WatchReadiness();
            try {
                while (!peer.Lifetime.IsCancellationRequested) {
                    var frame = await RelayPolicy.Read(peer.Socket, RelayPolicy.FrameLimit, 60000, peer.Lifetime.Token);
                    if (frame == null) break;
                    if (frame.Item2 != WebSocketMessageType.Text || !RelayPolicy.KeyAllowed(peer.Credential)) throw new InvalidDataException();
                    var msg = RelayPolicy.Parse(RelayPolicy.Utf8.GetString(frame.Item1));
                    string type = (string)msg["type"];
                    if (type == "connector_ready") { peer.RenewReadiness(); continue; }
                    if (type == "ping") { await HaTunnel.Send(peer, new { type = "pong" }); await HaTunnel.Send(peer, HaTunnel.Telemetry()); continue; }
                    string id = (string)msg["id"];
                    if (type.StartsWith("http_")) {
                        PendingReply completion;
                        if (HaTunnel.Requests.TryGetValue(id, out completion) && completion.Connector == peer) {
                            if (type == "http_response") completion.Completion.TrySetResult(msg);
                            else completion.StreamMessage(msg);
                        }
                    } else {
                        BrowserPeer browser;
                        if (!HaTunnel.Browsers.TryGetValue(id, out browser) || browser.Connector != peer) continue;
                        if (type == "ws_ready") browser.Ready.TrySetResult(true);
                        else if (type == "ws_close") { browser.Ready.TrySetResult(false); browser.Socket.Abort(); }
                        else if (type == "ws_data") {
                            var bytes = RelayPolicy.Payload(msg["data"], RelayPolicy.WsLimit);
                            try {
                                using (var timer = CancellationTokenSource.CreateLinkedTokenSource(peer.Lifetime.Token)) {
                                    timer.CancelAfter(10000);
                                    await browser.SendLock.WaitAsync(timer.Token);
                                    try { await browser.Socket.SendAsync(new ArraySegment<byte>(bytes), (string)msg["kind"] == "binary" ? WebSocketMessageType.Binary : WebSocketMessageType.Text, true, timer.Token); }
                                    finally { browser.SendLock.Release(); }
                                }
                            } catch {
                                // A closed/slow browser must not tear down the household's tunnel.
                                BrowserPeer removed; HaTunnel.Browsers.TryRemove(id, out removed);
                                browser.Socket.Abort();
                            }
                        }
                    }
                }
            } catch { Trace.TraceWarning("HA relay connector ended or invalid message rejected"); }
            finally { HaTunnel.Disconnect(peer); }
            await readinessWatch;
        });
        return Task.FromResult(0);
    }
}

public class HaRelay : HttpTaskAsyncHandler
{
    public override async Task ProcessRequestAsync(HttpContext context)
    {
        var watch = Stopwatch.StartNew();
        try { await RelayRequest(context); }
        finally { HaTunnel.Record(context, watch.ElapsedMilliseconds); }
    }
    async Task RelayRequest(HttpContext context)
    {
        // Addresses the app blocked never reach the connector, or even the setup page.
        if (RelayBlocks.IsBlocked(context.Request.UserHostAddress)) {
            context.Response.TrySkipIisCustomErrors = true;
            context.Response.StatusCode = 403; context.Response.ContentType = "text/plain"; context.Response.Write("Blocked"); return;
        }
        string originalUrl = context.Request.ServerVariables["UNENCODED_URL"] ?? context.Request.RawUrl;
        bool rootRequest = originalUrl == "/" || originalUrl.StartsWith("/?", StringComparison.Ordinal);
        if (context.Request.HttpMethod == "GET" && rootRequest && !HaTunnel.ForwardingEnabled) {
            if (!context.Request.IsSecureConnection) { context.Response.StatusCode = 403; return; }
            context.Response.Cache.SetCacheability(HttpCacheability.NoCache);
            context.Response.Cache.SetNoStore();
            context.Response.ContentType = "text/html; charset=utf-8";
            context.Response.Headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'";
            context.Response.Write(RelayState.IsPaired
                ? "<!doctype html><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>Home Tunnel paired</title><p>Home Tunnel is paired. Manage forwarding in Home Assistant.</p>"
                : SetupPage);
            return;
        }
        if (!HaTunnel.Secure(context)) return;
        string ip = context.Request.UserHostAddress ?? "unknown";
        string path; Dictionary<string, string> headers;
        try { path = HaTunnel.Path(context.Request); headers = HaTunnel.Headers(context.Request); }
        catch { context.Response.StatusCode = 400; return; }
        if (!HaTunnel.Budget.Rate(ip, false, DateTime.UtcNow)) { context.Response.StatusCode = 503; context.Response.Headers["Retry-After"] = "2"; return; }
        bool nativeClient = context.Request.Headers["Origin"] == null && ConfigurationManager.AppSettings["HaTunnelNativeClientsEnabled"] == "true";
        bool originAllowed = RelayPolicy.GoodWebSocketOrigin(context.Request.Headers["Origin"], nativeClient, path);
        if (context.IsWebSocketRequest && !originAllowed) { HaTunnel.RecordRefusal(ip, path, "origin"); context.Response.StatusCode = 403; return; }
        if (!HaTunnel.ForwardingEnabled) { context.Response.StatusCode = 503; context.Response.Write("Relay disabled"); return; }
        var connector = HaTunnel.Connector;
        if (connector == null || connector.Lifetime.IsCancellationRequested || !connector.IsReady) { context.Response.StatusCode = 503; context.Response.Write("Home connector offline"); return; }
        if (!RelayPolicy.Methods.Contains(context.Request.HttpMethod)) { context.Response.StatusCode = 405; return; }
        if (context.IsWebSocketRequest && (!RelayPolicy.AllowedWebSocketPath(path) || !originAllowed)) { HaTunnel.RecordRefusal(ip, path, "path"); context.Response.StatusCode = 403; return; }
        RelayLease lease;
        try { lease = context.IsWebSocketRequest ? HaTunnel.Budget.Acquire(ip, true) : await HaTunnel.Budget.AcquireHttp(ip, connector.Lifetime.Token); }
        catch { context.Response.StatusCode = 503; return; }
        if (lease == null) { context.Response.StatusCode = 503; context.Response.Headers["Retry-After"] = "2"; return; }
        string id = Guid.NewGuid().ToString("N");
        if (context.IsWebSocketRequest) {
            try {
                context.AcceptWebSocketRequest(async ws => {
                    using (lease) {
                        var browser = new BrowserPeer { Socket = ws.WebSocket, Connector = connector };
                        HaTunnel.Browsers[id] = browser;
                        try {
                            if (nativeClient)
                                await HaTunnel.Send(connector, new { type = "ws_open", id = id, path = path, headers = headers, client_ip = ip, native_client = true });
                            else
                                await HaTunnel.Send(connector, new { type = "ws_open", id = id, path = path, headers = headers, client_ip = ip });
                            if (await Task.WhenAny(browser.Ready.Task, Task.Delay(15000, connector.Lifetime.Token)) != browser.Ready.Task || !await browser.Ready.Task) throw new IOException();
                            var started = DateTime.UtcNow;
                            while (!connector.Lifetime.IsCancellationRequested && (DateTime.UtcNow - started).TotalMinutes < 30) {
                                var frame = await RelayPolicy.Read(browser.Socket, RelayPolicy.WsLimit, 90000, connector.Lifetime.Token);
                                if (frame == null) break;
                                if (frame.Item2 == WebSocketMessageType.Text) RelayPolicy.Utf8.GetString(frame.Item1);
                                await HaTunnel.Send(connector, new { type = "ws_data", id = id, kind = frame.Item2 == WebSocketMessageType.Binary ? "binary" : "text", data = Convert.ToBase64String(frame.Item1) });
                            }
                        } catch { Trace.TraceInformation("HA relay browser connection ended"); }
                        finally {
                            BrowserPeer ignored; HaTunnel.Browsers.TryRemove(id, out ignored);
                            browser.Socket.Abort();
                        }
                        try { await HaTunnel.Send(connector, new { type = "ws_close", id = id }); } catch { }
                    }
                });
                context.Items["HaWsAccepted"] = true;
            } catch { lease.Dispose(); context.Response.StatusCode = 502; }
            return;
        }
        using (lease) {
            if (context.Request.ContentLength > RelayPolicy.HttpLimit) { context.Response.StatusCode = 413; return; }
            var pending = new PendingReply { Connector = connector };
            HaTunnel.Requests[id] = pending;
            try {
                byte[] body;
                using (var timer = CancellationTokenSource.CreateLinkedTokenSource(connector.Lifetime.Token)) {
                    timer.CancelAfter(15000);
                    body = await RelayPolicy.BoundedRead(context.Request.InputStream, RelayPolicy.HttpLimit, timer.Token);
                }
                await HaTunnel.Send(connector, new { type = "http", id = id, method = context.Request.HttpMethod, path = path, headers = headers, body = Convert.ToBase64String(body) });
                if (await Task.WhenAny(pending.Completion.Task, Task.Delay(50000, connector.Lifetime.Token)) != pending.Completion.Task) { context.Response.StatusCode = connector.Lifetime.IsCancellationRequested ? 503 : 504; return; }
                var reply = await pending.Completion.Task;
                context.Response.StatusCode = (int)reply["status"];
                foreach (var entry in RelayPolicy.ValidateHeaders(reply["headers"] as Dictionary<string, object>, true)) {
                    if (entry.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase)) context.Response.ContentType = entry.Value;
                    else context.Response.Headers[entry.Key] = entry.Value;
                }
                context.Response.Headers["X-Content-Type-Options"] = "nosniff";
                if ((string)reply["type"] == "http_start") {
                    context.Response.BufferOutput = false;
                    using (var timer = CancellationTokenSource.CreateLinkedTokenSource(connector.Lifetime.Token)) {
                        timer.CancelAfter(60000); int sequence = 0; long total = 0;
                        while (true) {
                            var chunk = await pending.Next(timer.Token); if (chunk.Length == 0) break;
                            await context.Response.OutputStream.WriteAsync(chunk, 0, chunk.Length, timer.Token);
                            await context.Response.OutputStream.FlushAsync(timer.Token);
                            total += chunk.Length; context.Items["HaResponseBytes"] = total;
                            await HaTunnel.Send(connector, new { type = "http_ack", id = id, sequence = sequence++ });
                        }
                    }
                    return;
                }
                var bytes = RelayPolicy.LoginPage(path, (int)reply["status"], context.Response.ContentType, RelayPolicy.Payload(reply["body"], RelayPolicy.HttpLimit));
                context.Items["HaResponseBytes"] = (long)bytes.Length;
                using (var timer = CancellationTokenSource.CreateLinkedTokenSource(connector.Lifetime.Token)) {
                    timer.CancelAfter(10000);
                    await context.Response.OutputStream.WriteAsync(bytes, 0, bytes.Length, timer.Token);
                }
            } catch (InvalidDataException) { context.Response.StatusCode = 413; }
            catch { if (pending.Streaming) context.Response.Close(); else context.Response.StatusCode = connector.Lifetime.IsCancellationRequested ? 503 : 502; }
            finally { PendingReply ignored; HaTunnel.Requests.TryRemove(id, out ignored); }
        }
    }

    static readonly string SetupPage = @"<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><meta name='referrer' content='no-referrer'><title>Home Tunnel setup</title><style>
*{box-sizing:border-box}body{margin:0;background:#101820;color:#f3f6f8;font:16px system-ui,sans-serif;min-height:100vh;display:grid;place-items:center;padding:20px}.card{width:min(100%,520px);background:#1b2833;border:1px solid #354655;border-radius:18px;padding:clamp(20px,5vw,36px);box-shadow:0 14px 50px #0005}h1{font-size:1.55rem;margin:0 0 12px}p{line-height:1.55;color:#c5d1d9}.small{font-size:.9rem;color:#a9bac5;line-height:1.5}</style><main class='card'><h1>Home Tunnel is awaiting setup</h1><p>Continue in the Home Tunnel app in Home Assistant to pair this relay.</p><p class='small'>This public page is informational. Pairing is configured in Home Assistant and requires the one-time setup hash from the private web.config.</p></main></html>";
}

public class HaPairing : IHttpHandler
{
    public bool IsReusable { get { return true; } }
    public void ProcessRequest(HttpContext context)
    {
        context.Response.TrySkipIisCustomErrors = true;
        context.Response.Cache.SetCacheability(HttpCacheability.NoCache);
        context.Response.Cache.SetNoStore();
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        context.Response.Headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'";
        if (!context.Request.IsSecureConnection) { context.Response.StatusCode = 403; return; }
        string action = context.Request.QueryString["action"] ?? "";
        string authorization = context.Request.Headers["Authorization"] ?? "";
        if (action == "challenge" || action == "claim") {
            if (context.Request.HttpMethod != "POST") { context.Response.StatusCode = 405; return; }
            string body;
            try {
                body = ReadBody(context, 1024);
                var data = RelayPolicy.Json().Deserialize<Dictionary<string, object>>(body);
                if (data == null) throw new InvalidDataException();
                if (!RelayState.AllowAttempt(action, context.Request.UserHostAddress, 20, 600)) { context.Response.StatusCode = 429; return; }
                string clientNonce = data["client_nonce"] as string;
                string origin = data["origin"] as string;
                string requestOrigin = context.Request.Url.GetLeftPart(UriPartial.Authority);
                if (action == "challenge") {
                    string serverNonce, serverProof;
                    if (!RelayState.StartPair(clientNonce, origin, requestOrigin, out serverNonce, out serverProof)) { context.Response.StatusCode = 409; return; }
                    Json(context, new { server_nonce = serverNonce, server_proof = serverProof }); return;
                }
                string serverNonceClaim = data["server_nonce"] as string;
                string serverProofClaim = data["server_proof"] as string;
                string clientProof = data["client_proof"] as string;
                string issuedProof;
                string key = RelayState.ClaimPair(clientNonce, serverNonceClaim, origin, requestOrigin, serverProofClaim, clientProof, out issuedProof);
                if (key == null) { context.Response.StatusCode = 409; return; }
                Json(context, new { status = "paired", connector_token = key, server_proof = issuedProof }); return;
            } catch (InvalidDataException) { context.Response.StatusCode = 400; return; }
            catch (UnauthorizedAccessException) { context.Response.StatusCode = 500; return; }
            catch (IOException) { context.Response.StatusCode = 500; return; }
            catch { context.Response.StatusCode = 400; return; }
        }
        if (action == "rotate" || action == "confirm_rotation" || action == "unpair" || action == "blocks") {
            string bearer = authorization.StartsWith("Bearer ", StringComparison.Ordinal) ? authorization.Substring("Bearer ".Length) : "";
            if (context.Request.HttpMethod != "POST") { context.Response.StatusCode = 405; return; }
            if (!RelayState.AllowAttempt(action, context.Request.UserHostAddress, 30, 600)) { context.Response.StatusCode = 429; return; }
            try {
                if (action == "rotate") {
                    string token = RelayState.Rotate(bearer);
                    if (token == null) { context.Response.StatusCode = 403; return; }
                    Json(context, new { status = "pending", connector_token = token }); return;
                }
                if (action == "confirm_rotation") {
                    if (!RelayState.ConfirmRotation(bearer)) { context.Response.StatusCode = 403; return; }
                    // The connector still holds the old key; drop it so it reconnects with the new one.
                    var current = HaTunnel.Connector; if (current != null) HaTunnel.Disconnect(current);
                    Json(context, new { status = "rotated" }); return;
                }
                if (action == "unpair") {
                    if (!RelayState.Reset(bearer)) { context.Response.StatusCode = 403; return; }
                    RelayBlocks.Clear();
                    var current = HaTunnel.Connector; if (current != null) HaTunnel.Disconnect(current);
                    Json(context, new { status = "unpaired" }); return;
                }
                if (!RelayPolicy.KeyAllowed(authorization)) { context.Response.StatusCode = 403; return; }
                string text = ReadBody(context, RelayBlocks.BodyLimit);
                RelayPolicy.RejectDuplicateFields(text);
                var data = new JavaScriptSerializer { MaxJsonLength = RelayBlocks.BodyLimit, RecursionLimit = 6 }.Deserialize<Dictionary<string, object>>(text);
                object list;
                if (data == null || data.Count != 1 || !data.TryGetValue("blocks", out list)) throw new InvalidDataException();
                var rules = RelayBlocks.FromJson(list);
                if (rules == null) throw new InvalidDataException();
                RelayBlocks.Replace(rules, text);
                Json(context, new { status = "saved", count = rules.Count }); return;
            } catch (InvalidDataException) { context.Response.StatusCode = 400; return; }
            catch (UnauthorizedAccessException) { context.Response.StatusCode = 500; return; }
            catch (IOException) { context.Response.StatusCode = 500; return; }
            catch { context.Response.StatusCode = 400; return; }
        }
        if (action == "refused") {
            if (context.Request.HttpMethod != "POST" || !RelayPolicy.KeyAllowed(authorization)) { context.Response.StatusCode = 403; return; }
            Json(context, new { refused = HaTunnel.Refusals(), native_clients = RelayBuild.NativeClients }); return;
        }
        if (action == "finalize" || action == "enable" || action == "disable" || action == "version") {
            string bearer = authorization.StartsWith("Bearer ", StringComparison.Ordinal) ? authorization.Substring("Bearer ".Length) : "";
            bool authorized = action == "finalize" ? RelayState.PairingKeyAllowed(bearer) : RelayPolicy.KeyAllowed(authorization);
            if (context.Request.HttpMethod != "POST" || !authorized) { context.Response.StatusCode = 403; return; }
            if (action == "version") { Json(context, new { version = RelayBuild.Version, features = RelayBuild.Features, native_clients = RelayBuild.NativeClients }); return; }
            string key = bearer;
            bool ok = action == "finalize" ? RelayState.Finalize(key) : RelayState.SetEnabled(key, action == "enable");
            if (!ok) { context.Response.StatusCode = 409; return; }
            Json(context, new { status = action == "enable" ? "enabled" : action == "disable" ? "disabled" : "finalized" }); return;
        }
        context.Response.StatusCode = 404;
    }

    static string ReadBody(HttpContext context, int limit)
    {
        if (context.Request.ContentLength > limit) throw new InvalidDataException();
        var text = new StringBuilder();
        var buffer = new char[1024];
        using (var reader = new StreamReader(context.Request.InputStream, Encoding.UTF8)) {
            int count;
            while ((count = reader.Read(buffer, 0, buffer.Length)) > 0) {
                if (text.Length + count > limit) throw new InvalidDataException();
                text.Append(buffer, 0, count);
            }
        }
        return text.ToString();
    }

    static void Json(HttpContext context, object value)
    {
        context.Response.ContentType = "application/json; charset=utf-8";
        context.Response.Write(RelayPolicy.Json().Serialize(value));
    }
}

public class HaClientInfo : IHttpHandler
{
    public bool IsReusable { get { return true; } }
    public void ProcessRequest(HttpContext context)
    {
        if (!HaTunnel.Secure(context)) return;
        if (context.Request.HttpMethod != "GET") { context.Response.StatusCode = 405; return; }
        if (context.Request.Headers["Origin"] != null && !RelayPolicy.GoodOrigin(context.Request.Headers["Origin"])) { context.Response.StatusCode = 403; return; }
        System.Net.IPAddress address;
        if (!System.Net.IPAddress.TryParse(context.Request.UserHostAddress, out address)) { context.Response.StatusCode = 503; return; }
        context.Response.ContentType = "application/json";
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        context.Response.Write(RelayPolicy.Json().Serialize(new { ip = address.ToString() }));
    }
}
