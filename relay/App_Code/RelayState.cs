using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web.Hosting;
using System.Web.Script.Serialization;

public sealed class RelayStateData
{
    public string origin { get; set; }
    public string active_key_hash { get; set; }
    public bool forwarding_enabled { get; set; }
    public bool pairing_finalized { get; set; }
    public string pending_client_nonce { get; set; }
    public string pending_server_nonce { get; set; }
    public string pending_origin { get; set; }
    public string pending_expires_utc { get; set; }
    public string pending_bootstrap_fingerprint { get; set; }
}

public static class RelayState
{
    static readonly object Gate = new object();
    static readonly Dictionary<string, Queue<DateTime>> Limits = new Dictionary<string, Queue<DateTime>>();
    static readonly JavaScriptSerializer Json = new JavaScriptSerializer { MaxJsonLength = 8192 };

    static string FilePath
    {
        get {
            string root = HostingEnvironment.MapPath("~/App_Data");
            if (String.IsNullOrEmpty(root)) throw new InvalidOperationException("Relay data path unavailable");
            Directory.CreateDirectory(root);
            return Path.Combine(root, "home-tunnel-state.json");
        }
    }

    static RelayStateData Read()
    {
        try {
            var path = FilePath;
            if (new FileInfo(path).Length > 8192) throw new InvalidDataException("Relay state is too large");
            var data = Json.Deserialize<RelayStateData>(File.ReadAllText(path, Encoding.UTF8));
            return data ?? new RelayStateData();
        } catch (FileNotFoundException) { return new RelayStateData(); }
    }

    static void Write(RelayStateData data)
    {
        string path = FilePath;
        string temp = path + ".tmp";
        if (File.Exists(temp)) File.Delete(temp);
        File.WriteAllText(temp, Json.Serialize(data), new UTF8Encoding(false));
        if (File.Exists(path)) File.Replace(temp, path, null);
        else File.Move(temp, path);
    }

    public static bool AllowAttempt(string action, string address, int maximum, int seconds)
    {
        lock (Gate) {
            DateTime now = DateTime.UtcNow;
            string id = action + ":" + (address ?? "unknown");
            Queue<DateTime> times;
            if (!Limits.TryGetValue(id, out times)) {
                if (Limits.Count >= 1024) {
                    foreach (var key in Limits.Where(p => p.Value.Count == 0 || (now - p.Value.Peek()).TotalSeconds > 600).Select(p => p.Key).ToArray()) Limits.Remove(key);
                    if (Limits.Count >= 1024) return false;
                }
                Limits[id] = times = new Queue<DateTime>();
            }
            while (times.Count > 0 && (now - times.Peek()).TotalSeconds >= seconds) times.Dequeue();
            if (times.Count >= maximum) return false;
            times.Enqueue(now);
            return true;
        }
    }

    static bool ValidHex(string value)
    {
        return value != null && System.Text.RegularExpressions.Regex.IsMatch(value, "\\A[0-9a-f]{64}\\z");
    }

    static byte[] BootstrapKey()
    {
        string value = System.Configuration.ConfigurationManager.AppSettings["HaTunnelBootstrapCodeHash"];
        if (!ValidHex(value)) return null;
        byte[] bytes = new byte[32];
        for (int i = 0; i < bytes.Length; i++) bytes[i] = Convert.ToByte(value.Substring(i * 2, 2), 16);
        return bytes;
    }

    static byte[] HashBytes(string value)
    {
        using (var sha = SHA256.Create()) return sha.ComputeHash(Encoding.ASCII.GetBytes(value ?? ""));
    }

    static string Hash(string value)
    {
        return BitConverter.ToString(HashBytes(value)).Replace("-", "").ToLowerInvariant();
    }

    static string Fingerprint(byte[] value)
    {
        using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(value)).Replace("-", "").ToLowerInvariant();
    }

    static string Hmac(byte[] key, string purpose, string origin, string clientNonce, string serverNonce, string value = "")
    {
        string message = "home-tunnel-pair-v1\n" + purpose + "\n" + origin + "\n" + clientNonce + "\n" + serverNonce + "\n" + value;
        using (var hmac = new HMACSHA256(key)) return BitConverter.ToString(hmac.ComputeHash(Encoding.UTF8.GetBytes(message))).Replace("-", "").ToLowerInvariant();
    }

    static string RandomHex()
    {
        byte[] bytes = new byte[32];
        using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(bytes);
        return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
    }

    static string CreateServerNonce()
    {
        long seconds = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
        return seconds.ToString("x16") + RandomHex().Substring(0, 48);
    }

    static bool FreshServerNonce(string nonce)
    {
        try {
            long seconds = Convert.ToInt64(nonce.Substring(0, 16), 16);
            long now = (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            return seconds <= now + 60 && now - seconds <= 600;
        } catch { return false; }
    }

    static bool FixedEquals(string expected, string actual)
    {
        byte[] a = Encoding.ASCII.GetBytes(expected ?? ""), b = Encoding.ASCII.GetBytes(actual ?? "");
        int mismatch = a.Length ^ b.Length;
        int length = Math.Max(a.Length, b.Length);
        for (int i = 0; i < length; i++) mismatch |= (i < a.Length ? a[i] : 0) ^ (i < b.Length ? b[i] : 0);
        return mismatch == 0;
    }

    static bool CanonicalOrigin(string origin, string requestOrigin, out string canonical)
    {
        canonical = null;
        Uri parsed;
        if (!Uri.TryCreate(origin, UriKind.Absolute, out parsed) || parsed.Scheme != Uri.UriSchemeHttps
            || parsed.UserInfo.Length != 0 || parsed.AbsolutePath != "/" || parsed.Query.Length != 0 || parsed.Fragment.Length != 0) return false;
        canonical = parsed.GetLeftPart(UriPartial.Authority).TrimEnd('/');
        return String.Equals(canonical, requestOrigin, StringComparison.OrdinalIgnoreCase);
    }

    static bool ChallengeLive(RelayStateData state)
    {
        DateTime expiry;
        return ValidHex(state.pending_client_nonce) && ValidHex(state.pending_server_nonce)
            && DateTime.TryParse(state.pending_expires_utc, null, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out expiry)
            && DateTime.UtcNow < expiry;
    }

    public static string Origin
    {
        get { lock (Gate) return Read().origin ?? ""; }
    }

    public static bool IsPaired
    {
        get { lock (Gate) return !String.IsNullOrEmpty(Read().active_key_hash); }
    }

    public static bool ForwardingEnabled
    {
        get { lock (Gate) return Read().forwarding_enabled; }
    }

    public static bool KeyAllowed(string key)
    {
        if (!ValidHex(key)) return false;
        lock (Gate) {
            var state = Read();
            return state.pairing_finalized && !String.IsNullOrEmpty(state.active_key_hash) && FixedEquals(state.active_key_hash, Hash(key));
        }
    }

    public static bool PairingKeyAllowed(string key)
    {
        if (!ValidHex(key)) return false;
        lock (Gate) {
            var state = Read();
            return !String.IsNullOrEmpty(state.active_key_hash) && FixedEquals(state.active_key_hash, Hash(key));
        }
    }

    public static bool StartPair(string clientNonce, string origin, string requestOrigin, out string serverNonce, out string serverProof)
    {
        serverNonce = serverProof = null;
        string canonical;
        if (!ValidHex(clientNonce) || !CanonicalOrigin(origin, requestOrigin, out canonical)) return false;
        lock (Gate) {
            var state = Read();
            byte[] key = BootstrapKey();
            if (key == null) return false;
            if (!String.IsNullOrEmpty(state.active_key_hash)) {
                if (state.pairing_finalized) return false;
                if (ChallengeLive(state)) {
                    if (FixedEquals(state.pending_bootstrap_fingerprint, Fingerprint(key))) {
                        if (!FixedEquals(state.pending_client_nonce, clientNonce)
                            || !String.Equals(state.pending_origin, canonical, StringComparison.OrdinalIgnoreCase)) return false;
                        serverNonce = state.pending_server_nonce;
                        serverProof = Hmac(key, "server", canonical, clientNonce, serverNonce);
                        return true;
                    }
                }
                state.active_key_hash = null;
                state.origin = null;
                state.forwarding_enabled = false;
                state.pending_client_nonce = null;
                state.pending_server_nonce = null;
                state.pending_origin = null;
                state.pending_expires_utc = null;
                state.pending_bootstrap_fingerprint = null;
                Write(state);
            }
            serverNonce = CreateServerNonce();
            serverProof = Hmac(key, "server", canonical, clientNonce, serverNonce);
            return true;
        }
    }

    public static string ClaimPair(string clientNonce, string serverNonce, string origin, string requestOrigin, string suppliedServerProof, string clientProof, out string serverProof)
    {
        serverProof = null;
        string canonical;
        if (!ValidHex(clientNonce) || !ValidHex(serverNonce) || !ValidHex(suppliedServerProof) || !ValidHex(clientProof)
            || !FreshServerNonce(serverNonce) || !CanonicalOrigin(origin, requestOrigin, out canonical)) return null;
        lock (Gate) {
            var state = Read();
            if (state.pairing_finalized) return null;
            bool retry = !String.IsNullOrEmpty(state.active_key_hash);
            if (retry && (!ChallengeLive(state) || !FixedEquals(state.pending_client_nonce, clientNonce)
                || !FixedEquals(state.pending_server_nonce, serverNonce)
                || !String.Equals(state.pending_origin, canonical, StringComparison.OrdinalIgnoreCase))) return null;
            byte[] key = BootstrapKey();
            if (key == null) return null;
            if (!FixedEquals(Hmac(key, "server", canonical, clientNonce, serverNonce), suppliedServerProof)) return null;
            string expected = Hmac(key, "client", canonical, clientNonce, serverNonce);
            if (!FixedEquals(expected, clientProof)) return null;

            // Deterministic within this short challenge window so a lost HTTP response can be retried.
            string token = Hmac(key, "connector", canonical, clientNonce, serverNonce);
            string tokenHash = Hash(token);
            if (!String.IsNullOrEmpty(state.active_key_hash) && !FixedEquals(state.active_key_hash, tokenHash)) return null;
            state.origin = canonical;
            state.active_key_hash = tokenHash;
            state.forwarding_enabled = false;
            state.pairing_finalized = false;
            state.pending_client_nonce = clientNonce;
            state.pending_server_nonce = serverNonce;
            state.pending_origin = canonical;
            state.pending_expires_utc = DateTime.UtcNow.AddMinutes(10).ToString("o");
            state.pending_bootstrap_fingerprint = Fingerprint(key);
            Write(state);
            serverProof = Hmac(key, "issued", canonical, clientNonce, serverNonce, token);
            return token;
        }
    }

    public static bool Finalize(string key)
    {
        lock (Gate) {
            var state = Read();
            if (String.IsNullOrEmpty(state.active_key_hash) || !FixedEquals(state.active_key_hash, Hash(key))) return false;
            state.pairing_finalized = true;
            state.pending_client_nonce = null;
            state.pending_server_nonce = null;
            state.pending_origin = null;
            state.pending_expires_utc = null;
            state.pending_bootstrap_fingerprint = null;
            Write(state);
            return true;
        }
    }

    public static bool SetEnabled(string key, bool enabled)
    {
        lock (Gate) {
            var state = Read();
            if (!state.pairing_finalized || String.IsNullOrEmpty(state.active_key_hash) || !FixedEquals(state.active_key_hash, Hash(key))) return false;
            state.forwarding_enabled = enabled;
            Write(state);
            return true;
        }
    }
}
