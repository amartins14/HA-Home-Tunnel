# Configuration

## Home Assistant app options

Set these through the Home Assistant app configuration UI:

| Option | Required value | Purpose |
| --- | --- | --- |
| `homeassistant_url` | Defaults automatically | Advanced override for the HA server this connector may reach. Normal installs use `http://homeassistant:8123`. No path, query, credentials, or fragment. |
| `metrics_token` | 64 lowercase hexadecimal characters, or blank | Optional shared key for the Home Tunnel integration. Blank lets the app create a private key for its own dashboard automatically. |
| `geolocation_lookup` | `false` by default | Enables city/region lookups for public caller IPs through ipapi.co (*Show city names*). The provider receives each IP looked up. Results are cached in memory for 24 hours, with a 200-new-IP daily cap. Countries don't use this. It can also be changed in the dashboard Settings page; changing this app option later resets the dashboard value. |

Caller IP history is stored in the app's private state for up to 30 days and capped at 2,048 addresses. The Activity page can search and filter callers and clear the stored history. *Signed in to HA* is recorded only after the connector observes Home Assistant's `auth_ok` WebSocket response; *No sign-in seen* means no such response was observed.

Enter the public HTTPS URL once, in the setup steps on the dashboard's Overview tab. It derives the relay WebSocket address and the browser-facing origin from that URL. The app connects to Home Assistant automatically at `http://homeassistant:8123`; only change `homeassistant_url` in the app's Configuration tab for an unusual network layout.

The connector accepts only relative paths from the relay and joins them to the configured local HA origin. Redirects are rejected. The destination cannot be selected by a browser request.

## Dashboard settings

The app's **Settings** tab holds settings that change while it runs and are stored in private app data:

- **What the tunnel lets through**: read-only. Lists the requests and WebSockets that reach Home Assistant and whether Companion app connections are on. The rules are built into the relay and the connector, not settings.
- **Automatic lockdown**: on by default. Blocks an address at the relay for 60 minutes after 20 denied (401/403) answers or 15 login attempts (`POST /auth/login_flow`) in 10 minutes. Thresholds and duration can be changed. Addresses with a confirmed Home Assistant sign-in are never blocked automatically.
- **Countries and locations**: countries come from DB-IP's free country database, downloaded to `/data/state/dbip-country-lite.csv.gz` on first start and then monthly, and looked up inside the app. A country rule can block listed countries or allow only listed ones; each address is checked within about 15 seconds of being seen, so its first requests still get through. The rule applies to addresses with a confirmed Home Assistant sign-in too. *Show city names* (ipapi.co, off by default) adds approximate cities to Activity and is not needed for country rules.
- **Notifications**: off until you pick where they go: Home Assistant's notification bell (`persistent_notification`) or any `notify.*` service. Each alert type can be turned off.
- **Connector key** rotation and **Unpair**.

Blocked addresses are managed on the **Activity** tab. Up to 256 addresses or ranges (no wider than /8 for IPv4 or /16 for IPv6) can be blocked. Per-minute traffic history is kept for 24 hours in `/data/state/traffic-history.json`.

## Private key files

Generate a one-time 64-character setup code in the Home Tunnel dashboard. The UI also gives you a `web.config` line containing its SHA-256 hash. Replace the blank `HaTunnelBootstrapCodeHash` value in the site's existing `<appSettings>` section with that line. The setup code is never sent to IIS; HA and the relay prove they know it through HMAC challenge-response. After verification, they derive a unique permanent connector key, and the setup state is consumed. A private metrics token is generated automatically for dashboard telemetry. Set `metrics_token` in the app's Configuration tab only if you also want a known token for the optional Home Tunnel integration. Older installs can continue using `metrics-token.txt` in the app configuration folder. Do not expose the metrics port 8100 through the public host.

The relay stores its permanent key verifier and forwarding state in `App_Data`; the HA app stores its key in private app data. Do not publish either state directory or commit the one-time code. Treat the bootstrap hash in `web.config` as a credential: an attacker who reads it can impersonate the relay during setup. Do not expose configuration through custom diagnostics or logs.

## Relay settings

`relay/web.config` contains IIS routing and security settings plus the per-install `HaTunnelBootstrapCodeHash`. The public origin, pairing state, connector key verifier, and forwarding toggle are stored through the relay's private state store and managed by the app UI.

Native HA Companion clients remain disabled in the shipped configuration (`HaTunnelNativeClientsEnabled`). The dashboard shows the relay's current value.

Configure HTTPS certificates and HTTP-to-HTTPS redirection in IIS or the upstream proxy. The relay itself rejects non-HTTPS requests and requests sent to a different host.
