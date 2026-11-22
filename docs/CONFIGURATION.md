# Configuration

## Home Assistant app options

Set these through the Home Assistant app configuration UI:

| Option | Required value | Purpose |
| --- | --- | --- |
| `homeassistant_url` | Defaults automatically | Advanced override for the HA server this connector may reach. Normal installs use `http://homeassistant:8123`. No path, query, credentials, or fragment. |
| `metrics_token` | 64 lowercase hexadecimal characters, or blank | Optional shared key for the Home Tunnel integration. Blank lets the app create a private key for its own dashboard automatically. |

Enter the public HTTPS URL once in the app's ingress setup page. It derives the relay WebSocket address and the browser-facing origin from that URL. The app connects to Home Assistant automatically at `http://homeassistant:8123`; only change `homeassistant_url` in the app's Configuration tab for an unusual network layout.

The connector accepts only relative paths from the relay and joins them to the configured local HA origin. Redirects are rejected. The destination cannot be selected by a browser request.

## Private key files

Generate a one-time 64-character setup code in the Home Tunnel dashboard. The UI also gives you a `web.config` line containing its SHA-256 hash. Replace the blank `HaTunnelBootstrapCodeHash` value in the site's existing `<appSettings>` section with that line. The setup code is never sent to IIS; HA and the relay prove they know it through HMAC challenge-response. After verification, they derive a unique permanent connector key, and the setup state is consumed. A private metrics token is generated automatically for dashboard telemetry. Set `metrics_token` in the app's Configuration tab only if you also want a known token for the optional Home Tunnel integration. Older installs can continue using `metrics-token.txt` in the app configuration folder. Do not expose the metrics port 8100 through the public host.

The relay stores its permanent key verifier and forwarding state in `App_Data`; the HA app stores its key in private app data. Do not publish either state directory or commit the one-time code. Treat the bootstrap hash in `web.config` as a credential: an attacker who reads it can impersonate the relay during setup. Do not expose configuration through custom diagnostics or logs.

## Relay settings

`relay/web.config` contains IIS routing and security settings plus the per-install `HaTunnelBootstrapCodeHash`. The public origin, pairing state, connector key verifier, and forwarding toggle are stored through the relay's private state store and managed by the app UI.

Native HA Companion clients remain disabled in the shipped configuration.

Configure HTTPS certificates and HTTP-to-HTTPS redirection in IIS or the upstream proxy. The relay itself rejects non-HTTPS requests and requests sent to a different host.
