# Home Tunnel app setup

## Configuration options

The Home Assistant URL and optional metrics token are available in the app's **Configuration** tab, so it can be configured without opening the dashboard. The URL is also editable from the dashboard's **Settings** section. Dashboard URL changes are stored in private app data; if the app Configuration URL is changed later, that new value takes effect on restart. Changing the URL restarts the connector, so an active remote session may briefly disconnect.

Configure these options on the app's Configuration tab:

Home Assistant Core 2026.9.0 or newer is required.

| Option | Example | Description |
| --- | --- | --- |
| `homeassistant_url` | `http://homeassistant:8123` | The local Home Assistant origin, with no path or credentials. The default works for typical Home Assistant OS installs. |
| `metrics_token` | 64 lowercase hexadecimal characters | Optional private key for dashboard traffic telemetry and the read-only metrics endpoint. Leave blank to hide telemetry. |

For older installations, the app configuration folder's `metrics-token.txt` remains a fallback if the new `metrics_token` field is blank. The connector key is created automatically during setup and stored in the app's private data folder. The tunnel works without a metrics token; connection controls and status remain available.

## Start and verify

Start the app and open **Home Tunnel** from the sidebar, or use **Settings → Apps → Home Tunnel → Open Web UI**. This single dashboard contains connection and traffic status, recent activity, settings, pairing, relay information, and forwarding controls. Generate the one-time setup code and copy the displayed hash line into the relay's `web.config`, replacing the blank `HaTunnelBootstrapCodeHash` setting. Then enter the public relay URL and start pairing. The app derives the WebSocket address and public origin, authenticates the relay using HMAC challenge-response without sending the code, and stores the newly derived permanent key in private app data. The setup code expires after 24 hours. Then wait for the connector to connect and choose **Enable forwarding**. The connector verifies it runs as its dedicated unprivileged user, has no Linux capabilities, has no HA configuration or Supervisor token, and reads its key only from private app data. A failed isolation check prevents connector startup.

The dashboard reads telemetry directly from the app's private metrics endpoint. It does not require a separate Lovelace dashboard or custom integration. Install the optional **Home Tunnel** integration from this repository only if you also want telemetry entities in Home Assistant; configure it with the app's internal hostname, port `8100`, and the metrics token.

Enable forwarding from the Home Tunnel dashboard after the connector establishes a healthy connection. Review the full setup steps in the repository's [README](../README.md) and [relay deployment guide](../docs/RELAY-DEPLOYMENT.md).

## Limitations

- The relay in this repository currently supports IIS with classic ASP.NET Framework 4.8 and URL Rewrite only.
- Browser login and authorization are performed by Home Assistant. The tunnel does not replace HA authentication or MFA.
- The ingress UI uses port 8099. The optional read-only metrics listener uses port 8100 on the private app network; do not publish it to the internet.
- The optional integration config flow requires the app's internal hostname and metrics token.
- The relay app pool must have persistent write access to `App_Data`; some shared hosts require enabling this in their control panel or support request.
- This development package is not a drop-in replacement for the deployed 0.3.6 app.
