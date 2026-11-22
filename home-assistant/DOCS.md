# Home Tunnel app setup

## Configuration options

The app's **Configuration** tab seeds its initial Home Assistant URL. After startup, manage that URL from **Home Tunnel → Settings** in the app's web UI. The value is stored in private app data and takes precedence over the original option. Changing it restarts the connector; an active remote session may briefly disconnect.

Configure these options on the app's Configuration tab:

Home Assistant Core 2026.9.0 or newer is required.

| Option | Example | Description |
| --- | --- | --- |
| `homeassistant_url` | `http://homeassistant:8123` | The local Home Assistant origin, with no path or credentials. The default works for typical Home Assistant OS installs. |

The app's configuration folder may contain `metrics-token.txt`, a separate 64-character lowercase hexadecimal value for the optional HA integration and dashboard. The connector key is created automatically during setup and stored in the app's private data folder. The tunnel works without the optional metrics file; the dashboard remains unavailable until it is configured.

## Start and verify

Start the app and open **Settings → Apps → Home Tunnel → Open Web UI**. To keep the management page handy, enable **Show in sidebar** on the app's Info page; it appears as **Home Tunnel**. Use its **Settings** section to change the local Home Assistant URL, and its pairing and forwarding sections to manage the tunnel. Generate the one-time setup code and copy the displayed hash line into the relay's `web.config`, replacing the blank `HaTunnelBootstrapCodeHash` setting. Then enter the public relay URL and start pairing. The app derives the WebSocket address and public origin, authenticates the relay using HMAC challenge-response without sending the code, and stores the newly derived permanent key in private app data. The setup code expires after 24 hours. Then wait for the connector to connect and choose **Enable forwarding**. The connector verifies it runs as its dedicated unprivileged user, has no Linux capabilities, has no HA configuration or Supervisor token, and reads its key only from private app data. A failed isolation check prevents connector startup.

The tunnel remains available independently of dashboard polling. Install the **Home Tunnel** custom integration from this repository using HACS or by copying `custom_components/home_tunnel/` into HA's `custom_components` folder. Then open **Settings → Devices & services → Add integration → Home Tunnel**. Enter the internal app hostname (`<repository-id>-home-tunnel`), port `8100`, and the metrics token from `metrics-token.txt`. The repository ID is shown in the HA app store or by `ha store`.

The app's ingress page is the management dashboard for settings, pairing, relay updates, and forwarding. The optional [`dashboard/tunnel.yaml`](../dashboard/tunnel.yaml) is a separate telemetry dashboard; it requires the integration and metrics token and is not needed to manage the app.

Enable forwarding from the Home Tunnel app UI after the connector establishes a healthy connection. Review the full setup steps in the repository's [README](../README.md) and [relay deployment guide](../docs/RELAY-DEPLOYMENT.md).

## Limitations

- The relay in this repository currently supports IIS with classic ASP.NET Framework 4.8 and URL Rewrite only.
- Browser login and authorization are performed by Home Assistant. The tunnel does not replace HA authentication or MFA.
- The ingress UI uses port 8099. The optional read-only metrics listener uses port 8100 on the private app network; do not publish it to the internet.
- The integration config flow requires the app's internal hostname and metrics token.
- The relay app pool must have persistent write access to `App_Data`; some shared hosts require enabling this in their control panel or support request.
- This development package is not a drop-in replacement for the deployed 0.3.6 app.
