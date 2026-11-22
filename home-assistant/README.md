# Home Tunnel app

The Home Tunnel app creates an outbound encrypted connection to the configured relay and forwards only to the configured Home Assistant origin. It does not request the Home Assistant API, Supervisor API, Docker socket, host network, host PID, or host mounts. It requires Home Assistant Core 2026.9.0 or newer.

The built-in ingress page is the single Home Tunnel dashboard for status, traffic telemetry, settings, pairing, relay updates, and forwarding. Open it from the sidebar or from **Settings → Apps → Home Tunnel → Open Web UI**. The Home Assistant URL and optional metrics token also remain available on the app's **Configuration** tab.

See [DOCS.md](DOCS.md) for installation, options, key setup, and limitations. See the repository's [security notes](../docs/SECURITY.md) before enabling the public relay.
