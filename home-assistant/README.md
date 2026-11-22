# Home Tunnel app

The Home Tunnel app creates an outbound encrypted connection to the configured relay and forwards only to the configured Home Assistant origin. It does not request the Home Assistant API, Supervisor API, Docker socket, host network, host PID, or host mounts. It requires Home Assistant Core 2026.9.0 or newer.

The built-in ingress page manages the local URL, pairing, relay updates, and forwarding. Open it from **Settings → Apps → Home Tunnel → Open Web UI**; enable **Show in sidebar** on the app's Info page for a persistent sidebar entry. The optional YAML dashboard is for telemetry only, not app management.

See [DOCS.md](DOCS.md) for installation, options, key setup, and limitations. See the repository's [security notes](../docs/SECURITY.md) before enabling the public relay.
