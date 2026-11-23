# Home Tunnel app

The Home Tunnel app creates an outbound encrypted connection to the configured relay and forwards only to the configured Home Assistant origin. It does not request the Home Assistant API, Supervisor API, Docker socket, host network, host PID, or host mounts. It requires Home Assistant Core 2026.9.0 or newer.

The built-in ingress page is the single Home Tunnel dashboard for status, recent request IPs and paths, settings, pairing, relay updates, and forwarding. Open it from the sidebar or from **Settings → Apps → Home Tunnel → Open Web UI**. The Home Assistant URL, optional metrics token, and optional approximate geolocation lookups also remain available on the app's **Configuration** tab. Request details are held in a small in-memory buffer; query strings are not displayed and the buffer clears when the app restarts. Geolocation is off by default; enabling it sends public caller IPs to ipapi.co, with results that may be inaccurate, cached for 24 hours, and limited to 200 new IPs per day.

See [DOCS.md](DOCS.md) for installation, options, key setup, and limitations. See the repository's [security notes](../docs/SECURITY.md) before enabling the public relay.
