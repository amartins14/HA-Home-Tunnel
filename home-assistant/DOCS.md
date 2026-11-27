# Home Tunnel

Home Tunnel lets you reach this Home Assistant from anywhere through a relay you host on an IIS web server. This app opens an outgoing, encrypted connection to the relay; the relay sends visitors' requests down it, and the app forwards them to Home Assistant only. Nothing on your router needs to be opened, and Home Assistant's own sign-in, MFA and user permissions apply to every request.

Open the dashboard from **Home Tunnel** in the sidebar, or **Settings → Apps → Home Tunnel → Open web UI**. It has three tabs: **Overview**, **Activity** and **Settings**.

## First-time setup

You need the relay files on your IIS site first. Download `home-tunnel-relay-<version>.zip` from the [latest release](https://github.com/amartins14/HA-Home-Tunnel/releases/latest) and copy its contents to the site root. The [relay deployment guide](https://github.com/amartins14/HA-Home-Tunnel/blob/main/docs/RELAY-DEPLOYMENT.md) covers the IIS settings.

Then open the dashboard. Until it is paired, **Overview** shows three steps:

1. **Create a setup code.** The app makes a one-time code and keeps it. The relay only ever gets its hash.
2. **Add its hash to the relay.** Copy the `web.config` line shown and replace the empty `HaTunnelBootstrapCodeHash` line in the relay's `web.config`, using your host's file manager or FTP. Treat that line as a password.
3. **Connect to the relay.** Enter the relay's public address, such as `https://tunnel.example.com`, with no path, and choose **Pair**.

The app and relay prove to each other that they know the code, without sending it, and agree a permanent connector key. Pairing retries until it works or the code expires after 24 hours. If the relay rejects the hash, check the `web.config` line and the address.

When the connector shows **Connected**, turn on **Forwarding**. Then sign in from a phone on mobile data to check it works.

## Overview

- **Status:** *Online*, *Forwarding off*, *Connector offline* or *Public check failing*, also shown at the top right on every tab.
- **Forwarding:** the switch that lets the public address reach Home Assistant. If you're using the dashboard through the tunnel, it warns you before you turn it off, because the page would disconnect.
- **Public health check:** every 30 seconds the app requests its own public address and confirms the request comes back through this tunnel. Two failures in a row make it reconnect.
- **Traffic:** live requests per minute, latency, data sent and open WebSockets, plus charts for the last 1, 6 or 24 hours. History survives restarts. **Export CSV** saves the per-minute history.
- **Health:** uptime, reconnects, callers in the last 15 minutes, signed-in sessions, denied requests and server errors.
- Notes appear here when something needs you: a burst of denied requests, a relay update, an HTTPS certificate close to expiring, or blocks the relay isn't enforcing.

## Activity

- **Countries** (with caller locations on): callers and requests per country. Select a country to show only its callers, or block it straight from here.
- **Callers:** every address that reached the relay in the last 30 days, up to 2,048. *Signed in to HA* means Home Assistant confirmed a sign-in from that address; *No sign-in seen* means it never did. Select an address to show only its requests. **Block** blocks it at the relay.
- **Recent requests:** the last 20 requests, with method, path, status, time and address. Query strings, ingress tokens and login-flow IDs are never shown.
- **Blocked addresses:** everything the relay is turning away, why, and for how long. Add an address or range (like `203.0.113.0/24`) here, or **Unblock** one.
- The search box filters callers and requests by address, place or path. **CSV** exports either list.
- **Clear caller history** forgets the caller list. Blocked addresses stay blocked.

## Settings

### Relay

Shows the paired address, the connector, the relay's response time and its HTTPS certificate (checked every 6 hours).

- **Rotate key** replaces the connector key. The old key keeps working until the relay confirms the new one, so the tunnel only drops for a few seconds.
- **Unpair** makes the app and the relay forget each other and stops the tunnel. To pair again you need a new setup code and `web.config` line. If the relay can't be reached, you can unpair only here; the relay then stays paired until you delete `App_Data\home-tunnel-state.json` on the IIS host.

Rotation, unpairing and blocking need relay 0.5.0 or newer. The dashboard says so if the relay is older.

### What the tunnel lets through

A read-only list of what reaches Home Assistant: its pages and API, its WebSocket, WebSockets inside app web UIs (Zigbee2MQTT, Node-RED, ESPHome and others), and whether Companion app connections are on. Everything else is refused. These rules are built into the relay and this app, so a mistake can't open Home Assistant further.

### Automatic lockdown

On by default. An address is blocked for 60 minutes after **20 denied answers** (401 or 403) or **15 login attempts** within 10 minutes. A normal sign-in takes 2 or 3 attempts, so 15 is about five failed passwords. Addresses that have signed in to Home Assistant are never blocked automatically. You can change the limits and the block time.

Don't use Home Assistant's own `ip_ban_enabled` for this: behind the tunnel every request reaches Home Assistant from this app, so an IP ban there would block the tunnel itself.

### Caller locations and countries

**Look up caller locations** sends public caller addresses to [ipapi.co](https://ipapi.co) for an approximate city and country. It's off by default. Results are cached for a day, and at most 200 new addresses are looked up per day.

With it on, you can set a country rule:

- **Block listed:** callers from the listed countries are blocked.
- **Allow only listed:** callers from any other country are blocked.

Each address is checked the first time it's seen, so its first requests get through. Addresses that have signed in are never blocked by country, so travelling won't lock you out. Country blocks last 30 days by default.

**Turning caller locations off also turns off country data and country blocking.** Addresses already blocked stay blocked until their block ends.

### Notifications

Pick where alerts go: Home Assistant's notification bell or any `notify` service, such as the Companion app on your phone. **Send test** checks it. Each alert can be turned off:

| Alert | When |
| --- | --- |
| Tunnel offline | The connector can't reach the relay for 3 minutes, and again when it's back |
| New sign-in | Someone signs in from an address that never signed in before |
| Needs attention | Bursts of denied requests or server errors, or dropped audit events |
| Address blocked | Automatic lockdown or a country rule blocks an address |
| Relay update | A new relay release is published |
| Certificate expiring | The relay's HTTPS certificate has less than 14 days left |

### Versions

The app version, the relay version and whether a newer relay is out, with links to the release notes and update guide. Home Assistant updates the app; you update the relay by copying its new `App_Code` files to IIS.

## App options

Set these on the app's **Configuration** tab. Most installs never need to.

| Option | Default | What it does |
| --- | --- | --- |
| `homeassistant_url` | `http://homeassistant:8123` | The only Home Assistant address the connector may reach. Origin only: no path or credentials. Changing it restarts the connector. |
| `metrics_token` | empty | A 64-character hex key for the optional Home Tunnel integration. Leave empty unless you use the integration; the dashboard makes its own private key. |
| `geolocation_lookup` | `false` | The starting value of *Look up caller locations*. Changing this option later overrides the dashboard setting. |

## Optional integration

The **Home Tunnel** integration in the same GitHub repository adds sensors for status, traffic, latency, reconnects and the security review. Install it through HACS as a custom repository, set `metrics_token` here, then add the integration with this app's hostname, port `8100` and the token. The dashboard works without it.

## What is stored

Everything stays in the app's private data:

- The connector key, pairing state and settings.
- Caller addresses for 30 days (up to 2,048), with request counts and sign-in times.
- Per-minute traffic for 24 hours.
- The block list, which is also sent to the relay.
- A rotating audit log of requests (10 MiB, four backups).

Uninstalling the app or removing its data deletes all of this and unpairs it on this side.

## Troubleshooting

- **Connector offline:** check the relay address opens in a browser, the IIS site has WebSockets on, and its app pool can write to `App_Data`.
- **Pairing stuck with "rejected the setup code hash":** the `web.config` line doesn't match the current code. Paste it again, or make a new code.
- **Public check failing:** the relay answers, but requests aren't coming back through this tunnel. Usually a proxy or CDN in front of IIS, or a second relay worker. The app reconnects on its own.
- **An app's web UI doesn't load through the tunnel:** check **Activity → Refused WebSocket connections**. Home Assistant's own WebSocket and any WebSocket inside an app web UI are allowed (relay 0.5.1 or newer; older relays only allow Zigbee2MQTT's). **Settings → What the tunnel lets through** shows the rules.
- **Notifications say there's no API access:** restart the app; if that doesn't help, reinstall it so Home Assistant grants the permission again.

## Limits

- The relay runs on IIS with ASP.NET Framework 4.8 only.
- The relay host sees traffic after TLS ends there; run it somewhere you trust.
- Caller addresses are what IIS sees. A proxy in front of IIS makes every caller look like the proxy.
- Port 8100 is a private metrics port on the app network. Never publish it.
