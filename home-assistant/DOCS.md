# Home Tunnel

Home Tunnel lets you reach this Home Assistant from anywhere through a relay you host on an IIS web server. This app opens an outgoing, encrypted connection to the relay; the relay sends visitors' requests down it, and the app forwards them to Home Assistant only. Nothing on your router needs to be opened, and Home Assistant's own sign-in, MFA and user permissions apply to every request.

Open the dashboard from **Home Tunnel** in the sidebar, or **Settings → Apps → Home Tunnel → Open web UI**. It has four tabs: **Overview**, **Activity**, **Security** and **Settings**.

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
- **Uptime strip:** the last 24 hours in 15-minute slices: green when online, amber when forwarding was off, red when the connector was offline, grey when the app wasn't running. Each slice shows its worst minute; hover one for its time.
- **Forwarding:** the switch that lets the public address reach Home Assistant. If you're using the dashboard through the tunnel, it warns you before you turn it off, because the page would disconnect.
- **Latest block:** the newest blocked address and why. Select it to open the Security tab.
- **Connection details** (expand it): the connector, the public health check, uptime, reconnects, callers in the last 15 minutes, signed-in sessions, open WebSockets, denied requests and server errors. Every 30 seconds the app requests its own public address and confirms the request comes back through this tunnel; two failures in a row make it reconnect.
- **Traffic:** requests per minute, latency, denied and failed requests, and data sent. Select a number to chart it over the last 1, 6 or 24 hours. History survives restarts. **CSV** saves the per-minute history.
- **Timeline:** what happened lately: sign-ins from new addresses, blocks and unblocks, the tunnel going offline and coming back, forwarding changes, country rule and travel mode changes, relay updates and certificate warnings. Anything that needs you now (a burst of denied requests, an HTTPS certificate close to expiring, blocks the relay isn't enforcing) is pinned on top. The app keeps the last 100 events, whether or not notifications are on.

## Activity

One list with three views: **Callers**, **Requests** and, when the relay has turned any away, **Refused**.

- **Callers:** every address that reached the relay in the last 30 days, up to 2,048, with its country, devices (such as *Safari · iPhone*), request count and when it was last seen. Each shows one status: *Signed in* (Home Assistant confirmed a sign-in from it), *Not signed in*, a count of recent denied answers and login attempts, or *Blocked*. Select an address for its details: country, place, devices, first and last seen, last sign-in, its recent requests, and a block button with a duration. The block button on the row blocks it for a day.
- **Requests:** the last 20 requests, with method, path, status, time and address. **Problems only** shows just the denied and failed ones (4xx and 5xx). Query strings, ingress tokens and login-flow IDs are never shown.
- **Refused:** WebSockets the relay refused, with path, address and reason. If an app's web UI doesn't load through the tunnel, look here first.
- The search box filters by address, place, device or path; the filters above the list narrow it to signed-in or unknown callers, or to one country. **CSV** exports the list you're looking at.

## Security

### Blocked addresses

Everything the relay is turning away, why, and for how long. Add an address or range (like `203.0.113.0/24`) at the bottom, or **Unblock** one. Blocking needs relay 0.5.0 or newer.

### Country rule

- **Off:** countries are shown, nothing is blocked by country.
- **Block these:** callers from the listed countries are blocked; every other country gets through.
- **Only allow these:** callers from the listed countries get through; every other country is blocked.

The card says in plain words what the rule does and how many recent callers it blocks. Add countries with the picker, or with one tap from the countries your callers came from. Before saving, the dashboard tells you who a change would newly block (and asks again if it would block you or switches between the two modes, since the same list means the opposite). Changing the rule, turning it off or using travel mode lifts the blocks it no longer wants straight away. Each address is checked within about 15 seconds of being seen, so its first requests get through. **The rule applies to every address, including ones that have signed in to Home Assistant.** If you'll be travelling, add the countries you'll visit first, or you'll be locked out until you change the rule from your home network. The card warns you, and the dashboard asks before saving, when a rule would block the browser you're using. Country blocks last 30 days by default.

**Travel mode** lets a country through for a while: pick it and how long (1 day to 90 days), then **Let through**. The rule doesn't block callers from there until the time runs out, existing country blocks for it are lifted straight away, and it turns itself off afterwards. Set it up before you leave, from home or while you're still allowed in.

### Automatic lockdown

On by default. An address is blocked for 60 minutes after **20 denied answers** (401 or 403) or **15 login attempts** within 10 minutes. A normal sign-in takes 2 or 3 attempts, so 15 is about five failed passwords. Addresses that have signed in to Home Assistant are never blocked automatically. **Change thresholds** sets the limits and the block time.

Don't use Home Assistant's own `ip_ban_enabled` for this: behind the tunnel every request reaches Home Assistant from this app, so an IP ban there would block the tunnel itself.

## Settings

### Relay

The paired address, the relay's response time, its HTTPS certificate (checked every 6 hours), the relay and app versions, and whether a newer relay is out, with links to the release notes and update guide. Home Assistant updates the app; you update the relay by copying its new `App_Code` files to IIS.

### Notifications

Pick where alerts go: Home Assistant's notification bell or any `notify` service, such as the Companion app on your phone. **Send test** checks it. Expand **Alerts** to turn each one off:

| Alert | When |
| --- | --- |
| Tunnel offline | The connector can't reach the relay for 3 minutes, and again when it's back |
| New sign-in | Someone signs in from an address that never signed in before |
| Needs attention | Bursts of denied requests or server errors, or dropped audit events |
| Address blocked | Automatic lockdown or a country rule blocks an address |
| Relay update | A new relay release is published |
| Certificate expiring | The relay's HTTPS certificate has less than 14 days left |

### Locations

**Country data** comes from DB-IP's free *IP to Country Lite* database ([IP geolocation by DB-IP](https://db-ip.com), CC BY 4.0). The app downloads it (about 5 MB) when it first starts and then once a month, and looks addresses up itself: no caller address is sent anywhere. If a download fails, it keeps using the last good copy. The card shows which edition is in use.

**Show city names** is optional and off by default. It sends public caller addresses to [ipapi.co](https://ipapi.co) for an approximate city on the Activity tab. Countries don't need it. Results are cached for a day, at most 200 new addresses are looked up per day, and the card says when ipapi.co is limiting lookups.

### Maintenance

- **Rotate the connector key** replaces the connector key. The old key keeps working until the relay confirms the new one, so the tunnel only drops for a few seconds.
- **Clear caller history** forgets the caller list. Blocked addresses stay blocked.
- **Unpair** makes the app and the relay forget each other and stops the tunnel. To pair again you need a new setup code and `web.config` line. If the relay can't be reached, you can unpair only here; the relay then stays paired until you delete `App_Data\home-tunnel-state.json` on the IIS host.

Rotation, unpairing and blocking need relay 0.5.0 or newer. The dashboard says so if the relay is older.

### Developer

Collapsed by default. Technical details, all fixed in the relay and this app:

- **What the tunnel lets through** — a read-only list of what reaches Home Assistant: its pages and API, its WebSocket, WebSockets inside app web UIs (Zigbee2MQTT, Node-RED, ESPHome and others), and whether Companion app connections are on. Everything else is refused, so a mistake can't open Home Assistant further.
- **Size limits** — the largest request body, WebSocket message and response the tunnel passes. The WebSocket limit (8 MB, with relay 0.5.4 or newer) gives multi-megabyte frontend replies, such as the add-on store catalogue, room to come through.

## App options

Set these on the app's **Configuration** tab. Most installs never need to.

| Option | Default | What it does |
| --- | --- | --- |
| `homeassistant_url` | `http://homeassistant:8123` | The only Home Assistant address the connector may reach. Origin only: no path or credentials. Changing it restarts the connector. |
| `metrics_token` | empty | A 64-character hex key for the optional Home Tunnel integration. Leave empty unless you use the integration; the dashboard makes its own private key. |
| `geolocation_lookup` | `false` | The starting value of *Show city names* (ipapi.co lookups). Countries don't depend on it. Changing this option later overrides the dashboard setting. |

## Optional integration

The **Home Tunnel** integration in the same GitHub repository adds sensors for status, traffic, latency, reconnects and the security review. Install it through HACS as a custom repository, set `metrics_token` here, then add the integration with this app's hostname, port `8100` and the token. The dashboard works without it.

## What is stored

Everything stays in the app's private data:

- The connector key, pairing state and settings.
- Caller addresses for 30 days (up to 2,048), with request counts, sign-in times and up to four device labels each.
- Per-minute traffic for 24 hours.
- The block list, which is also sent to the relay.
- The last 100 timeline events and 24 hours of per-minute tunnel uptime.
- A rotating audit log of requests (10 MiB, four backups).

Uninstalling the app or removing its data deletes all of this and unpairs it on this side.

## Troubleshooting

- **Connector offline:** check the relay address opens in a browser, the IIS site has WebSockets on, and its app pool can write to `App_Data`.
- **Pairing stuck with "rejected the setup code hash":** the `web.config` line doesn't match the current code. Paste it again, or make a new code.
- **Public check failing:** the relay answers, but requests aren't coming back through this tunnel. Usually a proxy or CDN in front of IIS, or a second relay worker. The app reconnects on its own.
- **An app's web UI doesn't load through the tunnel:** check **Activity → Refused**. Home Assistant's own WebSocket and any WebSocket inside an app web UI are allowed (relay 0.5.1 or newer; older relays only allow Zigbee2MQTT's). **Settings → Developer → What the tunnel lets through** shows the rules.
- **A data-heavy page (like the add-on store) shows "Connection lost":** update to app 0.7.9 and relay 0.5.4. Older versions cut off WebSocket messages over 1 MB, and the catalogue reply is several MB.
- **A country rule didn't block my test:** give it 15 seconds after the first request. **Settings → Locations** shows whether the country database is ready.
- **An iPhone offers to download a file called "authorize":** update the relay to 0.5.2. Older relays sent an empty error while Home Assistant reconnected, which Safari treats as a download.
- **Notifications say there's no API access:** restart the app; if that doesn't help, reinstall it so Home Assistant grants the permission again.

## Limits

- The relay runs on IIS with ASP.NET Framework 4.8 only.
- The relay host sees traffic after TLS ends there; run it somewhere you trust.
- Caller addresses are what IIS sees. A proxy in front of IIS makes every caller look like the proxy.
- Port 8100 is a private metrics port on the app network. Never publish it.
