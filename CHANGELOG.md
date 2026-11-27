# Changelog

Release notes for Home Tunnel. Relay releases are installed manually on IIS; the Home Assistant app is updated through Supervisor.

## Unreleased

- Let crawlers fetch the IIS relay so they can read its no-index response header.
- Add an app icon and logo for the Home Assistant app store, and rewrite the README, app documentation and architecture guide with screenshots, badges and My Home Assistant buttons.

## 0.7.4

- Show which kind of device used each caller address, such as "Safari · iPhone" or "Home Assistant app · iOS 18", from the User-Agent of the browser or app that opened Home Assistant. Only this short label is kept, up to four per address. Search, CSV export and new sign-in notifications include it.
- Needs relay 0.5.2 to stop iPhones offering to download a file named "authorize" while Home Assistant reconnects.

### Relay 0.5.2

- Give every relay error a body and a content type. A bare 502 or 503 while the connector reconnected made Safari, and home-screen web apps above all, offer to download the sign-in page as a file named "authorize". Browsers now get a short page that retries by itself.

## 0.7.3

- Bring the configuration and security guides up to date, and remove emoji from the documentation.
- Show countries as two-letter codes instead of flag emoji on the Activity and Settings pages.
- Fix country blocking missing most callers: location lookups now run one at a time, pause when ipapi.co rate-limits, and retry instead of remembering an empty answer for 15 minutes. The Settings page says when lookups are limited or used up.
- Fix the dashboard's location lookups failing through the tunnel on hosts whose firewall refuses a comma-separated list of IP addresses.
- Fix the notify service list failing on installs with many integrations, and the release check, which could read a partial answer.

## 0.7.2

- Let every app web UI work through the tunnel, not only Zigbee2MQTT: WebSockets anywhere below an app's web UI address are now allowed. Home Assistant checks the app session for these; paths that try to step outside are still refused.
- Show what the tunnel lets through on the Settings page, read-only, including whether Companion app connections are allowed.
- List the WebSocket connections the relay refused on the Activity page, with the reason, so a broken app web UI is easy to diagnose.
- Hide app web UI session tokens in every displayed path, not only on the socket path.
- Needs relay 0.5.1 for app web UIs other than Zigbee2MQTT and for the refused list.

### Relay 0.5.1

- Allow WebSockets anywhere below an app's web UI address, and keep refusing percent-encoded and dot segments.
- Remember the last 20 refused WebSocket connections and report them, and whether Companion app connections are on, to the authenticated app.
- Hide app web UI session tokens in every displayed path.

## 0.7.1

- Fix the dashboard failing to load (`/api/status` returned an error) in 0.7.0.

## 0.7.0

- Replace the MyStay-style dashboard with one that matches Home Assistant and the Access panel: theme colours, Overview / Activity / Settings tabs, and a step-by-step relay setup.
- Keep 24 hours of per-minute traffic in the app (requests, latency, data sent, denied and failed answers, sign-ins) and chart 1, 6 or 24 hours.
- Block an address or range at the relay from the Activity page, for a set time or until you unblock it.
- Automatic lockdown, on by default: block an address for an hour after 20 denied answers or 15 login attempts in 10 minutes. Addresses that have signed in to Home Assistant are never blocked automatically.
- Send notifications through Home Assistant when the tunnel goes offline or recovers, a new address signs in, the security review needs attention, an address is blocked, a relay update is published, or the relay certificate is about to expire. The app now has Home Assistant API access for this; the connector still has none.
- Block by country on first sight: block listed countries, or allow only listed ones. Needs caller locations (ipapi.co); turning locations off also turns off country data and country blocking. Each new address is checked once, its first requests still get through, signed-in addresses are never blocked, and lookups share the 200-a-day limit.
- Show each caller's country, a per-country summary, and a country filter on the Activity page.
- Rotate the connector key and unpair from the Settings page.
- Check the relay's HTTPS certificate expiry and response time.
- Show callers in the last 15 minutes and open signed-in sessions.
- Export callers, recent requests and traffic history as CSV.
- Requires relay 0.5.0 for blocking, key rotation and remote unpairing. Older relays keep working without these.

### Relay 0.5.0

- Enforce the app's block list (`App_Data/home-tunnel-blocks.json`) before a request reaches the connector.
- Add authenticated `rotate`, `confirm_rotation`, `unpair` and `blocks` pairing actions; the old key keeps working until the app confirms the new one.
- Report supported features from the `version` action.

## 0.6.1

- Keep the Home Tunnel wordmark inside the desktop sidebar and label the connection status.

## 0.6.0

- Match the MyStay dashboard layout on desktop and mobile, with a system, light or dark theme and a local accent picker.
- Separate requests and callers in Activity and move pairing and preferences into focused dialogs.

## 0.5.1

- Filter recent activity by caller search and authenticated or unknown status.
- Click an IP in the caller list or request log to filter both views to that address.
- Label IPs with a confirmed Home Assistant login as “This device”.

## 0.5.0

- Show every sanitized relay path and keep a searchable, private caller IP history with confirmed HA login status.
- Keep caller IP history for 30 days, cap it at 2,048 addresses, and add a clear-history control.
- Record all successful frontend requests in the recent activity list.
- Show up to 20 recent relay requests instead of 10.

## 0.4.9

- Replace the AdGuard-like layout with Home Tunnel's own responsive sidebar and navy-and-teal theme.
- Keep the overview to core connection health, request rate, latency, active WebSockets, and one live graph.
- Show caller IP addresses and sanitized request paths in the recent activity list.
- Offer optional, disabled-by-default approximate geolocation through ipapi.co; the provider receives each public caller IP looked up.
- Mask ingress tokens and login-flow IDs, and omit query strings from displayed paths.
- Keep request identity and location cache data in bounded, in-memory buffers.

## 0.4.8

- Replace the dashboard's text arrow brand mark with an inline shield-and-route icon.

## 0.4.7

- Split the app into Dashboard, Settings, About, and Activity views.
- Add live graphs for request rate, traffic, and latency with a selectable time window.
- Use Home Assistant's internal destination automatically; retain the Configuration-tab override for advanced networks.
- Restyle the dashboard with a dark overview, metric cards, and responsive management panels.
- Keep relay controls, setup, version information, and activity in the Home Tunnel app.
- The Home Assistant app reports the paired relay version and checks the public compatibility manifest.
- Add an authenticated relay version action and a manual IIS update guide.
- Keep older relay deployments connected when version reporting is unavailable.
- Declare Home Assistant Core 2026.9.0 as the minimum version for the app and optional integration.
- Add automated connector, relay, container-build, and custom-integration import checks.
- Add the MIT license, contribution instructions, and explicit stable-release gates.

## 0.4.6-dev

- Rework the single dashboard into a responsive, AdGuard-inspired dark layout with a compact header and statistics cards.
- Keep setup, connection controls, settings, and relay release information reachable on the same page.

## 0.4.5-dev

- Explain when the relay version matches development metadata but no stable release is available.
- Prepare tagged development releases with verified relay packages and changelog notes.

## 0.4.4-dev

- Generate and persist a private metrics credential when none is configured, so the unified dashboard shows telemetry without extra setup.

## 0.4.3-dev

- Combine connection management and private relay telemetry in the single Home Tunnel ingress dashboard.
- Keep the Home Assistant URL and optional metrics token available in the app's Configuration tab, with changed app options reconciled on restart.
- Remove the separate Lovelace dashboard; the custom integration remains optional for HA entities.

## 0.4.2-dev

- Add a named Home Tunnel ingress sidebar panel and manage the local Home Assistant URL from the app web UI.
- Store the editable URL in private app state and restart the connector when it changes.

## 0.4.1-dev

- Fix connector startup when Home Assistant keeps `/data/options.json` root-only by passing only the configured destination URL into the isolated connector environment.
- Keep Supervisor options unreadable by the connector; its explicit destination remains validated by the existing URL policy.

## 0.4.0-dev

- Development version; not a supported public release.
