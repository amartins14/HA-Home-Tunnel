# Changelog

Release notes for Home Tunnel. Relay releases are installed manually on IIS; the Home Assistant app is updated through Supervisor.

## Unreleased

- Restyle the dashboard with a dark overview, metric cards, and responsive management panels.
- Keep settings, setup, connection controls, and relay information on the same dashboard.
- Distinguish development relay metadata from a published stable release in the dashboard.
- Publish tagged development builds as GitHub prereleases with a relay ZIP after CI passes.
- The Home Assistant app reports the paired relay version and checks the public compatibility manifest.
- Added an authenticated relay version action and a manual IIS update guide.
- Existing relay deployments that do not support version reporting continue to connect; their version is shown as unavailable.
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
