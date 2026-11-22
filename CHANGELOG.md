# Changelog

Release notes for Home Tunnel. Relay releases are installed manually on IIS; the Home Assistant app is updated through Supervisor.

## Unreleased

- The Home Assistant app reports the paired relay version and checks the public compatibility manifest.
- Added an authenticated relay version action and a manual IIS update guide.
- Existing relay deployments that do not support version reporting continue to connect; their version is shown as unavailable.
- Declare Home Assistant Core 2026.9.0 as the minimum version for the app and optional integration.
- Add automated connector, relay, container-build, and custom-integration import checks.
- Add the MIT license, contribution instructions, and explicit stable-release gates.

## 0.4.0-dev

- Development version; not a supported public release.
