# Home Tunnel

Home Tunnel is a self-hosted reverse relay for reaching one Home Assistant instance through an HTTPS endpoint. The Home Assistant app opens an outbound WebSocket to a relay you operate. The relay forwards browser requests to the single Home Assistant URL configured for that connector.

The relay is not an identity provider or an access-control layer. Home Assistant continues to handle login, MFA, permissions, and API authorization. Keep the public endpoint protected with Home Assistant authentication and use a unique, high-entropy connector key.

## Project layout

- `home-assistant/` — installable Home Assistant app and connector.
- `custom_components/home_tunnel/` — GUI-configured HA integration that creates status entities.
- The app's ingress page is the single Home Tunnel dashboard for settings, controls, status, and telemetry.
- `relay/` — ASP.NET Framework 4.8 handlers and IIS configuration for the public endpoint.
- `tools/rotate_key.py` — legacy manual-key tool; the setup UI does not use it.
- `tests/` — protocol and connector regression checks.
- `docs/` — architecture, configuration, security, operations, and hosting notes.

## Requirements

- Home Assistant OS or Supervised, Core 2026.9.0 or newer, with app support; supported app architectures are `aarch64` and `amd64`.
- A public DNS name with valid HTTPS and WebSocket support.
- A Windows IIS host running ASP.NET Framework 4.8 and URL Rewrite. The current relay implementation targets IIS; other hosting platforms are not supported by this release.
- The IIS application pool identity needs write access to its private `App_Data` directory for relay state.

## Configure

1. Create a dedicated IIS site with its public hostname and HTTPS certificate, then deploy `relay/` to its application root. Ensure the app pool can write its private `App_Data` directory.
2. Add this repository as a Home Assistant app repository, install **Home Tunnel**, and start it. Open the app's Web UI and generate a setup code.
3. Replace the blank `HaTunnelBootstrapCodeHash` setting in the existing `<appSettings>` section with the displayed `web.config` line. Use the host's File Manager or FTP; keep the hash private because it acts as a setup credential.
4. Return to the Home Assistant UI, enter the IIS site's public HTTPS URL, and start pairing. HA and IIS authenticate each other using challenge-response; the one-time code is never sent. They exchange a unique permanent connector key and consume the setup code automatically.
5. In the Home Tunnel app UI, enable forwarding after the connector reports connected.
6. The dashboard generates a private metrics token automatically. Set a token in the app's **Configuration** tab only if you also want to configure the optional Home Tunnel integration for Home Assistant entities.
7. Verify the public endpoint and HA login from an external network.

See [configuration](docs/CONFIGURATION.md), [relay deployment](docs/RELAY-DEPLOYMENT.md), and [security](docs/SECURITY.md) before exposing the endpoint.

## Status

This repository is licensed under MIT. The current `0.4.6-dev` build is a development version, not a supported production release. A stable release requires green verification checks for the exact commit, a fresh IIS deployment with pairing and rollback validated, and review of the documented security limits. See [contribution and release checks](CONTRIBUTING.md) and [GitHub Releases](https://github.com/amartins14/HA-Home-Tunnel/releases).
