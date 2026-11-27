# Home Tunnel

Reach your Home Assistant from anywhere through a relay you host. No open ports at home and no third-party cloud; Home Assistant still handles every sign-in.

![Supports aarch64](https://img.shields.io/badge/aarch64-yes-41BDF5?style=flat-square) ![Supports amd64](https://img.shields.io/badge/amd64-yes-41BDF5?style=flat-square) ![Home Assistant 2026.9+](https://img.shields.io/badge/Home%20Assistant-2026.9%2B-41BDF5?style=flat-square&logo=homeassistant&logoColor=white)

## What you get

- **One switch** to turn public access on or off, with a live check that your public address really reaches Home Assistant.
- **Pairing with a one-time code** that never leaves Home Assistant, plus key rotation and unpairing from the dashboard.
- **24 hours of traffic charts**: requests, latency, data, denied and failed answers, sign-ins.
- **Every caller for 30 days**, with sign-in status, optional city and country, and CSV export.
- **Blocking at the relay**: by address or range, automatically after repeated failures, or by country.
- **App web UIs through the tunnel**: Zigbee2MQTT, Node-RED, ESPHome and others.
- **Notifications through Home Assistant** when the tunnel goes down, someone new signs in, or the relay needs attention.

The dashboard lives in the sidebar and follows your Home Assistant theme.

## Before you install

You also need a relay: a Windows IIS site with ASP.NET Framework 4.8, WebSockets and URL Rewrite, on a hostname with a valid HTTPS certificate. The relay package is attached to each [GitHub release](https://github.com/amartins14/HA-Home-Tunnel/releases/latest).

## Permissions

- **Home Assistant API:** used only to list notify services and send notifications. The connector, which handles the public traffic, never receives this access and refuses to start if it finds it.
- **Ingress:** the dashboard opens inside Home Assistant for administrators only.
- No host network, Docker socket, privileged mode or Home Assistant configuration folder.

Open the **Documentation** tab for setup and a tour of every screen.
