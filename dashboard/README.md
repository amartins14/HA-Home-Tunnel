# Home Tunnel dashboard

This dashboard uses Home Assistant's built-in Lovelace cards and entities from the bundled `home_tunnel` integration.

1. Install and configure the integration first.
2. Copy `tunnel.yaml` into `/config/dashboards/home_tunnel.yaml`.
3. Add this under the existing `lovelace:` key in `/config/configuration.yaml`, merging it if that key already exists:

   ```yaml
   lovelace:
     dashboards:
       home-tunnel:
         mode: yaml
         title: Home Tunnel
         icon: mdi:lan-connect
         show_in_sidebar: true
         require_admin: true
         filename: dashboards/home_tunnel.yaml
   ```

4. Restart Home Assistant and open **Home Tunnel** from the sidebar.

The integration removes client IP addresses and authenticated session identities from its entity data. The dashboard shows request method, broad route category, result, duration, and observation time. Its layout uses native cards, so it follows Home Assistant's responsive behavior on phones, tablets, and desktop screens.
