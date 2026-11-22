# Deploying the IIS relay

1. Create a dedicated IIS site with a dedicated hostname and valid TLS certificate. Enable WebSocket Protocol, ASP.NET 4.8, and IIS URL Rewrite.
2. Deploy the contents of `relay/` as the site application root. The app pool needs persistent write access to the site's private `App_Data` directory. Do not publish that directory.
3. Start Home Tunnel in HA and generate a setup code in its ingress UI. Replace the blank `HaTunnelBootstrapCodeHash` setting in the existing `<appSettings>` section of `web.config` with the displayed line. Keep the hash private; it acts as a setup credential.
4. Confirm that `_connect.ashx` and `/_pair.ashx` are reachable over HTTPS and that WebSocket upgrade works through IIS and every upstream proxy. Do not publish `App_Data` or source-control/deployment metadata.
5. In the HA app, enter the IIS site's public HTTPS URL and start pairing. The relay proves its identity and HA proves the matching one-time code with HMAC challenge-response; neither side sends the code. They derive a unique permanent connector key, which is stored in private app data. Pairing is one-time and forwarding remains disabled.
6. Wait for the connector to report connected. Enable forwarding from the Home Tunnel app UI only after the public endpoint and HA login have been reviewed.

## Updating the IIS relay

The IIS relay is updated manually. The Home Assistant app checks the public `release-manifest.json` over HTTPS every six hours, reports the paired relay version, and links to the release notes and this procedure. This check sends no Home Assistant configuration or entity data. Release metadata lists the Home Tunnel app versions verified with that relay build. If the installed app version is not listed, review compatibility notes before updating.

1. Download the relay package attached to the selected GitHub release. Do not deploy a source checkout or a development build as a production update.
2. Keep a temporary, private recovery copy of the current relay files, `web.config`, and `App_Data` until the new relay passes the checks below. These files contain the pairing configuration and live connector state; do not put them in Git or a public web root.
3. Stop the IIS application pool, replace the relay code and static files, and retain the existing `web.config` and `App_Data` unchanged. In particular, preserve the bootstrap-code hash setting and the active key verifier/state.
4. Start the application pool. Confirm the IIS site responds over HTTPS, `/_pair.ashx?action=version` is available to the authenticated HA app, the HA app reports the connector connected, and the public Home Assistant login works.
5. If a health check fails, stop the pool, restore the previous code while keeping the original `web.config` and `App_Data`, then start the pool and verify recovery. Remove the temporary recovery copy after the update succeeds.

Home Assistant app updates remain managed by Supervisor. An app update does not install relay files on IIS. If the HA app reports an unknown relay version, it may be an older relay without the authenticated version action; this does not by itself indicate a tunnel failure.

The relay requires full-trust classic ASP.NET on IIS and the .NET Framework 4.8 runtime. Linux containers and non-IIS reverse-proxy hosting are not supported by this code. Shared hosting must allow the application pool to write persistent files under `App_Data`; use the host's permission controls or ask the provider if it does not.

If the code or hash is lost before pairing, generate a replacement in HA and replace the setting in `web.config`. The app keeps the code privately for up to 24 hours while pairing is pending. Preserve `App_Data` after pairing; it contains the active key verifier and forwarding state. Removing it unpairs the connector and disables forwarding.

For rollback, retain the previous relay files and the private `App_Data` state in protected recovery storage until the new build passes health checks. Never place backups or keys in Git or the public web root.
