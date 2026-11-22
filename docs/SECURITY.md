# Security

Home Tunnel makes a Home Assistant login page reachable from the public internet. Anyone who can reach the configured host can attempt to authenticate to Home Assistant. The tunnel does not replace Home Assistant authentication, MFA, user permissions, or security updates.

- Generate a unique 256-bit setup code in the Home Assistant app. Put its SHA-256 verifier in the IIS `web.config`; protect both the code and verifier as credentials. Keep the code in HA's private app data. HMAC challenge-response authenticates both sides without sending the code. The parties derive a separate permanent connector key, and the relay consumes the setup after finalization.
- Forwarding starts disabled. Enable it from the Home Tunnel app only after the connector is connected and the public endpoint has been reviewed. Disable it immediately if the connector or hosting account is compromised.
- Keep TLS valid and enable secure HTTP-to-HTTPS redirection at IIS or the upstream proxy.
- Do not expose the connector metrics listener or IIS `App_Data` publicly.
- The connector runs as an unprivileged UID, without HA/Supervisor APIs, host networking, or host mounts. It checks these runtime boundaries before connecting.
- The relay enforces exact origin checks for browser WebSockets. Native clients are separately controlled by `HaTunnelNativeClientsEnabled` and default off.
- The public IIS setup page is informational only. Pairing requires a high-entropy setup code generated inside the authenticated HA app. The relay applies rate limits and persists a one-time paired state before accepting the permanent connector key.
- The application audit log records bounded request metadata. IIS and hosting-provider logs are separate and may retain URLs, IP addresses, and query strings. Configure their access and retention deliberately.
- The relay host can see proxied Home Assistant traffic after TLS termination. Operate it on a trusted host and protect its deployment account.

Report vulnerabilities privately to the repository maintainer. Do not include live keys, session cookies, signed URLs, or unredacted logs in an issue.
