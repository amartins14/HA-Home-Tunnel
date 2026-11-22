# Architecture

```text
Browser ── HTTPS/WSS ──> Public IIS relay ── authenticated relay protocol ──> HA app connector ── HTTP(S) ──> configured HA origin
```

The connector creates an outbound TLS WebSocket, so the Home Assistant host does not need an inbound port opened. The relay has no general-purpose proxy target: the connector validates every requested relative path and sends it only to its configured Home Assistant origin. The relay checks its configured public origin, requires the shared key for connector setup, bounds request sizes and concurrency, and fails closed when disabled or the connector is unavailable.

Browser requests still reach Home Assistant's regular login and authorization flows. TLS termination, DNS, firewalling, and provider-level request logging are controlled by the operator's hosting stack and provider.

The current public relay is implemented as classic ASP.NET handlers for IIS on .NET Framework 4.8. Hosting that relay elsewhere requires a separate implementation of the same authenticated protocol and is outside this repository's current support.
