"""Fetch bounded Home Tunnel telemetry for Home Assistant."""
import asyncio
import ipaddress
import logging
import re

import aiohttp
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import CONF_HOST, CONF_PORT, CONF_TOKEN, DOMAIN, TIMEOUT_SECONDS, UPDATE_INTERVAL

_HEX_TOKEN = re.compile(r"\A[0-9a-f]{64}\Z")


def validate_endpoint(host: str, port: int) -> tuple[str, int]:
    """Validate an internal app host and TCP port; return normalized values."""
    if not isinstance(host, str) or not host or len(host) > 253 or any(char in host for char in "/?#@\\"):
        raise ValueError("Enter the Home Tunnel app's internal hostname")
    try:
        address = ipaddress.ip_address(host.strip("[]"))
        host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    except ValueError:
        if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", host):
            raise ValueError("Enter a valid hostname or IP address")
        host = host.lower()
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    return host, port


def sanitize(data: dict) -> dict:
    """Keep the data needed by entities and dashboard; omit client identities."""
    safe = dict(data)
    safe.pop("clients", None)
    safe.pop("authenticated_sessions", None)
    safe.pop("authenticated_ips", None)
    safe.pop("last_client_ip", None)
    requests = safe.get("recent_requests")
    if isinstance(requests, list):
        safe["recent_requests"] = [
            {key: value for key, value in row.items() if key != "ip"}
            for row in requests if isinstance(row, dict)
        ]
    return safe


class HomeTunnelCoordinator(DataUpdateCoordinator[dict]):
    """Poll the add-on's authenticated, read-only metrics endpoint."""

    def __init__(self, hass: HomeAssistant, entry):
        self.host, self.port = validate_endpoint(entry.data[CONF_HOST], entry.data[CONF_PORT])
        self.token = entry.data[CONF_TOKEN]
        if not isinstance(self.token, str) or not _HEX_TOKEN.fullmatch(self.token):
            raise ValueError("Metrics token must be 64 lowercase hexadecimal characters")
        self.url = f"http://{self.host}:{self.port}/metrics"
        self.session = async_get_clientsession(hass)
        super().__init__(
            hass,
            logger=logging.getLogger(__name__),
            name=DOMAIN,
            update_interval=UPDATE_INTERVAL,
        )

    async def _async_update_data(self) -> dict:
        try:
            timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)
            async with self.session.get(
                self.url,
                headers={"Authorization": f"Bearer {self.token}"},
                timeout=timeout,
            ) as response:
                if response.status == 401:
                    raise UpdateFailed("Metrics token was rejected")
                response.raise_for_status()
                data = await response.json()
        except UpdateFailed:
            raise
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as err:
            raise UpdateFailed("Home Tunnel metrics endpoint is unavailable") from err
        if not isinstance(data, dict) or not isinstance(data.get("status"), str):
            raise UpdateFailed("Home Tunnel returned invalid metrics")
        return sanitize(data)
