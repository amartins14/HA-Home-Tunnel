"""Redacted diagnostics for Home Tunnel."""
from homeassistant.components.diagnostics import async_redact_data

from .const import CONF_TOKEN, DOMAIN

TO_REDACT = {CONF_TOKEN}


async def async_get_config_entry_diagnostics(hass, entry):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    return {
        "config": async_redact_data(dict(entry.data), TO_REDACT),
        "metrics": coordinator.data,
    }
