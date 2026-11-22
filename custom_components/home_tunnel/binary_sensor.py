"""Home Tunnel health and availability binary sensors."""
from homeassistant.components.binary_sensor import BinarySensorEntity, BinarySensorEntityDescription
from homeassistant.core import callback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import CONF_HOST, CONF_PORT, DOMAIN

SENSORS = (
    BinarySensorEntityDescription(key="healthy", name="Home Tunnel healthy", device_class="connectivity", icon="mdi:check-network-outline"),
    BinarySensorEntityDescription(key="public_reachable", name="Home Tunnel public endpoint reachable", device_class="connectivity", icon="mdi:web-check"),
    BinarySensorEntityDescription(key="audit_healthy", name="Home Tunnel audit storage healthy", icon="mdi:text-box-check-outline"),
)


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(HomeTunnelBinarySensor(coordinator, entry, description) for description in SENSORS)


class HomeTunnelBinarySensor(CoordinatorEntity, BinarySensorEntity):
    """Represent one Home Tunnel health flag."""

    def __init__(self, coordinator, entry, description):
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{entry.data[CONF_HOST]}_{entry.data[CONF_PORT]}_{description.key}"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, f"{entry.data[CONF_HOST]}:{entry.data[CONF_PORT]}")},
            "name": "Home Tunnel",
            "manufacturer": "Home Tunnel",
            "model": "HA connector and relay",
        }

    @property
    @callback
    def is_on(self):
        return bool(self.coordinator.data.get(self.entity_description.key, False))
