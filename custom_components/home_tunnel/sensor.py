"""Home Tunnel metrics sensors."""
from dataclasses import dataclass

from homeassistant.components.sensor import SensorEntity, SensorEntityDescription
from homeassistant.const import UnitOfTime
from homeassistant.core import callback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import CONF_HOST, CONF_PORT, DOMAIN


@dataclass(frozen=True, kw_only=True)
class HomeTunnelSensorDescription(SensorEntityDescription):
    value_key: str
    attribute_keys: tuple[str, ...] = ()


SENSORS = (
    HomeTunnelSensorDescription(key="status", name="Home Tunnel status", value_key="status", icon="mdi:lan-connect"),
    HomeTunnelSensorDescription(key="security_review", name="Home Tunnel security review", value_key="risk_status", icon="mdi:shield-search", attribute_keys=("risk_issues",)),
    HomeTunnelSensorDescription(key="requests_per_minute", name="Home Tunnel requests per minute", value_key="requests_per_minute", native_unit_of_measurement="req/min", icon="mdi:chart-line"),
    HomeTunnelSensorDescription(key="http_kib_per_second", name="Home Tunnel traffic", value_key="http_kib_per_second", native_unit_of_measurement="KiB/s", icon="mdi:swap-vertical"),
    HomeTunnelSensorDescription(key="recent_latency_ms", name="Home Tunnel recent latency", value_key="recent_latency_ms", native_unit_of_measurement="ms", icon="mdi:timer-outline"),
    HomeTunnelSensorDescription(key="uptime_seconds", name="Home Tunnel relay uptime", value_key="uptime_seconds", native_unit_of_measurement=UnitOfTime.SECONDS, device_class="duration", icon="mdi:clock-outline"),
    HomeTunnelSensorDescription(key="reconnects", name="Home Tunnel reconnects", value_key="automatic_reconnects", icon="mdi:autorenew"),
    HomeTunnelSensorDescription(key="public_check_age", name="Home Tunnel public check age", value_key="public_check_age_seconds", native_unit_of_measurement=UnitOfTime.SECONDS, device_class="duration", icon="mdi:web-clock"),
    HomeTunnelSensorDescription(key="denied_5m", name="Home Tunnel denied requests", value_key="denied_5m", icon="mdi:shield-alert"),
    HomeTunnelSensorDescription(key="failures_5m", name="Home Tunnel server failures", value_key="failures_5m", icon="mdi:server-off"),
    HomeTunnelSensorDescription(key="active_connections", name="Home Tunnel active connections", value_key="active_http", icon="mdi:lan-pending"),
    HomeTunnelSensorDescription(key="websockets", name="Home Tunnel active WebSockets", value_key="active_ws", icon="mdi:access-point-network"),
    HomeTunnelSensorDescription(key="dropped_events", name="Home Tunnel dropped events", value_key="events_dropped", icon="mdi:text-box-remove"),
    HomeTunnelSensorDescription(key="telemetry_age", name="Home Tunnel telemetry age", value_key="telemetry_age_seconds", native_unit_of_measurement=UnitOfTime.SECONDS, device_class="duration", icon="mdi:clock-check-outline"),
    HomeTunnelSensorDescription(key="connector_version", name="Home Tunnel connector version", value_key="version", icon="mdi:package-variant"),
    HomeTunnelSensorDescription(key="recent_activity", name="Home Tunnel recent activity", value_key="recent_request_count", icon="mdi:format-list-bulleted", attribute_keys=("recent_requests",)),
)


async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities(HomeTunnelSensor(coordinator, entry, description) for description in SENSORS)


class HomeTunnelSensor(CoordinatorEntity, SensorEntity):
    """Represent one connector telemetry value."""

    entity_description: HomeTunnelSensorDescription

    def __init__(self, coordinator, entry, description):
        super().__init__(coordinator)
        self.entity_description = description
        host = entry.data[CONF_HOST]
        port = entry.data[CONF_PORT]
        self._attr_unique_id = f"{host}_{port}_{description.key}"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, f"{host}:{port}")},
            "name": "Home Tunnel",
            "manufacturer": "Home Tunnel",
            "model": "HA connector and relay",
        }

    @property
    def native_value(self):
        return self.coordinator.data.get(self.entity_description.value_key)

    @property
    @callback
    def extra_state_attributes(self):
        return {key: self.coordinator.data.get(key) for key in self.entity_description.attribute_keys}
