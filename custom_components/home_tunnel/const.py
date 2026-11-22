"""Constants for Home Tunnel."""
from datetime import timedelta

DOMAIN = "home_tunnel"
CONF_HOST = "host"
CONF_PORT = "port"
CONF_TOKEN = "token"
DEFAULT_PORT = 8100
UPDATE_INTERVAL = timedelta(seconds=15)
TIMEOUT_SECONDS = 5
