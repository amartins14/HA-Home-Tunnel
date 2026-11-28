#!/bin/sh
# HA creates /data as root. Prepare only our log directory, then drop privileges
# before importing the connector or opening any network connection.
set -eu
if [ -L /data/logs ]; then
    echo 'Audit directory must not be a symbolic link' >&2
    exit 1
fi
if [ -L /data/state ]; then
    echo 'Private state directory must not be a symbolic link' >&2
    exit 1
fi
mkdir -p /data/logs
mkdir -p /data/state
chown 10001:10001 /data/logs
chown 10001:10001 /data/state
chmod 0700 /data/logs
chmod 0700 /data/state
# Read configured app options before dropping privileges.
homeassistant_url="$(python -c 'import json; print(json.loads(open("/data/options.json", encoding="utf-8").read()).get("homeassistant_url", ""))')"
metrics_token="$(python -c 'import json; print(json.loads(open("/data/options.json", encoding="utf-8").read()).get("metrics_token", ""))')"
# Size limits (MB): the isolated connector can't read options.json, so pass them in here as root.
ws_limit_mb="$(python -c 'import json; print(json.loads(open("/data/options.json", encoding="utf-8").read()).get("websocket_limit_mb", ""))')"
req_limit_mb="$(python -c 'import json; print(json.loads(open("/data/options.json", encoding="utf-8").read()).get("request_limit_mb", ""))')"
resp_limit_mb="$(python -c 'import json; print(json.loads(open("/data/options.json", encoding="utf-8").read()).get("response_limit_mb", ""))')"
if [ -z "$homeassistant_url" ]; then
    echo 'Home Assistant URL option is missing' >&2
    exit 1
fi
# The Supervisor token (homeassistant_api, used only to send notifications) is renamed so
# nothing picks it up by accident; service.py takes it out of its environment at start
# and never passes it to the connector, which verifies it has no such token.
exec su-exec 10001:10001 env -u SUPERVISOR_TOKEN -u HASSIO_TOKEN HOME_TUNNEL_SUPERVISOR_TOKEN="${SUPERVISOR_TOKEN:-}" HOMEASSISTANT_URL="$homeassistant_url" HOME_TUNNEL_METRICS_TOKEN="$metrics_token" HOME_TUNNEL_WEBSOCKET_LIMIT_MB="$ws_limit_mb" HOME_TUNNEL_REQUEST_LIMIT_MB="$req_limit_mb" HOME_TUNNEL_RESPONSE_LIMIT_MB="$resp_limit_mb" "$@"
