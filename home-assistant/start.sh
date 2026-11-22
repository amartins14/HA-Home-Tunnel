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
exec su-exec 10001:10001 env -u SUPERVISOR_TOKEN -u HASSIO_TOKEN "$@"
