#!/bin/sh
set -e

OPTIONS=/data/options.json

DOMAIN_NAME="$(jq -r '.domain_name' "$OPTIONS")"
EXTERNAL_IP="$(jq -r '.external_ip' "$OPTIONS")"
LOG_LEVEL="$(jq -r '.log_level' "$OPTIONS")"
export DOMAIN_NAME EXTERNAL_IP LOG_LEVEL

# /keys is symlinked to /data/keys so the self-signed cert survives restarts
mkdir -p /data/keys

exec python /app/gree-dummy-tls-server.py
