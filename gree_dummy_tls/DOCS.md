# Gree Dummy TLS Server

Answers the cloud requests of Gree AC units locally, so the units can be
fully blocked from the internet.

## Requirements

1. A DNS rewrite for `*.gree.com` pointing at your Home Assistant host
   (AdGuard Home, Pi-hole, router, etc.). Without it the units may get
   stuck in a DNS query loop.
2. Gree firmware older than 1.31. Newer firmware uses MQTT, which is not
   supported.

## Options

| Option        | Description                                                  |
|---------------|--------------------------------------------------------------|
| `domain_name` | A DNS name that resolves to your Home Assistant host.        |
| `external_ip` | LAN IP of your Home Assistant host (what the AC connects to).|
| `log_level`   | DEBUG, INFO, WARNING, ERROR or CRITICAL.                     |

## Ports

- 1813/tcp: TLS
- 5000/tcp: plain TCP

Based on https://codeberg.org/joserebelo/gree-dummy-tls-server (AGPL-3.0).
