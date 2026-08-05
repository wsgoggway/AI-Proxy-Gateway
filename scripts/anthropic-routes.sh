#!/usr/bin/env bash
# Route Anthropic traffic through wg0 (foreign exit) to bypass geo-blocking.
# Anthropic blocks requests from Russian IPs with 403 "Request not allowed".
# Run as root on the proxy server.
#
# Anthropic owns 160.79.104.0/21 (ASN AP-2440, US). All main domains
# (api.anthropic.com, claude.ai, console, platform, www, docs, support)
# resolve into this range. downloads.claude.ai (Google) and
# status.anthropic.com (CloudFront) use separate IPs.
#
# Must be applied together with /etc/gai.conf: prefer IPv4 —
#   echo 'precedence ::ffff:0:0/96  100' >> /etc/gai.conf
# otherwise clients pick AAAA (2607:6bc0::/32) which has no wg0 route
# and still goes out via eth0 (RU IP) -> 403.
#
# For persistence add the same `ip route add ... dev wg0` lines to
# PostUp in /etc/wireguard/wg0.conf (applied on every tunnel start).

set -euo pipefail

ROUTES=(
  "160.79.104.0/21"    # Anthropic PBC (api.anthropic.com, claude.ai, console, www, docs, platform, support)
  "35.190.46.17/32"    # downloads.claude.ai (Google Cloud)
  "18.239.83.22/32"    # status.anthropic.com (CloudFront)
  "18.239.83.70/32"
  "18.239.83.81/32"
  "18.239.83.122/32"
)

if ! ip link show wg0 >/dev/null 2>&1; then
  echo "ERROR: wg0 interface not found" >&2
  exit 1
fi

for cidr in "${ROUTES[@]}"; do
  ip route replace "$cidr" dev wg0 metric 16 || {
    echo "ERROR: failed to add route $cidr" >&2
    exit 1
  }
  echo "route: $cidr -> wg0"
done

# Verify
for host in api.anthropic.com downloads.claude.ai status.anthropic.com; do
  ip=$(getent ahostsv4 "$host" | awk '{print $1}' | head -1)
  dev=$(ip route get "$ip" 2>/dev/null | grep -oE 'dev [a-z0-9]+' | head -1 | cut -d' ' -f2)
  echo "check: $host ($ip) -> $dev"
done

echo "Done. Expect 401 (not 403) on unauthenticated Anthropic calls."
