#!/bin/bash
set -e

TOPOLOGY="isp-topology.yml"
BRIDGE="ext-lan"
BRIDGE_IP="10.100.0.1/24"

# Always destroy with cleanup before redeploy (idempotent, no error if nothing to destroy)
sudo containerlab destroy -t "$TOPOLOGY" --cleanup 2>/dev/null || true

if ! ip link show "$BRIDGE" >/dev/null 2>&1; then
    sudo ip link add name "$BRIDGE" type bridge
fi
sudo ip link set "$BRIDGE" up

if ! ip -4 addr show dev "$BRIDGE" | grep -q "${BRIDGE_IP%/*}"; then
    sudo ip addr add "$BRIDGE_IP" dev "$BRIDGE"
fi

sudo containerlab deploy -t "$TOPOLOGY"

echo "----"
echo "bridge $BRIDGE = $BRIDGE_IP ready"
ip -br addr show "$BRIDGE"