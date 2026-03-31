#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TOPO_DIR="$SCRIPT_DIR/../topology"

echo "Generating SCION topology from $TOPO_DIR/topology.topo"
echo "TODO: integrate with scion-pki testcrypto once SCION v0.14.0 is installed"
echo "See: https://docs.scion.org/en/latest/tutorials/deploy.html"
