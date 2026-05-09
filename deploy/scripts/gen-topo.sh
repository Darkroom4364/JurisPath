#!/usr/bin/env bash
# gen-topo.sh — Generate SCION crypto material for JurisPath 3-ISD topology.
#
# This script generates TRCs, AS certificates, and keys for all 5 ASes. It uses
# scion-pki if available, then the JurisPath SCION Docker image if present, and
# otherwise falls back to openssl-based placeholder material.
#
# Usage: ./gen-topo.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOY_DIR="$SCRIPT_DIR/.."
TOPO_DIR="$DEPLOY_DIR/topology"
CRYPTO_DIR="$DEPLOY_DIR/crypto"
SCION_PKI_IMAGE="${JURISPATH_SCION_PKI_IMAGE:-jurispath-scion-base}"

# AS definitions: ISD-AS / directory-name / is-core
declare -a AS_LIST=(
  "1-ff00:0:110|isd-ch/as110|core"
  "1-ff00:0:111|isd-ch/as111|noncore"
  "2-ff00:0:210|isd-eu/as210|core"
  "2-ff00:0:211|isd-eu/as211|noncore"
  "3-ff00:0:310|isd-x/as310|core"
)

# ISD definitions: ISD number / directory-name
declare -a ISD_LIST=(
  "1|isd-ch"
  "2|isd-eu"
  "3|isd-x"
)

echo "=== JurisPath SCION Crypto Material Generator ==="
echo "Output directory: $CRYPTO_DIR"

crypto_as_dir() {
  local isd_num="$1"
  local as_raw="$2"
  local as_sanitized="${as_raw//:/_}"
  local candidate

  for candidate in \
    "$CRYPTO_DIR/ISD${isd_num}/AS${as_raw}" \
    "$CRYPTO_DIR/ISD${isd_num}/AS${as_sanitized}" \
    "$CRYPTO_DIR/AS${as_raw}" \
    "$CRYPTO_DIR/AS${as_sanitized}"
  do
    if [ -d "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  echo "missing crypto directory for ISD${isd_num} AS${as_raw}" >&2
  return 1
}

distribute_crypto() {
  echo "Distributing crypto to AS topology directories..."

  for as_entry in "${AS_LIST[@]}"; do
    IFS='|' read -r isd_as as_dir as_type <<< "$as_entry"
    isd_num="${isd_as%%-*}"
    as_raw="${isd_as#*-}"

    src_as="$(crypto_as_dir "$isd_num" "$as_raw")"
    DEST="$TOPO_DIR/$as_dir/crypto"
    rm -rf "$DEST"
    mkdir -p "$DEST/as" "$DEST/trcs" "$DEST/keys" "$DEST/certs"
    mkdir -p "$src_as/keys"

    for master_key in master0.key master1.key; do
      if [ ! -s "$src_as/keys/$master_key" ]; then
        openssl rand -hex 16 > "$src_as/keys/$master_key"
      fi
    done

    # Copy AS-specific crypto
    cp "$src_as/crypto/as/"* "$DEST/as/"
    cp "$src_as/keys/"* "$DEST/keys/"

    # Copy all TRCs and certificate chains so cross-ISD core links have the
    # trust material they need during process startup and path exchange.
    find "$CRYPTO_DIR" -path "*/trcs/*.trc" -type f -exec cp {} "$DEST/trcs/" \;
    find "$CRYPTO_DIR" -path "*/trcs/*.trc" -type f -exec cp {} "$DEST/certs/" \;
    find "$CRYPTO_DIR" \( -name "*.pem" -o -name "*.crt" \) -type f -exec cp {} "$DEST/certs/" \;

    echo "  $as_dir -> crypto distributed"
  done
}

# ── Method 1: Use scion-pki testcrypto if available ──────────────────────
if command -v scion-pki &>/dev/null; then
  echo "Found scion-pki, using testcrypto..."
  rm -rf "$CRYPTO_DIR"
  cd "$TOPO_DIR"
  scion-pki testcrypto -t topology.topo -o "$CRYPTO_DIR"
  echo "Crypto material generated via scion-pki at $CRYPTO_DIR"
  cd "$DEPLOY_DIR"
  distribute_crypto
  echo "Done."
  exit 0
fi

# ── Method 2: Use scion-pki from the local SCION Docker image ─────────────
if command -v docker &>/dev/null && docker image inspect "$SCION_PKI_IMAGE" >/dev/null 2>&1; then
  echo "Found Docker image $SCION_PKI_IMAGE, using bundled scion-pki..."
  rm -rf "$CRYPTO_DIR"
  mkdir -p "$CRYPTO_DIR"
  docker run --rm \
    --user "$(id -u):$(id -g)" \
    -v "$TOPO_DIR:/work/topology:ro" \
    -v "$CRYPTO_DIR:/work/crypto" \
    "$SCION_PKI_IMAGE" \
    scion-pki testcrypto -t /work/topology/topology.topo -o /work/crypto
  echo "Crypto material generated via Docker scion-pki at $CRYPTO_DIR"
  distribute_crypto
  echo "Done."
  exit 0
fi

echo "scion-pki not found and Docker image $SCION_PKI_IMAGE is unavailable."
echo "Generating placeholder crypto material with openssl..."

# ── Method 3: Generate self-signed crypto with openssl ───────────────────
# This produces the directory structure that SCION services expect:
#   crypto/
#     ISDx/
#       trcs/
#         ISD1-B1-S1.trc
#       ASy/
#         crypto/as/
#           cp-as.key
#           ISDx-ASy.pem
#         keys/
#           master0.key
#           master1.key

# Clean previous output
rm -rf "$CRYPTO_DIR"

for isd_entry in "${ISD_LIST[@]}"; do
  IFS='|' read -r isd_num isd_dir <<< "$isd_entry"

  ISD_DIR="$CRYPTO_DIR/ISD${isd_num}"
  TRC_DIR="$ISD_DIR/trcs"
  mkdir -p "$TRC_DIR"

  echo "--- ISD $isd_num ---"

  # Generate a self-signed TRC placeholder.
  # In production, TRCs are created by voting ASes. This creates a minimal
  # placeholder so services can start. Replace with real TRCs for production.
  cat > "$TRC_DIR/ISD${isd_num}-B1-S1.trc.json" <<TRCEOF
{
  "isd": ${isd_num},
  "base_version": 1,
  "serial_version": 1,
  "description": "JurisPath ISD-${isd_num} test TRC",
  "voting_quorum": 1,
  "grace_period": "0s",
  "validity": {
    "not_before": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "not_after": "$(date -u -v+365d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '+365 days' +%Y-%m-%dT%H:%M:%SZ)"
  }
}
TRCEOF
  # Binary TRC placeholder (services need the .trc file, not just JSON)
  # Copy JSON as a stand-in; scion-pki would produce the real binary.
  cp "$TRC_DIR/ISD${isd_num}-B1-S1.trc.json" "$TRC_DIR/ISD${isd_num}-B1-S1.trc"
done

for as_entry in "${AS_LIST[@]}"; do
  IFS='|' read -r isd_as as_dir as_type <<< "$as_entry"

  # Extract ISD number and AS number
  isd_num="${isd_as%%-*}"
  as_raw="${isd_as#*-}"  # ff00:0:110

  AS_CRYPTO="$CRYPTO_DIR/ISD${isd_num}/AS${as_raw}"
  AS_KEY_DIR="$AS_CRYPTO/crypto/as"
  AS_MASTER_DIR="$AS_CRYPTO/keys"
  mkdir -p "$AS_KEY_DIR" "$AS_MASTER_DIR"

  echo "Generating keys for $isd_as ($as_type) ..."

  # Generate CP-AS private key (ECDSA P-256)
  openssl ecparam -name prime256v1 -genkey -noout \
    -out "$AS_KEY_DIR/cp-as.key" 2>/dev/null

  # Generate self-signed CP-AS certificate
  openssl req -new -x509 -key "$AS_KEY_DIR/cp-as.key" \
    -out "$AS_KEY_DIR/ISD${isd_num}-AS${as_raw}.pem" \
    -days 365 -subj "/CN=${isd_as}/O=JurisPath" 2>/dev/null

  # Generate master keys (forwarding/decryption secrets, 32 bytes hex)
  openssl rand -hex 16 > "$AS_MASTER_DIR/master0.key"
  openssl rand -hex 16 > "$AS_MASTER_DIR/master1.key"

  echo "  Keys:   $AS_KEY_DIR/cp-as.key"
  echo "  Cert:   $AS_KEY_DIR/ISD${isd_num}-AS${as_raw}.pem"
  echo "  Master: $AS_MASTER_DIR/master0.key, master1.key"
done

echo ""
echo "=== Crypto generation complete ==="
echo ""
echo "IMPORTANT: The generated TRCs are placeholders and will not satisfy"
echo "SCION service trust-material parsing. For a working SCION process"
echo "smoke test, install scion-pki and re-run this script, or run"
echo "make scion-image before make topo so the Docker-bundled scion-pki"
echo "can generate real testcrypto material."
echo ""

# ── Copy crypto into per-AS topology directories ────────────────────────
distribute_crypto

echo ""
echo "Done. All crypto material is in $CRYPTO_DIR and copied to per-AS dirs."
