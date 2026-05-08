#!/usr/bin/env bash
# =============================================================================
# inspect-cert.sh — Inspect a GoBless-issued SSH certificate
# EXAMPLE ONLY — NOT FOR PRODUCTION
#
# Usage:
#   ./inspect-cert.sh /path/to/issued-cert.pub
#
# Or inspect inline if you have the cert as a file already:
#   ssh-keygen -L -f /path/to/issued-cert.pub
# =============================================================================

set -euo pipefail

CERT_FILE="${1:-}"

if [[ -z "$CERT_FILE" ]]; then
  echo "Usage: $0 /path/to/issued-cert.pub"
  echo ""
  echo "Example:"
  echo "  $0 ~/.ssh/id_rsa-cert.pub"
  exit 1
fi

if [[ ! -f "$CERT_FILE" ]]; then
  echo "Error: cert file not found: $CERT_FILE"
  exit 1
fi

echo "=== Inspecting certificate: $CERT_FILE ==="
echo ""

# -L prints the full certificate details in human-readable form.
ssh-keygen -L -f "$CERT_FILE"

echo ""
echo "=== What to verify ==="
echo ""
echo "  Type:         Should be 'user' or 'host' matching your request."
echo "  Signing CA:   Should match the fingerprint of your GoBless CA key."
echo "                Get the expected CA fingerprint with:"
echo "                  aws kms get-public-key --key-id <your-kms-key-id> | ..."
echo "  Key ID:       GoBless stamps certs with format:"
echo "                  gobless-<cert-type>-<principal>-<unix-timestamp>-<hex8>"
echo "                Example: gobless-user-alice-1746500000-a1b2c3d4"
echo "  Serial:       Random non-zero uint64. Useful for audit/revocation."
echo "  Valid:        Check ValidAfter and ValidBefore are reasonable."
echo "                Short-lived certs (1h) are expected for user certs."
echo "  Principals:   Should match the username (user cert) or hostname (host cert)."
echo "  Extensions:   For user certs, expect all five permit-* extensions:"
echo "                  permit-agent-forwarding, permit-port-forwarding,"
echo "                  permit-pty, permit-user-rc, permit-X11-forwarding"
echo "                Host certs carry no extensions."
echo "  Critical Options:"
echo "    source-address: If set, value must be a CIDR (e.g. 10.0.1.0/24)."
echo "                    Cert is only usable from that network range."
echo "                    Verify this matches the source_address in your request."
echo ""
echo "=== If something looks wrong ==="
echo "  - Wrong CA fingerprint → cert was NOT issued by your GoBless instance."
echo "  - Missing source-address → source_address was not set in the request."
echo "  - Unexpected principals → audit the request that triggered this issuance."
echo "  - Key ID format mismatch → may indicate cert was not issued by GoBless."
