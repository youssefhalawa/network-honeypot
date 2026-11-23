#!/usr/bin/env bash
# Download the free MaxMind GeoLite2 City + ASN databases (Member 7)
#
#   1. Make a free account: https://www.maxmind.com/en/geolite2/signup
#   2. Create a licence key: Account -> Manage License Keys
#   3. Run:  MAXMIND_LICENSE_KEY=your_key bash scripts/setup_geoip.sh
#
# The files go to data/ (the paths GEOIP_DB_PATH and GEOIP_ASN_DB_PATH point to).
# Without them the honeypot still works: IPs are just stored as "OFFLINE".
set -euo pipefail

cd "$(dirname "$0")/.."
DATA_DIR="data"
mkdir -p "$DATA_DIR"

if [[ -z "${MAXMIND_LICENSE_KEY:-}" ]]; then
    read -r -p "MaxMind licence key: " MAXMIND_LICENSE_KEY
fi
if [[ -z "$MAXMIND_LICENSE_KEY" ]]; then
    echo "[x] No licence key given. See the instructions at the top of this script."
    exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

for EDITION in GeoLite2-City GeoLite2-ASN; do
    echo "[*] Downloading $EDITION ..."
    URL="https://download.maxmind.com/app/geoip_download?edition_id=${EDITION}&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"
    if ! curl -fsSL "$URL" -o "$TMP/$EDITION.tar.gz"; then
        echo "[x] Download failed for $EDITION (check the licence key and your internet connection)"
        exit 1
    fi
    tar -xzf "$TMP/$EDITION.tar.gz" -C "$TMP"
    find "$TMP" -name "$EDITION.mmdb" -exec mv {} "$DATA_DIR/$EDITION.mmdb" \;
    echo "[✓] $DATA_DIR/$EDITION.mmdb"
done

echo "[✓] Done. Restart the honeypot to use the new databases."
