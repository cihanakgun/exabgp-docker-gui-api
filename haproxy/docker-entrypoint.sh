#!/bin/sh
set -e

CERT_DIR=/etc/ssl/haproxy
CERT_FILE="$CERT_DIR/haproxy.pem"

mkdir -p "$CERT_DIR"

if [ ! -f "$CERT_FILE" ]; then
    echo "[entrypoint] Generating self-signed TLS certificate..."

    # Read optional env vars for cert subject fields
    CN="${TLS_CN:-exabgp-manager}"
    ORG="${TLS_ORG:-ExaBGP Manager}"
    COUNTRY="${TLS_COUNTRY:-US}"
    DAYS="${TLS_DAYS:-3650}"

    openssl req -x509 \
        -newkey rsa:4096 \
        -keyout /tmp/key.pem \
        -out    /tmp/cert.pem \
        -days   "$DAYS" \
        -nodes \
        -subj   "/CN=$CN/O=$ORG/C=$COUNTRY"

    # HAProxy expects cert + key concatenated in a single PEM file
    cat /tmp/cert.pem /tmp/key.pem > "$CERT_FILE"
    chmod 600 "$CERT_FILE"
    rm -f /tmp/key.pem /tmp/cert.pem

    echo "[entrypoint] Certificate generated: $CERT_FILE (valid $DAYS days)"
    echo "[entrypoint] CN=$CN  O=$ORG  C=$COUNTRY"
else
    echo "[entrypoint] Using existing certificate: $CERT_FILE"
fi

echo "[entrypoint] Starting HAProxy..."
exec haproxy -f /usr/local/etc/haproxy/haproxy.cfg -W
