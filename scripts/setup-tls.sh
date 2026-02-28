#!/bin/bash
# Provision TLS certificate for mcp.cybersorted.io via Let's Encrypt
# Run this AFTER DNS is pointing to the VM and BEFORE starting docker compose
set -euo pipefail

DOMAIN="${1:-mcp.cybersorted.io}"
EMAIL="${2:-admin@cybersorted.io}"

echo "=== Provisioning TLS certificate for ${DOMAIN} ==="

# Check DNS resolves to this machine
VM_IP=$(curl -s https://api.ipify.org)
DNS_IP=$(dig +short "${DOMAIN}" A | head -1)

if [ "${VM_IP}" != "${DNS_IP}" ]; then
    echo "WARNING: DNS for ${DOMAIN} resolves to ${DNS_IP}, but this VM's IP is ${VM_IP}"
    echo "Ensure the DNS A record points to ${VM_IP} before continuing."
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Stop nginx if running (certbot needs port 80)
docker compose down nginx 2>/dev/null || true

# Request certificate using standalone mode (first time)
certbot certonly \
    --standalone \
    --non-interactive \
    --agree-tos \
    --email "${EMAIL}" \
    --domain "${DOMAIN}" \
    --preferred-challenges http

echo "=== TLS certificate provisioned successfully ==="
echo "Certificate: /etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
echo "Private key: /etc/letsencrypt/live/${DOMAIN}/privkey.pem"
echo ""
echo "Start the services: docker compose up -d"
