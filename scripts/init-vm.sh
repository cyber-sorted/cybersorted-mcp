#!/bin/bash
# Cloud-init script for CyberSorted MCP Server VM
# Installs Docker, Docker Compose, and certbot on Ubuntu 24.04 LTS
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

echo "=== CyberSorted MCP VM Initialisation ==="

# Update system
apt-get update -y
apt-get upgrade -y

# Install prerequisites
apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    ufw \
    fail2ban \
    unattended-upgrades

# Install Docker (official repo)
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Enable and start Docker
systemctl enable docker
systemctl start docker

# Add admin user to docker group
usermod -aG docker cybersorted

# Install certbot (standalone — we use webroot mode via nginx)
apt-get install -y certbot

# Configure UFW firewall
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    # SSH
ufw allow 80/tcp    # HTTP (Let's Encrypt)
ufw allow 443/tcp   # HTTPS (MCP)
ufw --force enable

# Configure fail2ban for SSH
cat > /etc/fail2ban/jail.local <<'EOF'
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
findtime = 600
EOF
systemctl enable fail2ban
systemctl restart fail2ban

# Enable automatic security updates
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

# Create application directory
mkdir -p /app/credentials
chown -R cybersorted:cybersorted /app

echo "=== CyberSorted MCP VM initialisation complete ==="
echo "Next steps:"
echo "  1. Copy GCP service account key to /app/credentials/gcp-sa-key.json"
echo "  2. Copy .env file to /app/.env"
echo "  3. Run scripts/setup-tls.sh to provision TLS certificate"
echo "  4. Run docker compose up -d to start services"
