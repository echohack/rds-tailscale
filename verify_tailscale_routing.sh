#!/bin/bash
set -e

# Verify Tailscale subnet routing to RDS
# Usage: ./verify_tailscale_routing.sh <rds_endpoint> <username> <password> [ec2_hostname_pattern] [vpc_cidr]

if [ "$#" -lt 3 ]; then
  echo "Usage: $0 <rds_endpoint> <username> <password> [ec2_hostname_pattern] [vpc_cidr]"
  exit 1
fi

RDS_ENDPOINT="$1"
USERNAME="$2"
PASSWORD="$3"
EC2_HOSTNAME_PATTERN="${4:-ip-172-16}"  # Pattern to match EC2 hostname, default to ip-172-16
VPC_CIDR="${5:-172.16.0.0/16}"  # Optional VPC CIDR, defaults to 172.16.0.0/16

echo "» Verifying Tailscale subnet router --> RDS connection"
if ! command -v tailscale &> /dev/null; then
  echo "✗ Tailscale not found. Please install Tailscale on this machine."
  exit 1
fi
echo "✓ Verified local Tailscale installation."

echo "» Verifying Tailscale authentication status"
TAILSCALE_STATUS=$(tailscale status)
if [ $? -ne 0 ]; then
  echo "✗ Tailscale not running or not authenticated."
  exit 1
fi
echo "✓ Verified Tailscale is authenticated and running."

echo "» Verifying subnet router configuration"
SUBNET_PEERS=$(tailscale status --peers)

ROUTER_LINE=$(echo "$SUBNET_PEERS" | grep "$EC2_HOSTNAME_PATTERN" || echo "")
if [ -z "$ROUTER_LINE" ]; then
  echo "✗ No subnet router with hostname pattern '$EC2_HOSTNAME_PATTERN' found in tailscale peers."
  exit 1
else
  ROUTER_TS_IP=$(echo "$ROUTER_LINE" | awk '{print $1}')
  ROUTER_NAME=$(echo "$ROUTER_LINE" | awk '{print $2}')
  echo "✓ Verified subnet router: $ROUTER_NAME (Tailscale IP: $ROUTER_TS_IP)"
fi

echo "» Verifying route acceptance status"
if echo "$SUBNET_PEERS" | grep -q "accept-routes is false"; then
  echo "✗ Route acceptance is disabled. Enable it with: tailscale set --accept-routes=true"
  exit 1
fi
echo "✓ Verified route acceptance is enabled."

echo "» Verifying IP forwarding on subnet router"
if ! ping -c 1 -W 2 "$ROUTER_TS_IP" > /dev/null 2>&1; then
  echo "✗ Cannot ping the subnet router at $ROUTER_TS_IP."
  exit 1
fi

IP_FORWARD=$(ssh -i ~/.ssh/tailscale-rds -o StrictHostKeyChecking=no ubuntu@$ROUTER_TS_IP 'cat /proc/sys/net/ipv4/ip_forward')
if [ "$IP_FORWARD" = "1" ]; then
  echo "✓ Verified IP forwarding is enabled on subnet router."
else
  echo "✗ IP forwarding is not enabled on the subnet router."
  exit 1
fi

echo "» Verifying RDS endpoint DNS"
RESOLVED_IP=$(dig +short "$RDS_ENDPOINT")
if [ -z "$RESOLVED_IP" ]; then
  echo "✗ Failed to resolve $RDS_ENDPOINT"
  echo "✗  You may need to configure split DNS in the Tailscale admin console."
  echo "✗  Add your AWS DNS server (VPC CIDR + 2, e.g., ${VPC_CIDR%.*}.0.2) and restrict it to *.rds.amazonaws.com domains."
  exit 1
fi
echo "✓ Verified $RDS_ENDPOINT to $RESOLVED_IP"

echo "» Verifying network connectivity to port 5432"
if nc -z -w5 "$RDS_ENDPOINT" 5432 > /dev/null 2>&1; then
  echo "✓ Verified network connectivity to $RDS_ENDPOINT:5432."
else
  echo "✗ Cannot connect to $RDS_ENDPOINT:5432. Check security groups and routing."
  exit 1
fi

echo "» Verifying PostgreSQL connection"
if PGPASSWORD="$PASSWORD" PAGER=cat psql -h "$RDS_ENDPOINT" -U "$USERNAME" -d postgres -c "SELECT 'Connection successful', current_timestamp, version();" -t > /dev/null 2>&1; then
  echo "✓ Verified PostgreSQL connection"
else
  echo "✗ PostgreSQL connection failed. This might be a credentials issue or database configuration problem."
  exit 1
fi

echo ""
echo "✓ All tests passed! Your Tailscale subnet router to RDS is working."