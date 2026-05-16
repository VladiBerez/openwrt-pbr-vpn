#!/bin/sh
# Seed routes — known public CIDR ranges that don't change often.
# Copy to ./vpn-routes.sh on first run; `ovpn-pbr update` will append more.
# Tweak `$S` if your interface isn't named "vpnclient".

S="pbr_vpnclient_4_dst_ip_user"

# --- Telegram (https://core.telegram.org/resources/cidr.txt) ---
nft add element inet fw4 $S "{ 91.108.4.0/22, 91.108.8.0/22, 91.108.12.0/22, 91.108.16.0/22, 91.108.20.0/22, 91.108.56.0/22, 91.105.192.0/23, 149.154.160.0/20, 185.76.151.0/24 }" 2>/dev/null

# --- Meta / Instagram / Facebook (well-known prefixes) ---
nft add element inet fw4 $S "{ 31.13.0.0/16, 66.220.0.0/16, 69.63.0.0/16, 69.171.0.0/16, 74.119.0.0/16, 102.132.0.0/16, 102.221.0.0/16, 103.4.0.0/16, 129.134.0.0/16, 157.240.0.0/16, 163.70.0.0/16, 163.77.128.0/17, 163.114.0.0/16, 173.252.0.0/16, 179.60.0.0/16, 185.60.0.0/16, 185.89.0.0/16 }" 2>/dev/null

# --- Cloudflare edges (covers Claude, Discord, many CF-hosted apps) ---
nft add element inet fw4 $S "{ 104.16.0.0/13, 172.64.0.0/13, 162.158.0.0/15, 188.114.96.0/20, 141.101.64.0/18, 108.162.192.0/18, 190.93.240.0/20, 197.234.240.0/22, 198.41.128.0/17, 173.245.48.0/20, 103.21.244.0/22, 103.22.200.0/22, 103.31.4.0/22, 131.0.72.0/22 }" 2>/dev/null

# --- Google / YouTube edges ---
nft add element inet fw4 $S "{ 64.233.160.0/19, 74.125.0.0/16, 142.250.0.0/15, 172.217.0.0/16, 172.253.144.0/20, 173.194.0.0/16, 192.178.128.0/17, 216.58.192.0/19 }" 2>/dev/null

# --- Twitter / X ---
nft add element inet fw4 $S "{ 104.244.40.0/21, 199.232.0.0/16, 199.59.148.0/22 }" 2>/dev/null

# --- Fastly / CDN ---
nft add element inet fw4 $S "{ 146.75.0.0/16, 151.101.0.0/16, 199.232.0.0/16 }" 2>/dev/null

# --- GitHub ---
nft add element inet fw4 $S "{ 140.82.112.0/20, 185.199.108.0/22 }" 2>/dev/null
