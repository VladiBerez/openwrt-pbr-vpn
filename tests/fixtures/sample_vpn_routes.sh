#!/bin/sh
S="pbr_vpnclient_4_dst_ip_user"
nft add element inet fw4 $S "{ 157.240.0.0/16, 91.108.4.0/22, 1.2.3.4 }" 2>/dev/null
nft add element inet fw4 $S "{ 172.217.0.0/16, 142.250.0.0/15 }" 2>/dev/null
# comment line, must not be parsed: 9.9.9.9
