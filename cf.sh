#!/bin/bash
# My Telegram : https://t.me/kopet
# ==========================================
# Color
RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
LIGHT='\033[0;37m'
# ==========================================
# Getting
clear
read -rp "Input Your Domain For This Server :" -e DOMAIN_BARU
printf "$DOMAIN_BARU\nns-${DOMAIN_BARU}" > /root/domain
echo $DOMAIN_BARU >/root/domain

rm -f /root/cf.sh
