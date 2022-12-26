#!/bin/bash
apt install jq curl socat -y
DOMAIN=project-kel10.me
sub=$(tr </dev/urandom -dc a-z0-9 | head -c4)

DOMAIN_BARU=${sub}.project-kel10.me # >> Nih hasil domain random ya hotod ( alias horas tod )

CF_ID="amsalsiregar12@gmail.com"
CF_KEY="796e45662b9bfe66fd1d15c9a05a41eb8c96f"
IPV4=$(wget -qO- https://myip.cpanel.net/)

export ZONA_ID=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones?name=${GET_DOMAIN}&status=active" -H "X-Auth-Email: ${CF_ID}" -H "X-Auth-Key: ${CF_KEY}" -H "Content-Type: application/json" | jq -r .result[0].id )
export RECORD=$(curl -sLX POST "https://api.cloudflare.com/client/v4/zones/${ZONA_ID}/dns_records" -H "X-Auth-Email: ${CF_ID}" -H "X-Auth-Key: ${CF_KEY}" -H "Content-Type: application/json" --data '{"type":"A","name":"'${DOMAIN_BARU}'","content":"'${IPV4}'","ttl":0,"proxied":false}' | jq -r .result.id)
export RESULT=$(curl -sLX PUT "https://api.cloudflare.com/client/v4/zones/${ZONA_ID}/dns_records/${RECORD}" -H "X-Auth-Email: ${CF_ID}" -H "X-Auth-Key: ${CF_KEY}" -H "Content-Type: application/json" --data '{"type":"A","name":"'${DOMAIN_BARU}'","content":"'${IPV4}'","ttl":0,"proxied":false}')
export ZONA_ID=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones?name=${GET_DOMAIN}&status=active" -H "X-Auth-Email: ${CF_ID}" -H "X-Auth-Key: ${CF_KEY}" -H "Content-Type: application/json" | jq -r .result[0].id )
export RECORD=$(curl -sLX POST "https://api.cloudflare.com/client/v4/zones/${ZONA_ID}/dns_records" -H "X-Auth-Email: ${CF_ID}" -H "X-Auth-Key: ${CF_KEY}" -H "Content-Type: application/json" --data '{"type":"A","name":"'*.${DOMAIN_BARU}'","content":"'${IPV4}'","ttl":0,"proxied":false}' | jq -r .result.id)
export RESULT=$(curl -sLX PUT "https://api.cloudflare.com/client/v4/zones/${ZONA_ID}/dns_records/${RECORD}" -H "X-Auth-Email: ${CF_ID}" -H "X-Auth-Key: ${CF_KEY}" -H "Content-Type: application/json" --data '{"type":"A","name":"'*.${DOMAIN_BARU}'","content":"'${IPV4}'","ttl":0,"proxied":false}')
export ZONA_ID=$(curl -sLX GET "https://api.cloudflare.com/client/v4/zones?name=${GET_DOMAIN}&status=active" -H "X-Auth-Email: ${CF_ID}" -H "X-Auth-Key: ${CF_KEY}" -H "Content-Type: application/json" | jq -r .result[0].id )
export RECORD=$(curl -sLX POST "https://api.cloudflare.com/client/v4/zones/${ZONA_ID}/dns_records" -H "X-Auth-Email: ${CF_ID}" -H "X-Auth-Key: ${CF_KEY}" -H "Content-Type: application/json" --data '{"type":"NS","name":"'ns-${DOMAIN_BARU}'","content":"'${DOMAIN_BARU}'","ttl":0,"proxied":false}' | jq -r .result.id)
export RESULT=$(curl -sLX PUT "https://api.cloudflare.com/client/v4/zones/${ZONA_ID}/dns_records/${RECORD}" -H "X-Auth-Email: ${CF_ID}" -H "X-Auth-Key: ${CF_KEY}" -H "Content-Type: application/json" --data '{"type":"NS","name":"'ns-${DOMAIN_BARU}'","content":"'${DOMAIN_BARU}'","ttl":0,"proxied":false}')

printf "$DOMAIN_BARU\nns-${DOMAIN_BARU}" > /root/domain
echo $DOMAIN_BARU >/root/domain

rm -f /root/cf.sh
