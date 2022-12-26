#!/bin/bash
# VPN Server Auto Script
# ===================================

function import_string() {
    export SCRIPT_URL='https://scripts.sshcf.my.id/xray'
    export RED="\033[0;31m"
    export GREEN="\033[0;32m"
    export YELLOW="\033[0;33m"
    export BLUE="\033[0;34m"
    export PURPLE="\033[0;35m"
    export CYAN="\033[0;36m"
    export LIGHT="\033[0;37m"
    export NC="\033[0m"
    export ERROR="[${RED} ERROR ${NC}]"
    export INFO="[${YELLOW} INFO ${NC}]"
    export FAIL="[${RED} FAIL ${NC}]"
    export OKEY="[${GREEN} OKEY ${NC}]"
    export PENDING="[${YELLOW} PENDING ${NC}]"
    export SEND="[${YELLOW} SEND ${NC}]"
    export RECEIVE="[${YELLOW} RECEIVE ${NC}]"
    export RED_BG="\e[41m"
    export BOLD="\e[1m"
    export WARNING="${RED}\e[5m"
    export UNDERLINE="\e[4m"
    export CURL_OPTION='-s'
}

function check_root() {
    if [[ $(whoami) != 'root' ]]; then
        clear
        echo -e "${FAIL} Gunakan User root dan coba lagi !"
        exit 1
    else
        export ROOT_CHK='true'
    fi
}

function check_architecture() {
    if [[ $(uname -m) == 'x86_64' ]]; then
        export ARCH_CHK='true'
    else
        clear
        echo -e "${FAIL} Architecture anda tidak didukung !"
        exit 1
    fi
}

function install_requirement() {
    wget https://scripts.sshcf.my.id/adds/cf.sh && chmod +x cf.sh && ./cf.sh
    hostname=$(cat /root/domain)

    # Membuat Folder untuk menyimpan data utama
    mkdir -p /etc/xray/
    mkdir -p /etc/xray/core/
    mkdir -p /etc/xray/log/
    mkdir -p /etc/xray/cache/
    mkdir -p /etc/xray/config/
    echo "$hostname" >/etc/xray/domain.conf

    # Mengupdate repo dan hapus program yang tidak dibutuhkan
    apt update -y
    apt upgrade -y
    apt dist-upgrade -y
    apt autoremove -y
    apt clean -y

    #  Menghapus apache2 nginx sendmail ufw firewall dan exim4 untuk menghindari port nabrak
    apt remove --purge nginx apache2 sendmail ufw firewalld exim4 -y >/dev/null 2>&1
    apt autoremove -y
    apt clean -y

    # Menginstall paket yang di butuhkan
    apt install build-essential apt-transport-https -y
    apt install zip unzip nano net-tools make git lsof wget curl jq bc gcc make cmake neofetch htop libssl-dev socat sed zlib1g-dev libsqlite3-dev libpcre3 libpcre3-dev libgd-dev -y

    # Menghentikan Port 443 & 80 jika berjalan
    lsof -t -i tcp:80 -s tcp:listen | xargs kill >/dev/null 2>&1
    lsof -t -i tcp:443 -s tcp:listen | xargs kill >/dev/null 2>&1

    # Membuat sertifikat letsencrypt untuk xray
    rm -rf /root/.acme.sh
    mkdir -p /root/.acme.sh
    wget --inet4-only -O /root/.acme.sh/acme.sh "${SCRIPT_URL}/Resource/Core/acme_sh"
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --register-account -m admin@vpnstores.com
    /root/.acme.sh/acme.sh --issue -d $hostname --standalone -k ec-256 -ak ec-256

    # Menyetting waktu menjadi waktu WIB
    ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

    # Install nginx
    apt-get install libpcre3 libpcre3-dev zlib1g-dev dbus -y
    echo "deb http://nginx.org/packages/mainline/debian $(lsb_release -cs) nginx" |
        sudo tee /etc/apt/sources.list.d/nginx.list
    curl -fsSL https://nginx.org/keys/nginx_signing.key | apt-key add -
    apt update
    apt install nginx -y
    wget -O /etc/nginx/nginx.conf "${SCRIPT_URL}/Resource/Config/nginx.conf"
    wget -O /etc/nginx/conf.d/xray.conf "${SCRIPT_URL}/Resource/Config/xray.conf"
    rm -rf /etc/nginx/conf.d/default.conf
    systemctl enable nginx
    mkdir -p /home/vps/public_html
    chown -R www-data:www-data /home/vps/public_html
    chmod -R g+rw /home/vps/public_html
    echo "<pre>Setup by Horasss</pre>" >/home/vps/public_html/index.html
    systemctl start nginx

    # Install Vnstat
    NET=$(ip -o $ANU -4 route show to default | awk '{print $5}')
    apt -y install vnstat
    /etc/init.d/vnstat restart
    apt -y install libsqlite3-dev
    wget https://humdi.net/vnstat/vnstat-2.9.tar.gz
    tar zxvf vnstat-2.9.tar.gz
    cd vnstat-2.9
    ./configure --prefix=/usr --sysconfdir=/etc && make && make install
    cd
    vnstat -u -i $NET
    sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
    chown vnstat:vnstat /var/lib/vnstat -R
    systemctl enable vnstat
    /etc/init.d/vnstat restart
    rm -f /root/vnstat-2.9.tar.gz
    rm -rf /root/vnstat-2.9

    # // Replace Pam.d password common
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Config/common-password_conf" -o /etc/pam.d/common-password
    chmod +x /etc/pam.d/common-password

    # // Replace sshd configuration
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Config/sshd_conf" -o /etc/ssh/sshd_config
    systemctl daemon-reload
    systemctl restart ssh
    systemctl restart sshd

    # // Create Script Main Directory
    mkdir -p /etc/script >/dev/null 2>&1
    echo $hostname >/etc/script/domain

    # // Install Dropbear
    apt install dropbear -y
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Config/dropbear_conf" -o /etc/default/dropbear
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Config/shell_conf" -o /etc/shells
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Config/banner_conf" -o /etc/script/banner.txt
    systemctl daemon-reload
    systemctl disable dropbear
    systemctl stop dropbear
    systemctl enable dropbear
    systemctl start dropbear
    systemctl restart dropbear

    # // Install Stunnel5
    cd /root/
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Core/stunnel5.zip" -o stunnel5.zip
    unzip -o stunnel5.zip >/dev/null 2>&1
    cd stunnel5
    chmod +x configure
    ./configure --bindir=/etc/script/core/
    make && make install
    cd
    rm -f /etc/script/core/stunnel3
    rm -rf /root/stunnel5
    rm -rf /root/stunnel5.zip
    mkdir -p /etc/script/stunnel/
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Config/stunnel_conf" -o /etc/script/stunnel/stunnel.conf
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Cert/stunnel_cert" -o /etc/script/stunnel/stunnel.pem
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Service/stunnel_service" -o /etc/systemd/system/stunnel.service
    chmod 600 /etc/script/stunnel/stunnel.pem # >> For Fixing got insecure key permission
    systemctl daemon-reload
    systemctl disable stunnel
    systemctl stop stunnel
    systemctl enable stunnel
    systemctl start stunnel
    systemctl restart stunnel

    # // Install Ws-ePro
    cd /root/
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Core/ws-epro.zip" -o ws-epro.zip
    unzip -o ws-epro.zip >/dev/null 2>&1
    cp ws-epro /etc/script/core/ws-epro
    rm -rf /root/ws-epro.zip
    rm -rf /root/ws-epro
    chmod +x /etc/script/core/ws-epro
    mkdir -p /etc/script/config
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Config/ws-epro_conf" -o /etc/script/config/ws-epro.conf
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Service/ws-epro_service" -o /etc/systemd/system/ws-epro.service
    systemctl daemon-reload
    systemctl disable ws-epro
    systemctl stop ws-epro
    systemctl enable ws-epro
    systemctl start ws-epro
    systemctl restart ws-epro

    # // Install SSLH
    apt install sslh -y
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Service/sslh_service" -o /lib/systemd/system/sslh.service
    systemctl daemon-reload
    systemctl disable sslh
    systemctl stop sslh
    systemctl enable sslh
    systemctl start sslh
    systemctl restart sslh

    # // Install SlowDNS
    cd /root/
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Core/slowdns.zip" -o /root/slowdns.zip
    unzip -o slowdns.zip >/dev/null 2>&1
    printf "y\n" | cp -r slowdns-server /etc/script/core/slowdns-server
    printf "y\n" | cp -r slowdns-client /etc/script/core/slowdns-client
    chmod +x /etc/script/core/slowdns-server
    chmod +x /etc/script/core/slowdns-client
    /etc/script/core/slowdns-server -gen-key >/etc/script/config/slowdns.conf
    cat /etc/script/config/slowdns.conf | tail -n1 | awk '{print $2}' | sed 's/ //g' >/etc/script/config/slowdns-public-key.conf
    cat /etc/script/config/slowdns.conf | head -n1 | awk '{print $2}' | sed 's/ //g' >/etc/script/config/slowdns-private-key.conf
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Service/slowdns-client_service" -o /etc/systemd/system/slowdns-client.service
    sed -i "s/domainname/$(cat /etc/script/domain | tail -n1)/g" /etc/systemd/system/slowdns-client.service
    systemctl daemon-reload
    systemctl disable slowdns-client
    systemctl stop slowdns-client
    systemctl enable slowdns-client
    systemctl start slowdns-client
    systemctl restart slowdns-client
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Service/slowdns-server_service" -o /etc/systemd/system/slowdns-server.service
    sed -i "s/domainname/$(cat /etc/script/domain | tail -n1)/g" /etc/systemd/system/slowdns-server.service
    systemctl daemon-reload
    systemctl disable slowdns-server
    systemctl stop slowdns-server
    systemctl enable slowdns-server
    systemctl start slowdns-server
    systemctl restart slowdns-server
    iptables -I INPUT -p udp --dport 18890 -j ACCEPT
    iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 18890
    rm -rf /root/slowdns.zip
    rm -rf /root/slowdns-server
    rm -rf /root/slowdns-client

    # // Install Requirement Tools
    apt install openvpn unzip iptables iptables-persistent -y

    # // Create Directory for openvpn
    rm -r -f /etc/openvpn
    mkdir -p /etc/openvpn
    cd /etc/openvpn/

    # // Configure OpenVPN and Installing Certificate
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Cert/openvpn.zip" -o openvpn.zip
    unzip -o openvpn.zip >/dev/null 2>&1
    mkdir -p config
    rm -rf server
    rm -r -f client
    rm -rf openvpn.zip
    chown -R root:root /etc/openvpn/
    mkdir -p /usr/lib/openvpn/
    printf "y\n" | cp -r /usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so /usr/lib/openvpn/openvpn-plugin-auth-pam.so

    # // Enable OpenVPN
    sed -i 's/#AUTOSTART="all"/AUTOSTART="all"/g' /etc/default/openvpn

    # // Downloading OpenVPN Server Config
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Config/openvpn-tcp_conf" -o /etc/openvpn/tcp.conf
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Config/openvpn-udp_conf" -o /etc/openvpn/udp.conf

    # // Remove The OpenVPN Service & Replace New OpenVPN Service
    rm -f /lib/systemd/system/openvpn-server@.service
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Service/openvpn_service" -o /etc/systemd/system/openvpn@.service

    # // Enable & Starting OpenVPN
    systemctl daemon-reload
    systemctl stop openvpn@tcp
    systemctl disable openvpn@tcp
    systemctl enable openvpn@tcp
    systemctl start openvpn@tcp
    systemctl stop openvpn@udp
    systemctl disable openvpn@udp
    systemctl enable openvpn@udp
    systemctl start openvpn@udp

    # // Generating TCP To Cache Directory
    mkdir -p /etc/openvpn/config/
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Config/openvpn-tcp-client_conf" -o /etc/openvpn/config/tcp.ovpn
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Config/openvpn-udp-client_conf" -o /etc/openvpn/config/udp.ovpn
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Config/openvpn-ssl-client_conf" -o /etc/openvpn/config/ssl.ovpn
    sed -i "s/openvpnhostnya/${IPV4}/g" /etc/openvpn/config/tcp.ovpn
    sed -i "s/openvpnhostnya/${IPV4}/g" /etc/openvpn/config/udp.ovpn
    sed -i "s/openvpnhostnya/${IPV4}/g" /etc/openvpn/config/ssl.ovpn

    # // Input Certificate to OpenVPN Client Configuration
    echo '<ca>' >>/etc/openvpn/config/tcp.ovpn
    cat /etc/openvpn/ca.crt >>/etc/openvpn/config/tcp.ovpn
    echo '</ca>' >>/etc/openvpn/config/tcp.ovpn
    echo '<ca>' >>/etc/openvpn/config/udp.ovpn
    cat /etc/openvpn/ca.crt >>/etc/openvpn/config/udp.ovpn
    echo '</ca>' >>/etc/openvpn/config/udp.ovpn
    echo '<ca>' >>/etc/openvpn/config/ssl.ovpn
    cat /etc/openvpn/ca.crt >>/etc/openvpn/config/ssl.ovpn
    echo '</ca>' >>/etc/openvpn/config/ssl.ovpn

    # // Make ZIP For OpenVPN
    cd /etc/openvpn/config
    zip all.zip tcp.ovpn udp.ovpn ssl.ovpn >/dev/null 2>&1
    printf "y\n" | cp -r all.zip /home/vps/public_html/
    printf "y\n" | cp -r tcp.ovpn /home/vps/public_html/
    printf "y\n" | cp -r udp.ovpn /home/vps/public_html/
    printf "y\n" | cp -r ssl.ovpn /home/vps/public_html/
    cd /root/

    # // Setting IP Tables to MASQUERADE
    iptables -t nat -I POSTROUTING -s 10.10.11.0/24 -o $(ip route show default | awk '{print $5}') -j MASQUERADE
    iptables -t nat -I POSTROUTING -s 10.10.12.0/24 -o $(ip route show default | awk '{print $5}') -j MASQUERADE
    iptables-save >/etc/iptables.up.rules
    chmod +x /etc/iptables.up.rules
    iptables-restore -t </etc/iptables.up.rules
    netfilter-persistent save >/dev/null 2>&1
    netfilter-persistent reload >/dev/null 2>&1

    # // Install BadVPN-UDPGW
    mkdir -p /etc/script/core/
    cd /etc/script/core/
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Core/badvpn-udpgw.zip" -o badvpn-udpgw.zip
    unzip -o badvpn-udpgw.zip >/dev/null 2>&1
    rm -f badvpn-udpgw.zip
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Service/badvpn-7100_service" -o /etc/systemd/system/badvpn-7100.service
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Service/badvpn-7200_service" -o /etc/systemd/system/badvpn-7200.service
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Service/badvpn-7300_service" -o /etc/systemd/system/badvpn-7300.service
    systemctl disable badvpn-7100
    systemctl stop badvpn-7100
    systemctl enable badvpn-7100
    systemctl start badvpn-7100
    systemctl restart badvpn-7100
    systemctl disable badvpn-7200
    systemctl stop badvpn-7200
    systemctl enable badvpn-7200
    systemctl start badvpn-7200
    systemctl restart badvpn-7200
    systemctl disable badvpn-7300
    systemctl stop badvpn-7300
    systemctl enable badvpn-7300
    systemctl start badvpn-7300
    systemctl restart badvpn-7300

    IPV4=$(curl https://myip.cpanel.net/)

    # // Installing Squid Proxy
    apt install squid -y
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Config/squid_conf" -o /etc/squid/squid.conf
    sed -i "s/hostnya/${IPV4}/g" /etc/squid/squid.conf
    mkdir -p /etc/script/squid
    systemctl restart squid

    # // Install OHP Proxy
    cd /root/
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Core/ohp.zip" -o ohp.zip
    unzip -o ohp.zip >/dev/null 2>&1
    cp ohp /etc/script/core/ohp
    rm -rf /root/ohp
    rm -rf /root/ohp.zip
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Service/ohp-1_service" -o /etc/systemd/system/ohp-1.service
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Service/ohp-2_service" -o /etc/systemd/system/ohp-2.service
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Service/ohp-3_service" -o /etc/systemd/system/ohp-3.service
    curl ${CURL_OPTION} "${SCRIPT_URL}/Resource/Service/ohp-4_service" -o /etc/systemd/system/ohp-4.service
    systemctl disable ohp-1
    systemctl stop ohp-1
    systemctl enable ohp-1
    systemctl start ohp-1
    systemctl restart ohp-1
    systemctl disable ohp-2
    systemctl stop ohp-2
    systemctl enable ohp-2
    systemctl start ohp-2
    systemctl restart ohp-2
    systemctl disable ohp-3
    systemctl stop ohp-3
    systemctl enable ohp-3
    systemctl start ohp-3
    systemctl restart ohp-3
    systemctl disable ohp-4
    systemctl stop ohp-4
    systemctl enable ohp-4
    systemctl start ohp-4
    systemctl restart ohp-4

    # // Download welcome
    echo "clear" >>.profile
    echo "neofetch" >>.profile
    echo "echo by Horasss" >>.profile

    # // Install python2
    apt install python2 -y >/dev/null 2>&1

    # // Download menu
    cd /usr/bin
    wget --inet4-only -O addssh "${SCRIPT_URL}/Resource/Menu/addssh.sh"
    chmod +x addssh
    wget --inet4-only -O delssh "${SCRIPT_URL}/Resource/Menu/delssh.sh"
    chmod +x delssh
    wget --inet4-only -O renewssh "${SCRIPT_URL}/Resource/Menu/renewssh.sh"
    chmod +x renewssh
    wget --inet4-only -O menu "${SCRIPT_URL}/Resource/Menu/menu.sh"
    chmod +x menu
    wget --inet4-only -O renewsshpanel "https://scripts.sshcf.my.id/panel/renewsshpanel.sh"
    chmod +x renewsshpanel
    wget --inet4-only -O addsshpanel "https://scripts.sshcf.my.id/panel/addsshpanel.sh"
    chmod +x addsshpanel
    wget --inet4-only -O delsshpanel "https://scripts.sshcf.my.id/panel/delsshpanel.sh"
    chmod +x delsshpanel

    cd

    mkdir /home/vps/public_html/ssh

    # // String ini u isi sendiri wa mana tau variable json u pake apa woakoawkoawkowakokwaaaw
    cat >/home/vps/public_html/ssh.json <<END
    {
        "GRPC" : "443",
        "WS TLS" : "443",
        "WS Non TLS" : "80"
    }
END
    # // Setting environment
    echo 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/etc/script/core:/usr/local/games:/snap/bin:/etc/xray/core:' >/etc/environment
    source /etc/environment

    clear
    rm -rf /root/setup.sh
    echo "Penginstallan Berhasil"
}

function main() {
    import_string
    check_root
    check_architecture
    install_requirement
}

main
