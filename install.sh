#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
#  ██╗   ██╗██████╗ ███╗   ██╗    ██████╗ ██████╗ ███████╗███╗   ███╗██╗██╗   ██╗███╗   ███╗
#  ██║   ██║██╔══██╗████╗  ██║    ██╔══██╗██╔══██╗██╔════╝████╗ ████║██║██║   ██║████╗ ████║
#  ██║   ██║██████╔╝██╔██╗ ██║    ██████╔╝██████╔╝█████╗  ██╔████╔██║██║██║   ██║██╔████╔██║
#  ╚██╗ ██╔╝██╔═══╝ ██║╚██╗██║    ██╔═══╝ ██╔══██╗██╔══╝  ██║╚██╔╝██║██║██║   ██║██║╚██╔╝██║
#   ╚████╔╝ ██║     ██║ ╚████║    ██║     ██║  ██║███████╗██║ ╚═╝ ██║██║╚██████╔╝██║ ╚═╝ ██║
#    ╚═══╝  ╚═╝     ╚═╝  ╚═══╝    ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝ ╚═════╝ ╚═╝     ╚═╝
# ═══════════════════════════════════════════════════════════════════════════════
#  VPN Premium All-in-One Auto Script
#  Supported: Ubuntu 20.04 / 22.04 LTS
#  Version: 2.0.0
# ═══════════════════════════════════════════════════════════════════════════════

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'
BOLD='\033[1m'

# Directories
INSTALL_DIR="/etc/vpn-premium"
XRAY_DIR="/usr/local/etc/xray"
LOG_DIR="/var/log/vpn-premium"
USER_DB="/etc/vpn-premium/users"

# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

print_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║                                                                       ║
    ║   ██╗   ██╗██████╗ ███╗   ██╗    ██████╗ ██████╗ ███████╗███╗   ███╗  ║
    ║   ██║   ██║██╔══██╗████╗  ██║    ██╔══██╗██╔══██╗██╔════╝████╗ ████║  ║
    ║   ██║   ██║██████╔╝██╔██╗ ██║    ██████╔╝██████╔╝█████╗  ██╔████╔██║  ║
    ║   ╚██╗ ██╔╝██╔═══╝ ██║╚██╗██║    ██╔═══╝ ██╔══██╗██╔══╝  ██║╚██╔╝██║  ║
    ║    ╚████╔╝ ██║     ██║ ╚████║    ██║     ██║  ██║███████╗██║ ╚═╝ ██║  ║
    ║     ╚═══╝  ╚═╝     ╚═╝  ╚═══╝    ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝  ║
    ║                                                                       ║
    ║               🚀 VPN PREMIUM ALL-IN-ONE INSTALLER 🚀                  ║
    ║                    Version 2.0.0 | Ubuntu 20/22                       ║
    ╚═══════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_progress() { echo -e "${BLUE}[====]${NC} $1"; }

generate_uuid() { cat /proc/sys/kernel/random/uuid; }
generate_password() { openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c 16; }
get_ip() { curl -s4 ifconfig.me 2>/dev/null || curl -s4 icanhazip.com 2>/dev/null; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Script ini harus dijalankan sebagai root!"
        exit 1
    fi
}

check_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        if [[ "$ID" != "ubuntu" ]] || [[ ! "$VERSION_ID" =~ ^(20.04|22.04)$ ]]; then
            log_error "OS tidak didukung! Gunakan Ubuntu 20.04 atau 22.04 LTS"
            exit 1
        fi
        log_success "OS Terdeteksi: Ubuntu $VERSION_ID"
    else
        log_error "Tidak dapat mendeteksi OS!"
        exit 1
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# USER INPUT
# ═══════════════════════════════════════════════════════════════════════════════

get_user_input() {
    print_banner
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${WHITE}           KONFIGURASI AWAL - INPUT DATA${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    while true; do
        read -p "$(echo -e ${CYAN}[?]${NC} Masukkan Domain ${YELLOW}[contoh: vpn.domain.com]${NC}: )" DOMAIN
        if [[ -n "$DOMAIN" ]] && [[ "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
            break
        else
            log_error "Format domain tidak valid!"
        fi
    done
    
    echo ""
    read -p "$(echo -e ${CYAN}[?]${NC} NS Domain untuk SlowDNS ${YELLOW}[contoh: ns.domain.com]${NC}: )" NS_DOMAIN
    NS_DOMAIN=${NS_DOMAIN:-"ns.$DOMAIN"}
    
    echo ""
    read -p "$(echo -e ${CYAN}[?]${NC} Token Bot Telegram ${YELLOW}[kosongkan jika tidak ada]${NC}: )" BOT_TOKEN
    
    if [[ -n "$BOT_TOKEN" ]]; then
        read -p "$(echo -e ${CYAN}[?]${NC} Chat ID Admin Telegram: )" CHAT_ID
    fi
    
    SERVER_IP=$(get_ip)
    
    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo -e " Domain        : ${GREEN}$DOMAIN${NC}"
    echo -e " NS Domain     : ${GREEN}$NS_DOMAIN${NC}"
    echo -e " Bot Token     : ${GREEN}${BOT_TOKEN:-'Tidak diset'}${NC}"
    echo -e " IP Server     : ${GREEN}$SERVER_IP${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    read -p "$(echo -e ${CYAN}[?]${NC} Lanjutkan instalasi? ${YELLOW}[y/n]${NC}: )" confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        exit 0
    fi
    
    mkdir -p $INSTALL_DIR $USER_DB/{ssh,vmess,vless,trojan,shadowsocks} $LOG_DIR
    cat > $INSTALL_DIR/config << EOF
DOMAIN=$DOMAIN
NS_DOMAIN=$NS_DOMAIN
BOT_TOKEN=$BOT_TOKEN
CHAT_ID=$CHAT_ID
SERVER_IP=$SERVER_IP
INSTALL_DATE=$(date +%Y-%m-%d)
EOF
}

# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM PREPARATION
# ═══════════════════════════════════════════════════════════════════════════════

update_system() {
    print_progress "Update & upgrade sistem..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y > /dev/null 2>&1
    apt-get upgrade -y > /dev/null 2>&1
    apt-get autoremove -y > /dev/null 2>&1
    log_success "Sistem berhasil diupdate"
}

set_timezone() {
    print_progress "Setting timezone ke Asia/Jakarta..."
    timedatectl set-timezone Asia/Jakarta
    log_success "Timezone diset ke Asia/Jakarta (WIB)"
}

install_dependencies() {
    print_progress "Menginstall dependensi..."
    apt-get install -y curl wget socat python3 python3-pip git zip unzip jq \
        net-tools gnupg lsb-release ca-certificates apt-transport-https \
        software-properties-common build-essential cmake libssl-dev uuid-runtime \
        cron iptables screen vnstat htop neofetch dropbear stunnel4 > /dev/null 2>&1
    log_success "Dependensi terinstall"
}

remove_conflicts() {
    print_progress "Menghapus paket yang konflik..."
    for pkg in apache2 ufw firewalld; do
        systemctl stop $pkg 2>/dev/null
        systemctl disable $pkg 2>/dev/null
        apt-get remove -y $pkg > /dev/null 2>&1
    done
    log_success "Paket konflik dihapus"
}

enable_bbr() {
    print_progress "Mengaktifkan BBR Congestion Control..."
    if ! sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
        cat >> /etc/sysctl.conf << EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.ip_forward=1
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
EOF
        sysctl -p > /dev/null 2>&1
    fi
    log_success "BBR diaktifkan"
}

# ═══════════════════════════════════════════════════════════════════════════════
# XRAY INSTALLATION
# ═══════════════════════════════════════════════════════════════════════════════

install_xray() {
    print_progress "Menginstall Xray-core terbaru..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install > /dev/null 2>&1
    
    UUID_VMESS=$(generate_uuid)
    UUID_VLESS=$(generate_uuid)
    UUID_TROJAN=$(generate_uuid)
    SS_PASSWORD=$(generate_password)
    
    # Generate Reality keys
    local keys=$(xray x25519 2>/dev/null)
    REALITY_PRIVATE=$(echo "$keys" | grep "Private key:" | cut -d ' ' -f 3)
    REALITY_PUBLIC=$(echo "$keys" | grep "Public key:" | cut -d ' ' -f 3)
    
    cat > $INSTALL_DIR/credentials << EOF
UUID_VMESS=$UUID_VMESS
UUID_VLESS=$UUID_VLESS
UUID_TROJAN=$UUID_TROJAN
SS_PASSWORD=$SS_PASSWORD
REALITY_PRIVATE_KEY=$REALITY_PRIVATE
REALITY_PUBLIC_KEY=$REALITY_PUBLIC
EOF
    
    log_success "Xray-core terinstall"
}

configure_xray() {
    print_progress "Mengkonfigurasi Xray-core..."
    source $INSTALL_DIR/credentials
    
    mkdir -p /var/log/xray
    cat > $XRAY_DIR/config.json << EOF
{
  "log": {"loglevel": "warning", "access": "/var/log/xray/access.log", "error": "/var/log/xray/error.log"},
  "inbounds": [
    {"tag": "vmess-ws-tls", "port": 10001, "listen": "127.0.0.1", "protocol": "vmess",
      "settings": {"clients": [{"id": "$UUID_VMESS", "alterId": 0, "email": "admin@vmess"}]},
      "streamSettings": {"network": "ws", "wsSettings": {"path": "/vmess-ws"}}},
    {"tag": "vmess-ws-ntls", "port": 10010, "listen": "127.0.0.1", "protocol": "vmess",
      "settings": {"clients": [{"id": "$UUID_VMESS", "alterId": 0, "email": "admin@vmess-ntls"}]},
      "streamSettings": {"network": "ws", "wsSettings": {"path": "/vmess-ws"}}},
    {"tag": "vless-ws-tls", "port": 10002, "listen": "127.0.0.1", "protocol": "vless",
      "settings": {"clients": [{"id": "$UUID_VLESS", "email": "admin@vless"}], "decryption": "none"},
      "streamSettings": {"network": "ws", "wsSettings": {"path": "/vless-ws"}}},
    {"tag": "vless-xtls-reality", "port": 8443, "protocol": "vless",
      "settings": {"clients": [{"id": "$UUID_VLESS", "flow": "xtls-rprx-vision", "email": "admin@vless-reality"}], "decryption": "none"},
      "streamSettings": {"network": "tcp", "security": "reality",
        "realitySettings": {"show": false, "dest": "www.google.com:443", "xver": 0,
          "serverNames": ["www.google.com", "google.com"],
          "privateKey": "$REALITY_PRIVATE", "shortIds": ["", "0123456789abcdef"]}}},
    {"tag": "trojan-ws-tls", "port": 10003, "listen": "127.0.0.1", "protocol": "trojan",
      "settings": {"clients": [{"password": "$UUID_TROJAN", "email": "admin@trojan"}]},
      "streamSettings": {"network": "ws", "wsSettings": {"path": "/trojan-ws"}}},
    {"tag": "shadowsocks", "port": 2087, "protocol": "shadowsocks",
      "settings": {"method": "aes-256-gcm", "password": "$SS_PASSWORD", "network": "tcp,udp"}}
  ],
  "outbounds": [{"tag": "direct", "protocol": "freedom"}, {"tag": "blocked", "protocol": "blackhole"}],
  "routing": {"rules": [{"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"}]}
}
EOF
    
    systemctl enable xray > /dev/null 2>&1
    systemctl restart xray
    log_success "Xray-core dikonfigurasi"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SSH & DROPBEAR
# ═══════════════════════════════════════════════════════════════════════════════

configure_ssh() {
    print_progress "Mengkonfigurasi SSH..."
    
    cat > /etc/ssh/sshd_config << EOF
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
ClientAliveInterval 60
ClientAliveCountMax 3
Banner /etc/issue.net
EOF

    cat > /etc/issue.net << 'EOF'
═══════════════════════════════════════════════════════════════
       🚀 VPN PREMIUM SERVER - Unauthorized Access Prohibited 🚀
═══════════════════════════════════════════════════════════════
EOF

    systemctl restart sshd
    log_success "OpenSSH dikonfigurasi"
}

configure_dropbear() {
    print_progress "Mengkonfigurasi Dropbear..."
    cat > /etc/default/dropbear << EOF
NO_START=0
DROPBEAR_PORT=109
DROPBEAR_EXTRA_ARGS="-p 143"
DROPBEAR_BANNER="/etc/issue.net"
EOF
    systemctl enable dropbear > /dev/null 2>&1
    systemctl restart dropbear
    log_success "Dropbear dikonfigurasi (Port 109, 143)"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SSH WEBSOCKET
# ═══════════════════════════════════════════════════════════════════════════════

install_sshws() {
    print_progress "Menginstall SSH WebSocket..."
    pip3 install websockets > /dev/null 2>&1
    
    mkdir -p $INSTALL_DIR/scripts
    cat > $INSTALL_DIR/scripts/sshws.py << 'SSHWS'
#!/usr/bin/env python3
import asyncio, sys, logging
from http.server import BaseHTTPRequestHandler
from io import BytesIO

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = BytesIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()
    def send_error(self, code, message=None):
        self.error_code = code

async def handle_client(reader, writer):
    try:
        data = await asyncio.wait_for(reader.read(4096), timeout=30)
        if not data: return
        
        target_port = 22
        try:
            req = HTTPRequest(data)
            if hasattr(req, 'path'):
                if ':109' in req.path: target_port = 109
                elif ':143' in req.path: target_port = 143
        except: pass
        
        try:
            ssh_r, ssh_w = await asyncio.open_connection('127.0.0.1', target_port)
        except:
            writer.close()
            return
        
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        
        async def forward(src, dst):
            try:
                while True:
                    d = await src.read(8192)
                    if not d: break
                    dst.write(d)
                    await dst.drain()
            except: pass
        
        await asyncio.gather(forward(reader, ssh_w), forward(ssh_r, writer))
    except: pass
    finally:
        try: writer.close()
        except: pass

async def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 2082
    server = await asyncio.start_server(handle_client, '0.0.0.0', port)
    logging.info(f"SSH-WS Server running on port {port}")
    async with server: await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
SSHWS
    chmod +x $INSTALL_DIR/scripts/sshws.py
    
    cat > /etc/systemd/system/sshws.service << EOF
[Unit]
Description=SSH WebSocket
After=network.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 $INSTALL_DIR/scripts/sshws.py 2082
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable sshws > /dev/null 2>&1
    systemctl start sshws
    log_success "SSH WebSocket diinstall (Port 2082)"
}

# ═══════════════════════════════════════════════════════════════════════════════
# BADVPN UDPGW
# ═══════════════════════════════════════════════════════════════════════════════

install_badvpn() {
    print_progress "Menginstall BadVPN UDPGW..."
    cd /tmp
    wget -q https://github.com/ambrop72/badvpn/archive/refs/heads/master.zip -O badvpn.zip
    unzip -q badvpn.zip && cd badvpn-master
    mkdir build && cd build
    cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 > /dev/null 2>&1
    make > /dev/null 2>&1
    cp udpgw/badvpn-udpgw /usr/local/bin/
    cd /tmp && rm -rf badvpn*
    
    for port in 7100 7200 7300; do
        cat > /etc/systemd/system/badvpn-$port.service << EOF
[Unit]
Description=BadVPN UDPGW $port
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:$port --max-clients 1000
Restart=always
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable badvpn-$port > /dev/null 2>&1
        systemctl start badvpn-$port
    done
    log_success "BadVPN UDPGW diinstall (Port 7100-7300)"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SLOWDNS
# ═══════════════════════════════════════════════════════════════════════════════

install_slowdns() {
    print_progress "Menginstall SlowDNS..."
    source $INSTALL_DIR/config
    
    # Install Go
    if ! command -v go &> /dev/null; then
        wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz -O /tmp/go.tar.gz
        tar -C /usr/local -xzf /tmp/go.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    fi
    
    cd /tmp
    git clone https://www.bamsoftware.com/git/dnstt.git > /dev/null 2>&1
    cd dnstt/dnstt-server
    /usr/local/go/bin/go build > /dev/null 2>&1
    cp dnstt-server /usr/local/bin/
    
    /usr/local/bin/dnstt-server -gen-key -privkey-file $INSTALL_DIR/slowdns.key -pubkey-file $INSTALL_DIR/slowdns.pub 2>/dev/null
    SLOWDNS_PUB=$(cat $INSTALL_DIR/slowdns.pub)
    echo "SLOWDNS_PUBKEY=$SLOWDNS_PUB" >> $INSTALL_DIR/credentials
    
    rm -rf /tmp/dnstt /tmp/go.tar.gz
    
    cat > /etc/systemd/system/slowdns.service << EOF
[Unit]
Description=SlowDNS Server
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/dnstt-server -udp :5300 -privkey-file $INSTALL_DIR/slowdns.key $NS_DOMAIN 127.0.0.1:22
Restart=always
[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable slowdns > /dev/null 2>&1
    systemctl start slowdns
    log_success "SlowDNS diinstall (Port 5300)"
}

# ═══════════════════════════════════════════════════════════════════════════════
# NGINX & SSL
# ═══════════════════════════════════════════════════════════════════════════════

install_nginx() {
    print_progress "Menginstall Nginx..."
    apt-get install -y nginx > /dev/null 2>&1
    rm -f /etc/nginx/sites-enabled/default
    log_success "Nginx terinstall"
}

configure_nginx() {
    print_progress "Mengkonfigurasi Nginx..."
    source $INSTALL_DIR/config
    
    cat > /etc/nginx/sites-available/vpn << EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    root /var/www/html;
    
    location /.well-known/acme-challenge/ { root /var/www/html; }
    location /vmess-ws {
        if (\$http_upgrade != "websocket") { return 404; }
        proxy_pass http://127.0.0.1:10010;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 86400s;
    }
    location /ssh-ws {
        proxy_pass http://127.0.0.1:2082;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400s;
    }
    location / { try_files \$uri \$uri/ =404; }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;
    root /var/www/html;
    
    ssl_certificate /etc/ssl/xray/fullchain.crt;
    ssl_certificate_key /etc/ssl/xray/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    
    location /vmess-ws {
        if (\$http_upgrade != "websocket") { return 404; }
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 86400s;
    }
    location /vless-ws {
        if (\$http_upgrade != "websocket") { return 404; }
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 86400s;
    }
    location /trojan-ws {
        if (\$http_upgrade != "websocket") { return 404; }
        proxy_pass http://127.0.0.1:10003;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 86400s;
    }
    location /ssh-ws {
        proxy_pass http://127.0.0.1:2082;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400s;
    }
    location / { try_files \$uri \$uri/ =404; }
}
EOF
    
    ln -sf /etc/nginx/sites-available/vpn /etc/nginx/sites-enabled/
    
    mkdir -p /var/www/html
    cat > /var/www/html/index.html << 'HTML'
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPN Premium</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui;background:linear-gradient(135deg,#1a1a2e,#16213e,#0f3460);min-height:100vh;display:flex;justify-content:center;align-items:center;color:#fff}
.container{text-align:center;padding:40px;background:rgba(255,255,255,.1);border-radius:20px;backdrop-filter:blur(10px)}
h1{font-size:2.5rem;margin-bottom:20px;background:linear-gradient(45deg,#00d9ff,#00ff88);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.status{padding:10px 30px;background:linear-gradient(45deg,#00ff88,#00d9ff);color:#1a1a2e;border-radius:30px;font-weight:bold}
</style></head>
<body><div class="container"><h1>🚀 VPN Premium Server</h1><p style="margin-bottom:20px;opacity:.8">High-Performance VPN Infrastructure</p><div class="status">✓ Server Online</div></div></body></html>
HTML
    
    log_success "Nginx dikonfigurasi"
}

install_ssl() {
    print_progress "Menginstall SSL Certificate..."
    source $INSTALL_DIR/config
    
    curl -sL https://get.acme.sh | sh -s email=admin@$DOMAIN > /dev/null 2>&1
    mkdir -p /etc/ssl/xray
    
    systemctl stop nginx 2>/dev/null
    ~/.acme.sh/acme.sh --issue -d $DOMAIN --standalone --keylength ec-256 --force > /dev/null 2>&1
    
    if [[ $? -eq 0 ]]; then
        ~/.acme.sh/acme.sh --install-cert -d $DOMAIN --ecc \
            --fullchain-file /etc/ssl/xray/fullchain.crt \
            --key-file /etc/ssl/xray/private.key > /dev/null 2>&1
        log_success "SSL Certificate dari Let's Encrypt"
    else
        log_warn "Gagal dari Let's Encrypt, membuat self-signed..."
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/ssl/xray/private.key \
            -out /etc/ssl/xray/fullchain.crt \
            -subj "/C=ID/ST=Jakarta/L=Jakarta/O=VPN/CN=$DOMAIN" > /dev/null 2>&1
    fi
    
    chmod 644 /etc/ssl/xray/fullchain.crt
    chmod 600 /etc/ssl/xray/private.key
    systemctl start nginx
}

# ═══════════════════════════════════════════════════════════════════════════════
# MENU & USER MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

install_menu() {
    print_progress "Menginstall Menu System..."
    
    cat > /usr/local/bin/menu << 'MENUEOF'
#!/bin/bash
RED='\033[0;31m';GREEN='\033[0;32m';YELLOW='\033[1;33m';CYAN='\033[0;36m';WHITE='\033[1;37m';NC='\033[0m'
source /etc/vpn-premium/config 2>/dev/null
source /etc/vpn-premium/credentials 2>/dev/null

show_menu() {
    clear
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}${WHITE}              🚀 VPN PREMIUM SERVER PANEL 🚀                     ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}╠═══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC} Domain: ${GREEN}$DOMAIN${NC}"
    echo -e "${CYAN}║${NC} IP: ${GREEN}$SERVER_IP${NC}"
    echo -e "${CYAN}╠═══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}[1]${NC} SSH Menu          ${GREEN}[5]${NC} Service Status                     ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}[2]${NC} VMess Menu        ${GREEN}[6]${NC} Speedtest                          ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}[3]${NC} VLESS Menu        ${GREEN}[7]${NC} System Info                        ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}  ${GREEN}[4]${NC} Trojan Menu       ${GREEN}[8]${NC} Reboot Server                      ${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}                      ${RED}[0]${NC} Exit                               ${CYAN}║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════╝${NC}"
    read -p "Select [0-8]: " opt
    case $opt in
        1) ssh_menu ;;
        2) vmess_menu ;;
        3) vless_menu ;;
        4) trojan_menu ;;
        5) echo "Services:"; for s in xray nginx sshd dropbear sshws slowdns; do echo "  $s: $(systemctl is-active $s)"; done; read -p "Enter..."; show_menu ;;
        6) speedtest-cli 2>/dev/null || pip3 install speedtest-cli && speedtest-cli; read -p "Enter..."; show_menu ;;
        7) neofetch 2>/dev/null || (echo "OS: $(cat /etc/os-release | grep PRETTY | cut -d'"' -f2)"; free -h); read -p "Enter..."; show_menu ;;
        8) read -p "Reboot? [y/n]: " c; [[ "$c" =~ ^[Yy]$ ]] && reboot ;;
        0) exit 0 ;;
        *) show_menu ;;
    esac
}

ssh_menu() {
    clear
    echo -e "${CYAN}═══ SSH MENU ═══${NC}"
    echo -e "${GREEN}[1]${NC} Create  ${GREEN}[2]${NC} Delete  ${GREEN}[3]${NC} List  ${RED}[0]${NC} Back"
    read -p "Select: " opt
    case $opt in
        1) read -p "Username: " u; read -p "Password: " p; read -p "Days [30]: " d; add-ssh "$u" "$p" "${d:-30}"; read -p "Enter..."; ssh_menu ;;
        2) read -p "Username: " u; del-ssh "$u"; read -p "Enter..."; ssh_menu ;;
        3) ls /etc/vpn-premium/users/ssh/ 2>/dev/null; read -p "Enter..."; ssh_menu ;;
        0) show_menu ;;
    esac
}

vmess_menu() {
    clear
    echo -e "${CYAN}═══ VMESS MENU ═══${NC}"
    echo -e "${GREEN}[1]${NC} Create  ${GREEN}[2]${NC} Delete  ${GREEN}[3]${NC} List  ${RED}[0]${NC} Back"
    read -p "Select: " opt
    case $opt in
        1) read -p "Username: " u; read -p "Days [30]: " d; add-vmess "$u" "${d:-30}"; read -p "Enter..."; vmess_menu ;;
        2) read -p "Username: " u; del-vmess "$u"; read -p "Enter..."; vmess_menu ;;
        3) ls /etc/vpn-premium/users/vmess/ 2>/dev/null; read -p "Enter..."; vmess_menu ;;
        0) show_menu ;;
    esac
}

vless_menu() {
    clear
    echo -e "${CYAN}═══ VLESS MENU ═══${NC}"
    echo -e "${GREEN}[1]${NC} Create  ${GREEN}[2]${NC} Delete  ${GREEN}[3]${NC} List  ${RED}[0]${NC} Back"
    read -p "Select: " opt
    case $opt in
        1) read -p "Username: " u; read -p "Days [30]: " d; add-vless "$u" "${d:-30}"; read -p "Enter..."; vless_menu ;;
        2) read -p "Username: " u; del-vless "$u"; read -p "Enter..."; vless_menu ;;
        3) ls /etc/vpn-premium/users/vless/ 2>/dev/null; read -p "Enter..."; vless_menu ;;
        0) show_menu ;;
    esac
}

trojan_menu() {
    clear
    echo -e "${CYAN}═══ TROJAN MENU ═══${NC}"
    echo -e "${GREEN}[1]${NC} Create  ${GREEN}[2]${NC} Delete  ${GREEN}[3]${NC} List  ${RED}[0]${NC} Back"
    read -p "Select: " opt
    case $opt in
        1) read -p "Username: " u; read -p "Days [30]: " d; add-trojan "$u" "${d:-30}"; read -p "Enter..."; trojan_menu ;;
        2) read -p "Username: " u; del-trojan "$u"; read -p "Enter..."; trojan_menu ;;
        3) ls /etc/vpn-premium/users/trojan/ 2>/dev/null; read -p "Enter..."; trojan_menu ;;
        0) show_menu ;;
    esac
}

show_menu
MENUEOF
    chmod +x /usr/local/bin/menu
    ln -sf /usr/local/bin/menu /usr/bin/vpn
    log_success "Menu system terinstall"
}

install_user_scripts() {
    print_progress "Menginstall user management scripts..."
    
    # add-ssh
    cat > /usr/local/bin/add-ssh << 'EOF'
#!/bin/bash
source /etc/vpn-premium/config 2>/dev/null
[[ -z "$1" || -z "$2" ]] && { echo "Usage: add-ssh <user> <pass> [days]"; exit 1; }
id "$1" &>/dev/null && { echo "User exists!"; exit 1; }
EXP=$(date -d "+${3:-30} days" +%Y-%m-%d)
useradd -e "$EXP" -s /bin/false -M "$1" && echo "$1:$2" | chpasswd
mkdir -p /etc/vpn-premium/users/ssh
echo -e "user=$1\npass=$2\nexp=$EXP" > /etc/vpn-premium/users/ssh/$1
echo -e "✅ SSH Created!\nUser: $1\nPass: $2\nHost: $DOMAIN\nPorts: 22, 109, 143\nWS: 80, 443 (/ssh-ws)\nExp: $EXP"
EOF
    
    # del-ssh
    cat > /usr/local/bin/del-ssh << 'EOF'
#!/bin/bash
[[ -z "$1" ]] && { echo "Usage: del-ssh <user>"; exit 1; }
userdel -f "$1" 2>/dev/null; rm -f /etc/vpn-premium/users/ssh/$1
echo "✅ Deleted: $1"
EOF

    # add-vmess
    cat > /usr/local/bin/add-vmess << 'EOF'
#!/bin/bash
source /etc/vpn-premium/config 2>/dev/null
[[ -z "$1" ]] && { echo "Usage: add-vmess <user> [days]"; exit 1; }
UUID=$(cat /proc/sys/kernel/random/uuid); EXP=$(date -d "+${2:-30} days" +%Y-%m-%d)
CFG="/usr/local/etc/xray/config.json"; TMP=$(mktemp)
jq --arg u "$UUID" --arg e "$1@vmess" '(.inbounds[]|select(.tag|startswith("vmess"))|.settings.clients)+=[{"id":$u,"alterId":0,"email":$e}]' "$CFG" > "$TMP" && mv "$TMP" "$CFG"
systemctl restart xray
mkdir -p /etc/vpn-premium/users/vmess
echo -e "user=$1\nuuid=$UUID\nexp=$EXP" > /etc/vpn-premium/users/vmess/$1
LINK="vmess://$(echo -n '{"v":"2","ps":"'$1'","add":"'$DOMAIN'","port":"443","id":"'$UUID'","aid":"0","net":"ws","path":"/vmess-ws","tls":"tls","sni":"'$DOMAIN'"}' | base64 -w 0)"
echo -e "✅ VMess Created!\nUser: $1\nUUID: $UUID\nDomain: $DOMAIN\nPort: 443 (TLS) / 80 (NTLS)\nPath: /vmess-ws\nExp: $EXP\n\nLink:\n$LINK"
EOF

    # del-vmess
    cat > /usr/local/bin/del-vmess << 'EOF'
#!/bin/bash
[[ -z "$1" ]] && { echo "Usage: del-vmess <user>"; exit 1; }
CFG="/usr/local/etc/xray/config.json"; TMP=$(mktemp)
jq --arg e "$1@vmess" '(.inbounds[]|select(.tag|startswith("vmess"))|.settings.clients)|=map(select(.email!=$e))' "$CFG" > "$TMP" && mv "$TMP" "$CFG"
rm -f /etc/vpn-premium/users/vmess/$1; systemctl restart xray
echo "✅ Deleted: $1"
EOF

    # add-vless
    cat > /usr/local/bin/add-vless << 'EOF'
#!/bin/bash
source /etc/vpn-premium/config 2>/dev/null; source /etc/vpn-premium/credentials 2>/dev/null
[[ -z "$1" ]] && { echo "Usage: add-vless <user> [days]"; exit 1; }
UUID=$(cat /proc/sys/kernel/random/uuid); EXP=$(date -d "+${2:-30} days" +%Y-%m-%d)
CFG="/usr/local/etc/xray/config.json"; TMP=$(mktemp)
jq --arg u "$UUID" --arg e "$1@vless" '(.inbounds[]|select(.tag=="vless-ws-tls")|.settings.clients)+=[{"id":$u,"email":$e}]' "$CFG" > "$TMP" && mv "$TMP" "$CFG"
jq --arg u "$UUID" --arg e "$1@vless-r" '(.inbounds[]|select(.tag=="vless-xtls-reality")|.settings.clients)+=[{"id":$u,"flow":"xtls-rprx-vision","email":$e}]' "$CFG" > "$TMP" && mv "$TMP" "$CFG"
systemctl restart xray
mkdir -p /etc/vpn-premium/users/vless
echo -e "user=$1\nuuid=$UUID\nexp=$EXP" > /etc/vpn-premium/users/vless/$1
LINK1="vless://${UUID}@${DOMAIN}:443?encryption=none&security=tls&sni=${DOMAIN}&type=ws&path=%2Fvless-ws#${1}"
LINK2="vless://${UUID}@${SERVER_IP}:8443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.google.com&fp=chrome&pbk=${REALITY_PUBLIC_KEY}&sid=0123456789abcdef&type=tcp#${1}-Reality"
echo -e "✅ VLESS Created!\nUser: $1\nUUID: $UUID\nExp: $EXP\n\nWS-TLS:\n$LINK1\n\nReality:\n$LINK2"
EOF

    # del-vless
    cat > /usr/local/bin/del-vless << 'EOF'
#!/bin/bash
[[ -z "$1" ]] && { echo "Usage: del-vless <user>"; exit 1; }
CFG="/usr/local/etc/xray/config.json"; TMP=$(mktemp)
jq --arg e "$1@vless" --arg e2 "$1@vless-r" '(.inbounds[]|select(.tag|startswith("vless"))|.settings.clients)|=map(select(.email!=$e and .email!=$e2))' "$CFG" > "$TMP" && mv "$TMP" "$CFG"
rm -f /etc/vpn-premium/users/vless/$1; systemctl restart xray
echo "✅ Deleted: $1"
EOF

    # add-trojan
    cat > /usr/local/bin/add-trojan << 'EOF'
#!/bin/bash
source /etc/vpn-premium/config 2>/dev/null
[[ -z "$1" ]] && { echo "Usage: add-trojan <user> [days]"; exit 1; }
PASS=$(cat /proc/sys/kernel/random/uuid); EXP=$(date -d "+${2:-30} days" +%Y-%m-%d)
CFG="/usr/local/etc/xray/config.json"; TMP=$(mktemp)
jq --arg p "$PASS" --arg e "$1@trojan" '(.inbounds[]|select(.tag=="trojan-ws-tls")|.settings.clients)+=[{"password":$p,"email":$e}]' "$CFG" > "$TMP" && mv "$TMP" "$CFG"
systemctl restart xray
mkdir -p /etc/vpn-premium/users/trojan
echo -e "user=$1\npass=$PASS\nexp=$EXP" > /etc/vpn-premium/users/trojan/$1
LINK="trojan://${PASS}@${DOMAIN}:443?security=tls&sni=${DOMAIN}&type=ws&path=%2Ftrojan-ws#${1}"
echo -e "✅ Trojan Created!\nUser: $1\nPassword: $PASS\nDomain: $DOMAIN\nPort: 443\nPath: /trojan-ws\nExp: $EXP\n\nLink:\n$LINK"
EOF

    # del-trojan
    cat > /usr/local/bin/del-trojan << 'EOF'
#!/bin/bash
[[ -z "$1" ]] && { echo "Usage: del-trojan <user>"; exit 1; }
CFG="/usr/local/etc/xray/config.json"; TMP=$(mktemp)
jq --arg e "$1@trojan" '(.inbounds[]|select(.tag=="trojan-ws-tls")|.settings.clients)|=map(select(.email!=$e))' "$CFG" > "$TMP" && mv "$TMP" "$CFG"
rm -f /etc/vpn-premium/users/trojan/$1; systemctl restart xray
echo "✅ Deleted: $1"
EOF

    # cek-login
    cat > /usr/local/bin/cek-login << 'EOF'
#!/bin/bash
echo "=== Online Users ===" 
echo "SSH:"; who 2>/dev/null
echo ""; echo "Connections:"
netstat -tnpa 2>/dev/null | grep -E "sshd|xray" | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort -u
EOF

    chmod +x /usr/local/bin/{add-ssh,del-ssh,add-vmess,del-vmess,add-vless,del-vless,add-trojan,del-trojan,cek-login}
    log_success "User scripts terinstall"
}

# ═══════════════════════════════════════════════════════════════════════════════
# TELEGRAM BOT
# ═══════════════════════════════════════════════════════════════════════════════

install_bot() {
    print_progress "Menginstall Telegram Bot..."
    source $INSTALL_DIR/config
    
    pip3 install python-telegram-bot>=20.0 > /dev/null 2>&1
    
    cat > $INSTALL_DIR/bot.py << 'BOTPY'
#!/usr/bin/env python3
import os,sys,subprocess,uuid
from datetime import datetime,timedelta
try:
    from telegram import Update
    from telegram.ext import Application,CommandHandler,ContextTypes
except:
    subprocess.check_call([sys.executable,"-m","pip","install","python-telegram-bot>=20.0"])
    from telegram import Update
    from telegram.ext import Application,CommandHandler,ContextTypes

CFG={}
with open("/etc/vpn-premium/config") as f:
    for l in f:
        if '=' in l: k,v=l.strip().split('=',1);CFG[k]=v

TOKEN=CFG.get('BOT_TOKEN','')
ADMIN=CFG.get('CHAT_ID','')
DOMAIN=CFG.get('DOMAIN','')

def run(c): return subprocess.run(c,shell=True,capture_output=True,text=True).stdout.strip()

async def start(u:Update,c):
    await u.message.reply_text(f"🚀 VPN Bot\nDomain: {DOMAIN}\n\n/create <type> <user> [days]\n/list\n/status")

async def create(u:Update,c):
    if str(u.effective_user.id)!=ADMIN: return await u.message.reply_text("⛔ Access Denied")
    if len(c.args)<2: return await u.message.reply_text("Usage: /create ssh/vmess/vless/trojan <user> [days]")
    t,user=c.args[0],c.args[1];days=c.args[2] if len(c.args)>2 else "30"
    if t=="ssh": r=run(f"add-ssh {user} {str(uuid.uuid4())[:8]} {days}")
    elif t=="vmess": r=run(f"add-vmess {user} {days}")
    elif t=="vless": r=run(f"add-vless {user} {days}")
    elif t=="trojan": r=run(f"add-trojan {user} {days}")
    else: return await u.message.reply_text("Invalid type!")
    await u.message.reply_text(f"```\n{r}\n```",parse_mode='Markdown')

async def lst(u:Update,c):
    if str(u.effective_user.id)!=ADMIN: return
    r="📋 Users:\n"
    for p in ['ssh','vmess','vless','trojan']:
        try: users=os.listdir(f"/etc/vpn-premium/users/{p}");r+=f"\n{p.upper()}: {len(users)}\n"
        except: pass
    await u.message.reply_text(r)

async def status(u:Update,c):
    if str(u.effective_user.id)!=ADMIN: return
    r=f"📊 Status\nXray: {run('systemctl is-active xray')}\nNginx: {run('systemctl is-active nginx')}\nUptime: {run('uptime -p')}"
    await u.message.reply_text(r)

def main():
    if not TOKEN: print("No BOT_TOKEN!");sys.exit(1)
    app=Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler('start',start))
    app.add_handler(CommandHandler('create',create))
    app.add_handler(CommandHandler('list',lst))
    app.add_handler(CommandHandler('status',status))
    print("Bot starting...");app.run_polling()

if __name__=='__main__': main()
BOTPY

    cat > /etc/systemd/system/bot-telegram.service << EOF
[Unit]
Description=VPN Telegram Bot
After=network.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 $INSTALL_DIR/bot.py
Restart=always
[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    if [[ -n "$BOT_TOKEN" ]]; then
        systemctl enable bot-telegram > /dev/null 2>&1
        systemctl start bot-telegram
        log_success "Telegram Bot aktif"
    else
        log_warn "Telegram Bot tidak aktif (token kosong)"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════════
# FINALIZE
# ═══════════════════════════════════════════════════════════════════════════════

finalize() {
    print_progress "Finalisasi instalasi..."
    
    # Cron cleanup
    cat > $INSTALL_DIR/cleanup.sh << 'EOF'
#!/bin/bash
for d in ssh vmess vless trojan; do
    for f in /etc/vpn-premium/users/$d/*; do
        [[ -f "$f" ]] || continue
        exp=$(grep "exp=" "$f" | cut -d= -f2)
        [[ $(date -d "$exp" +%s 2>/dev/null) -lt $(date +%s) ]] && /usr/local/bin/del-$d "$(basename $f)" 2>/dev/null
    done
done
EOF
    chmod +x $INSTALL_DIR/cleanup.sh
    (crontab -l 2>/dev/null; echo "0 0 * * * $INSTALL_DIR/cleanup.sh") | crontab -
    
    systemctl enable nginx xray sshd dropbear sshws > /dev/null 2>&1
    systemctl restart nginx xray
    
    chmod -R 700 $INSTALL_DIR
    log_success "Instalasi selesai!"
}

show_result() {
    source $INSTALL_DIR/config
    source $INSTALL_DIR/credentials
    clear
    echo -e "${GREEN}"
    cat << "EOF"
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║             ✅ INSTALASI VPN PREMIUM BERHASIL! ✅                     ║
    ╚═══════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo -e " Domain        : ${CYAN}$DOMAIN${NC}"
    echo -e " IP            : ${CYAN}$SERVER_IP${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo -e " ${WHITE}PORTS:${NC}"
    echo -e "   SSH         : ${CYAN}22, 109, 143${NC}"
    echo -e "   SSH-WS      : ${CYAN}80, 443${NC} (path: /ssh-ws)"
    echo -e "   VMess       : ${CYAN}80, 443${NC} (path: /vmess-ws)"
    echo -e "   VLESS       : ${CYAN}443${NC} (path: /vless-ws)"
    echo -e "   VLESS Real  : ${CYAN}8443${NC}"
    echo -e "   Trojan      : ${CYAN}443${NC} (path: /trojan-ws)"
    echo -e "   SS          : ${CYAN}2087${NC}"
    echo -e "   UDPGW       : ${CYAN}7100-7300${NC}"
    echo -e "   SlowDNS     : ${CYAN}5300${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo -e " ${WHITE}DEFAULT UUID:${NC}"
    echo -e "   VMess       : ${CYAN}$UUID_VMESS${NC}"
    echo -e "   VLESS       : ${CYAN}$UUID_VLESS${NC}"
    echo -e "   Reality Key : ${CYAN}$REALITY_PUBLIC_KEY${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo -e " ${WHITE}COMMANDS:${NC}"
    echo -e "   ${GREEN}menu${NC}         - Panel management"
    echo -e "   ${GREEN}add-ssh${NC}      - Buat SSH"
    echo -e "   ${GREEN}add-vmess${NC}    - Buat VMess"
    echo -e "   ${GREEN}add-vless${NC}    - Buat VLESS"
    echo -e "   ${GREEN}add-trojan${NC}   - Buat Trojan"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}        Ketik '${WHITE}menu${GREEN}' untuk membuka panel management${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

main() {
    check_root
    check_os
    get_user_input
    
    print_banner
    echo ""
    log_info "Memulai instalasi..."
    echo ""
    
    update_system
    set_timezone
    install_dependencies
    remove_conflicts
    enable_bbr
    
    install_xray
    configure_xray
    configure_ssh
    configure_dropbear
    install_sshws
    install_badvpn
    install_slowdns
    
    install_nginx
    configure_nginx
    install_ssl
    
    install_menu
    install_user_scripts
    install_bot
    
    finalize
    show_result
}

main "$@"
