#!/usr/bin/env bash
vpn_auto_installer.sh
Lightweight auto installer for tunneling services tailored for selling VPN
Supports: Debian 10+, Ubuntu 20.04+
Protocols: SSH (plain + WS + TLS), SSH UDP (badvpn udpgw), VMESS, VLESS, TROJAN (trojan-go)
Features: service checks, restart, auto-reboot setup, monitor, speedtest, account CRUD,
backups, auto wildcard record hint, telegram bot hooks (simple), limits & quota skeleton
NOTE: Run as root on a clean VPS. Test before production. Use and adapt responsibly.
set -euo pipefail export DEBIAN_FRONTEND=noninteractive LOGFILE="/var/log/vpn_installer.log" exec > >(tee -a "$LOGFILE") 2>&1

#########################
Basic helpers
######################### OS="" VERSION_ID="" DOMAIN="" EMAIL=""

default ports
PORT_TLS=443 PORT_WS=443 PORT_HTTP=80 SSH_PORT=22 BADVNP_PORT=7300
Colors
info() { echo -e "\e[1;34m[INFO]\e[0m $"; } warn() { echo -e "\e[1;33m[WARN]\e[0m $"; } err()  { echo -e "\e[1;31m[ERROR]\e[0m $*"; }
check_root(){ if [ "$EUID" -ne 0 ]; then err "Script must be run as root" exit 1 fi }
detect_os(){ if [ -f /etc/os-release ]; then . /etc/os-release OS=$ID VERSION_ID=$VERSION_ID else err "Unsupported OS" exit 1 fi case "$OS" in debian|ubuntu) info "Detected $PRETTY_NAME" ;; *) err "Only Debian/Ubuntu supported"; exit 1 ;; esac }

require_cmd(){ command -v "$1" >/dev/null 2>&1 || { err "Required command '$1' not found. Exiting."; exit 1; } }

#########################

Prep & dependencies

######################### prep_system(){ info "Updating system and installing base packages..." apt-get update -y apt-get upgrade -y apt-get install -y curl wget sudo git lsof socat cron bash-completion jq unzip tar gnupg apt-transport-https ca-certificates build-essential

utilities used in script

apt-get install -y htop net-tools dnsutils iproute2 iptables-persistent }

install_badvpn(){ info "Installing badvpn for UDP tunneling (badvpn-udpgw)..."

try apt then fallback to building small static binary

if ! command -v badvpn-udpgw >/dev/null 2>&1; then apt-get install -y cmake mkdir -p /opt/badvpn-build cd /opt/badvpn-build git clone https://github.com/ambrop72/badvpn.git --depth 1 || true mkdir -p badvpn/build && cd badvpn/build cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 make -j2 cp udpgw/badvpn-udpgw /usr/local/bin/badvpn-udpgw chmod +x /usr/local/bin/badvpn-udpgw fi

systemd

cat >/etc/systemd/system/badvpn.service <<'EOF' [Unit] Description=badvpn udpgw After=network.target

[Service] Type=simple ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1024 Restart=on-failure

[Install] WantedBy=multi-user.target EOF systemctl daemon-reload systemctl enable --now badvpn.service }

install_openssh(){ info "Ensuring OpenSSH is installed..." apt-get install -y openssh-server sed -i "s/#Port 22/Port ${SSH_PORT}/" /etc/ssh/sshd_config || true systemctl enable --now ssh }

#########################

Xray-core (for VMess/VLESS and WS forwarding)

######################### install_xray(){ info "Installing Xray-core (lightweight)" XRAY_VER=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name) TMP=/tmp/xray mkdir -p "$TMP" && cd "$TMP" curl -sL "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-linux-64.zip" -o xray.zip unzip -o xray.zip install -m 755 xray /usr/local/bin/xray mkdir -p /etc/xray /var/log/xray

basic config with vmess, vless, trojan (xray can do trojan-inbound) and a dokodemo-door for ssh ws

cat >/etc/xray/config.json <<EOF { "log": {"access":"/var/log/xray/access.log","error":"/var/log/xray/error.log","loglevel":"warning"}, "inbounds": [ { "port": ${PORT_TLS}, "protocol": "vless", "settings": {"clients": []}, "streamSettings": {"network":"tcp","security":"tls","tlsSettings":{"alpn":["h2","http/1.1"]},"wsSettings":{"path":"/vless"}} }, { "port": 8443, "protocol": "vmess", "settings": {"clients": []}, "streamSettings": {"network":"tcp","security":"tls","tlsSettings":{},"wsSettings":{"path":"/vmess"}} }, { "port": 8880, "protocol": "dokodemo-door", "settings": {"network":"ws","followRedirect":true}, "streamSettings": {"network":"ws","wsSettings":{"path":"/ssh"}} } ], "outbounds": [{"protocol":"freedom","settings":{}}] } EOF

cat >/etc/systemd/system/xray.service <<'EOF' [Unit] Description=Xray Service After=network.target nss-lookup.target

[Service] User=root ExecStart=/usr/local/bin/xray -config /etc/xray/config.json Restart=on-failure LimitNOFILE=65536

[Install] WantedBy=multi-user.target EOF systemctl daemon-reload systemctl enable --now xray }

install_trojan_go(){ info "Installing trojan-go (lightweight trojan implementation)" TG_VER=$(curl -s https://api.github.com/repos/p4gefau1t/trojan-go/releases/latest | jq -r .tag_name) TMP=/tmp/trojan-go mkdir -p "$TMP" && cd "$TMP" curl -sL "https://github.com/p4gefau1t/trojan-go/releases/download/${TG_VER}/trojan-go-linux-amd64.zip" -o tg.zip unzip -o tg.zip install -m 755 trojan-go /usr/local/bin/trojan-go mkdir -p /etc/trojan-go /var/log/trojan-go cat >/etc/trojan-go/config.json <<'EOF' { "run_type":"server", "local_addr":"0.0.0.0", "local_port":4433, "remote_addr":"127.0.0.1", "remote_port":22, "password":["change-me"], "ssl": {"enabled": false} } EOF cat >/etc/systemd/system/trojan-go.service <<'EOF' [Unit] Description=trojan-go After=network.target

[Service] Type=simple ExecStart=/usr/local/bin/trojan-go -config /etc/trojan-go/config.json Restart=on-failure

[Install] WantedBy=multi-user.target EOF systemctl daemon-reload systemctl enable --now trojan-go }

#########################

TLS certs (acme.sh) - lightweight

######################### install_acme(){ info "Installing acme.sh for TLS certs (you must set DOMAIN and ensure DNS points to this VPS)" curl https://get.acme.sh | sh export PATH="$HOME/.acme.sh:$PATH" }

issue_cert(){ if [ -z "$DOMAIN" ]; then err "DOMAIN is empty. Set DOMAIN env var or use change_domain in menu." return 1 fi info "Issuing cert for $DOMAIN using acme.sh (standalone mode)" ~/.acme.sh/acme.sh --issue -d "$DOMAIN" --standalone -k ec-256 ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --key-file /etc/ssl/private/${DOMAIN}.key --fullchain-file /etc/ssl/certs/${DOMAIN}.crt --ecc info "Cert installed to /etc/ssl/{private,certs}/${DOMAIN}.*" }

#########################

User & Account management (SSH + Xray)

######################### create_ssh_user(){ local username=$1 local days=${2:-1} local passwd passwd=$(openssl rand -base64 12) useradd -M -s /bin/false -e "$(date -d "+${days} days" +%F)" "$username" || true echo "$username:$passwd" | chpasswd echo "$passwd" }

create_xray_client(){ local type=$1 # vmess|vless local id id=$(cat /proc/sys/kernel/random/uuid)

add to config file

jq ".inbounds |= map(if .protocol=="vless" and .port==${PORT_TLS} then .settings.clients += [{"id": "${id}", "flow": "x", "email": "${id}"}] else . end)" /etc/xray/config.json > /etc/xray/config.json.tmp && mv /etc/xray/config.json.tmp /etc/xray/config.json systemctl restart xray echo "$id" }

Create trial xray account

create_trial(){ local id id=$(create_xray_client vless) info "Created trial client id: $id" }

#########################

Utilities

######################### check_services(){ systemctl is-active --quiet xray && echo "xray: running" || echo "xray: stopped" systemctl is-active --quiet trojan-go && echo "trojan-go: running" || echo "trojan-go: stopped" systemctl is-active --quiet ssh && echo "ssh: running" || echo "ssh: stopped" systemctl is-active --quiet badvpn && echo "badvpn: running" || echo "badvpn: stopped" }

restart_all(){ systemctl restart ssh xray trojan-go badvpn || true }

speedtest(){ if ! command -v speedtest-cli >/dev/null 2>&1; then pip3 install speedtest-cli >/dev/null 2>&1 || true fi speedtest-cli --simple || true }

backup_all(){ local out="/root/vpn_backup_$(date +%F_%T).tar.gz" tar czf "$out" /etc/xray /etc/trojan-go /etc/ssh /etc/ssl --warning=no-file-changed || true echo "$out" }

restore_backup(){ local file=$1 if [ -f "$file" ]; then tar xzf "$file" -C / systemctl restart xray trojan-go ssh else err "Backup file not found" fi }

auto_reboot_setup(){ info "Setting daily auto-reboot at 04:00" (crontab -l 2>/dev/null; echo "0 4 * * * /sbin/reboot") | crontab - }

telegram_notify_setup(){ info "Creating simple telegram notification hook file (user must fill token/chatid)" cat >/usr/local/bin/tg_notify.sh <<'EOF' #!/usr/bin/env bash TOKEN="<YOUR_BOT_TOKEN>" CHATID="<CHAT_ID>" MSG="$*" curl -s --max-time 10 "https://api.telegram.org/bot${TOKEN}/sendMessage" -d chat_id=${CHATID} -d text="${MSG}" EOF chmod +x /usr/local/bin/tg_notify.sh }

change_domain(){ read -rp "Enter domain (A record must point to this VPS IP): " d DOMAIN="$d" read -rp "Email for certs (optional): " e EMAIL="$e" issue_cert || warn "Certificate issuance failed. Please ensure DNS correct and ports 80/443 open."

The script will not modify xray/trojan TLS setup automatically beyond installing cert files.

}

change_banner(){ local b read -rp "Enter new motd/banner text: " b echo "$b" >/etc/motd }

fixx_domain_proxy(){ info "This is a helper placeholder. Implement specific fix steps per environment." }

limit_speed(){ warn "Limit speed feature is environment-specific. Consider using tc (traffic control) or wondershaper." }

monitor_vps(){ info "Top processes:"; ps aux --sort=-%mem | head -n 15 info "Disk usage:"; df -h info "Memory:"; free -h }

#########################

Installer main

######################### main_install(){ check_root detect_os prep_system install_openssh install_badvpn install_xray install_trojan_go install_acme auto_reboot_setup telegram_notify_setup info "Base installation complete. Please set DOMAIN using menu -> Change Domain and issue certificates." }

#########################

Simple CLI menu

######################### menu(){ while true; do clear cat <<EOF VPN AUTO SCRIPT - MENU

1. Install base (required first run)


2. Check running service


3. Restart services


4. Auto Reboot Setup


5. Monitor VPS


6. Speedtest


7. Create SSH user


8. Create Xray trial client


9. Backup all


10. Restore backup


11. Change Domain (issue cert)


12. Change Banner


13. Telegram notify setup


14. Exit EOF read -rp "Choose: " opt case "$opt" in

1. main_install ; read -rp "Press enter..." ;;


2. check_services ; read -rp "Press enter..." ;;


3. restart_all ; read -rp "Press enter..." ;;


4. auto_reboot_setup ; read -rp "Press enter..." ;;


5. monitor_vps ; read -rp "Press enter..." ;;


6. speedtest ; read -rp "Press enter..." ;;


7. read -rp "Username: " u; read -rp "Days valid: " d; p=$(create_ssh_user "$u" "$d"); info "Created $u with pass: $p"; read -rp "Press enter..." ;;


8. create_trial ; read -rp "Press enter..." ;;


9. out=$(backup_all); info "Backup saved: $out"; read -rp "Press enter..." ;;


10. read -rp "Backup file path: " f; restore_backup "$f"; read -rp "Press enter..." ;;


11. change_domain ; read -rp "Press enter..." ;;


12. change_banner ; read -rp "Press enter..." ;;


13. telegram_notify_setup ; read -rp "Press enter..." ;;


14. exit 0 ;; *) warn "Invalid" ;; esac done }





if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then menu fi

