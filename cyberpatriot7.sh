#!/bin/bash

# Print start message
echo "Starting..."
echo "This script should be run as root (sudo)."

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Create a log file
exec 1> >(tee "security_hardening_$(date +%F_%H%M%S).log")
exec 2>&1

echo "=== Starting security hardening at $(date) ==="

# 1. Remove unauthorized packages
echo "=== Removing unauthorized packages ==="
PACKAGES_TO_REMOVE=(
    "telnet"
    "ftp"
    "vnc"
    "nfs-common"
    "nfs-kernel-server"
    "apache2"
    "nginx"
    "netcat"
    "netcat-traditional"
    "netcat-openbsd"
    "hydra"
    "john"
    "aircrack-ng"
    "fcrackzip"
    "lcrack"
    "ophcrack"
    "pdfcrack"
    "pyrit"
    "rarcrack"
    "sipcrack"
    "irpas"
    "logkeys"
    "zeitgeist"
    "wireshark"
    "aisleriot"
    "vsftpd"
    "pure-ftpd"
    "tftpd"
    "snmp"
    "xinetd"
    "owasp-zap"
)

for package in "${PACKAGES_TO_REMOVE[@]}"; do
    echo "Removing $package..."
    apt-get purge -y "$package"
done

apt-get autoremove -y

# 2. Disable unauthorized services
echo "=== Disabling unauthorized services ==="
SERVICES_TO_DISABLE=(
    "apache2"
    "nginx"
    "netcat"
    "vsftpd"
    "pure-ftpd"
    "tftpd"
    "nfs-server"
    "rpcbind"
    "snmpd"
    "xinetd"
)

for service in "${SERVICES_TO_DISABLE[@]}"; do
    if systemctl is-active --quiet "$service"; then
        echo "Stopping and disabling $service..."
        systemctl stop "$service"
        systemctl disable "$service"
    fi
done

# 3. Configure UFW firewall
echo "=== Configuring UFW firewall ==="
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
# Uncomment the following line if SSH access is needed
# ufw allow OpenSSH
ufw --force enable
ufw logging on

# 4. Configure sysctl security settings
echo "=== Configuring sysctl security settings ==="
cat << 'EOL' > /etc/sysctl.d/99-security-hardening.conf
kernel.core_uses_pid = 1
kernel.ctrl-alt-del = 0
kernel.sysrq = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.bootp_relay = 0
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.mc_forwarding = 0
net.ipv4.conf.all.proxy_arp = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_source_route = 0
EOL

# Apply sysctl settings
sysctl -p /etc/sysctl.d/99-security-hardening.conf

# 5. Configure password policies
echo "=== Configuring password policies ==="
# Update PAM password configuration
sed -i '/pam_unix.so/s/$/ remember=5 minlen=12/' /etc/pam.d/common-password
#sed -i '/pam_cracklib.so/s/$/ ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 minlen=12/' /etc/pam.d/common-password

# Update login.defs
sed -i 's/^PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*$/PASS_MIN_DAYS 10/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' /etc/login.defs

# Configure login attempt limits
#echo "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800" >> /etc/pam.d/common-auth

# 6. Harden file permissions
echo "=== Hardening file permissions ==="
# Set correct permissions for shadow file
chmod 640 /etc/shadow
chown root:shadow /etc/shadow

# Set correct permissions for passwd file
chmod 644 /etc/passwd
chown root:root /etc/passwd

# Set correct permissions for group file
chmod 644 /etc/group
chown root:root /etc/group

# 7. Disable guest account
echo "=== Disabling guest account ==="
if [ -f "/etc/lightdm/lightdm.conf" ]; then
    echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
fi

# Final system update
echo "=== Running final system update ==="
apt-get update
apt-get upgrade -y
apt-get autoremove -y
apt-get autoclean

echo "=== Security hardening completed at $(date) ==="
echo "Please review the log file for any errors and reboot the system."
echo "Note: If SSH access is needed, make sure to uncomment the UFW SSH rule before rebooting."
