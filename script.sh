#!/bin/bash

# Function to check and install packages
install_package() {
    if ! dpkg -l | grep -q "$1"; then
        apt-get install -y "$1"
    else
        echo "$1 is already installed."
    fi
}

# Update and upgrade the system
apt-get update && apt-get upgrade -y && apt-get dist-upgrade -y

# Enable and configure UFW
install_package ufw
ufw enable
ufw allow from 202.54.1.5/29 to any port 22

# Harden SSH settings
if grep -qF 'PermitRootLogin' /etc/ssh/sshd_config; then
    sed -i 's/^.*PermitRootLogin.*$/PermitRootLogin no/' /etc/ssh/sshd_config
else
    echo 'PermitRootLogin no' >> /etc/ssh/sshd_config
fi

cat <<EOL >> /etc/ssh/sshd_config
ChallengeResponseAuthentication no
PasswordAuthentication no
UsePAM no
PermitEmptyPasswords no
ClientAliveInterval 300
ClientAliveCountMax 0
IgnoreRhosts yes
EOL

# Check SSH configuration
sshd -t && systemctl restart sshd

# Lock root user
passwd -l root

# Change login policy
sed -i 's/PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/;s/PASS_MIN_DAYS.*$/PASS_MIN_DAYS 10/;s/PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' /etc/login.defs

# Update PAM settings
install_package libpam-cracklib
echo 'auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800' >> /etc/pam.d/common-auth
sed -i 's/\(pam_unix\.so.*\)$/\1 remember=5 minlen=8/' /etc/pam.d/common-password
sed -i 's/\(pam_cracklib\.so.*\)$/\1 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password

# Install and configure auditd
install_package auditd
auditctl -e 1

# Check for suspicious users
mawk -F: '$1 == "sudo"' /etc/group
mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd
mawk -F: '$2 == ""' /etc/passwd
mawk -F: '$3 == 0 && $1 != "root"' /etc/passwd

# Remove samba-related packages
apt-get remove -y .*samba.* .*smb.*

# Search for music and hacking tools
find /home/ -type f \( -name "*.mp3" -o -name "*.mp4" \)
find /home/ -type f \( -name "*.tar.gz" -o -name "*.tgz" -o -name "*.zip" -o -name "*.deb" \)

# Install and configure fail2ban
install_package fail2ban
systemctl restart fail2ban.service

# Find and remove world-writable files and no-user files
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print
find / -xdev \( -nouser -o -nogroup \) -print

# Set home directory permissions
for i in $(mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd); do
    [ -d /home/${i} ] && chmod -R 750 /home/${i}
done

# Kernel hardening
cat <<EOL >> /etc/sysctl.conf
kernel.exec-shield=1
kernel.randomize_va_space=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.accept_source_route=0
net.ipv6.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_max_syn_backlog=2048
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_syn_retries=5
net.ipv4.ip_forward=0
net.ipv4.conf.all.log_martians=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.conf.all.accept_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv4.icmp_echo_ignore_all=1
EOL
sysctl -p

# Prevent IP spoofing
if grep -qF 'multi on' /etc/host.conf; then
    sed -i 's/multi/nospoof/' /etc/host.conf
else
    echo 'nospoof on' >> /etc/host.conf
fi

# Disable USB storage
echo 'install usb-storage /bin/true' >> /etc/modprobe.d/disable-usb-storage.conf

# Disable Firewire and Thunderbolt
cat <<EOL >> /etc/modprobe.d/blacklist.conf
blacklist firewire-core
blacklist thunderbolt
EOL

# Install tools for rootkit detection
install_package chkrootkit
install_package rkhunter
chkrootkit
rkhunter --update
rkhunter --check

echo "System hardening complete."
