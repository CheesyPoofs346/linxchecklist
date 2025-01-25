#!/bin/bash
# =============================================================================
# mega_hardening.sh - Extensive Hardening Script (No User/Password/Samba Changes)
# =============================================================================
# This script attempts to maximize security-related actions in a typical CyberPatriot
# or general hardening environment WITHOUT touching:
#   - Existing user accounts or their passwords.
#   - Samba (smbd) or its configuration.
#   - CCS Client or any scoring processes.
#   - The time zone or clock settings.
# =============================================================================
# USE WITH CAUTION: Review scenario-specific rules before applying these changes.
# =============================================================================

################################################################################
# 0. Preliminary Checks
################################################################################

if [ "$(id -u)" -ne 0 ]; then
  echo "[-] Please run this script as root (e.g., sudo ./mega_hardening.sh)."
  exit 1
fi

echo "[+] Starting mega_hardening.sh..."

################################################################################
# 1. Update & Upgrade System Packages
################################################################################

echo "[+] Updating and upgrading system packages..."
apt-get update -y && apt-get upgrade -y
# Optional: apt-get dist-upgrade -y
# Potentially also: apt-get autoremove -y && apt-get autoclean -y

################################################################################
# 2. Remove Hacking/Unwanted Tools (But Keep Samba & CCS)
################################################################################
# The scenario says hacking tools and non-work software are prohibited.
# We'll also remove compilers or debugging tools if not needed.

TO_REMOVE=(
  # Common hacking/pentesting tools
  "ncat" "netcat" "netcat-openbsd" "netcat-traditional" "telnet" "rsh-client"
  "hydra" "ophcrack" "medusa" "john" "wireshark"

  # Potential compilers/debuggers not needed for normal business use
  # (Check scenario if these might be needed for local dev)
  "gcc" "g++" "gdb"
)

echo "[+] Removing hacking tools and possibly unneeded dev packages..."
for pkg in "${TO_REMOVE[@]}"; do
  if dpkg -l | grep -qw "$pkg"; then
    echo "[+] Removing $pkg..."
    apt-get remove -y "$pkg"
  fi
done

# If ncat or netcat is manually placed in /usr/local/bin, remove it
if [ -f /usr/local/bin/ncat ]; then
  echo "[+] Removing custom /usr/local/bin/ncat..."
  rm -f /usr/local/bin/ncat
fi

# Kill any netcat processes that might be running (like backdoors on port 8970)
pkill ncat 2>/dev/null || true

################################################################################
# 3. Remove Non-Work-Related Media Files
################################################################################
# The scenario states that non-work related media is prohibited.

echo "[+] Searching for non-work-related media files in /home..."
find /home -type f \( \
  -iname "*.mp3" -o -iname "*.mp4" -o -iname "*.wav" -o -iname "*.mov" \
  -o -iname "*.avi" -o -iname "*.mkv" -o -iname "*.wmv" -o -iname "*.flac" \
\) \
-print -exec rm -f {} \;

################################################################################
# 4. Enforce Password Policies (No Actual Password Changes)
################################################################################
# We won't modify any existing user passwords or remove users.

if ! dpkg -l | grep -qw libpam-pwquality; then
  echo "[+] Installing libpam-pwquality..."
  apt-get install -y libpam-pwquality
fi

PAM_FILE="/etc/pam.d/common-password"
if [ -f "$PAM_FILE" ]; then
  cp "$PAM_FILE" "${PAM_FILE}.bak"
  echo "[+] Enforcing strong password policy in $PAM_FILE..."
  if ! grep -q "pam_pwquality.so" "$PAM_FILE"; then
    sed -i '/pam_unix.so/a password requisite pam_pwquality.so retry=3 minlen=12 \
dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1' "$PAM_FILE"
  fi
fi

################################################################################
# 5. Configure & Harden the UFW Firewall
################################################################################
# We keep Samba open, do not disrupt CCS, and do not remove any required ports.

echo "[+] Enabling UFW with default deny incoming..."
ufw --force enable
ufw default deny incoming
ufw default allow outgoing

# Allow SSH
if ! ufw status | grep -q "22/tcp"; then
  ufw allow 22/tcp
fi

# Samba ports (139, 445)
ufw allow 139/tcp
ufw allow 445/tcp

# If you need other ports (like 631 for CUPS) confirm or remove as needed
# e.g., ufw allow 631/tcp  # for printing

################################################################################
# 6. Secure SSH: Disable Root Login
################################################################################

SSHD_CONFIG="/etc/ssh/sshd_config"
if [ -f "$SSHD_CONFIG" ]; then
  cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"
  echo "[+] Disabling SSH root login..."
  sed -i 's/.*PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONFIG"
  if ! grep -q "^PermitRootLogin" "$SSHD_CONFIG"; then
    echo "PermitRootLogin no" >> "$SSHD_CONFIG"
  fi
  systemctl restart ssh || service ssh restart
fi

################################################################################
# 7. Disable Guest Account (LightDM)
################################################################################
# The scenario states the display manager should remain LightDM; we'll disable guest.

if [ -d /etc/lightdm/lightdm.conf.d ]; then
  echo "[+] Disabling guest sessions in LightDM..."
  GUEST_FILE="/etc/lightdm/lightdm.conf.d/50-no-guest.conf"
  echo "[SeatDefaults]" > "$GUEST_FILE"
  echo "allow-guest=false" >> "$GUEST_FILE"
fi

################################################################################
# 8. Remove or Disable Unneeded Services/Packages
################################################################################
# We won't remove Samba or CCS. We'll remove Apache if not required.

# 8a. Remove Apache if found (assuming not a web server)
if dpkg -l | grep -qw apache2; then
  echo "[+] Removing Apache2 (machine not a web server)..."
  apt-get remove -y apache2
  apt-get autoremove -y
fi

# 8b. Remove Bluetooth if not required (some images do not need it)
if systemctl is-enabled bluetooth >/dev/null 2>&1; then
  echo "[+] Disabling Bluetooth service (not business critical for most images)..."
  systemctl disable bluetooth
  systemctl stop bluetooth
fi

################################################################################
# 9. Install or Verify Required Software
################################################################################
# The scenario says we need the latest stable versions of:
#  - Chromium
#  - CherryTree
#  - Stellarium
#  - LibreOffice

NEEDED_PKGS=("chromium-browser" "cherrytree" "stellarium" "libreoffice")
for pkg in "${NEEDED_PKGS[@]}"; do
  if ! dpkg -l | grep -qw "$pkg"; then
    echo "[+] Installing $pkg..."
    apt-get install -y "$pkg"
  fi
done

################################################################################
# 10. System & Network Hardening (Optional Extras)
################################################################################
# Some competitions award points for sysctl tuning, especially for IPv4/IPv6 security.

SYSCTL_FILE="/etc/sysctl.conf"
echo "[+] Hardening network stack via sysctl..."

declare -A SYSCTL_SETTINGS=(
  # Disable IP forwarding (unless needed for routing)
  ["net.ipv4.ip_forward"]="0"
  # Ignore ICMP broadcast requests
  ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
  # Disable source routing
  ["net.ipv4.conf.all.accept_source_route"]="0"
  ["net.ipv4.conf.default.accept_source_route"]="0"
  # Disable ICMP redirects
  ["net.ipv4.conf.all.accept_redirects"]="0"
  ["net.ipv4.conf.default.accept_redirects"]="0"
  # Disable secure redirects
  ["net.ipv4.conf.all.secure_redirects"]="0"
  ["net.ipv4.conf.default.secure_redirects"]="0"
  # Log spoofed packets, source routed packets, redirect packets
  ["net.ipv4.conf.all.log_martians"]="1"
  ["net.ipv4.conf.default.log_martians"]="1"
)

for key in "${!SYSCTL_SETTINGS[@]}"; do
  value="${SYSCTL_SETTINGS[$key]}"
  if grep -q "$key" "$SYSCTL_FILE"; then
    sed -i "s/^$key.*/$key = $value/" "$SYSCTL_FILE"
  else
    echo "$key = $value" >> "$SYSCTL_FILE"
  fi
done

# Reload sysctl with new settings
sysctl -p

################################################################################
# 11. Check for World-Writable or Suspicious File Permissions
################################################################################
# Some competitions require removing or changing world-writable files in system directories.

echo "[+] Checking for world-writable directories (excluding /tmp, /var/tmp, /proc, /sys)..."

find / -type d -perm -0002 -not -path "/tmp*" -not -path "/var/tmp*" \
  -not -path "/proc*" -not -path "/sys*" -print 2>/dev/null | while read -r dir; do
  echo "World-writable dir found: $dir"
  # If needed, we can remove 'w' for others. But do so carefully:
  # chmod o-w "$dir"
done

################################################################################
# 12. Optional: Rootkit & Malware Scans
################################################################################

# 12a. Install & run rkhunter
if ! dpkg -l | grep -qw rkhunter; then
  echo "[+] Installing rkhunter..."
  apt-get install -y rkhunter
  rkhunter --update
fi
rkhunter --check --sk

# 12b. Install ClamAV for antivirus scanning
if ! dpkg -l | grep -qw clamav; then
  echo "[+] Installing ClamAV..."
  apt-get install -y clamav clamav-freshclam
  freshclam
fi

# Quick scan of /home for viruses
clamscan -r /home

################################################################################
# 13. Inspect Cron Jobs & Startup Scripts
################################################################################
# We won't remove anything automatically, but let's print them so you can manually review.

echo "[+] Inspecting root crontab..."
crontab -l

echo "[+] Inspecting /etc/cron.* and /etc/cron.d..."
ls -l /etc/cron.* 2>/dev/null
ls -l /etc/cron.d 2>/dev/null

echo "[+] Checking systemd services that start on boot..."
systemctl list-unit-files | grep enabled

echo "[+] If any suspicious or unauthorized startup scripts are found, remove or disable them."

################################################################################
# 14. Final Housekeeping
################################################################################

# Remove leftover apt caches (optional):
apt-get autoremove -y
apt-get autoclean -y

echo "[+] mega_hardening.sh completed. Review the output for any warnings or errors."
exit 0
