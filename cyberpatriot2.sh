#!/bin/bash

# Script Information
echo 'Script 2'
echo 'By Scooby Dooo'
echo
echo 'Welcome Dylan!'
echo

# update system
sudo apt-get update -y
sudo apt-get dist-upgrade -y
sudo apt-get upgrade -y
sudo apt-get install -f -y
sudo apt-get autoremove -y
sudo apt-get autoclean -y
sudo apt-get check

# install programs
sudo apt-get install -y chkrootkit clamav rkhunter apparmor apparmor-profiles ufw

# if ssh is critical service
#sudo apt-get install -y ssh openssh-server

# if not
#sudo apt-get autoremove --purge -y ssh openssh-server

# disable guest user
#sudo sed -i 'aallow-guest=false' /etc/lightdm/lightdm.conf
#sudo restart lightdm

# delete prohibited files
sudo find / -name '*.mp3' -type f -delete
sudo find / -name '*.mov' -type f -delete
sudo find / -name '*.mp4' -type f -delete
sudo find / -name '*.avi' -type f -delete
sudo find / -name '*.mpg' -type f -delete
sudo find / -name '*.mpeg' -type f -delete
sudo find / -name '*.flac' -type f -delete
sudo find / -name '*.m4a' -type f -delete
sudo find / -name '*.flv' -type f -delete
sudo find / -name '*.ogg' -type f -delete
sudo find /home -name '*.gif' -type f -delete
sudo find /home -name '*.png' -type f -delete
sudo find /home -name '*.jpg' -type f -delete
sudo find /home -name '*.jpeg' -type f -delete
 
# change user passwords
echo [USER1]:Cyb3rPatr!0t$ >> pass.txt
echo [USER2]:Cyb3rPatr!0t$ >> pass.txt
echo [USER3]:Cyb3rPatr!0t$ >> pass.txt
echo [USER4]:Cyb3rPatr!0t$ >> pass.txt
echo [USER5]:Cyb3rPatr!0t$ >> pass.txt
sudo chpasswd < pass.txt

# scan for viruses
sudo chkrootkit -q
rkhunter --update
rkhunter --propupd #Run this once at install
rkhunter -c --enable all --disable none

systemctl stop clamav-freshclam
freshclam --stdout
systemctl start clamav-freshclam
clamscan -r -i --stdout --exclude-dir="^/sys" /

# secure root
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
sudo service ssh reload

# enforce password reqs
sudo sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS    90/' /etc/login.defs
sudo sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS    7/' /etc/login.defs
sudo sed -i 's/PASS_WARN_AGE.*/PASS_WARN_AGE    14/' /etc/login.defs

# min password length and password history
sudo sed -i '/pam_unix.so/ s/$/ minlen=8 remember=5/' /etc/pam.d/common-password

# null passwords do not authenticate
sudo sed -i 's/nullok/ /g' /etc/pam.d/common-auth

# remove bad services
sudo systemctl stop nginx 
sudo systemctl disable nginx 
sudo apt-get purge netcat -y -qq
sudo apt-get purge netcat-openbsd -y -qq
sudo apt-get purge netcat-traditional -y -qq
sudo apt-get purge ncat -y -qq
sudo apt-get purge pnetcat -y -qq
sudo apt-get purge socat -y -qq
sudo apt-get purge sock -y -qq
sudo apt-get purge socket -y -qq
sudo apt-get purge sbd -y -qq
sudo apt-get purge hydra -y -qq
sudo apt-get purge hydra-gtk -y -qq
sudo apt-get purge john -y -qq
sudo apt-get purge john-data -y -qq
sudo apt-get purge aircrack-ng -y -qq
sudo apt-get purge fcrackzip -y -qq
sudo apt-get purge lcrack -y -qq
sudo apt-get purge ophcrack -y -qq
sudo apt-get purge ophcrack-cli -y -qq
sudo apt-get purge pdfcrack -y -qq
sudo apt-get purge pyrit -y -qq
sudo apt-get purge rarcrack -y -qq
sudo apt-get purge sipcrack -y -qq
sudo apt-get purge apache2 -y -qq
sudo apt-get purge wireshark

# enable firewall
sudo ufw enable
sudo ufw allow ssh
sudo ufw allow http
sudo ufw allow https
sudo ufw deny 23
sudo ufw deny 2049
sudo ufw deny 515
sudo ufw deny 111
sudo ufw logging high
sudo ufw status verbose
