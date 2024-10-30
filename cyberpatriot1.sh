#!/bin/bash

listOperations=(
"1) Manage Users" 
"2) Manage Groups" 
"3) Password Policy"
"4) Activate Firewall" 
"5) Configure Auditd" 
"6) Auto Login and Guest"
"7) Scan Crontab" 
"8) Software Check"
"9) Processes and Services" 
"10) Automatic Updates"
"11) Full Update" 
"99) Restore Backup"
)


mainMenu() {
	echo | tee -a /home/ScriptFiles/log.txt
	echo "$logTime: SCRIPT INITIALIZED" | tee -a /home/ScriptFiles/log.txt
	clear

	echo 'Script 1'
	echo 'By Scooby Doo'
	echo
	echo 'Welcome Dylan!'
	echo
	echo 'Tell yo boy what you need done'
	echo
	echo '0) Activate Multiple'
	for ((i=0; i<${#listOperations[@]}; i++)); do
		echo ${listOperations[i]}
	done
	echo
	read input
	case $((input)) in
		0)
		activateMultiple
		;;
		
		1)
		manageUsers
		;;
		
		2)
		manageGroups
		;;
		
		3)
		passwordPolicy
		;;

		4)
		activateFirewall
		;;
		
		5)
		configureAuditd
		;;

  		6)
    		autoLoginAndGuest
      		;;
		
		7)
		scanCrontab
		;;

  		8)
    		hackingTools
      		;;
		
		9)
		processesAndServices
		;;
		
		10)
		automaticUpdates
		;;
		
		11)
		updateAndAntiVirus
		;;
		
		99)
		restoreBackup
		;;
		
		*)
		mainMenu
		;;
		esac
	clear
}

activateMultiple() {
	clear
	opList=()
	
	echo 'Hello '$username'! Welcome to Activate Multiple.'
	echo
	echo " enter all the operations you wish to do."
	echo "Type 1 number into each line and press enter."
	echo "Each command will be documented then activated in DO NOT USE THIS order."
	echo
	echo "At any time, you can type 0 to start the operations."
	echo "You can also run all functions by typing -1."
	echo
	for ((;;)) do
		echo "DONT input the operation you wish to do. (-1 for auto, 0 to Start) DO NOT USE THIS"
		read input
		echo
		if [[ ! $input  == 0 ]] && [ ! $input == -1 ]; then
			opList=("${opList[@]}" "$input")
		elif [ $input == -1 ]; then
			opList=()
			autoScript
			break
		else
			break
		fi
	done
	echo "${opList[@]}"
	echo
	echo "Activating now!"
	echo
	for ((a=0;a<${#opList[@]}; a++)); do
		case ${opList[a]} in
			1)
			manageUsers
			;;

			2)
			manageGroups
			;;

			3)
			passwordPolicy
			;;

			4)
			activateFirewall
			;;
		
			5)
			configureAuditd
			;;

   			6)
      			autoLoginAndGuest
	 		;;
			
			7)
			scanCrontab
			;;

      			8)
	 		hackingTools
			;;
			
			9)
			processesAndServices
			;;
			
			10)
			automaticUpdates
			;;
			
			11)
			updateAndAntiVirus
			;;
			
			99)
			restoreBackup
			;;

			*)
			;;
		esac
	done
	clear
}

manageUsers() 
{
	echo | tee -a /home/ScriptFiles/log.txt
	clear
	echo "$logTime: Managing Users:" | tee -a /home/ScriptFiles/log.txt

	allUsers=(${authAdmins[@]} ${authUsers[@]})
	echo "$logTime: Authorized Users:" | tee -a /home/ScriptFiles/log.txt
	for user in "${allUsers[@]}"; do
		echo "$user" | tee -a /home/ScriptFiles/log.txt
	done
	
	mapfile -t systemUsers < <(cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1)
	
	for user in "${systemUsers[@]}"; do
		found=0
		for authorizedUser in "${allUsers[@]}"; do
        		if [[ "$user" == "$authorizedUser" ]]; then
            			found=1
            			break
        		fi
    		done
    		if [[ $found -eq 0 ]]; then
        		deluser --remove-home "$user"
        		echo "$logTime: Removed Unauthorized User - $user" | tee -a /home/ScriptFiles/log.txt
    		fi
	done
	
	mapfile -t systemUsers < <(cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1)
	
	for user in "${allUsers[@]}"; do
    		found=0
    		for sysUser in "${systemUsers[@]}"; do
        		if [[ "$user" == "$sysUser" ]]; then
            			found=1
            			break
        		fi
    		done
    		if [[ $found -eq 0 ]]; then\
        		useradd "$user"
        		echo "$logTime: Added Missing User - $user" | tee -a /home/ScriptFiles/log.txt
    		fi
	done
	
	mapfile -t systemUsers < <(cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1)
	clear
	
	read -a sudoers <<< $(echo "$(grep '^sudo:' /etc/group | cut -d ':' -f 4)" | tr ',' ' ')
	
	echo | tee -a /home/ScriptFiles/log.txt
	clear
	echo "Authorized Admins:" | tee -a /home/ScriptFiles/log.txt
	for user in "${sudoers[@]}"; do
		echo "$user" | tee -a /home/ScriptFiles/log.txt
	done
	
	for user in "${sudoers[@]}"; do
		found=0
		for authorizedUser in "${authAdmins[@]}"; do
        		if [[ "$user" == "$authorizedUser" ]]; then
            			found=1
            			break
        		fi
    		done
    		if [[ $found -eq 0 ]]; then
        		deluser "$user" sudo
        		echo "$logTime: Removed Unauthorized Admin Permissions - $user" | tee -a /home/ScriptFiles/log.txt
    		fi
	done
	
	for user in "${authAdmins[@]}"; do
    		found=0
    		for sudoUser in "${sudoers[@]}"; do
        		if [[ "$user" == "$sudoUser" ]]; then
            			found=1
            			break
        		fi
    		done
    		if [[ $found -eq 0 ]]; then
        		adduser "$user" sudo
        		echo "$logTime: Added Missing Admin Permissions - $user" | tee -a /home/ScriptFiles/log.txt
    		fi
	done
	clear
}

manageGroups()
{
	echo | tee -a /home/ScriptFiles/log.txt
	clear
	echo "$logTime: Managing Groups:" | tee -a /home/ScriptFiles/log.txt	
	
	while true; do
		echo "Do you want to add a new group?"
		read input
		if [ "$input" == "y" ]; then
			echo "Enter da name of the Group"
			read input 
			groupadd $input
			echo "$logTime: Added Group - $input" | tee -a /home/ScriptFiles/log.txt
			clear
		else
			break
		fi
	done

	while true; do
		echo "Do you want to delete a group?"
		read input
		if [ "$input" == "y" ]; then
			echo " enter the name of the Group"
			read input 
			groupdel $input
			echo "$logTime: Removed Group - $input" | tee -a /home/ScriptFiles/log.txt
			clear
		else
			break
		fi
	done

	while true; do
		echo "Do you want to add a user to a group?"
		read input
		if [ "$input" == "y" ]; then
			echo "What is the group name?"
			read input 
			echo "What is the username?"
			read username
			gpasswd -a $username $input
			echo "$logTime: Added User - $username, Group - $input" | tee -a /home/ScriptFiles/log.txt
			clear
		else
			break
		fi
	done

	while true; do
		echo "Do you want to remove a user from a group?"
		read input
		if [ "$input" == "y" ]; then
			echo "What is the group name?"
			read input 
			echo "What is the username?"
			read username
			gpasswd -d $username $input
			echo "$logTime: Removed User - $username, Group - $input" | tee -a /home/ScriptFiles/log.txt
			clear
		else
			break
		fi
	done
}

passwordPolicy()
{
	echo | tee -a /home/ScriptFiles/log.txt
	clear
	echo "$logTime: Password Policy" | tee -a /home/ScriptFiles/log.txt

	if [ ! -f /home/ScriptFiles/backupCheck ]; then
		touch /home/ScriptFiles/backupCheck
		echo "$logTime: Created the Flag File, backupCheck" | tee -a /home/ScriptFiles/log.txt
	fi
	
	cp /etc/pam.d/common-password /home/ScriptFiles/common-password.bak
	echo "$logTime: Created Backup for: /etc/pam.d/common-password at /home/ScriptFiles/common-password.bak" | tee -a /home/ScriptFiles/log.txt
	
	cp /etc/pam.d/common-auth /home/ScriptFiles/common-auth.bak
	echo "$logTime: Created Backup for: /etc/pam.d/common-auth at /home/ScriptFiles/common-auth.bak" | tee -a /home/ScriptFiles/log.txt
	
	cp /etc/login.defs /home/ScriptFiles/login.defs.bak
	echo "$logTime: Created Backup for: /etc/login.defs at /home/ScriptFiles/login.defs.bak" | tee -a /home/ScriptFiles/log.txt
	
	cp /etc/ssh/sshd_config /home/ScriptFiles/sshd_config.bak
	echo "$logTime: Created Backup for: /etc/ssh/sshd_config at /home/ScriptFiles/sshd_config.bak" | tee -a /home/ScriptFiles/log.txt

	sed -i 's/^password.*pam_pwquality.so.*/password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=3 maxclassrepeat=2/' /etc/pam.d/common-password
	echo "$logTime: Modified /etc/pam.d/common-password" | tee -a /home/ScriptFiles/log.txt

	sed -i 's/^auth\s*\[success=2\s*default=ignore\]\s*pam_unix\.so\s*nullok/auth	[success=2 default=ignore]	pam_unix.so/' /etc/pam.d/common-auth
	echo "auth required pam_faillock.so preauth silent audit deny=3 unlock_time=1200" | tee -a /home/ScriptFiles/log.txt
	echo "auth [default=die] pam_faillock.so authfail audit deny=3 unlock_time=1200" | tee -a /home/ScriptFiles/log.txt
	echo "auth sufficient pam_faillock.so authsucc" | tee -a /home/ScriptFiles/log.txt
	
	echo "$logTime: Modified /etc/pam.d/common-auth" | tee -a /home/ScriptFiles/log.txt

	sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   30/' /etc/login.defs
	sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   5/' /etc/login.defs
	sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   5/' /etc/login.defs
	echo "$logTime: Modified /etc/login.defs" | tee -a /home/ScriptFiles/log.txt

	sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
	echo "$logTime: Modified /etc/ssh/sshd_config" | tee -a /home/ScriptFiles/log.txt

	systemctl restart sshd
	echo "$logTime: Restarted SSHD" | tee -a /home/ScriptFiles/log.txt
	
	echo | tee -a /home/ScriptFiles/log.txt
	clear
	echo "$logTime: Passwords:" | tee -a /home/ScriptFiles/log.txt
	
	password=c0OlP@S5w0rD!1
	
	for user in "${allUsers[@]}"; do
		if [[ "$user" != "${allUsers[0]}" ]]; then
			echo "$user:$password" | chpasswd
			echo "$logTime: Password Changed - $user:$password" | tee -a /home/ScriptFiles/log.txt
		fi
	done
}

activateFirewall() 
{
	echo | tee -a /home/ScriptFiles/log.txt
	clear
	echo "$logTime: Activating Firewall..." | tee -a /home/ScriptFiles/log.txt
	apt install ufw
	echo "$logTime: UFW Installed" | tee -a /home/ScriptFiles/log.txt
	ufw enable
	echo "$logTime: UFW Enabled" | tee -a /home/ScriptFiles/log.txt
}

updateAndAntiVirus() 
{
	echo | tee -a /home/ScriptFiles/log.txt
	clear
	echo "$logTime: Full Update:" | tee -a /home/ScriptFiles/log.txt
 
	gnome-terminal -- bash -c "
	echo '$logTime: Terminal Opened' | tee -a /home/ScriptFiles/log.txt;
 	echo '$logTime: Update Starting' | tee -a /home/ScriptFiles/log.txt;
	apt-get update -y; 
	apt upgrade -y;
 	echo | tee -a /home/ScriptFiles/log.txt;
	echo '$logTime: UPDATE: Updates Complete' | tee -a /home/ScriptFiles/log.txt;
 
 	echo | tee -a /home/ScriptFiles/log.txt;
  	echo '$logTime: Anti-Virus' | tee -a /home/ScriptFiles/log.txt;
   	apt-get install clamav clamav-daemon -y;
	echo '$logTime: ClamAV Installed' | tee -a /home/ScriptFiles/log.txt;
	if ! systemctl is-active --quiet clamav-freshclam; then
    		systemctl start clamav-freshclam
	fi;
 	echo '$logTime: ClamAV Database Up to Date' | tee -a /home/ScriptFiles/log.txt;
	echo '$logTime: Scanning System' | tee -a /home/ScriptFiles/log.txt;
	clamscan -r --remove --exclude-dir="^/sys" --exclude-dir="^/proc" --exclude-dir="^/dev" /;
 	echo | tee -a /home/ScriptFiles/log.txt;
	echo '$logTime: ANTI-VIRUS: System Scanned' | tee -a /home/ScriptFiles/log.txt;
	exec bash"

	echo "$logTime: UPDATE + ANTI-VIRUS RUNNING IN BACKGROUND" | tee -a /home/ScriptFiles/log.txt
}

configureAuditd() 
{
	echo | tee -a /home/ScriptFiles/log.txt
	clear
	echo "$logTime: Auditd:" | tee -a /home/ScriptFiles/log.txt
	
	apt install auditd -y
	echo "$logTime: Auditd Installed" | tee -a /home/ScriptFiles/log.txt
	sudo auditctl -e 1
	echo "$logTime: Auditd Activated" | tee -a /home/ScriptFiles/log.txt
}

autoLoginAndGuest()
{
	echo "In Development..."
}

scanCrontab() 
{
	echo | tee -a /home/ScriptFiles/log.txt
	clear
	echo "$logTime: Crontabs:" | tee -a /home/ScriptFiles/log.txt 

	cronDir="/var/spool/cron/crontabs"
	cronRes="ls $cronDir"
	
	if [ -z "$cronRes" ]; then
		echo "$logTime: No Active Crontabs" | tee -a /home/ScriptFiles/log.txt
	else
		echo "$logTime: Crontabs Found" | tee -a /home/ScriptFiles/log.txt
		echo "$logTime: These Users have a Crontab:" | tee -a /home/ScriptFiles/log.txt
		for ((i=0; i<${#authUsers[@]}; i++)); do
			if [ -f $cronDir/"${authUsers[i]}" ]; then
				echo "$logTime: User - ${authUsers[i]}" | tee -a /home/ScriptFiles/log.txt
				echo "Show It? (y/n)"
				read input
				if [ "$input" = "y" ]; then
					echo "$logTime: Opening Crontab - ${authUsers[i]}" | tee -a /home/ScriptFiles/log.txt
					gnome-terminal -- bash -c "
					crontab -u ${authUsers[i]} -e;
					exit"
				elif [ "$input" = "n" ]; then
					echo "$logTime: Searching..." | tee -a /home/ScriptFiles/log.txt
				else
					echo "Invalid answer, asking again..."
					i=$((i-1))
					echo
				fi
			fi
		done
		echo "$logTime: Crontabs Complete" | tee -a /home/ScriptFiles/log.txt
	fi
}

hackingTools()
{
	echo "$logTime: Hacking Tools:" | tee -a /home/ScriptFiles/log.txt
 
	if dpkg -l | grep -q apache; then
        	echo "$logTime: Apache Found, Awaiting Decision" | tee -a /home/ScriptFiles/log.txt
	 	echo "Remove Apache? (y/n)"
	 	read input
        	if [ $input = y ]; then
	 		echo "$logTime: Removing Apache" | tee -a /home/ScriptFiles/log.txt
      	        	apt-get autoremove --purge apache2 -y
			echo "$logTime: Apache Removed" | tee -a /home/ScriptFiles/log.txt
		else
            		if [ -e /etc/apache2/apache2.conf ]; then
				chown -R root:root /etc/apache2
				chown -R root:root /etc/apache
				echo \<Directory \> >> /etc/apache2/apache2.conf
				echo -e ' \t AllowOverride None' >> /etc/apache2/apache2.conf
				echo -e ' \t Order Deny,Allow' >> /etc/apache2/apache2.conf
				echo -e ' \t Deny from all' >> /etc/apache2/apache2.conf
				echo UserDir disabled root >> /etc/apache2/apache2.conf
			else
				apt-get install apache2 -y
				chown -R root:root /etc/apache2
				chown -R root:root /etc/apache
				echo \<Directory \> >> /etc/apache2/apache2.conf
				echo -e ' \t AllowOverride None' >> /etc/apache2/apache2.conf
				echo -e ' \t Order Deny,Allow' >> /etc/apache2/apache2.conf
				echo -e ' \t Deny from all' >> /etc/apache2/apache2.conf
				echo UserDir disabled root >> /etc/apache2/apache2.conf
			fi
        	fi
	fi

 	echo | tee -a /home/ScriptFiles/log.txt
  	clear

	if [ -d /etc/samba ]; then
 		echo "$logTime: Samba Found, Awaiting Decision" | tee -a /home/ScriptFiles/log.txt
   		echo "Remove Samba? (y/n)"
		read input
		if [ $input = y ]; then
			echo "$logTime: Removing Samba" | tee -a /home/ScriptFiles/log.txt
			apt-get autoremove --purge samba -y
			echo "$logTime: Samba Removed" | tee -a /home/ScriptFiles/log.txt
		else
			sed -i '82 i\restrict anonymous = 2' /etc/samba/smb.conf
		fi
	else
		echo "$logTime: Samba Not Found" | tee -a /home/ScriptFiles/log.txt
	fi

  	echo | tee -a /home/ScriptFiles/log.txt
  	clear
 
	if [ -d /etc/bind ]; then
		echo "$logTime: DNS Server Found, Awaiting Decision" | tee -a /home/ScriptFiles/log.txt
   		echo "Remove DNS? (y/n)"
		read input
		if [ $input = y ]; then
  			echo "$logTime: Removing DNS" | tee -a /home/ScriptFiles/log.txt
			apt-get autoremove --purge bind9 -y
   			echo "$logTime: DNS Removed" | tee -a /home/ScriptFiles/log.txt
		fi
	else
		echo "$logTime: DNS Not Found" | tee -a /home/ScriptFiles/log.txt
	fi

  	echo | tee -a /home/ScriptFiles/log.txt
  	clear
 
	if dpkg -l | grep -iq 'vsftpd|ftp'; then
		echo "$logTime: FTP Server Found, Awaiting Decision" | tee -a /home/ScriptFiles/log.txt
   		echo "Remove FTP? (y/n)"
		read input
		if [ $input = y ]; then
  			echo "$logTime: Stopping and Removing FTP" | tee -a /home/ScriptFiles/log.txt
			PID = `pgrep vsftpd`
			sed -i 's/^/#/' /etc/vsftpd.conf
			kill $PID
			echo "$logTime: FTP Stopped" | tee -a /home/ScriptFiles/log.txt
   
			apt-get autoremove --purge vsftpd ftp -y
   			echo "$logTime: FTP Removed" | tee -a /home/ScriptFiles/log.txt
		else
  			echo "$logTime: FTP Not Removed, Securing" | tee -a /home/ScriptFiles/log.txt
			sed -i 's/anonymous_enable=.*/anonymous_enable=NO/' /etc/vsftpd.conf
			sed -i 's/local_enable=.*/local_enable=YES/' /etc/vsftpd.conf
			sed -i 's/#write_enable=.*/write_enable=YES/' /etc/vsftpd.conf
			sed -i 's/#chroot_local_user=.*/chroot_local_user=YES/' /etc/vsftpd.conf
   			echo "$logTime: FTP Secured" | tee -a /home/ScriptFiles/log.txt
		fi
	else
		echo "$logTime: FTP Not Found" | tee -a /home/ScriptFiles/log.txt
	fi

  	echo | tee -a /home/ScriptFiles/log.txt
  	clear
 
	if dpkg -l | grep -q tftpd; then
		echo "$logTime: TFTPD Found, Awaiting Decision" | tee -a /home/ScriptFiles/log.txt
   		echo "Remove TFTPD? (y/n)"
		read input
		if [ $input = y ]
		then
  			echo "$logTime: Removing TFTPD" | tee -a /home/ScriptFiles/log.txt
			apt-get autoremove --purge tftpd -y
   			echo "$logTime: TFTPD Removed" | tee -a /home/ScriptFiles/log.txt
		fi
	else
		echo "$logTime: TFTPD Not Found" | tee -a /home/ScriptFiles/log.txt
	fi

  	echo | tee -a /home/ScriptFiles/log.txt
  	clear
 
	if dpkg -l | grep -Eq 'x11vnc|tightvncserver'; then
		echo "$logTime: VNC Found, Awaiting Decision" | tee -a /home/ScriptFiles/log.txt
   		echo "Remove VNC? (y/n)"
		read input
		if [ $input = y ]
		then
  			echo "$logTime: Removing VNC" | tee -a /home/ScriptFiles/log.txt
			apt-get autoremove --purge x11vnc tightvncserver -y
   			echo "$logTime: VNC Removed" | tee -a /home/ScriptFiles/log.txt
		fi
	else
		echo "$logTime: VNC Not Found" | tee -a /home/ScriptFiles/log.txt
	fi

  	echo | tee -a /home/ScriptFiles/log.txt
  	clear

	if dpkg -l | grep -q nfs-kernel-server; then	
		echo "$logTime: NFS Found, Awaiting Decision" | tee -a /home/ScriptFiles/log.txt
   		echo "Remove NFS? (y/n)"
		read input
		if [ $input = y ]
		then
  			echo "$logTime: Removing NFS" | tee -a /home/ScriptFiles/log.txt
			apt-get autoremove --purge nfs-kernel-server -y
   			echo "$logTime: NFS Removed" | tee -a /home/ScriptFiles/log.txt
		fi
	else
		echo "$logTime: NFS Not Found" | tee -a /home/ScriptFiles/log.txt
	fi

  	echo | tee -a /home/ScriptFiles/log.txt
  	clear

	if dpkg -l | grep -q john; then
        	echo "$logTime: John the Ripper Found" | tee -a /home/ScriptFiles/log.txt
        	apt-get autoremove --purge john -y
        	echo "$logTime: John the Ripper Removed" | tee -a /home/ScripeFiles/log.txt
	else
        	echo "$logTime: John the Ripper Not Found" | tee -a /home/ScriptFiles/log.txt
	fi

  	echo | tee -a /home/ScriptFiles/log.txt
  	clear
 
	if dpkg -l | grep -q hydra; then
		echo "$logTime: Hydra Found" | tee -a /home/ScriptFiles/log.txt
		apt-get autoremove --purge hydra -y
  		echo "$logTime: Hydra Removed" | tee -a /home/ScriptFiles/log.txt
	else
		echo "$logTime: Hydra Not Found" | tee -a /home/ScriptFiles/log.txt
	fi

  	echo | tee -a /home/ScriptFiles/log.txt
  	clear

	if dpkg -l | grep -q nginx; then
        	echo "$logTime: Nginx Found" | tee -a /home/ScriptFiles/log.txt
        	apt-get autoremove --purge nginx -y
	 	echo "$logTime: Nginx Removed" | tee -a /home/ScriptFiles/log.txt
	else
        	echo "$logTime: Nginx Not Found" | tee -a /home/ScriptFiles/log.txt
	fi

	echo | tee -a /home/ScriptFiles/log.txt
  	clear

   	if dpkg -l | grep -q wireshark; then
        	echo "$logTime: Wireshark Found" | tee -a /home/ScriptFiles/log.txt
        	apt-get autoremove --purge wireshark -y
	 	echo "$logTime: Wireshark Removed" | tee -a /home/ScriptFiles/log.txt
	else
        	echo "$logTime: Wireshark Not Found" | tee -a /home/ScriptFiles/log.txt
	fi

 	echo | tee -a /home/ScriptFiles/log.txt
  	clear

   	if dpkg -l | grep -q ophcrack; then
        	echo "$logTime: Ophcrack Found" | tee -a /home/ScriptFiles/log.txt
        	apt-get autoremove --purge ophcrack -y
	 	echo "$logTime: Ophcrack Removed" | tee -a /home/ScriptFiles/log.txt
	else
        	echo "$logTime: Ophcrack Not Found" | tee -a /home/ScriptFiles/log.txt
	fi

 	echo | tee -a /home/ScriptFiles/log.txt
  	clear

   	if dpkg -l | grep -q deluge; then
        	echo "$logTime: Deluge Found" | tee -a /home/ScriptFiles/log.txt
        	apt-get autoremove --purge deluge -y
	 	echo "$logTime: Deluge Removed" | tee -a /home/ScriptFiles/log.txt
	else
        	echo "$logTime: Deluge Not Found" | tee -a /home/ScriptFiles/log.txt
	fi
 
 	echo | tee -a /home/ScriptFiles/log.txt
  	clear
   
   	if dpkg -l | grep -q ettercap; then
        	echo "$logTime: Ettercap Found" | tee -a /home/ScriptFiles/log.txt
        	apt-get autoremove --purge ettercap -y
	 	echo "$logTime: Ettercap Removed" | tee -a /home/ScriptFiles/log.txt
	else
        	echo "$logTime: Ettercap Not Found" | tee -a /home/ScriptFiles/log.txt
	fi

 	echo | tee -a /home/ScriptFiles/log.txt
  	clear
 
	if dpkg -l | grep -q snmp; then
		echo "$logTime: SNMP Found" | tee -a /home/ScriptFiles/log.txt
		apt-get autoremove --purge snmp -y
  		echo "$logTime: SNMP Removed" | tee -a /home/ScriptFiles/log.txt
	else
		echo "$logTime: SNMP Not Found" | tee -a /home/ScriptFiles/log.txt
	fi

  	echo | tee -a /home/ScriptFiles/log.txt
  	clear
 
	if dpkg -l | grep -Eq 'postfix|sendmail'; then
		echo "$logTime: Mail Server(s) Found" | tee -a /home/ScriptFiles/log.txt
		apt-get autoremove --purge postfix sendmail -y
  		echo "$logTime: Mail Server(s) Removed" | tee -a /home/ScriptFiles/log.txt
	else
		echo "$logTime: Mail Servers Not Found" | tee -a /home/ScriptFiles/log.txt
	fi

  	echo | tee -a /home/ScriptFiles/log.txt
  	clear
 
	if dpkg -l | grep -q xinetd; then
		echo "$logTime: XINETD Found" | tee -a /home/ScriptFiles/log.txt
		apt-get autoremove --purge xinetd -y
  		echo "$logTime: XINETD Removed" | tee -a /home/ScriptFiles/log.txt
	else
		echo "$logTime: XINETD Not Found" | tee -a /home/ScriptFiles/log.txt
	fi
}

processesAndServices() 
{
	echo | tee -a /home/ScriptFiles/log.txt
	clear
	echo "$logTime: Processes and Services:" | tee -a /home/ScriptFiles/log.txt

	echo "Processes:"
	netstat -tulnp
	echo
	for ((;;)) do
		echo "Would you like to remove any process(es)? (y/n)"
		read input
		if [ "$input" == "y" ]; then
			echo "What process would you like to remove? (By PID)"
			read input
			if [ -f "ps aux | grep -v "grep" | grep $input" ]; then
				kill $input
				echo
				echo "Process $input, has been Removed"
				echo
			else
				echo
				echo "Invalid Input"
				echo
			fi
		elif [ "$input" == "n" ]; then
			echo
			break
		fi
	done
	echo 'Services: '
	service --status-all
	echo
	for ((;;)) do
		echo 'Would you like to stop any services? (y/n)'
		read input
		if [ "$input" == "y" ]; then
			echo 'What service would you like to stop? (By Service Name)'
			read input
			if [ -f "sudo service --status-all | grep $input" ]; then
				apt-get --purge $input
				echo
				echo 'Service '$input', has been stopped.'
				echo
			else
				echo
				echo 'Invalid input.'
				echo
			fi
		elif [ "$input" == "n" ]; then
			echo
			break
		fi
	done
}

automaticUpdates()
{
	echo | tee -a /home/ScriptFiles/log.txt
	clear
	echo "$logTime: Automatic Updates:" | tee -a /home/ScriptFiles/log.txt
	
	configFile="/etc/apt/apt.conf.d/10periodic"
	
	if ! dpkg -l | grep -q unattended-upgrades; then
    		apt-get install -y unattended-upgrades
    		echo "$logTime: Installed unattended-upgrades" | tee -a /home/ScriptFiles/log.txt
	fi

	if [ ! -f "$configFile" ]; then
		touch "$configFile"
		echo "$logTime: Created $configFile" | tee -a /home/ScriptFiles/log.txt
	fi

	sed -i '/APT::Periodic::Update-Package-Lists/c\APT::Periodic::Update-Package-Lists "1";' "$configFile"
	sed -i '/APT::Periodic::Download-Upgradeable-Packages/c\APT::Periodic::Download-Upgradeable-Packages "1";' "$configFile"
	sed -i '/APT::Periodic::AutocleanInterval/c\APT::Periodic::AutocleanInterval "7";' "$configFile"
	sed -i '/APT::Periodic::Unattended-Upgrade/c\APT::Periodic::Unattended-Upgrade "1";' "$configFile"

	grep -q 'APT::Periodic::Update-Package-Lists' "$configFile" || echo 'APT::Periodic::Update-Package-Lists "1";' | tee -a "$configFile"
	grep -q 'APT::Periodic::Download-Upgradeable-Packages' "$configFile" || echo 'APT::Periodic::Download-Upgradeable-Packages "1";' | tee -a "$configFile"
	grep -q 'APT::Periodic::AutocleanInterval' "$configFile" || echo 'APT::Periodic::AutocleanInterval "7";' | tee -a "$configFile"
	grep -q 'APT::Periodic::Unattended-Upgrade' "$configFile" || echo 'APT::Periodic::Unattended-Upgrade "1";' | tee -a "$configFile"

	echo "$logTime: Configured Automatic Update Settings:" | tee -a /home/ScriptFiles/log.txt
	echo "$logTime: APT::Periodic::Update-Package-Lists \"1\"" | tee -a /home/ScriptFiles/log.txt
	echo "$logTime: APT::Periodic::Download-Upgradeable-Packages \"1\"" | tee -a /home/ScriptFiles/log.txt
	echo "$logTime: APT::Periodic::AutocleanInterval \"7\"" | tee -a /home/ScriptFiles/log.txt
	echo "$logTime: APT::Periodic::Unattended-Upgrade \"1\"" | tee -a /home/ScriptFiles/log.txt
	
	dpkg-reconfigure --priority=low unattended-upgrades
	echo "$logTime: Configured unattended-upgrades" | tee -a /home/ScriptFiles/log.txt

	systemctl restart unattended-upgrades
	echo "$logTime: Restarted unattended-upgrades" | tee -a /home/ScriptFiles/log.txt
}

restoreBackup()
{
	echo | tee -a /home/ScriptFiles/log.txt
	clear
	echo "$logTime: Restoring Backups:" | tee -a /home/ScriptFiles/log.txt
	
	if [ -f /home/ScriptFiles/backupCheck ]; then
		echo "$logTime: Backups Found!" | tee -a /home/ScriptFiles/log.txt
		
		cp /home/ScriptFiles/common-auth.bak /etc/pam.d/common-auth
		echo "$logTime: Backup Restored for: /etc/pam.d/common-auth from /home/ScriptFiles/common-auth.bak" | tee -a /home/ScriptFiles/log.txt
		
		cp /home/ScriptFiles/common-password.bak /etc/pam.d/common-password
		echo "$logTime: Backup Restored for: /etc/pam.d/common-password from /home/ScriptFiles/common-password.bak" | tee -a /home/ScriptFiles/log.txt
		
		cp /home/ScriptFiles/login.defs.bak /etc/login.defs
		echo "$logTime: Backup Restored for: /etc/login.defs from /home/ScriptFiles/login.defs.bak" | tee -a /home/ScriptFiles/log.txt
		
		cp /home/ScriptFiles/ssh/sshd_config.bak /etc/ssh/sshd_config
		echo "$logTime: Backup Restored for: /etc/ssh/sshd_config from /home/ScriptFiles/sshd_config.bak" | tee -a /home/ScriptFiles/log.txt
	else
		echo "$logTime: No Backups Found" | tee -a /home/ScriptFiles/log.txt
	fi
}

autoScript()
{
manageUsers
manageGroups
passwordPolicy
activateFirewall
configureAuditd
autoLoginAndGuest
scanCrontab
hackingTools
processesAndServices
automaticUpdates
updateAndAntiVirus
}

if [ "$EUID" -ne 0 ]; then
	echo "Run Script with "sudo" or as Root"
	exit
fi

cd /home
mkdir ScriptFiles
cd ScriptFiles

logFile="log.txt"
if [ ! -f "$logFile" ]; then
	touch log.txt
	echo "$logTime: Log Created" | tee -a /home/ScriptFiles/log.txt
fi

adminFile="manageAdmins.txt"
if [ ! -f "$adminFile" ]; then
	touch manageAdmins.txt
	gedit manageAdmins.txt

	echo "$logTime: Admin File Complete" | tee -a /home/ScriptFiles/log.txt
fi

userFile="manageUsers.txt"
if [ ! -f "$userFile" ]; then
	touch manageUsers.txt
	gedit manageUsers.txt
	
	echo "$logTime: User File Complete" | tee -a /home/ScriptFiles/log.txt
fi

mapfile -t authUsers < $userFile
mapfile -t authAdmins < $adminFile

allUsers=(${authAdmins[@]} ${authUsers[@]})
if ! grep -q "SCRIPT INITIALIZED" /home/ScriptFiles/log.txt; then
	echo | tee -a /home/ScriptFiles/log.txt
	echo "$logTime: Inputted Users:" | tee -a /home/ScriptFiles/log.txt
	for user in "${allUsers[@]}"; do
		echo "$user" | tee -a /home/ScriptFiles/log.txt
	done
	clear
fi

if ! apt list --installed | grep -q "dbus-x11"; then
	apt-get install dbus-x11
fi

if ! apt list --installed | grep -q "net-tools"; then
	apt install net-tools
fi

clear
echo 'What is your Username?'
read username

echo | tee -a /home/ScriptFiles/log.txt
echo "$logTime: Username: $username" | tee -a /home/ScriptFiles/log.txt

clear
mainMenu
