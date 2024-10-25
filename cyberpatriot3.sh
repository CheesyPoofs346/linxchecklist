#!/bin/bash

#VARIABLE DECLARATION:
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

#MAIN MENU:
#Shows the main menu and options for the script to execute.
mainMenu() {
	echo | tee -a /home/ScriptFiles/log.txt
	echo "SCRIPT INITIALIZED" | tee -a /home/ScriptFiles/log.txt
	clear

	echo 'Linux CyberPatriot Script'
	echo 'Written by Ryan George'
	echo
	echo 'Welcome '$username'!'
	echo
	echo 'Please input what you need to do. (0 for multiple)'
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
    		softwareCheck
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

# Additional script message:
echo 'Script 3'
echo 'By Scooby Dooo'
echo
echo 'Welcome Dylan!'
echo

#ACTIVATE MULTIPLE:
#Gives the user the option to activate multiple of the options available.
activateMultiple() {
	clear
	opList=()
	
	echo 'Hello '$username'! Welcome to Activate Multiple.'
	echo
	echo "Please enter all the operations you wish to do."
	echo "Type 1 number into each line and press enter."
	echo "Each command will be documented then activated in order."
	echo
	echo "At any time, you can type 0 to start the operations."
	echo "You can also run all functions by typing -1."
	echo
	for ((;;)) do
		echo "Please input the operation you wish to do. (-1 for auto, 0 to Start)"
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
	 		softwareCheck
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

#MANAGE USERS:
#Removes/Adds users onto the system, as well as removing/adding admin privileges based on input files.
manageUsers() 
{
	echo | tee -a /home/ScriptFiles/log.txt
	clear
	echo "Starting Manage Users..." | tee -a /home/ScriptFiles/log.txt

	#Combines files for a full list of expected users
	allUsers=(${authAdmins[@]} ${authUsers[@]})
	echo "Authorized Users:" | tee -a /home/ScriptFiles/log.txt
	for user in "${allUsers[@]}"; do
		echo "$user" | tee -a /home/ScriptFiles/log.txt
	done
	
	#Makes a list of what users are on the system currently
	mapfile -t systemUsers < <(cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1)
	
	#Checks if there is any unauthorized users on the system
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
        		echo "Removed Unauthorized User - $user" | tee -a /home/ScriptFiles/log.txt
    		fi
	done
	
	#Re-maps the file to include an updated list of users
	mapfile -t systemUsers < <(cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1)
	
	#Gets missing users on the system
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
        		echo "Added Missing User - $user" | tee -a /home/ScriptFiles/log.txt
    		fi
	done
	
	#Re-maps the file to include an updated list of users
	mapfile -t systemUsers < <(cut -d: -f1,3 /etc/passwd | egrep ':[0-9]{4}$' | cut -d: -f1)
	clear
	
	#//////////
	
	#ADMIN USERS
	read -a sudoers <<< $(echo "$(grep '^sudo:' /etc/group | cut -d ':' -f 4)" | tr ',' ' ')
	
	echo | tee -a /home/ScriptFiles/log.txt
	clear
	echo "Authorized Admins:" | tee -a /home/ScriptFiles/log.txt
	for user in "${sudoers[@]}"; do
		echo "$user" | tee -a /home/ScriptFiles/log.txt
	done
	
	#Removes any unauthorized Admins
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
        		echo "Removed Unauthorized Admin Permissions - $user" | tee -a /home/ScriptFiles/log.txt
    		fi
	done
	
	#Adds any Admins not on the system already
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
        		echo "Added Missing Admin Permissions - $user" | tee -a /home/ScriptFiles/log.txt
    		fi
	done
	clear
}

#MANAGE GROUPS:
#Uses user input to add/delete groups as well as adding/removing users from groups.
manageGroups()
{
	echo | tee -a /home/ScriptFiles/log.txt
	clear
	echo "Working on Groups..." | tee -a /home/ScriptFiles/log.txt	
	
	while true; do
		echo "Do you want to add a new group?"
		read input
		if [ "$input" == "y" ]; then
			echo "Please enter the name of the Group"
			read input 
			groupadd $input
			echo "Added Group - $input" | tee -a /home/ScriptFiles/log.txt
			clear
		else
			break
		fi
	done

	while true; do
		echo "Do you want to delete a group?"
		read input
		if [ "$input" == "y" ]; then
			echo "Please enter the name of the Group"
			read input 
			groupdel $input
			echo "Removed Group - $input" | tee -a /home/ScriptFiles/log.txt
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
			echo "Added User - $username, Group - $input" | tee -a /home/ScriptFiles/log.txt
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
			echo "Removed User - $username, Group - $input" | tee -a /home/ScriptFiles/log.txt
			clear
		else
			break
		fi
	done
}

#PASSWORD POLICY:
#Creates backups and changes security config files to secure passwords and authentication.
passwordPolicy()
{
	echo | tee -a /home/ScriptFiles/log.txt
	clear
	echo "Working on Password Policy..." | tee -a /home/ScriptFiles/log.txt

 	#apt-get install libpam-cracklib
  	#echo "Installed libpam-cracklib" | tee -a /home/ScriptFiles/log.txt

	#Flag File for Restoration
	if [ ! -f /home/ScriptFiles/backupCheck ]; then
		touch /home/ScriptFiles/backupCheck
		echo "Created the Flag File, backupCheck" | tee -a /home/ScriptFiles/log.txt
	fi
	
	# Backup Configuration Files
	cp /etc/pam.d/common-password /home/ScriptFiles/common-password.bak
	echo "Created Backup for: /etc/pam.d/common-password at /home/ScriptFiles/common-password.bak" | tee -a /home/ScriptFiles/log.txt
	
	cp /etc/pam.d/common-auth /home/ScriptFiles/common-auth.bak
	echo "Created Backup for: /etc/pam.d/common-auth at /home/ScriptFiles/common-auth.bak" | tee -a /home/ScriptFiles/log.txt
	
	cp /etc/login.defs /home/ScriptFiles/login.defs.bak
	echo "Created Backup for: /etc/login.defs at /home/ScriptFiles/login.defs.bak" | tee -a /home/ScriptFiles/log.txt
	
	cp /etc/ssh/sshd_config /home/ScriptFiles/sshd_config.bak
	echo "Created Backup for: /etc/ssh/sshd_config at /home/ScriptFiles/sshd_config.bak" | tee -a /home/ScriptFiles/log.txt

	#PAM Password Quality
	sed -i 's/^password.*pam_pwquality.so.*/password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=3 maxclassrepeat=2/' /etc/pam.d/common-password
	echo "Modified /etc/pam.d/common-password" | tee -a /home/ScriptFiles/log.txt

	#PAM Authentication
	sed -i 's/^auth\s*\[success=2\s*default=ignore\]\s*pam_unix\.so\s*nullok/auth	[success=2 default=ignore]	pam_unix.so/' /etc/pam.d/common-auth
	echo "auth required pam_faillock.so preauth silent audit deny=3 unlock_time=1200" | tee -a /home/ScriptFiles/log.txt
	echo "auth [default=die] pam_faillock.so authfail audit deny=3 unlock_time=1200" | tee -a /home/ScriptFiles/log.txt
	echo "auth sufficient pam_faillock.so authsucc" | tee -a /home/ScriptFiles/log.txt
	
	echo "Modified /etc/pam.d/common-auth" | tee -a /home/ScriptFiles/log.txt

	#Password Expiry Protocols
	sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   30/' /etc/login.defs
	sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   5/' /etc/login.defs
	sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   5/' /etc/login.defs
	echo "Modified /etc/login.defs" | tee -a /home/ScriptFiles/log.txt

	#Root Login + Reset
	sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
	echo "Modified /etc/ssh/sshd_config" | tee -a /home/ScriptFiles/log.txt
	systemctl restart sshd
	echo "Restarted SSHD" | tee -a /home/ScriptFiles/log.txt
	
	#Sets New Passwords for All Users
	echo | tee -a /home/ScriptFiles/log.txt
	clear
	echo "Changing Passwords..." | tee -a /home/ScriptFiles/log.txt
	
	password=c0OlP@S5w0rD!1
	
	for user in "${allUsers[@]}"; do
		if [[ "$user" != "${allUsers[0]}" ]]; then
			echo "$user:$password" | chpasswd
			echo "$user:$password" | tee -a /home/ScriptFiles/log.txt
		fi
	done
}

#ACTIVATE FIREWALL:
#Installs and enables uncomplicated firewall on the device.
activateFirewall() 
{
	echo | tee -a /home/ScriptFiles/log.txt
	clear
	echo "Activating Firewall..." | tee -a /home/ScriptFiles/log.txt
	apt install ufw
	echo "UFW Installed" | tee -a /home/ScriptFiles/log.txt
	ufw enable
	echo "UFW Enabled" | tee -a /home/ScriptFiles/log.txt
}

#UPDATE AND ANTI-VIRUS:
#Fully updates the device in a seperate terminal, then runs ClamAV to scan for virus infections
updateAndAntiVirus() 
{
	echo | tee -a /home/ScriptFiles/log.txt
	clear
	echo "Fully Updating the System..." | tee -a /home/ScriptFiles/log.txt
	
	gnome-terminal -- bash -c "
	echo 'Terminal Opened' | tee -a /home/ScriptFiles/log.txt;
 	echo 'Update Starting' | tee -a /home/ScriptFiles/log.txt;
	apt-get update -y; 
	apt upgrade -y;
 	echo | tee -a /home/ScriptFiles/log.txt;
	echo 'UPDATE: Updates Complete' | tee -a /home/ScriptFiles/log.txt;
 
 	echo | tee -a /home/ScriptFiles/log.txt;
  	echo 'Enacting Anti-Virus...' | tee -a /home/ScriptFiles/log.txt;
   	apt-get install clamav clamav-daemon -y;
	echo 'ClamAV Installed' | tee -a /home/ScriptFiles/log.txt;
	if ! systemctl is-active --quiet clamav-freshclam; then
    		systemctl start clamav-freshclam
	fi;
 	echo 'ClamAV Database Up to Date' | tee -a /home/ScriptFiles/log.txt;
	echo 'Scanning System' | tee -a /home/ScriptFiles/log.txt;
	clamscan -r --remove --exclude-dir="^/sys" --exclude-dir="^/proc" --exclude-dir="^/dev" /;
 	echo | tee -a /home/ScriptFiles/log.txt;
	echo 'ANTI-VIRUS: System Scanned, Viruses Removed' | tee -a /home/ScriptFiles/log.txt;
	exec bash"

	echo "Update in Progress..." | tee -a /home/ScriptFiles/log.txt
}

#CONFIGURE AUDITD:
#Downloads and activates Auditd to help security.
configureAuditd() 
{
	echo | tee -a /home/ScriptFiles/log.txt
	clear
	echo "Configuring Auditd..." | tee -a /home/ScriptFiles/log.txt
	
	apt install auditd -y
	echo "Auditd Installed" | tee -a /home/ScriptFiles/log.txt
	sudo auditctl -e 1
	echo "Auditd Activated" | tee -a /home/ScriptFiles/log.txt
}

autoLoginAndGuest()
{
	echo "In Development..."
}

#SCAN CRONTAB:
#Scans to see if there are any crontabs active, if so, lists them.
scanCrontab() 
{
	echo | tee -a /home/ScriptFiles/log.txt
	clear
	echo "Scanning Crontabs..." | tee -a /home/ScriptFiles/log.txt 

	cronDir="/var/spool/cron/crontabs"
	cronRes="ls $cronDir"
	
	if [ -z "$cronRes" ]; then
		echo "No Active Crontabs" | tee -a /home/ScriptFiles/log.txt
	else
		echo "Crontabs Found" | tee -a /home/ScriptFiles/log.txt
		echo "These Users have a Crontab:" | tee -a /home/ScriptFiles/log.txt
		for ((i=0; i<${#authUsers[@]}; i++)); do
			if [ -f $cronDir/"${authUsers[i]}" ]; then
				echo "${authUsers[i]}" | tee -a /home/ScriptFiles/log.txt
				echo "Show It? (y/n)"
				read input
				if [ "$input" = "y" ]; then
					echo "Opening Crontab - ${authUsers[i]}" | tee -a /home/ScriptFiles/log.txt
					gnome-terminal -- bash -c "
					crontab -u ${authUsers[i]} -e;
					exit"
				elif [ "$input" = "n" ]; then
					echo "Searching for Next User..." | tee -a /home/ScriptFiles/log.txt
				else
					echo "Invalid answer, asking again..."
					i=$((i-1))
					echo
				fi
			fi
		done
		echo "No More Crontabs Located" | tee -a /home/ScriptFiles/log.txt
	fi
}

#SOFTWARE CHECK:
#Scans the system for common unauthorized software and removes it.
softwareCheck()
{
	echo "In Progress..."
}

#PROCESSES AND SERVICES:
#Displays active processes and services as well as options to stop them.
processesAndServices() 
{
	echo | tee -a /home/ScriptFiles/log.txt
	clear
	echo "Examining Active Processes and Services..." | tee -a /home/ScriptFiles/log.txt

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
	echo "Configuring automatic updates..." | tee -a /home/ScriptFiles/log.txt
	
	configFile="/etc/apt/apt.conf.d/10periodic"
	
	#Checks if unattended-upgrades is installed, if not, installs it
	if ! dpkg -l | grep -q unattended-upgrades; then
    		apt-get install -y unattended-upgrades
    		echo "Installed unattended-upgrades" | tee -a /home/ScriptFiles/log.txt
	fi

	# Ensure the file exists
	if [ ! -f "$configFile" ]; then
		touch "$configFile"
		echo "Created $configFile" | tee -a /home/ScriptFiles/log.txt
	fi

	# Update the necessary configuration using sed
	sed -i '/APT::Periodic::Update-Package-Lists/c\APT::Periodic::Update-Package-Lists "1";' "$configFile"
	sed -i '/APT::Periodic::Download-Upgradeable-Packages/c\APT::Periodic::Download-Upgradeable-Packages "1";' "$configFile"
	sed -i '/APT::Periodic::AutocleanInterval/c\APT::Periodic::AutocleanInterval "7";' "$configFile"
	sed -i '/APT::Periodic::Unattended-Upgrade/c\APT::Periodic::Unattended-Upgrade "1";' "$configFile"

	# Add lines if they do not exist in the file
	grep -q 'APT::Periodic::Update-Package-Lists' "$configFile" || echo 'APT::Periodic::Update-Package-Lists "1";' | tee -a "$configFile"
	grep -q 'APT::Periodic::Download-Upgradeable-Packages' "$configFile" || echo 'APT::Periodic::Download-Upgradeable-Packages "1";' | tee -a "$configFile"
	grep -q 'APT::Periodic::AutocleanInterval' "$configFile" || echo 'APT::Periodic::AutocleanInterval "7";' | tee -a "$configFile"
	grep -q 'APT::Periodic::Unattended-Upgrade' "$configFile" || echo 'APT::Periodic::Unattended-Upgrade "1";' | tee -a "$configFile"

	echo "Configured Automatic Update Settings:" | tee -a /home/ScriptFiles/log.txt
	echo "APT::Periodic::Update-Package-Lists \"1\"" | tee -a /home/ScriptFiles/log.txt
	echo "APT::Periodic::Download-Upgradeable-Packages \"1\"" | tee -a /home/ScriptFiles/log.txt
	echo "APT::Periodic::AutocleanInterval \"7\"" | tee -a /home/ScriptFiles/log.txt
	echo "APT::Periodic::Unattended-Upgrade \"1\"" | tee -a /home/ScriptFiles/log.txt
	
	dpkg-reconfigure --priority=low unattended-upgrades
	echo "Configured unattended-upgrades" | tee -a /home/ScriptFiles/log.txt

	systemctl restart unattended-upgrades
	echo "Restarted unattended-upgrades" | tee -a /home/ScriptFiles/log.txt
}

restoreBackup()
{
	echo | tee -a /home/ScriptFiles/log.txt
	clear
	echo "Searching for Backups..." | tee -a /home/ScriptFiles/log.txt
	
	if [ -f /home/ScriptFiles/backupCheck ]; then
		echo "Backups Found, Restoring..." | tee -a /home/ScriptFiles/log.txt
		
		cp /home/ScriptFiles/common-auth.bak /etc/pam.d/common-auth
		echo "Backup Restored for: /etc/pam.d/common-auth from /home/ScriptFiles/common-auth.bak" | tee -a /home/ScriptFiles/log.txt
		
		cp /home/ScriptFiles/common-password.bak /etc/pam.d/common-password
		echo "Backup Restored for: /etc/pam.d/common-password from /home/ScriptFiles/common-password.bak" | tee -a /home/ScriptFiles/log.txt
		
		cp /home/ScriptFiles/login.defs.bak /etc/login.defs
		echo "Backup Restored for: /etc/login.defs from /home/ScriptFiles/login.defs.bak" | tee -a /home/ScriptFiles/log.txt
		
		cp /home/ScriptFiles/ssh/sshd_config.bak /etc/ssh/sshd_config
		echo "Backup Restored for: /etc/ssh/sshd_config from /home/ScriptFiles/sshd_config.bak" | tee -a /home/ScriptFiles/log.txt
	else
		echo "No Backups Found" | tee -a /home/ScriptFiles/log.txt
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
softwareCheck
processesAndServices
automaticUpdates
updateAndAntiVirus
}

#BELOW ARE RESOURCES FOR STARTING THE SCRIPT:

#SUDO/ROOT CHECK:
#Checks if the script was ran as root, if not, it exits the script
if [ "$EUID" -ne 0 ]; then
	echo "Run Script with "sudo" or as Root"
	exit
fi

#USER MANAGER FILE:
#Navigates to create a folder, then
#Creates files that can be used for other methods.

cd /home
mkdir ScriptFiles
cd ScriptFiles

logFile="log.txt"
if [ ! -f "$logFile" ]; then
	touch log.txt
	echo "Log Created" | tee -a /home/ScriptFiles/log.txt
fi

adminFile="manageAdmins.txt"
if [ ! -f "$adminFile" ]; then
	touch manageAdmins.txt
	gedit manageAdmins.txt

	echo "Admin File Complete" | tee -a /home/ScriptFiles/log.txt
fi

userFile="manageUsers.txt"
if [ ! -f "$userFile" ]; then
	touch manageUsers.txt
	gedit manageUsers.txt
	
	echo "User File Complete" | tee -a /home/ScriptFiles/log.txt
fi

#Assigns a list variable for all the users on the system
mapfile -t authUsers < $userFile
mapfile -t authAdmins < $adminFile

allUsers=(${authAdmins[@]} ${authUsers[@]})
if ! grep -q "SCRIPT INITIALIZED" /home/ScriptFiles/log.txt; then
	echo | tee -a /home/ScriptFiles/log.txt
	echo "Inputted Users:" | tee -a /home/ScriptFiles/log.txt
	for user in "${allUsers[@]}"; do
		echo "$user" | tee -a /home/ScriptFiles/log.txt
	done
	clear
fi

#DBUS CHECK:
#Ensures new terminals can be opened using Gnome
if ! apt list --installed | grep -q "dbus-x11"; then
	apt-get install dbus-x11
fi

#NETSTAT CHECK:
#Ensures the user has net-tools downloaded for the Processes and Services method.'
if ! apt list --installed | grep -q "net-tools"; then
	apt install net-tools
fi

#USERNAME INPUT:
#Gets the username of the user to later be used.
clear
echo 'What is your Username?'
read username

echo | tee -a /home/ScriptFiles/log.txt
echo "Username: $username" | tee -a /home/ScriptFiles/log.txt

#PROGRAM START:
#Calls the main menu to start the program.
clear
mainMenu
