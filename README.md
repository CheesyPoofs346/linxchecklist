# linxchecklist

Install Fail2ban

Protect against brute-force attacks:

Copy code
sudo apt-get install fail2ban


Configure /etc/fail2ban/jail. local as needed and start the service:

Copy code
sudo systemctl start fail2ban
sudo systemctl enable fail2ban

Install and Configure Lynis for Security Audits

Run a security audit to identify issues:

Copy code
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
