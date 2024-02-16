#!/bin/bash

# Ensure the script is run as root
if [ "$(id -u)" -ne "0" ]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

# Variables
SSH_CONFIG="/etc/ssh/sshd_config"
AIDE_CONFIG="/etc/aide/aide.conf"
BACKUP_DIR="/secure_backup"
LOGWATCH_CONFIG="/usr/share/logwatch/default.conf/logwatch.conf"
YOUR_USERNAME="your_username" # Replace with the username allowed for SSH

# Function to install packages based on the distribution
install_package() {
    if [[ -f /etc/redhat-release ]]; then
        yum install -y "$@"
    elif [[ -f /etc/lsb-release ]]; then
        apt-get update
        apt-get install -y "$@"
    else
        echo "Unsupported distribution."
        exit 1
    fi
}

# Remove SUID/SGID permissions
echo "Removing SUID/SGID permissions..."
find / -perm /6000 -type f -exec chmod a-s {} \; &> /dev/null

# Restrict Cron
echo "Restricting cron jobs to root..."
rm -f /etc/cron.deny
echo ALL > /etc/cron.allow
chmod 600 /etc/cron.allow

# Install Auditd
echo "Installing and configuring Auditd..."
install_package auditd
systemctl enable auditd
systemctl start auditd

# Basic Auditd rules - Extend based on specific requirements
echo "Setting up basic Auditd rules..."
cat << EOF > /etc/audit/rules.d/audit.rules
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege
-w /var/log/auth.log -p wa -k auth
-w /var/log/secure -p wa -k auth
EOF

auditctl -R /etc/audit/rules.d/audit.rules

# Secure SSH
echo "Securing SSH..."
if [ -f "$SSH_CONFIG" ]; then
    cp $SSH_CONFIG $SSH_CONFIG.backup
    echo "PermitRootLogin no" >> $SSH_CONFIG
    echo "PasswordAuthentication no" >> $SSH_CONFIG
    echo "AllowUsers $YOUR_USERNAME" >> $SSH_CONFIG
    systemctl restart sshd
else
    echo "SSH config not found."
fi

# Install and configure Fail2Ban
echo "Installing Fail2Ban..."
install_package fail2ban
cat << EOF > /etc/fail2ban/jail.local
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF
systemctl enable fail2ban
systemctl start fail2ban

# Backup critical directories
echo "Setting up backups..."
mkdir -p $BACKUP_DIR
cat << EOF > /usr/local/bin/system_backup.sh
#!/bin/bash
rsync -a /etc $BACKUP_DIR
rsync -a /var $BACKUP_DIR
rsync -a /home $BACKUP_DIR
EOF
chmod +x /usr/local/bin/system_backup.sh
(crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/system_backup.sh") | crontab -

# System Integrity Monitoring with AIDE
echo "Configuring AIDE..."
install_package aide
aideinit
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
echo "0 4 * * * aide --check" | crontab -

# Firewall configuration
echo "Configuring firewall..."
install_package ufw firewalld
if [[ -f /etc/lsb-release ]]; then
    ufw allow ssh
    ufw allow http
    ufw allow https
    ufw allow mysql
    ufw enable
else
    systemctl start firewalld
    systemctl enable firewalld
    firewall-cmd --permanent --add-service=ssh
    firewall-cmd --permanent --add-service=http
    firewall-cmd --permanent --add-service=https
    firewall-cmd --permanent --add-service=mysql
    firewall-cmd --reload
fi

# Kernel Hardening
echo "Applying kernel hardening settings..."
cat << EOF >> /etc/sysctl.conf
# Prevent SYN flood attacks
net.ipv4.tcp_syncookies = 1
# Disable IP source routing
net.ipv4.conf.all.accept_source_route = 0
# Disable ICMP redirect acceptance
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
# Enable IP spoofing protection
net.ipv4.conf.all.rp_filter = 1
# Log Martians
net.ipv4.conf.all.log_martians = 1
EOF
sysctl -p

# Sys Stats for Forensics
echo "Enabling process accounting..."
install_package acct
systemctl start psacct || systemctl start acct
systemctl enable psacct || systemctl enable acct

# ClamAV / Lynis
echo "Installing ClamAV and Lynis for regular security scans..."
install_package clamav lynis
echo "0 5 * * * clamscan -r /" | crontab -
echo "0 6 * * * lynis audit system" | crontab -

# Rootkit Hunters
echo "Installing rkhunter and chkrootkit..."
install_package rkhunter chkrootkit
echo "0 4 * * * /usr/bin/rkhunter --update && /usr/bin/rkhunter --checkall --skip-keypress" | crontab -
echo "0 5 * * * /usr/sbin/chkrootkit" | crontab -

# Enhance log management?
# Additional security measures?

echo "Linux hardening script completed."
