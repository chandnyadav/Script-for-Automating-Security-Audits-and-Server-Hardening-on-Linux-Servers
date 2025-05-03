#!/bin/bash

# ---------------------- COLORS & BANNER ----------------------
CYAN='\033[1;36m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

banner() {
    echo -e "${CYAN}"
    echo "+------------------------------------------------------------+"
    printf "|%60s|\n" " "
    printf "|%33s%-27s|\n" "LINUX SECURITY AUDIT DASHBOARD" " "
    echo "+------------------------------------------------------------+"
    echo -e "${NC}"
}

# ---------------------- AUDIT FUNCTIONS ----------------------

user_and_group_audit() {
    echo -e "${CYAN}========== USER AND GROUP AUDIT ==========${NC}"
    echo -e "${GREEN}[1] Human Users (UID >= 1000 with valid shell):${NC}"
    awk -F: '$3 >= 1000 && $7 !~ /(nologin|false)/ { print "- " $1 }' /etc/passwd
    echo
    echo -e "${GREEN}[2] Groups (GID >= 1000 and not 'nogroup'):${NC}"
    awk -F: '$3 >= 1000 && $1 != "nogroup" { print "- " $1 }' /etc/group
    echo
    echo -e "${YELLOW}[3] WARNING: Any Non-root UID 0 Users:${NC}"
    awk -F: '($3 == 0 && $1 != "root") { print "WARNING: Non-standard root user found: " $1 }' /etc/passwd
    echo
    echo -e "${YELLOW}[4] Users Without Passwords:${NC}"
    sudo awk -F: '
      NR==FNR && $3 >= 1000 && $7 !~ /(nologin|false)/ { users[$1]=$7; next }
      FNR!=NR && ($1 in users) && ($2 == "" || $2 ~ /^\*|^!/) {
        printf "%s (shell: %s) has NO password set\n", $1, users[$1]
      }
    ' /etc/passwd /etc/shadow
}

perm_check() {
    echo -e "${CYAN}\n========== FILE AND DIRECTORY PERMISSION AUDIT ==========${NC}"
    echo -e "${GREEN}[1] World-writable Files:${NC}"
    find / -xdev -type f -perm -0002 -exec echo "World-writable file found: {}" \; 2>/dev/null
    echo -e "${GREEN}[2] World-writable Directories:${NC}"
    find / -xdev -type d -perm -0002 -exec echo "World-writable directory found: {}" \; 2>/dev/null
    echo -e "${GREEN}[3] .ssh Directory and Key Permissions (for human users):${NC}"
    awk -F: '$3 >= 1000 && $7 !~ /(false|nologin)/ {print $1, $6}' /etc/passwd | while read user home; do
      ssh_dir="$home/.ssh"
      echo -e "\nUser: ${user}"
      if [ -d "$ssh_dir" ]; then
        echo -e "  ${GREEN}✔ Found .ssh directory at $ssh_dir${NC}"
        dir_perm=$(stat -c "%a" "$ssh_dir")
        if [ "$dir_perm" -ne 700 ]; then
          echo -e "  ${RED}❌ .ssh directory permission is $dir_perm (should be 700)${NC}"
        else
          echo -e "  ${GREEN}✅ .ssh directory permission is secure ($dir_perm)${NC}"
        fi
        for file in authorized_keys id_rsa id_rsa.pub; do
          filepath="$ssh_dir/$file"
          if [ -e "$filepath" ]; then
            perm=$(stat -c "%a" "$filepath")
            case "$file" in
              authorized_keys|id_rsa) expected=600 ;;
              id_rsa.pub) expected=644 ;;
            esac
            if [ "$perm" -ne "$expected" ]; then
              echo -e "  ${RED}❌ $file permission is $perm (should be $expected)${NC}"
            else
              echo -e "  ${GREEN}✅ $file permission is correct ($perm)${NC}"
            fi
          else
            echo -e "  ${YELLOW}⚠ $file not found in $ssh_dir${NC}"
          fi
        done
      else
        echo -e "  ${RED}❌ .ssh directory NOT found for user $user${NC}"
      fi
    done
    echo -e "${GREEN}[4] SUID/SGID Executable Files:${NC}"
    echo "=== SUID Executables ==="
    find / -type f -perm -4000 -exec ls -l {} \; 2>/dev/null
    echo
    echo "=== SGID Executables ==="
    find / -type f -perm -2000 -exec ls -l {} \; 2>/dev/null
}

service_audit() {
    echo -e "${CYAN}\n========== SERVICE AUDIT ==========${NC}"
    AUTHORIZED_SERVICES=("sshd" "cron" "rsyslog" "networking" "firewalld" "iptables")
    CRITICAL_SERVICES=("sshd" "iptables" "firewalld")
    echo -e "${GREEN}[1] Running services:${NC}"
    RUNNING_SERVICES=($(systemctl list-units --type=service --state=running 2>/dev/null | awk '{print $1}' | grep '\.service' | sed 's/\.service//'))
    for svc in "${RUNNING_SERVICES[@]}"; do
      echo " - $svc"
    done
    echo
    echo -e "${YELLOW}[2] Unauthorized or unexpected services:${NC}"
    for svc in "${RUNNING_SERVICES[@]}"; do
      if [[ ! " ${AUTHORIZED_SERVICES[@]} " =~ " $svc " ]]; then
          echo -e "${RED}[ERROR] Unauthorized service running: $svc${NC}"
      fi
    done
    echo
    echo -e "${GREEN}[3] Critical services status:${NC}"
    for crit_svc in "${CRITICAL_SERVICES[@]}"; do
      if systemctl is-active --quiet "$crit_svc"; then
        echo "[OK] $crit_svc is running"
      else
        echo -e "${RED}[ERROR] Critical service $crit_svc is NOT running${NC}"
      fi
    done
    echo
    echo -e "${GREEN}[4] SSH Configuration and Port Check:${NC}"
    SSHD_CONF="/etc/ssh/sshd_config"
    if [ -f "$SSHD_CONF" ]; then
      grep -E "^Port|^PermitRootLogin|^PasswordAuthentication" "$SSHD_CONF"
      SSH_PORT=$(grep "^Port" "$SSHD_CONF" | awk '{print $2}')
      [ -z "$SSH_PORT" ] && SSH_PORT=22
      if ss -tuln 2>/dev/null | grep -q ":$SSH_PORT"; then
        echo "[OK] SSH is listening on port $SSH_PORT"
      else
        echo -e "${RED}[ERROR] SSH is not listening on port $SSH_PORT${NC}"
      fi
    else
      echo -e "${RED}[ERROR] SSH config file not found!${NC}"
    fi
    echo
    echo -e "${GREEN}[5] All listening ports:${NC}"
    ss -tuln
    echo
    echo -e "${YELLOW}[6] Non-standard or insecure ports (besides common services):${NC}"
    LISTEN_PORTS=$(ss -tuln 2>/dev/null | awk '/LISTEN/ {split($5, a, ":"); print a[length(a)]}' | sort -n | uniq)
    STANDARD_PORTS=(22 53 80 123 443 25 110 143 587 993 995)
    for port in $LISTEN_PORTS; do
      if [[ ! " ${STANDARD_PORTS[@]} " =~ " $port " ]]; then
        echo -e "${RED}[WARNING] Unusual port open: $port${NC}"
      fi
    done
}

firewall_audit() {
    echo -e "${CYAN}========== FIREWALL STATUS CHECK ==========${NC}"
    if systemctl is-active --quiet firewalld; then
        echo -e "${GREEN}✔ firewalld is active${NC}"
        echo "Active Rules:"
        firewall-cmd --list-all
    elif systemctl is-active --quiet ufw; then
        echo -e "${GREEN}✔ UFW is active${NC}"
        ufw status verbose
    elif command -v iptables &> /dev/null && iptables -L -n | grep -q "ACCEPT"; then
        echo -e "${GREEN}✔ iptables is active${NC}"
        iptables -L -n -v
    else
        echo -e "${RED}✘ No active firewall service found (iptables, ufw, or firewalld)${NC}"
    fi
    echo -e "\n${CYAN}========== OPEN PORTS AND SERVICES ==========${NC}"
    if command -v ss &>/dev/null; then
        ss -tulnp
    elif command -v netstat &>/dev/null; then
        netstat -tulnp
    else
        echo -e "${RED}✘ Neither ss nor netstat is available to list open ports${NC}"
    fi
    echo -e "\n${CYAN}========== SSH STATUS & CONFIGURATION ==========${NC}"
    if systemctl is-active --quiet sshd; then
        echo -e "${GREEN}✔ SSH is active${NC}"
        sshd -T | grep -Ei 'port|permitrootlogin|passwordauthentication'
    else
        echo -e "${RED}✘ SSH service is not running${NC}"
    fi
    echo -e "\n${CYAN}========== IP FORWARDING STATUS ==========${NC}"
    ip_forward=$(sysctl net.ipv4.ip_forward | awk '{print $3}')
    if [ "$ip_forward" -eq 1 ]; then
        echo -e "${RED}✘ IP forwarding is ENABLED (net.ipv4.ip_forward = 1)${NC}"
    else
        echo -e "${GREEN}✔ IP forwarding is DISABLED (net.ipv4.ip_forward = 0)${NC}"
    fi
    echo -e "\n${CYAN}========== OTHER INSECURE NETWORK SETTINGS ==========${NC}"
    rp_filter=$(sysctl net.ipv4.conf.all.rp_filter | awk '{print $3}')
    if [ "$rp_filter" -ne 1 ]; then
        echo -e "${RED}✘ Reverse Path Filtering (rp_filter) is NOT fully enabled${NC}"
    else
        echo -e "${GREEN}✔ Reverse Path Filtering is enabled (rp_filter = 1)${NC}"
    fi
    icmp_redirects=$(sysctl net.ipv4.conf.all.accept_redirects | awk '{print $3}')
    if [ "$icmp_redirects" -ne 0 ]; then
        echo -e "${RED}✘ System accepts ICMP redirects (potential MITM risk)${NC}"
    else
        echo -e "${GREEN}✔ ICMP redirects are disabled${NC}"
    fi
}

network_audit() {
    echo -e "${CYAN}========== SERVER IP ADDRESS SUMMARY ==========${NC}"
    public_ip=$(curl -s ifconfig.me)
    echo -e "${RED}Public IP:${NC}  $public_ip"
    private_ips=$(hostname -I)
    for ip in $private_ips; do
        echo -e "${GREEN}Private IP:${NC} $ip"
    done
    echo -e "\n${CYAN}========== SSH PORT EXPOSURE CHECK ==========${NC}"
    echo -e "Ports and interfaces where SSH is listening:"
    ss -tnlp | grep ':22 ' | while read -r line; do
        ip=$(echo "$line" | awk '{print $4}' | cut -d':' -f1)
        if [[ "$ip" == "0.0.0.0" ]] || [[ "$ip" == "::" ]]; then
            echo -e "  ${RED}⚠ SSH is listening on all interfaces (including public)${NC}"
        elif [[ "$ip" =~ ^10\. || "$ip" =~ ^192\.168\. || "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
            echo -e "  ${GREEN}✔ SSH is bound to private IP: $ip${NC}"
        else
            echo -e "  ${RED}⚠ SSH is listening on public IP:  $public_ip${NC}"
        fi
    done
}

update_audit() {
    echo -e "${CYAN}========== SECURITY UPDATES AND PATCHING ==========${NC}"
    echo -e "\n🔍 Checking Network Connectivity...\n"
    ping -c 2 archive.ubuntu.com > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "❌ ERROR: Cannot reach archive.ubuntu.com. Check internet connection or DNS."
        return
    fi
    echo -e "\n🔍 Updating Package Lists (including Security)...\n"
    sudo apt update
    echo -e "\n🔒 Checking for Available Security Updates...\n"
    sudo apt list --upgradable 2>/dev/null | grep -i security
    echo -e "\n⚙️ Ensuring Automatic Security Updates are Enabled...\n"
    AUTO_UPDATE_FILE="/etc/apt/apt.conf.d/20auto-upgrades"
    if [ -f "$AUTO_UPDATE_FILE" ]; then
        echo "✅ Auto-update file exists. Checking contents:"
        cat "$AUTO_UPDATE_FILE"
    else
        echo "⚠️  Auto-update file not found. Creating it..."
        sudo bash -c "cat > $AUTO_UPDATE_FILE" <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
        echo "✅ Created auto-update configuration at $AUTO_UPDATE_FILE"
    fi
    echo -e "\n📦 Installing 'unattended-upgrades' package if not already installed...\n"
    dpkg -l | grep unattended-upgrades > /dev/null
    if [ $? -ne 0 ]; then
        sudo apt install -y unattended-upgrades
    else
        echo "✅ 'unattended-upgrades' is already installed."
    fi
    echo -e "\n✅ Script execution complete."
}

log_audit() {
    echo -e "${CYAN}========== LOG MONITORING ==========${NC}"
    LOG_FILE="/var/log/auth.log"
    echo "🔍 Checking for suspicious SSH login attempts..."
    echo "--------------------------------------------------"
    if [ ! -f "$LOG_FILE" ]; then
        echo "❌ Log file $LOG_FILE not found. Cannot proceed."
        return
    fi
    echo -e "📄 Recent failed SSH login attempts:"
    grep "Failed password" $LOG_FILE | tail -n 10
    echo
    echo "📊 Suspicious IPs with multiple failed logins:"
    grep "Failed password" $LOG_FILE | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head
    echo
    echo "🧑‍💻 Root login attempts (successful or failed):"
    grep "root" $LOG_FILE | grep "sshd"
    echo
    echo "✅ Log check complete."
}

# ------------------ HARDENING FUNCTIONS ----------------------

harden_ssh() {
  echo "🔐 SSH Key-Based Authentication Setup and Root Hardening"
  echo "---------------------------------------------------------"
  echo "📦 Checking for OpenSSH server..."
  if ! command -v sshd >/dev/null 2>&1; then
    echo "❌ OpenSSH server is not installed. Installing..."
    sudo apt update && sudo apt install -y openssh-server
  else
    echo "✅ OpenSSH server is installed."
  fi
  echo "📁 Creating .ssh directory if not present..."
  mkdir -p ~/.ssh
  chmod 700 ~/.ssh
  KEY_PATH=~/.ssh/id_rsa
  if [ -f "$KEY_PATH" ]; then
    echo "✅ SSH key already exists at $KEY_PATH"
  else
    echo "🔑 Generating SSH key..."
    ssh-keygen -t rsa -b 4096 -N "" -f "$KEY_PATH"
  fi
  echo "➕ Adding public key to ~/.ssh/authorized_keys"
  cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
  chmod 600 ~/.ssh/authorized_keys
  echo "🛠️ Backing up and modifying SSH config..."
  SSHD_CONFIG="/etc/ssh/sshd_config"
  if [ ! -f "${SSHD_CONFIG}.bak" ]; then
    sudo cp $SSHD_CONFIG ${SSHD_CONFIG}.bak
  fi
  sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' $SSHD_CONFIG
  sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' $SSHD_CONFIG
  sudo sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' $SSHD_CONFIG
  sudo sed -i 's/^#*UsePAM.*/UsePAM no/' $SSHD_CONFIG
  echo "🔁 Restarting SSH service..."
  sudo systemctl restart ssh
  echo "✅ SSH hardening complete!"
  echo "✔️ Key-based login is set up."
  echo "❌ Root password login is disabled."
}

harden_ipv6() {
  echo -e "${CYAN}========== DISABLING IPV6 AND CONFIGURING SAFESQUID ==========${NC}"
  SYSCTL_FILE="/etc/sysctl.conf"
  grep -q "disable_ipv6" "$SYSCTL_FILE" || cat <<EOF | sudo tee -a "$SYSCTL_FILE"
# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
  sudo sysctl -p &>/dev/null
  echo -e "${GREEN}✔ IPv6 disabled via sysctl.${NC}"
  GRUB_FILE="/etc/default/grub"
  if ! grep -q "ipv6.disable=1" "$GRUB_FILE"; then
    sudo sed -i 's/GRUB_CMDLINE_LINUX="/GRUB_CMDLINE_LINUX="ipv6.disable=1 /' "$GRUB_FILE"
    sudo update-grub &>/dev/null
    echo -e "${GREEN}✔ IPv6 disabled via GRUB (will apply on reboot).${NC}"
  else
    echo -e "${GREEN}✔ IPv6 already disabled in GRUB.${NC}"
  fi
  echo -e "\n${CYAN}→ Updating SafeSquid to use IPv4 only...${NC}"
  SAFE_CONF="/opt/safesquid/safesquid.conf"
  if [ -f "$SAFE_CONF" ]; then
    sudo sed -i 's/^bind_address=.*$/bind_address=0.0.0.0/' "$SAFE_CONF"
    echo -e "${GREEN}✔ Updated bind_address in safesquid.conf to IPv4 (0.0.0.0).${NC}"
  else
    echo -e "${RED}✘ SafeSquid configuration not found at $SAFE_CONF${NC}"
  fi
  echo -e "\n${CYAN}→ Restarting SafeSquid...${NC}"
  if sudo systemctl restart safesquid &>/dev/null; then
    echo -e "${GREEN}✔ SafeSquid restarted successfully.${NC}"
  else
    echo -e "${RED}✘ Failed to restart SafeSquid. Please check logs.${NC}"
  fi
  echo -e "\n${CYAN}→ Verifying IPv6 is disabled and SafeSquid is using IPv4...${NC}"
  ip a | grep inet6 &>/dev/null && echo -e "${RED}⚠ IPv6 addresses still present (reboot may be required).${NC}" || echo -e "${GREEN}✔ No active IPv6 addresses found.${NC}"
  ss -ltnp | grep safesquid | grep -E ':::|:::' && echo -e "${RED}⚠ SafeSquid is still bound to IPv6.${NC}" || echo -e "${GREEN}✔ SafeSquid is using IPv4 only.${NC}"
}

harden_grub() {
  echo -e "${GREEN}[+] Securing GRUB Bootloader on Ubuntu 20.04${NC}"
  read -s -p "Enter a password for GRUB admin: " grub_pass
  echo
  read -s -p "Confirm the password: " grub_pass2
  echo
  if [ "$grub_pass" != "$grub_pass2" ]; then
      echo -e "${RED}[-] Passwords do not match. Exiting.${NC}"
      return
  fi
  echo -e "${GREEN}[+] Generating GRUB password hash...${NC}"
  hashed_output=$(echo -e "$grub_pass\n$grub_pass" | grub-mkpasswd-pbkdf2 2>/dev/null)
  hashed_password=$(echo "$hashed_output" | grep "PBKDF2" | awk '{print $7}')
  if [ -z "$hashed_password" ]; then
      echo -e "${RED}[-] Failed to generate hashed password.${NC}"
      return
  fi
  grub_custom="/etc/grub.d/40_custom"
  if ! grep -q "set superusers=" "$grub_custom"; then
      echo -e "${GREEN}[+] Backing up 40_custom...${NC}"
      sudo cp "$grub_custom" "${grub_custom}.bak"
      echo -e "${GREEN}[+] Writing GRUB user config to 40_custom${NC}"
      cat <<EOF | sudo tee -a "$grub_custom" > /dev/null
# GRUB password protection
set superusers="admin"
password_pbkdf2 admin $hashed_password
EOF
  else
      echo -e "${CYAN}[i] GRUB user config already present in 40_custom. Skipping append.${NC}"
  fi
  echo -e "${GREEN}[+] Updating GRUB configuration...${NC}"
  if sudo update-grub; then
      echo -e "${GREEN}[✔] GRUB password setup complete. Unauthorized boot changes are now blocked.${NC}"
  else
      echo -e "${RED}[-] GRUB update failed. Check /etc/grub.d/ files for syntax issues.${NC}"
  fi
}

harden_firewall() {
  echo -e "${GREEN}[+] Configuring iptables firewall rules...${NC}"
  sudo iptables -F
  sudo iptables -X
  sudo iptables -t nat -F
  sudo iptables -t nat -X
  sudo iptables -t mangle -F
  sudo iptables -t mangle -X
  sudo iptables -P INPUT DROP
  sudo iptables -P FORWARD DROP
  sudo iptables -P OUTPUT ACCEPT
  sudo iptables -A INPUT -i lo -j ACCEPT
  sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT
  sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
  sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
  echo -e "${GREEN}[+] Applying rules...${NC}"
  sudo iptables -L -v
  if command -v iptables-save >/dev/null && [ -d /etc/iptables ]; then
      echo -e "${GREEN}[+] Saving rules for persistence...${NC}"
      sudo iptables-save > /etc/iptables/rules.v4
  else
      echo -e "${RED}[!] iptables-persistent not found. Install with: sudo apt install iptables-persistent${NC}"
  fi
  echo -e "${GREEN}[✔] Firewall configured successfully.${NC}"
}

harden_updates() {
  echo -e "${GREEN}[+] Enabling automatic security updates on Ubuntu 20.04...${NC}"
  echo -e "${GREEN}[+] Installing unattended-upgrades...${NC}"
  sudo apt update -y
  sudo apt install unattended-upgrades apt-listchanges -y
  echo -e "${GREEN}[+] Enabling in /etc/apt/apt.conf.d/20auto-upgrades...${NC}"
  sudo bash -c 'cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF'
  echo -e "${GREEN}[+] Configuring security upgrades and autoremove in 50unattended-upgrades...${NC}"
  sudo sed -i 's|//\s*"${distro_id}:${distro_codename}-security";|"${distro_id}:${distro_codename}-security";|' /etc/apt/apt.conf.d/50unattended-upgrades
  sudo sed -i 's|//Unattended-Upgrade::Remove-Unused-Dependencies.*|Unattended-Upgrade::Remove-Unused-Dependencies "true";|' /etc/apt/apt.conf.d/50unattended-upgrades
  sudo sed -i 's|//Unattended-Upgrade::Automatic-Reboot.*|Unattended-Upgrade::Automatic-Reboot "true";|' /etc/apt/apt.conf.d/50unattended-upgrades
  if systemctl list-timers --all | grep -q unattended-upgrades; then
    echo -e "${GREEN}[+] Restarting unattended-upgrades timer...${NC}"
    sudo systemctl restart unattended-upgrades
  fi
  echo -e "${GREEN}[+] Running unattended-upgrades dry run to test config...${NC}"
  sudo unattended-upgrade --dry-run --debug
  echo -e "${GREEN}[✔] Automatic security updates are now configured.${NC}"
}

hardening_menu() {
  while true; do
    echo -e "${CYAN}"
    echo "+---------------- SERVER HARDENING MENU --------------------+"
    echo "| 1) SSH Key-based Authentication & Root Hardening          |"
    echo "| 2) Disable IPv6 & Hardening for SafeSquid                |"
    echo "| 3) Secure GRUB/Bootloader                                |"
    echo "| 4) Firewall (Recommended iptables Rules)                 |"
    echo "| 5) Automatic Security Updates                            |"
    echo "| 6) ALL Hardening Steps                                   |"
    echo "| 0) Exit Hardening Menu                                   |"
    echo "+----------------------------------------------------------+"
    echo -ne "${NC}Enter choice (1-6, 0 to exit): "
    read -r hard_choice
    case "$hard_choice" in
      1) harden_ssh ;;
      2) harden_ipv6 ;;
      3) harden_grub ;;
      4) harden_firewall ;;
      5) harden_updates ;;
      6) harden_ssh; harden_ipv6; harden_grub; harden_firewall; harden_updates ;;
      0|q|Q) echo "Exiting server hardening menu."; break ;;
      *) echo -e "${YELLOW}Invalid selection. Please choose 1-6 or 0 to exit.${NC}" ;;
    esac
    echo
  done
}

# ---------------------- HELP/MENU/MAIN ----------------------

show_help() {
    echo "Usage: $0 [--useraudit] [--permcheck] [--serviceaudit] [--firewallaudit] [--networkaudit] [--updateaudit] [--logaudit] [--hardening] [--all]"
    echo
    echo "  --useraudit      Show user and group audit"
    echo "  --permcheck      Show file and directory permissions audit"
    echo "  --serviceaudit   Show service audit"
    echo "  --firewallaudit  Show firewall & network audit"
    echo "  --networkaudit   Show IP/network configuration checks"
    echo "  --updateaudit    Security updates audit"
    echo "  --logaudit       Log monitoring"
    echo "  --hardening      Interactive menu for server hardening steps"
    echo "  --all            Run all audits"
}

main() {
    banner
    [ $# -eq 0 ] && show_help && exit 1
    for sw in "$@"; do
        case "$sw" in
            --useraudit)      user_and_group_audit ;;
            --permcheck)      perm_check ;;
            --serviceaudit)   service_audit ;;
            --firewallaudit)  firewall_audit ;;
            --networkaudit)   network_audit ;;
            --updateaudit)    update_audit ;;
            --logaudit)       log_audit ;;
            --hardening)      hardening_menu ;;
            --all)            user_and_group_audit; perm_check; service_audit; firewall_audit; \
                              network_audit; update_audit; log_audit ;;
            --help|-h)        show_help ;;
            *)                echo "Unknown option: $sw"; show_help; exit 1 ;;
        esac
    done
}

main "$@"
