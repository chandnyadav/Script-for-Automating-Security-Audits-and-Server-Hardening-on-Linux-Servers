 # Linux Security Audits and Server Hardening
This script is designed to perform a comprehensive security audit on a Linux system. It checks user and group configurations, file permissions, running services, firewall settings, network configurations, available updates, and log monitoring. Additionally, it provides options for hardening the system against potential vulnerabilities.

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Usage](#usage)
4. [Audit Functions](#audit-functions)
   - [User and Group Audit](#user-and-group-audit)
   - [File and Directory Permission Audit](#file-and-directory-permission-audit)
   - [Service Audit](#service-audit)
   - [Firewall Audit](#firewall-audit)
   - [Network Audit](#network-audit)
   - [Update Audit](#update-audit)
   - [Log Monitoring](#log-monitoring)
5. [Hardening Functions](#hardening-functions)
   - [SSH Hardening](#ssh-hardening)
   - [IPv6 Hardening](#ipv6-hardening)
   - [GRUB Hardening](#grub-harden)
   - [Firewall Hardening](#firewall-harden)
   - [Automatic Updates Hardening](#harden-updates)
6. [Help and Menu](#help-and-menu)
7. [Conclusion](#conclusion)

## Overview

The Linux Security Audit Dashboard script is a powerful tool for system administrators to assess the security posture of their Linux servers. It provides detailed insights into user accounts, file permissions, running services, firewall configurations, and more, allowing for proactive security management.

## Features

- **User and Group Audit**: Identifies human users, groups, and any non-standard root users.
- **File and Directory Permission Audit**: Checks for world-writable files and directories, and verifies permissions for SSH keys.
- **Service Audit**: Lists running services and checks for unauthorized or unexpected services.
- **Firewall Audit**: Assesses the status of firewall services and lists open ports.
- **Network Audit**: Provides a summary of IP addresses and checks SSH port exposure.
- **Update Audit**: Checks for available security updates and ensures automatic updates are enabled.
- **Log Monitoring**: Monitors logs for suspicious activity, particularly related to SSH.

## Installation

1. **Clone the Repository** (if applicable):
   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. **Make the Script Executable**:
   ```bash
   chmod +x audit.sh
   ```

3. **Run the Script**:
   ```bash
   ./audit.sh
   ```


## Usage

To run the script, save it as `security_audit.sh` and execute it in the terminal with the desired options:

```bash
bash security_audit.sh [options]
```


 

The script can be executed with various options to perform specific audits or hardening tasks. Below are the available options:

### Options

- `--useraudit`: Show user and group audit.
- `--permcheck`: Show file and directory permissions audit.
- `--serviceaudit`: Show service audit.
- `--firewallaudit`: Show firewall & network audit.
- `--networkaudit`: Show IP/network configuration checks.
- `--updateaudit`: Security updates audit.
- `--logaudit`: Log monitoring.
- `--hardening`: Interactive menu for server hardening steps.
- `--all`: Run all audits.


### How to Use Audit Options


- **User and Group Audit**:
  ```bash
  ./audit.sh --useraudit
  ```

- **File and Directory Permission Audit**:
  ```bash
  ./audit.sh --permcheck
  ```

- **Service Audit**:
  ```bash
  ./audit.sh --serviceaudit
  ```

- **Firewall Audit**:
  ```bash
  ./audit.sh --firewallaudit
  ```

- **Network Audit**:
  ```bash
  ./audit.sh --networkaudit
  ```

- **Security Updates Audit**:
  ```bash
  ./audit.sh --updateaudit
  ```

- **Log Monitoring**:
  ```bash
  ./audit.sh --logaudit
  ```

- **Server Hardening Menu**:
  ```bash
  ./audit.sh --hardening
  ```

- **Run All Audits**:
  ```bash
  ./audit.sh --all
  ```

### Help Option

To display the help menu with all available options, run:
```bash
./audit.sh --help
```

## Audit Functions

### User and Group Audit

This function checks for human users (UID >= 1000) with valid shells, groups (GID >= 1000), non-root UID 0 users, and users without passwords.

```bash
user_and_group_audit() {
    echo -e "${CYAN}========== USER AND GROUP AUDIT ==========${NC}"
    echo -e "${GREEN}[1] Human Users (UID >= 1000 with valid shell):${NC}"
    awk -F: '$3 >= 1000 && $7 !~ /(nologin|false)/ { print "- " $1 }' /etc/passwd
    ...
}
```

### File and Directory Permission Audit

This function checks for world-writable files and directories, and verifies the permissions of `.ssh` directories and files for human users.

```bash
perm_check() {
    echo -e "${CYAN}\n========== FILE AND DIRECTORY PERMISSION AUDIT ==========${NC}"
    echo -e "${GREEN}[1] World-writable Files:${NC}"
    find / -xdev -type f -perm -0002 -exec echo "World-writable file found: {}" \; 2>/dev/null
    ...
}
```

### Service Audit

This function lists running services, checks for unauthorized services, and verifies the status of critical services.

```bash
service_audit() {
    echo -e "${CYAN}\n========== SERVICE AUDIT ==========${NC}"
    AUTHORIZED_SERVICES=("sshd" "cron" "rsyslog" "networking" "firewalld" "iptables")
    ...
}
```

### Firewall Audit

This function checks the status of firewall services (firewalld, UFW, iptables) and lists open ports.

```bash
firewall_audit() {
    echo -e "${CYAN}========== FIREWALL STATUS CHECK ==========${NC}"
    if systemctl is-active --quiet firewalld; then
        ...
    fi
}
```

### Network Audit

This function summarizes the server's IP addresses and checks SSH port exposure.

```bash
network_audit() {
    echo -e "${CYAN}========== SERVER IP ADDRESS SUMMARY ==========${NC}"
    public_ip=$(curl -s ifconfig.me)
    ...
}
```

### Update Audit

This function checks for available security updates and ensures automatic updates are enabled.

```bash
update_audit() {
    echo -e "${CYAN}========== SECURITY UPDATES AND PATCHING ==========${NC}"
    echo -e "\n🔍 Checking Network Connectivity...\n"
    ...
}
```

### Log Monitoring

This function checks logs for suspicious SSH login attempts and other relevant activities.

```bash
log_audit() {
    echo -e "${CYAN}========== LOG MONITORING ==========${NC}"
    LOG_FILE="/var/log/auth.log"
    ...
}
```

## Hardening Functions

### SSH Hardening

This function sets up SSH key-based authentication and hardens SSH configurations.

```bash
harden_ssh() {
  echo "🔐 SSH Key-Based Authentication Setup and Root Hardening"
  ...
}
```

### IPv6 Hardening

This function disables IPv6 and configures SafeSquid to use IPv4 only.

```bash
harden_ipv6() {
  echo -e "${CYAN}========== DISABLING IPV6 AND CONFIGURING SAFESQUID ==========${NC}"
  ...
}
```

### GRUB Hardening

This function secures the GRUB bootloader by setting a password.

```bash
harden_grub() {
  echo -e "${GREEN}[+] Securing GRUB Bootloader on Ubuntu 20.04${NC}"
  ...
}
```

### Firewall Hardening

This function configures iptables firewall rules for enhanced security.

```bash
harden_firewall() {
  echo -e "${GREEN}[+] Configuring iptables firewall rules...${NC}"
  ...
}
```

### Automatic Updates Hardening

This function enables automatic security updates on the system.

```bash
harden_updates() {
  echo -e "${GREEN}[+] Enabling automatic security updates on Ubuntu 20.04...${NC}"
  ...
}
```

## Help and Menu

The script provides a help menu that outlines the available options and their descriptions.

```bash
show_help() {
    echo "Usage: $0 [--useraudit] [--permcheck] [--serviceaudit] [--firewallaudit] [--networkaudit] [--updateaudit] [--logaudit] [--hardening] [--all]"
    ...
}
```

## Conclusion

The Linux Security Audit Dashboard script is an essential tool for maintaining the security of Linux systems. By regularly running this audit, system administrators can identify vulnerabilities and take proactive measures to secure their environments. The hardening functions further enhance the security posture of the system, ensuring that best practices are followed.
