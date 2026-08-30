import subprocess

# Global counters and remediation tracking
results = {"pass": 0, "fail": 0, "warn": 0}
remediations = []


def report(status, message, cis_ref="", fix=""):
    """Records and prints a check result. Tracks fixes for failures."""
    results[status] += 1
    label = {"pass": "[PASS]", "fail": "[FAIL]", "warn": "[WARN]"}
    ref = f" ({cis_ref})" if cis_ref else ""
    print(f"  {label[status]} {message}{ref}")
    if status == "fail" and fix:
        remediations.append((message, fix))


def run_command(command):
    """Runs a shell command and returns its stripped output."""
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout.strip()


# ---------- Section 5: Access, Authentication & SSH ----------

def check_ssh_root_login():
    config = run_command(['sudo', 'cat', '/etc/ssh/sshd_config'])
    if 'PermitRootLogin no' in config:
        report("pass", "SSH root login is disabled", "CIS 5.2.10")
    else:
        report("fail", "SSH root login is NOT disabled", "CIS 5.2.10",
               "Set 'PermitRootLogin no' in /etc/ssh/sshd_config")


def check_ssh_password_auth():
    config = run_command(['sudo', 'cat', '/etc/ssh/sshd_config'])
    if 'PasswordAuthentication no' in config:
        report("pass", "SSH password authentication is disabled", "CIS 5.2.11")
    else:
        report("warn", "SSH password auth enabled (key-based auth is safer)", "CIS 5.2.11",
               "Set 'PasswordAuthentication no' and use SSH keys")


def check_ssh_max_auth_tries():
    config = run_command(['sudo', 'cat', '/etc/ssh/sshd_config'])
    if 'MaxAuthTries 4' in config or 'MaxAuthTries 3' in config:
        report("pass", "SSH MaxAuthTries is set to 4 or fewer", "CIS 5.2.7")
    else:
        report("warn", "SSH MaxAuthTries not hardened", "CIS 5.2.7",
               "Set 'MaxAuthTries 4' in /etc/ssh/sshd_config")


def check_ssh_empty_passwords():
    config = run_command(['sudo', 'cat', '/etc/ssh/sshd_config'])
    if 'PermitEmptyPasswords no' in config:
        report("pass", "SSH empty passwords are disabled", "CIS 5.2.9")
    else:
        report("fail", "SSH allows empty passwords", "CIS 5.2.9",
               "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config")


def check_ssh_idle_timeout():
    config = run_command(['sudo', 'cat', '/etc/ssh/sshd_config'])
    if 'ClientAliveInterval' in config:
        report("pass", "SSH idle timeout is configured", "CIS 5.2.16")
    else:
        report("warn", "SSH idle timeout not configured", "CIS 5.2.16",
               "Set 'ClientAliveInterval 300' and 'ClientAliveCountMax 3'")


# ---------- Section 6: File Permissions ----------

def check_passwd_permissions():
    perms = run_command(['stat', '-c', '%a', '/etc/passwd'])
    if perms == '644':
        report("pass", f"/etc/passwd permissions are correct ({perms})", "CIS 6.1.2")
    else:
        report("fail", f"/etc/passwd permissions are {perms}, should be 644", "CIS 6.1.2",
               "Run: sudo chmod 644 /etc/passwd")


def check_shadow_permissions():
    perms = run_command(['stat', '-c', '%a', '/etc/shadow'])
    if perms in ['640', '600', '000']:
        report("pass", f"/etc/shadow permissions are correct ({perms})", "CIS 6.1.3")
    else:
        report("fail", f"/etc/shadow permissions are {perms}, should be 640 or stricter", "CIS 6.1.3",
               "Run: sudo chmod 640 /etc/shadow")


def check_group_permissions():
    perms = run_command(['stat', '-c', '%a', '/etc/group'])
    if perms == '644':
        report("pass", f"/etc/group permissions are correct ({perms})", "CIS 6.1.4")
    else:
        report("fail", f"/etc/group permissions are {perms}, should be 644", "CIS 6.1.4",
               "Run: sudo chmod 644 /etc/group")


def check_crontab_permissions():
    perms = run_command(['stat', '-c', '%a', '/etc/crontab'])
    if perms in ['600', '700']:
        report("pass", f"/etc/crontab permissions are correct ({perms})", "CIS 5.1.2")
    else:
        report("fail", f"/etc/crontab permissions are {perms}, should be 600", "CIS 5.1.2",
               "Run: sudo chmod 600 /etc/crontab")


# ---------- Section 3: Network Parameters ----------

def check_ip_forwarding():
    value = run_command(['cat', '/proc/sys/net/ipv4/ip_forward'])
    if value == '0':
        report("pass", "IP forwarding is disabled", "CIS 3.2.1")
    else:
        report("fail", "IP forwarding is ENABLED (should be disabled)", "CIS 3.2.1",
               "Run: sudo sysctl -w net.ipv4.ip_forward=0")


def check_syn_cookies():
    value = run_command(['cat', '/proc/sys/net/ipv4/tcp_syncookies'])
    if value == '1':
        report("pass", "TCP SYN cookies are enabled", "CIS 3.3.9")
    else:
        report("fail", "TCP SYN cookies are disabled (DoS protection)", "CIS 3.3.9",
               "Run: sudo sysctl -w net.ipv4.tcp_syncookies=1")


# ---------- Section 5: User Account Checks ----------

def check_empty_passwords():
    shadow = run_command(['sudo', 'cat', '/etc/shadow'])
    empty_found = False
    for line in shadow.splitlines():
        fields = line.split(':')
        if len(fields) > 1 and fields[1] == '':
            empty_found = True
            break
    if not empty_found:
        report("pass", "No accounts with empty passwords", "CIS 6.2.1")
    else:
        report("fail", "Account(s) with EMPTY password found", "CIS 6.2.1",
               "Lock or set passwords for affected accounts")


def check_duplicate_uids():
    passwd = run_command(['cat', '/etc/passwd'])
    uids = []
    for line in passwd.splitlines():
        fields = line.split(':')
        if len(fields) > 2:
            uids.append(fields[2])
    if len(uids) == len(set(uids)):
        report("pass", "No duplicate UIDs found", "CIS 6.2.5")
    else:
        report("fail", "Duplicate UID(s) found", "CIS 6.2.5",
               "Ensure each user has a unique UID")


def check_root_uid():
    passwd = run_command(['cat', '/etc/passwd'])
    root_accounts = []
    for line in passwd.splitlines():
        fields = line.split(':')
        if len(fields) > 2 and fields[2] == '0':
            root_accounts.append(fields[0])
    if root_accounts == ['root']:
        report("pass", "Only 'root' has UID 0", "CIS 6.2.9")
    else:
        report("fail", f"Multiple UID 0 accounts: {root_accounts}", "CIS 6.2.9",
               "Only the root account should have UID 0")


# ---------- Section 5: Password Policy ----------

def check_password_max_age():
    logindefs = run_command(['cat', '/etc/login.defs'])
    for line in logindefs.splitlines():
        line = line.strip()
        if line.startswith('PASS_MAX_DAYS'):
            parts = line.split()
            if len(parts) > 1 and parts[1].isdigit() and int(parts[1]) <= 365:
                report("pass", f"Password max age is {parts[1]} days", "CIS 5.4.1.1")
                return
    report("warn", "Password max age not set to 365 or fewer", "CIS 5.4.1.1",
           "Set 'PASS_MAX_DAYS 365' in /etc/login.defs")


def check_password_min_days():
    logindefs = run_command(['cat', '/etc/login.defs'])
    for line in logindefs.splitlines():
        line = line.strip()
        if line.startswith('PASS_MIN_DAYS'):
            parts = line.split()
            if len(parts) > 1 and parts[1].isdigit() and int(parts[1]) >= 1:
                report("pass", f"Password min age is {parts[1]} day(s)", "CIS 5.4.1.2")
                return
    report("warn", "Password min age not set to 1 or more", "CIS 5.4.1.2",
           "Set 'PASS_MIN_DAYS 1' in /etc/login.defs")


def check_password_warn_age():
    logindefs = run_command(['cat', '/etc/login.defs'])
    for line in logindefs.splitlines():
        line = line.strip()
        if line.startswith('PASS_WARN_AGE'):
            parts = line.split()
            if len(parts) > 1 and parts[1].isdigit() and int(parts[1]) >= 7:
                report("pass", f"Password warn age is {parts[1]} days", "CIS 5.4.1.3")
                return
    report("warn", "Password warn age not set to 7 or more", "CIS 5.4.1.3",
           "Set 'PASS_WARN_AGE 7' in /etc/login.defs")


def check_default_umask():
    logindefs = run_command(['cat', '/etc/login.defs'])
    for line in logindefs.splitlines():
        line = line.strip()
        if line.startswith('UMASK'):
            parts = line.split()
            if len(parts) > 1 and parts[1] in ['027', '077']:
                report("pass", f"Default umask is {parts[1]}", "CIS 5.4.5")
                return
    report("warn", "Default umask not set to 027 or stricter", "CIS 5.4.5",
           "Set 'UMASK 027' in /etc/login.defs")


def check_gshadow_permissions():
    perms = run_command(['stat', '-c', '%a', '/etc/gshadow'])
    if perms in ['640', '600', '000']:
        report("pass", f"/etc/gshadow permissions are correct ({perms})", "CIS 6.1.5")
    else:
        report("fail", f"/etc/gshadow permissions are {perms}, should be 640 or stricter", "CIS 6.1.5",
               "Run: sudo chmod 640 /etc/gshadow")


# ---------- Section 3: Firewall ----------

def check_firewall():
    status = run_command(['sudo', 'ufw', 'status'])
    if 'Status: active' in status:
        report("pass", "UFW firewall is active", "CIS 3.5.1.1")
    else:
        report("fail", "UFW firewall is NOT active", "CIS 3.5.1.1",
               "Run: sudo ufw enable")


def check_auditd():
    status = run_command(['systemctl', 'is-active', 'auditd'])
    if status == 'active':
        report("pass", "auditd logging service is running", "CIS 4.1.1.1")
    else:
        report("warn", "auditd is not running (needed for audit logging)", "CIS 4.1.1.1",
               "Run: sudo apt install auditd && sudo systemctl enable --now auditd")


def print_summary():
    total = results["pass"] + results["fail"] + results["warn"]
    print(f"\n{'=' * 45}")
    print(f"  SUMMARY")
    print(f"{'=' * 45}")
    print(f"  Passed:   {results['pass']}")
    print(f"  Failed:   {results['fail']}")
    print(f"  Warnings: {results['warn']}")
    if total > 0:
        score = (results["pass"] / total) * 100
        print(f"  Compliance Score: {score:.1f}%")

    if remediations:
        print(f"\n{'=' * 45}")
        print(f"  REMEDIATION GUIDANCE")
        print(f"{'=' * 45}")
        for issue, fix in remediations:
            print(f"  [!] {issue}")
            print(f"      Fix: {fix}\n")


print("=" * 45)
print("  CIS HARDENING AUDITOR")
print("=" * 45)
print()

check_ssh_root_login()
check_ssh_password_auth()
check_ssh_max_auth_tries()
check_ssh_empty_passwords()
check_ssh_idle_timeout()
check_passwd_permissions()
check_shadow_permissions()
check_group_permissions()
check_crontab_permissions()
check_ip_forwarding()
check_syn_cookies()
check_empty_passwords()
check_duplicate_uids()
check_root_uid()
check_password_max_age()
check_password_min_days()
check_password_warn_age()
check_default_umask()
check_gshadow_permissions()
check_firewall()
check_auditd()

print_summary()
