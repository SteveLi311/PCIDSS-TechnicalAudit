#!/bin/bash
#SecuCollab IDC Ubuntu 14.04 Compliance Monitoring
# This script targets Ubuntu 14.04 (Upstart-era; pre-systemd).
# Key differences vs. 18.04/20.04/22.04:
#   - Uses `service` / `initctl` instead of `systemctl`
#   - Uses `netstat` (with `ss` fallback) for listening ports
#   - Reads /var/log/auth.log directly instead of `journalctl`
#   - No `timedatectl`; uses `ntpq -p` and /etc/ntp.conf
#   - Falls back to python2 if python3 is not installed

myhost=$(hostname)
mycompany="cherri"

ip=$(hostname -I | awk '{print $1}')
echo "Target IP: $ip"

kk='--------------------------------'

date3=$(date +"%H:%M")
date1=$(date '+%Y%m%d')

# ensure outputs go under /mnt/ELK_Log/Security-Configuration

# Destination root for generated artifacts (must exist beforehand)
dest_root="/mnt/ELK_Log/Security-Configuration"

if [ ! -d "$dest_root" ]; then
  echo "Destination root path '$dest_root' does not exist." >&2
  exit 2
fi
# SecuCollab — host info collector (Ubuntu 14.04)

set -u

myhost=$(hostname 2>/dev/null || echo unknown-host)
ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo 127.0.0.1)
date_ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Detect Ubuntu version for metadata
ubuntu_ver=""
if [ -r /etc/os-release ]; then
  ubuntu_ver=$(. /etc/os-release 2>/dev/null; echo "${VERSION_ID:-unknown}")
elif [ -r /etc/lsb-release ]; then
  ubuntu_ver=$(. /etc/lsb-release 2>/dev/null; echo "${DISTRIB_RELEASE:-unknown}")
fi
echo "Detected Ubuntu version: ${ubuntu_ver:-unknown}"

base="$dest_root/${ip}_${myhost}-security-audit"
raw_dir="$base/raw"
report_file="$base/${ip}_${myhost}_report.json"
mkdir -p "$raw_dir"

echo "Collecting host info for $ip / $myhost"

safe_collect() {
  local dest="$1"; shift
  echo "- $dest"
  { "$@" 2>/dev/null || true; } > "$dest" || true
}

# Collect minimal items
safe_collect "$raw_dir/os.txt" uname -a
safe_collect "$raw_dir/os_release.txt" sh -c 'cat /etc/os-release 2>/dev/null || cat /etc/lsb-release 2>/dev/null || true'
safe_collect "$raw_dir/lsb_release.txt" lsb_release -a
safe_collect "$raw_dir/kernel.txt" uname -r
safe_collect "$raw_dir/accounts.txt" sh -c 'cat /etc/passwd 2>/dev/null | sed "/^\s*$/d"'
safe_collect "$raw_dir/ssh.txt" sh -c 'sshd -T 2>/dev/null || true; sed -n "1,200p" /etc/ssh/sshd_config 2>/dev/null || true'
safe_collect "$raw_dir/suid.txt" sh -c 'find /usr/bin /bin -type f -perm -4000 -ls 2>/dev/null | head -n 200'
safe_collect "$raw_dir/cron.txt" sh -c 'cat /etc/crontab 2>/dev/null || true; ls -al /etc/cron.d 2>/dev/null || true'
safe_collect "$raw_dir/permissions.txt" sh -c 'ls -al /etc/passwd /etc/shadow /etc/gshadow /etc/sudoers 2>/dev/null || true'

# Additional host-level security evidence collections
# Package / updates summary
safe_collect "$raw_dir/apt_history.txt" sh -c 'tail -n 200 /var/log/apt/history.log 2>/dev/null || true'
safe_collect "$raw_dir/dpkg_list.txt" sh -c 'dpkg -l 2>/dev/null || true'

# Kernel & hardening
safe_collect "$raw_dir/sysctl_security.txt" sh -c 'sysctl -a 2>/dev/null | egrep "ip_forward|tcp_syncookies|accept_redirects|randomize_va_space|exec-shield|kernel.randomize_va_space" || true'
# Audit subsystem (auditd; no systemctl on 14.04, fall back to service/status)
safe_collect "$raw_dir/auditd.txt" sh -c 'command -v auditctl >/dev/null 2>&1 && auditctl -s 2>/dev/null; service auditd status 2>/dev/null || /etc/init.d/auditd status 2>/dev/null || true'

# Services: list all running services using Upstart + SysV
safe_collect "$raw_dir/services_running.txt" sh -c '
echo "[initctl list - Upstart jobs]"
initctl list 2>/dev/null | egrep "running" | egrep -v "nginx|apache2|httpd|tomcat|php-fpm" || true
echo
echo "[service --status-all - SysV / mixed]"
service --status-all 2>&1 | egrep -v "nginx|apache2|httpd|tomcat|php-fpm" || true
'

# Listening ports — prefer ss if available, otherwise fall back to netstat (which is standard on 14.04)
safe_collect "$raw_dir/listening_ports.txt" sh -c '
if command -v ss >/dev/null 2>&1; then
  ss -ltnp 2>/dev/null | egrep -v "nginx|apache|httpd|tomcat|php" || ss -ltn 2>/dev/null || true
else
  netstat -ltnp 2>/dev/null | egrep -v "nginx|apache|httpd|tomcat|php" || netstat -ltn 2>/dev/null || true
fi
'

# Auth / login data (last, lastlog, auth.log) — limited size
safe_collect "$raw_dir/lastlog.txt" sh -c 'lastlog 2>/dev/null || true'
safe_collect "$raw_dir/last_logins.txt" sh -c 'last -n 50 2>/dev/null || true'
# 14.04 has no journalctl; read auth.log directly
safe_collect "$raw_dir/auth_journal.txt" sh -c 'tail -n 200 /var/log/auth.log 2>/dev/null || true'

# Password policies and aging
safe_collect "$raw_dir/login_defs.txt" sh -c 'cat /etc/login.defs 2>/dev/null || true'
safe_collect "$raw_dir/passwd_shadow_perms.txt" sh -c 'ls -l /etc/passwd /etc/shadow /etc/gshadow 2>/dev/null || true'

# Kernel randomization (ASLR)
safe_collect "$raw_dir/aslr.txt" sh -c 'cat /proc/sys/kernel/randomize_va_space 2>/dev/null || true'

# Logrotate / rsyslog
safe_collect "$raw_dir/logrotate.conf" sh -c 'cat /etc/logrotate.conf 2>/dev/null || true; ls -al /etc/logrotate.d 2>/dev/null || true'
safe_collect "$raw_dir/rsyslog.conf" sh -c 'cat /etc/rsyslog.conf 2>/dev/null || true; ls -al /etc/rsyslog.d 2>/dev/null || true'

# Time sync / NTP information (no timedatectl on 14.04)
safe_collect "$raw_dir/timedatectl_status.txt" sh -c '
echo "[/etc/timezone]"
cat /etc/timezone 2>/dev/null || true
echo
echo "[date]"
date 2>/dev/null || true
echo
echo "[hwclock]"
hwclock --show 2>/dev/null || true
'
safe_collect "$raw_dir/ntp_conf.txt" sh -c 'cat /etc/ntp.conf 2>/dev/null || true'
safe_collect "$raw_dir/ntp_service.txt" sh -c 'service ntp status 2>/dev/null || /etc/init.d/ntp status 2>/dev/null || true'
safe_collect "$raw_dir/chrony_tracking.txt" sh -c 'command -v chronyc >/dev/null 2>&1 && chronyc tracking 2>/dev/null || true'
safe_collect "$raw_dir/chrony_sources.txt" sh -c 'command -v chronyc >/dev/null 2>&1 && chronyc sources 2>/dev/null || true'
safe_collect "$raw_dir/ntpq_peers.txt" sh -c 'command -v ntpq >/dev/null 2>&1 && ntpq -pn 2>/dev/null || true'

# PAM and /etc/security password-policy related files (host-level only)
safe_collect "$raw_dir/pam_common_password.txt" sh -c 'sed -n "1,200p" /etc/pam.d/common-password 2>/dev/null || true'
safe_collect "$raw_dir/pam_common_auth.txt" sh -c 'sed -n "1,200p" /etc/pam.d/common-auth 2>/dev/null || true'
safe_collect "$raw_dir/pam_all_configs.txt" sh -c 'for f in /etc/pam.d/* 2>/dev/null; do echo "--- $f ---"; sed -n "1,200p" "$f" 2>/dev/null || true; done'

# Collect /etc/security modules and pwquality config (if present)
safe_collect "$raw_dir/etc_security_list.txt" sh -c 'ls -al /etc/security 2>/dev/null || true'
safe_collect "$raw_dir/pwquality.conf" sh -c 'cat /etc/security/pwquality.conf 2>/dev/null || true'
safe_collect "$raw_dir/security_files.txt" sh -c 'for f in /etc/security/* 2>/dev/null; do [ -f "$f" ] && echo "--- $f ---" && sed -n "1,200p" "$f" 2>/dev/null || true; done'

# Grep for common PAM password modules
# Note: Ubuntu 14.04 typically uses pam_cracklib + pam_tally2 (no pam_faillock by default)
safe_collect "$raw_dir/pam_password_modules.txt" sh -c 'egrep "pam_pwquality|pam_cracklib|pam_unix|pam_tally2|pam_faillock|pam_passwdqc" /etc/pam.d/* 2>/dev/null || true'

#================= Additional security product evidence ==============
# Threat-Sonar / Endpoint protection evidence (using Upstart-friendly checks)
safe_collect "$raw_dir/threat_sonar.txt" sh -c '
echo "[Process check]"
ps aux | egrep -i "threat|sonar" | grep -v grep || true

echo
echo "[Service check - initctl]"
initctl list 2>/dev/null | egrep -i "threat|sonar" || true

echo
echo "[Service check - service]"
service --status-all 2>&1 | egrep -i "threat|sonar" || true
'
# Wazuh agent & FIM evidence (Wazuh on 14.04 uses /etc/init.d/wazuh-agent)
safe_collect "$raw_dir/wazuh_fim.txt" sh -c '
echo "[Wazuh agent status]"
service wazuh-agent status 2>/dev/null || /etc/init.d/wazuh-agent status 2>/dev/null || true
'
#================= End of additional security product evidence ==============

cat > "$base/metadata.txt" <<EOF
company: $mycompany
hostname: $myhost
ip: $ip
ubuntu_version: ${ubuntu_ver:-unknown}
collected_at: $date_ts
tool: SecureVectors--collector
EOF

# Generate JSON report. On Ubuntu 14.04 python3 may not be installed; try python3, then python2.
python_bin=""
if command -v python3 >/dev/null 2>&1; then
  python_bin="python3"
elif command -v python >/dev/null 2>&1; then
  python_bin="python"
elif command -v python2 >/dev/null 2>&1; then
  python_bin="python2"
fi

if [ -n "$python_bin" ]; then
  "$python_bin" - "$base" <<'PY' > "$report_file"
# -*- coding: utf-8 -*-
import json, sys, os, io
base = sys.argv[1]
raw = os.path.join(base, 'raw')
meta_file = os.path.join(base, 'metadata.txt')
out = {'metadata': {}, 'raw': {}}
if os.path.exists(meta_file):
    f = io.open(meta_file, 'r', encoding='utf-8', errors='replace')
    for line in f:
        if ':' in line:
            k, v = line.split(':', 1)
            out['metadata'][k.strip()] = v.strip()
    f.close()
if os.path.isdir(raw):
    for fname in sorted(os.listdir(raw)):
        path = os.path.join(raw, fname)
        try:
            f = io.open(path, 'r', encoding='utf-8', errors='replace')
            data = f.read()
            f.close()
            if data is None or data.strip() == '':
                out['raw'][fname] = 'NA (no data collected)'
            else:
                out['raw'][fname] = data
        except Exception:
            out['raw'][fname] = 'ERROR_READING_FILE'
sys.stdout.write(json.dumps(out, ensure_ascii=False, indent=2))
PY
else
  echo "python (3 or 2) is required to generate JSON report. report not created." >&2
fi

echo "Done. Generated: $report_file"

# Print scope declaration to stdout (no file write)
echo
cat <<'DECL'
---------------- Scope Declaration -----------------
This report focuses exclusively on host-level security evidence,
including operating system configuration, privilege control,
remote access settings, and kernel hardening status.

Web applications, middleware, and application-layer vulnerability
assessments are outside the scope of this report and are not collected as part of this assessment.
---------------- End of Scope ----------------
DECL
