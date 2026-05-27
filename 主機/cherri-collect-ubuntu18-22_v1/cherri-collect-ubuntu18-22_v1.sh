#!/bin/bash
#SecuCollab IDC Ubuntu Compliance Monitoring
# Compatible with Ubuntu 18.04 / 20.04 / 22.04 (systemd based)
# This script is identical across 18.04, 20.04, and 22.04 packages.
# Differences between those versions are handled by feature-detection at runtime.

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
# SecuCollab — host info collector

set -u

myhost=$(hostname 2>/dev/null || echo unknown-host)
ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo 127.0.0.1)
date_ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Detect Ubuntu version for metadata / conditional behaviour
ubuntu_ver=""
if [ -r /etc/os-release ]; then
  ubuntu_ver=$(. /etc/os-release 2>/dev/null; echo "${VERSION_ID:-unknown}")
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
safe_collect "$raw_dir/os_release.txt" cat /etc/os-release
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
# Audit subsystem
safe_collect "$raw_dir/auditd.txt" sh -c 'command -v auditctl >/dev/null 2>&1 && auditctl -s 2>/dev/null || systemctl status auditd 2>/dev/null || true'

# Services: list running services but filter out common web app services
safe_collect "$raw_dir/services_running.txt" sh -c 'systemctl list-units --type=service --state=running --no-pager 2>/dev/null | egrep -v "nginx|apache2|httpd|tomcat|php-fpm" || true'

# Listening ports
safe_collect "$raw_dir/listening_ports.txt" sh -c "ss -ltnp 2>/dev/null | egrep -v 'nginx|apache|httpd|tomcat|php' || ss -ltn 2>/dev/null || true"

# Auth / login data (last, lastlog, journal for auth) — limited size
safe_collect "$raw_dir/lastlog.txt" sh -c 'lastlog 2>/dev/null || true'
safe_collect "$raw_dir/last_logins.txt" sh -c 'last -n 50 2>/dev/null || true'
safe_collect "$raw_dir/auth_journal.txt" sh -c 'journalctl -n 200 --no-pager _COMM=sshd 2>/dev/null || tail -n 200 /var/log/auth.log 2>/dev/null || true'

# Password policies and aging
safe_collect "$raw_dir/login_defs.txt" sh -c 'cat /etc/login.defs 2>/dev/null || true'
safe_collect "$raw_dir/passwd_shadow_perms.txt" sh -c 'ls -l /etc/passwd /etc/shadow /etc/gshadow 2>/dev/null || true'

# Kernel randomization (ASLR)
safe_collect "$raw_dir/aslr.txt" sh -c 'cat /proc/sys/kernel/randomize_va_space 2>/dev/null || true'

# Logrotate / rsyslog
safe_collect "$raw_dir/logrotate.conf" sh -c 'cat /etc/logrotate.conf 2>/dev/null || true; ls -al /etc/logrotate.d 2>/dev/null || true'
safe_collect "$raw_dir/rsyslog.conf" sh -c 'cat /etc/rsyslog.conf 2>/dev/null || true; ls -al /etc/rsyslog.d 2>/dev/null || true'

# Time sync / NTP information
safe_collect "$raw_dir/timedatectl_status.txt" sh -c 'timedatectl status 2>/dev/null || true'
safe_collect "$raw_dir/timedatectl_timesync.txt" sh -c 'timedatectl show-timesync --all 2>/dev/null || true'
safe_collect "$raw_dir/systemd_timesyncd.txt" sh -c 'systemctl status systemd-timesyncd 2>/dev/null || true'
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

# Grep for common PAM password modules (pwquality/cracklib/unix/tally/faillock)
# Note: Ubuntu 22.04 prefers pam_faillock; Ubuntu 18.04/20.04 often uses pam_tally2.
safe_collect "$raw_dir/pam_password_modules.txt" sh -c 'egrep "pam_pwquality|pam_cracklib|pam_unix|pam_tally2|pam_faillock|pam_passwdqc" /etc/pam.d/* 2>/dev/null || true'

#================= Additional security product evidence ==============
# Threat-Sonar / Endpoint protection evidence
safe_collect "$raw_dir/threat_sonar.txt" sh -c '
echo "[Process check]"
ps aux | egrep -i "threat|sonar" | grep -v grep || true

echo
echo "[Service check]"
systemctl list-units --type=service --all 2>/dev/null | egrep -i "threat|sonar" || true
'
# Wazuh agent & FIM evidence
safe_collect "$raw_dir/wazuh_fim.txt" sh -c '
echo "[Wazuh agent status]"
systemctl status wazuh-agent 2>/dev/null || true
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

# Generate JSON report using python3 (pass base as argv[1])
if command -v python3 >/dev/null 2>&1; then
  python3 - "$base" <<'PY' > "$report_file"
import json,sys,os
base = sys.argv[1]
raw = os.path.join(base,'raw')
meta_file = os.path.join(base,'metadata.txt')
out = {'metadata':{}, 'raw':{}}
if os.path.exists(meta_file):
    for line in open(meta_file):
        if ':' in line:
            k,v=line.split(':',1)
            out['metadata'][k.strip()]=v.strip()
if os.path.isdir(raw):
  for fname in sorted(os.listdir(raw)):
    path = os.path.join(raw, fname)
    try:
      with open(path,'r',errors='replace') as f:
        data = f.read()
      # If file is empty or only whitespace, mark clearly as NA so downstream
      # consumers know the collector produced no data for this item.
      if data is None or data.strip() == '':
        out['raw'][fname] = 'NA (no data collected)'
      else:
        out['raw'][fname] = data
    except Exception:
      out['raw'][fname] = 'ERROR_READING_FILE'
print(json.dumps(out, ensure_ascii=False, indent=2))
PY
else
  echo "python3 is required to generate JSON report. report not created." >&2
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
