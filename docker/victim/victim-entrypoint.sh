#!/usr/bin/env bash
set -euo pipefail

WAZUH_MANAGER="${WAZUH_MANAGER:-wazuh.manager}"
WAZUH_AGENT_NAME="${WAZUH_AGENT_NAME:-victim-agent}"
MONITOR_INTERFACE="${MONITOR_INTERFACE:-eth0}"
ENROLL_MAX_RETRIES="${ENROLL_MAX_RETRIES:-30}"
ENROLL_RETRY_INTERVAL="${ENROLL_RETRY_INTERVAL:-5}"

mkdir -p /var/log/snort /var/log/zeek /opt/victim-www
echo "victim node online: $(date -u)" > /opt/victim-www/index.html

append_localfile() {
  local location="$1"
  local alias_name="$2"
  local log_format="$3"

  if ! grep -q "<alias>${alias_name}</alias>" /var/ossec/etc/ossec.conf; then
    sed -i "/<\/ossec_config>/i\\
  <localfile>\\
    <log_format>${log_format}</log_format>\\
    <location>${location}</location>\\
    <alias>${alias_name}</alias>\\
  </localfile>" /var/ossec/etc/ossec.conf
  fi
}

touch /var/log/auth.log
append_localfile "/var/log/snort/alert" "snort-alerts" "syslog"
append_localfile "/var/log/zeek/current/notice.log" "zeek-notice" "syslog"
append_localfile "/var/log/auth.log" "auth-log" "syslog"

if [ ! -s /var/ossec/etc/client.keys ]; then
  echo "Waiting for Wazuh enrollment service at ${WAZUH_MANAGER}:1515 ..."
  for attempt in $(seq 1 "${ENROLL_MAX_RETRIES}"); do
    if (echo >"/dev/tcp/${WAZUH_MANAGER}/1515") >/dev/null 2>&1; then
      echo "Enrollment service is reachable. Registering agent..."
      if /var/ossec/bin/agent-auth -m "${WAZUH_MANAGER}" -A "${WAZUH_AGENT_NAME}"; then
        break
      fi
    fi

    if [ "${attempt}" -eq "${ENROLL_MAX_RETRIES}" ]; then
      echo "Enrollment retry limit reached. Agent will continue and reconnect later."
      break
    fi
    sleep "${ENROLL_RETRY_INTERVAL}"
  done
fi

/var/ossec/bin/wazuh-control start

if [ -f /etc/snort/rules/local.rules ] && ! grep -q "sid:1000001" /etc/snort/rules/local.rules; then
  cat <<'EOF' >> /etc/snort/rules/local.rules
alert icmp any any -> any any (msg:"ICMP test traffic detected"; sid:1000001; rev:1;)
alert tcp any any -> any 8080 (msg:"HTTP request detected on victim"; sid:1000002; rev:1;)
EOF
fi

snort -i "${MONITOR_INTERFACE}" -A fast -q -c /etc/snort/snort.conf -l /var/log/snort &
ZEEK_BIN="$(command -v zeek || true)"
if [ -z "${ZEEK_BIN}" ] && [ -x /opt/zeek/bin/zeek ]; then
  ZEEK_BIN="/opt/zeek/bin/zeek"
fi
if [ -z "${ZEEK_BIN}" ]; then
  echo "Zeek binary not found in PATH or /opt/zeek/bin/zeek"
  exit 1
fi
cd /var/log/zeek && "${ZEEK_BIN}" -i "${MONITOR_INTERFACE}" local &
python3 -m http.server 8080 --directory /opt/victim-www &

wait -n
