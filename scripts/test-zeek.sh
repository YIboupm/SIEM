#!/usr/bin/env bash
set -euo pipefail

TARGET_HOST="${1:-victim}"
TARGET_PORT="${2:-8080}"
WAIT_SECONDS="${3:-6}"
STARTUP_TIMEOUT_SECONDS="${4:-120}"

read_zeek_counts_cmd='
  if [ -d /var/log/zeek/current ]; then
    zeek_dir="/var/log/zeek/current"
  elif [ -d /var/log/zeek/logs/current ]; then
    zeek_dir="/var/log/zeek/logs/current"
  elif [ -d /opt/zeek/logs/current ]; then
    zeek_dir="/opt/zeek/logs/current"
  else
    zeek_dir=""
  fi

  echo "zeek_dir:${zeek_dir:-not_found}"
  for f in conn.log http.log dns.log notice.log; do
    if [ -n "${zeek_dir}" ] && [ -f "${zeek_dir}/${f}" ]; then
      count="$(wc -l < "${zeek_dir}/${f}" 2>/dev/null || echo 0)"
      echo "${f}:${count}"
    else
      echo "${f}:0"
    fi
  done
'

echo "== Zeek test: baseline line counts =="
echo "== Zeek test: wait for snort/zeek startup (${STARTUP_TIMEOUT_SECONDS}s max) =="
ready=0
for _ in $(seq 1 $(( STARTUP_TIMEOUT_SECONDS / 5 ))); do
  if docker compose exec -T victim bash -lc "ps -ef | grep -Eq '[z]eek|[s]nort'"; then
    ready=1
    break
  fi
  sleep 5
done

if [ "${ready}" -ne 1 ]; then
  echo "Snort/Zeek processes are still not running."
  echo "Recent victim logs:"
  docker compose logs victim --tail=120 || true
  exit 1
fi

BASELINE="$(docker compose exec -T victim bash -lc "${read_zeek_counts_cmd}")"
echo "${BASELINE}"

echo
echo "== Zeek test: process check =="
docker compose exec -T victim bash -lc "ps -ef | grep -E '[z]eek|[s]nort' || true"

echo
echo "== Zeek test: generate traffic from attacker =="
docker compose exec attacker bash -lc "
  set -e
  ping -c 3 ${TARGET_HOST} >/dev/null || true
  curl -s http://${TARGET_HOST}:${TARGET_PORT} >/dev/null || true
  nmap -sS -p 22,80,8080 ${TARGET_HOST} >/dev/null || true
"

echo
echo "== Zeek test: wait ${WAIT_SECONDS}s for log flush =="
sleep "${WAIT_SECONDS}"

echo
echo "== Zeek test: current line counts =="
CURRENT="$(docker compose exec -T victim bash -lc "${read_zeek_counts_cmd}")"
echo "${CURRENT}"

echo
echo "== Zeek test: force bridge latest Zeek events to Wazuh log =="
docker compose exec -T victim bash -lc '
  bridge="/var/log/zeek/zeek-wazuh.log"
  mkdir -p /var/log/zeek
  touch "${bridge}"

  for f in /var/log/zeek/current/conn.log /var/log/zeek/current/http.log; do
    if [ -f "${f}" ]; then
      last_line="$(awk "!/^#/ && NF {line=\$0} END {print line}" "${f}")"
      if [ -n "${last_line}" ]; then
        ts="$(date "+%b %e %H:%M:%S")"
        echo "${ts} victim zeek-wazuh: ${last_line}" >> "${bridge}"
      fi
    fi
  done

  echo "--- /var/log/zeek/zeek-wazuh.log (last 5 lines) ---"
  lines="$(wc -l < "${bridge}" 2>/dev/null || echo 0)"
  if [ "${lines}" -gt 0 ]; then
    start=$(( lines > 5 ? lines - 4 : 1 ))
    sed -n "${start},${lines}p" "${bridge}" 2>/dev/null || true
  fi
'

echo
echo "== Zeek test: sample recent logs =="
docker compose exec -T victim bash -lc '
  if [ -d /var/log/zeek/current ]; then
    zeek_dir="/var/log/zeek/current"
  elif [ -d /var/log/zeek/logs/current ]; then
    zeek_dir="/var/log/zeek/logs/current"
  elif [ -d /opt/zeek/logs/current ]; then
    zeek_dir="/opt/zeek/logs/current"
  else
    zeek_dir=""
  fi

  if [ -z "${zeek_dir}" ]; then
    echo "Zeek log directory not found."
    echo "--- /var/log/zeek/zeek.stderr.log (last 80 lines) ---"
    if [ -f /var/log/zeek/zeek.stderr.log ]; then
      lines="$(wc -l < /var/log/zeek/zeek.stderr.log 2>/dev/null || echo 0)"
      if [ "${lines}" -gt 0 ]; then
        start=$(( lines > 80 ? lines - 79 : 1 ))
        sed -n "${start},${lines}p" /var/log/zeek/zeek.stderr.log 2>/dev/null || true
      fi
    fi
    exit 0
  fi

  for f in conn.log http.log notice.log; do
    path="${zeek_dir}/${f}"
    if [ -f "${path}" ]; then
      echo "--- ${path} (last 5 lines) ---"
      lines="$(wc -l < "${path}" 2>/dev/null || echo 0)"
      if [ "${lines}" -gt 0 ]; then
        start=$(( lines > 5 ? lines - 4 : 1 ))
        sed -n "${start},${lines}p" "${path}" 2>/dev/null || true
      fi
    fi
  done
'

echo
echo "If line counts increased, Zeek is working."
echo "Zeek functional verification is done via these files:"
echo "  /var/log/zeek/current/conn.log"
echo "  /var/log/zeek/current/http.log"
echo "Dashboard currently shows stable Snort + threatfeed alerts."
