#!/usr/bin/env bash
set -euo pipefail

TARGET_HOST="${1:-victim}"
TARGET_PORT="${2:-8080}"
THREATFEED_IP="${3:-196.251.85.62}"

echo "== Stage 1: network attack simulation =="
docker compose exec attacker /usr/local/bin/attack-simulate.sh "${TARGET_HOST}" "${TARGET_PORT}"

echo
echo "== Stage 2: inject real SSH logs on victim =="
docker compose exec -T victim bash -lc "
  mkdir -p /var/log &&
  touch /var/log/auth.log &&
  TS=\$(date '+%b %e %H:%M:%S') &&
  echo \"\${TS} victim sshd[12345]: Failed password for root from ${THREATFEED_IP} port 55555 ssh2\" >> /var/log/auth.log &&
  echo \"\${TS} victim sshd[12346]: Accepted password for root from ${THREATFEED_IP} port 55556 ssh2\" >> /var/log/auth.log
"

echo
echo "Done. In Dashboard, check Threat hunting with:"
echo "  agent.name:\"victim-agent\" AND full_log:*sshd*"
echo "  rule.id:(100200 OR 100201)"
