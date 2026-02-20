# siem-demo

Python demo for SIEM correlation based on the updated architecture.

## Files
- match_threat.py
- threat_feed.json
- login_logs.json

## Run
```bash
cd siem-demo
python3 match_threat.py
```

## OpenSearch Source
Set OPENSEARCH_URL to read threatfeed from Wazuh Indexer, match login IPs against threatfeed CIDR, and write alerts to OpenSearch.

```bash
export OPENSEARCH_URL=https://localhost:9201
export OPENSEARCH_USERNAME=admin
export OPENSEARCH_PASSWORD=SecretPassword
export OPENSEARCH_SSL_VERIFY=false
export OPENSEARCH_THREAT_INDEX="threatfeed-*"
export OPENSEARCH_LOGIN_INDEX="login-logs"
export OPENSEARCH_ALERT_INDEX="alerts"
python3 match_threat.py
```

## Output
The script prints alert records where login source_ip matches threatfeed CIDR ranges and writes them to OPENSEARCH_ALERT_INDEX. If no matches exist, it seeds a few simulated login logs to demonstrate alert indexing.
