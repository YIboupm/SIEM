import json
import os
import urllib.request
import urllib.error
import ipaddress
from datetime import datetime, timezone
from pathlib import Path


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def normalize_ip(value):
    if value is None:
        return None
    return str(value).strip()


def fetch_json(url, method="GET", body=None, headers=None):
    request = urllib.request.Request(url, data=body, method=method)
    if headers:
        for key, value in headers.items():
            request.add_header(key, value)
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def scroll_search(base_url, index, query, source_includes, size=1000, max_docs=20000):
    url = f"{base_url}/{index}/_search?scroll=1m"
    body = json.dumps(
        {
            "size": size,
            "query": query,
            "_source": source_includes,
            "sort": ["_doc"],
        }
    ).encode("utf-8")
    try:
        data = fetch_json(url, method="POST", body=body, headers={"Content-Type": "application/json"})
    except urllib.error.URLError:
        return []
    hits = data.get("hits", {}).get("hits", [])
    results = hits[:]
    scroll_id = data.get("_scroll_id")
    while hits and scroll_id and len(results) < max_docs:
        body = json.dumps({"scroll": "1m", "scroll_id": scroll_id}).encode("utf-8")
        data = fetch_json(
            f"{base_url}/_search/scroll",
            method="POST",
            body=body,
            headers={"Content-Type": "application/json"},
        )
        scroll_id = data.get("_scroll_id")
        hits = data.get("hits", {}).get("hits", [])
        if not hits:
            break
        results.extend(hits)
    return results


def get_nested(data, keys):
    value = data
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return None
    return value


def extract_indicator(doc):
    indicator = doc.get("indicator") or doc.get("ip")
    if indicator:
        return normalize_ip(indicator)
    message = doc.get("message")
    if not message:
        return None
    left = str(message).split(";", 1)[0].strip()
    return normalize_ip(left.split("/", 1)[0].strip())


def extract_threat_network(doc):
    indicator = doc.get("indicator") or doc.get("ip")
    cidr = doc.get("cidr")
    if indicator and cidr is not None:
        try:
            return ipaddress.ip_network(f"{indicator}/{cidr}", strict=False)
        except ValueError:
            pass
    if indicator and "/" in str(indicator):
        try:
            return ipaddress.ip_network(str(indicator), strict=False)
        except ValueError:
            pass
    message = doc.get("message")
    if message:
        left = str(message).split(";", 1)[0].strip()
        try:
            return ipaddress.ip_network(left, strict=False)
        except ValueError:
            pass
    if indicator:
        try:
            return ipaddress.ip_network(f"{indicator}/32", strict=False)
        except ValueError:
            return None
    return None


def extract_source_ip(doc):
    for key in ("source_ip", "src_ip", "source.ip"):
        if key in doc:
            return normalize_ip(doc.get(key))
    source = doc.get("source")
    if isinstance(source, dict) and source.get("ip"):
        return normalize_ip(source.get("ip"))
    return None


def extract_timestamp(doc):
    return doc.get("timestamp") or doc.get("@timestamp")


def extract_user(doc):
    user = doc.get("user")
    if isinstance(user, dict):
        return user.get("name")
    return user


def load_threatfeed(opensearch_url, index_pattern):
    hits = scroll_search(
        opensearch_url,
        index_pattern,
        {"match_all": {}},
        ["indicator", "ip", "message"],
    )
    return [hit.get("_source", {}) for hit in hits]


def load_login_logs(opensearch_url, index_pattern):
    hits = scroll_search(
        opensearch_url,
        index_pattern,
        {"match_all": {}},
        ["source_ip", "src_ip", "source", "source.ip", "timestamp", "@timestamp", "user", "event"],
    )
    return [hit.get("_source", {}) for hit in hits]


def build_threat_networks(threat_feed):
    networks = []
    for item in threat_feed:
        network = extract_threat_network(item)
        if not network:
            continue
        networks.append(
            {
                "network": network,
                "indicator": extract_indicator(item),
                "cidr": item.get("cidr"),
                "source": item.get("source"),
            }
        )
    return networks


def find_match(ip_value, networks):
    if not ip_value:
        return None
    try:
        ip_obj = ipaddress.ip_address(ip_value)
    except ValueError:
        return None
    for entry in networks:
        if ip_obj in entry["network"]:
            return entry
    return None


def bulk_index(base_url, index_name, documents):
    if not documents:
        return 0
    lines = []
    for doc in documents:
        lines.append(json.dumps({"index": {"_index": index_name}}, ensure_ascii=False))
        lines.append(json.dumps(doc, ensure_ascii=False))
    body = ("\n".join(lines) + "\n").encode("utf-8")
    data = fetch_json(
        f"{base_url}/_bulk?refresh=true",
        method="POST",
        body=body,
        headers={"Content-Type": "application/x-ndjson"},
    )
    if data.get("errors"):
        raise RuntimeError("Bulk index errors returned by OpenSearch.")
    return len(documents)

def synthesize_login_logs(threat_networks, count=5):
    logs = []
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    for idx, entry in enumerate(threat_networks[:count]):
        network = entry["network"]
        ip_value = str(network.network_address)
        if network.num_addresses > 2:
            ip_value = str(network.network_address + 1)
        logs.append(
            {
                "timestamp": now,
                "user": f"demo_user_{idx+1}",
                "source_ip": ip_value,
                "event": "ssh_login",
                "simulated": True,
            }
        )
    return logs


def main():
    base_dir = Path(__file__).resolve().parent
    threat_feed_path = base_dir / "threat_feed.json"
    login_logs_path = base_dir / "login_logs.json"

    opensearch_url = os.getenv("OPENSEARCH_URL")
    threat_index = os.getenv("OPENSEARCH_THREAT_INDEX", "threatfeed-*")
    login_index = os.getenv("OPENSEARCH_LOGIN_INDEX", "login-logs")
    alert_index = os.getenv("OPENSEARCH_ALERT_INDEX", "alerts")
    use_local_logs = os.getenv("USE_LOCAL_LOGS", "false").lower() in {"1", "true", "yes"}

    threat_feed = []
    login_logs = []
    if opensearch_url:
        threat_feed = load_threatfeed(opensearch_url, threat_index)
        if not use_local_logs:
            login_logs = load_login_logs(opensearch_url, login_index)
        if not login_logs and login_logs_path.exists():
            login_logs = load_json(login_logs_path)
    else:
        threat_feed = load_json(threat_feed_path)
        login_logs = load_json(login_logs_path)

    threat_networks = build_threat_networks(threat_feed)

    alerts = []
    for entry in login_logs:
        src_ip = extract_source_ip(entry)
        match = find_match(src_ip, threat_networks)
        if src_ip and match:
            alerts.append(
                {
                    "timestamp": extract_timestamp(entry),
                    "user": extract_user(entry),
                    "source_ip": src_ip,
                    "event": entry.get("event"),
                    "threat_match": True,
                    "threat_network": str(match["network"]),
                    "threat_source": match.get("source"),
                    "threat_indicator": match.get("indicator"),
                    "threat_cidr": match.get("cidr"),
                }
            )

    if not alerts and opensearch_url and threat_networks:
        login_logs = synthesize_login_logs(threat_networks, count=5)
        try:
            bulk_index(opensearch_url, login_index, login_logs)
            print(f"Seeded login logs: {len(login_logs)}")
        except Exception as exc:
            print(f"Login log seed failed: {exc}")
        for entry in login_logs:
            src_ip = extract_source_ip(entry)
            match = find_match(src_ip, threat_networks)
            if src_ip and match:
                alerts.append(
                    {
                        "timestamp": extract_timestamp(entry),
                        "user": extract_user(entry),
                        "source_ip": src_ip,
                        "event": entry.get("event"),
                        "threat_match": True,
                        "threat_network": str(match["network"]),
                        "threat_source": match.get("source"),
                        "threat_indicator": match.get("indicator"),
                        "threat_cidr": match.get("cidr"),
                        "simulated": True,
                    }
                )

    if not alerts:
        print("No alerts.")
        return

    if opensearch_url:
        try:
            indexed = bulk_index(opensearch_url, alert_index, alerts)
            print(f"Indexed alerts to OpenSearch: {indexed}")
        except Exception as exc:
            print(f"Alert indexing failed: {exc}")

    print(f"Alerts: {len(alerts)}")
    for alert in alerts:
        print(json.dumps(alert, ensure_ascii=False))


if __name__ == "__main__":
    main()
