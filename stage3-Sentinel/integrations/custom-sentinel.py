#!/var/ossec/framework/python/bin/python3
"""
custom-sentinel.py
Wazuh integration that forwards alerts to Microsoft Sentinel through the
Azure Monitor Logs Ingestion API.

How Wazuh runs it
  wazuh-integratord calls this script once per alert that passes the
  <integration> filter in ossec.conf, with:
    argv[1]  path to a temp file holding the alert (JSON)
    argv[2]  api_key   (unused, secrets live in sentinel.json)
    argv[3]  hook_url  (unused)

What it does
  1. Reads the alert and keeps only the fields Sentinel needs (about 1 KB).
  2. Gets an Entra ID token (client credentials) and caches it until it
     is close to expiry, so we are not asking for a new token per alert.
  3. POSTs the record to the Data Collection Rule stream.

Local test (no network):
  python3 custom-sentinel.py --dry-run /path/to/alert.json

Only the Python standard library is used, so it runs on Wazuh's bundled
interpreter without installing anything.

Author: Mohammed Aadil Khan
"""

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

CONFIG_PATH = os.environ.get(
    "SENTINEL_CONFIG", "/var/ossec/integrations/sentinel.json")
TOKEN_CACHE_DIRS = ["/var/ossec/tmp", "/tmp"]
TOKEN_CACHE_NAME = "wazuh-sentinel-token.json"
LOG_PATH = "/var/ossec/logs/integrations.log"
API_VERSION = "2023-01-01"
TIMEOUT = 10  # seconds per HTTP call

# Wazuh's bundled Python does not look in the OS certificate store, so HTTPS
# fails with CERTIFICATE_VERIFY_FAILED. Point it at the system CA bundle.
# Verification stays ON: we only tell Python where the trusted CAs live.
CA_BUNDLES = [
    os.environ.get("SSL_CERT_FILE", ""),
    "/etc/ssl/certs/ca-certificates.crt",   # Ubuntu / Debian
    "/etc/pki/tls/certs/ca-bundle.crt",     # RHEL / Amazon Linux
]

# Wazuh rule groups that tell us which honeypot an alert came from.
HONEYPOT_GROUPS = [
    "cowrie", "heralding", "rdp_honeypot", "conpot", "dionaea", "windows_bait",
]


# ---------------------------------------------------------------- logging

def log(msg):
    line = "{} custom-sentinel: {}\n".format(
        datetime.now(timezone.utc).strftime("%Y/%m/%d %H:%M:%S"), msg)
    try:
        with open(LOG_PATH, "a") as f:
            f.write(line)
    except OSError:
        sys.stderr.write(line)


# ---------------------------------------------------------------- mapping

def dig(d, *path):
    """Safe nested lookup: dig(alert, 'data', 'win', 'eventdata', 'ipAddress')."""
    for key in path:
        if not isinstance(d, dict):
            return None
        d = d.get(key)
    return d


def first(*values):
    for v in values:
        if v not in (None, "", "-"):
            return v
    return None


def to_iso_utc(ts):
    """Wazuh writes 2026-10-24T18:49:47.935+0000. Azure wants ISO 8601."""
    if not ts:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            dt = datetime.strptime(ts, fmt)
            return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except ValueError:
            continue
    return ts


def as_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def honeypot_from_groups(groups, location=None):
    joined = ",".join(groups).lower()
    for name in HONEYPOT_GROUPS:
        if name in joined:
            return name
    # Wazuh's built-in Windows rules carry no honeypot group, but they only
    # come from the bait host's event channels.
    if location == "EventChannel":
        return "windows_bait"
    return "other"


def map_alert(alert):
    rule = alert.get("rule", {}) or {}
    data = alert.get("data", {}) or {}
    groups = rule.get("groups", []) or []
    mitre = rule.get("mitre", {}) or {}
    win = dig(data, "win", "eventdata") or {}

    record = {
        "TimeGenerated": to_iso_utc(alert.get("timestamp")),
        "AlertId": alert.get("id"),
        "RuleId": str(rule.get("id", "")),
        "RuleLevel": as_int(rule.get("level")),
        "RuleDescription": rule.get("description"),
        "RuleGroups": groups,
        "MitreIds": mitre.get("id", []),
        "MitreTactics": mitre.get("tactic", []),
        "Honeypot": honeypot_from_groups(groups, alert.get("location")),
        "AgentId": dig(alert, "agent", "id"),
        "AgentName": dig(alert, "agent", "name"),
        "SrcIp": first(data.get("src_ip"), data.get("source_ip"),
                       data.get("srcip"), win.get("ipAddress")),
        "SrcPort": as_int(first(data.get("src_port"), data.get("source_port"),
                                win.get("ipPort"))),
        "DstPort": as_int(first(data.get("dst_port"),
                                data.get("destination_port"))),
        "Protocol": first(dig(data, "connection", "protocol"),
                          data.get("protocol")),
        "Username": first(data.get("username"), win.get("targetUserName")),
        "Password": data.get("password"),
        "Command": first(data.get("input"), win.get("commandLine")),
        "Session": first(data.get("session"), data.get("session_id")),
        "EventId": first(data.get("eventid"), dig(data, "win", "system", "eventID"),
                         data.get("event_type")),
        "Url": data.get("url"),
        "FileHash": data.get("shasum"),
        "Location": alert.get("location"),
    }
    # Drop empty fields so we do not pay to store nulls.
    return {k: v for k, v in record.items() if v not in (None, "", [], {})}


# ---------------------------------------------------------------- tls

def make_ssl_context():
    """Certificate-checking context that trusts the OS CA bundle."""
    for path in CA_BUNDLES:
        if path and os.path.isfile(path):
            return ssl.create_default_context(cafile=path)
    return ssl.create_default_context()


SSL_CTX = make_ssl_context()


def http_open(req):
    return urllib.request.urlopen(req, timeout=TIMEOUT, context=SSL_CTX)


# ---------------------------------------------------------------- auth

def token_cache_path():
    for d in TOKEN_CACHE_DIRS:
        if os.path.isdir(d) and os.access(d, os.W_OK):
            return os.path.join(d, TOKEN_CACHE_NAME)
    return None


def read_cached_token():
    path = token_cache_path()
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            cached = json.load(f)
        if cached.get("expires_at", 0) - 300 > time.time():
            return cached["access_token"]
    except (OSError, ValueError, KeyError):
        pass
    return None


def fetch_token(cfg):
    url = "https://login.microsoftonline.com/{}/oauth2/v2.0/token".format(
        cfg["tenant_id"])
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
        "scope": "https://monitor.azure.com/.default",
    }).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with http_open(req) as resp:
        payload = json.load(resp)

    token = payload["access_token"]
    path = token_cache_path()
    if path:
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump({"access_token": token,
                           "expires_at": time.time() + int(payload.get("expires_in", 3600))}, f)
        except OSError as e:
            log("could not cache token: {}".format(e))
    return token


def get_token(cfg, force=False):
    if not force:
        cached = read_cached_token()
        if cached:
            return cached
    return fetch_token(cfg)


# ---------------------------------------------------------------- send

def ingestion_url(cfg):
    return "{}/dataCollectionRules/{}/streams/{}?api-version={}".format(
        cfg["ingestion_endpoint"].rstrip("/"), cfg["dcr_immutable_id"],
        cfg["stream_name"], API_VERSION)


def post_records(cfg, records, token):
    req = urllib.request.Request(
        ingestion_url(cfg), data=json.dumps(records).encode("utf-8"), method="POST")
    req.add_header("Authorization", "Bearer " + token)
    req.add_header("Content-Type", "application/json")
    with http_open(req) as resp:
        return resp.status


def send(cfg, records):
    token = get_token(cfg)
    try:
        return post_records(cfg, records, token)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            # Cached token may be stale or revoked. Try once with a fresh one.
            token = get_token(cfg, force=True)
            return post_records(cfg, records, token)
        raise


# ---------------------------------------------------------------- main

def load_config():
    with open(CONFIG_PATH) as f:
        cfg = json.load(f)
    required = ["tenant_id", "client_id", "client_secret",
                "ingestion_endpoint", "dcr_immutable_id", "stream_name"]
    missing = [k for k in required if not cfg.get(k)]
    if missing:
        raise ValueError("sentinel.json is missing: " + ", ".join(missing))
    return cfg


def main(argv):
    dry_run = "--dry-run" in argv
    args = [a for a in argv[1:] if a != "--dry-run"]
    if not args:
        log("no alert file given")
        return 1

    try:
        with open(args[0]) as f:
            alert = json.load(f)
    except (OSError, ValueError) as e:
        log("cannot read alert file {}: {}".format(args[0], e))
        return 1

    record = map_alert(alert)

    if dry_run:
        print(json.dumps(record, indent=2))
        return 0

    try:
        cfg = load_config()
        status = send(cfg, [record])
        if status not in (200, 204):
            log("unexpected status {} for rule {}".format(status, record.get("RuleId")))
            return 1
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:300]
        log("HTTP {} sending rule {}: {}".format(e.code, record.get("RuleId"), detail))
        return 1
    except Exception as e:  # never crash integratord over one alert
        log("error sending rule {}: {}".format(record.get("RuleId"), e))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
