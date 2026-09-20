"""
Génère des logs de sécurité synthétiques pour simuler la base que l'outil MCP
search_logs interrogera. Mélange de trafic normal et de patterns d'attaque
connus (scans de ports, tentatives de connexion répétées, accès à des
endpoints sensibles), avec des timestamps étalés sur les 30 derniers jours.

Usage :
    python -m ingestion.generate_synthetic_logs --count 300 --output data/synthetic/security_logs.jsonl
"""

import argparse
import ipaddress
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(42)  # reproductibilité

NORMAL_USERS = ["jsmith", "mchen", "aroberts", "klopez", "dwright", "system", "backup_svc"]
INTERNAL_IPS = [f"10.0.{random.randint(0, 5)}.{i}" for i in range(1, 60)]
SUSPICIOUS_IPS = [
    "185.220.101.47", "45.155.205.233", "193.42.33.12",
    "91.240.118.172", "23.129.64.200", "104.244.79.6",
]

NORMAL_ENDPOINTS = ["/dashboard", "/api/v1/users/me", "/reports", "/login", "/static/logo.png", "/api/v1/orders"]
SENSITIVE_ENDPOINTS = ["/admin", "/api/v1/admin/users", "/.env", "/wp-admin", "/phpmyadmin", "/api/v1/config"]

COMMON_PORTS = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017, 9200]


def random_timestamp(days_back: int = 30) -> datetime:
    delta = timedelta(
        days=random.randint(0, days_back),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59),
    )
    return datetime.now(timezone.utc) - delta


def make_normal_auth_log() -> dict:
    ts = random_timestamp()
    return {
        "timestamp": ts.isoformat(),
        "log_type": "auth",
        "source_ip": random.choice(INTERNAL_IPS),
        "user": random.choice(NORMAL_USERS),
        "event": "login_success",
        "message": f"Successful login for user {random.choice(NORMAL_USERS)} from internal network",
    }


def make_normal_access_log() -> dict:
    ts = random_timestamp()
    return {
        "timestamp": ts.isoformat(),
        "log_type": "access",
        "source_ip": random.choice(INTERNAL_IPS),
        "user": random.choice(NORMAL_USERS),
        "event": "http_request",
        "endpoint": random.choice(NORMAL_ENDPOINTS),
        "status_code": random.choice([200, 200, 200, 304]),
        "message": f"GET {random.choice(NORMAL_ENDPOINTS)} 200 OK",
    }


def make_repeated_login_failure_pattern() -> list[dict]:
    """Simule des tentatives de connexion répétées depuis une IP inconnue (brute force)."""
    ip = random.choice(SUSPICIOUS_IPS)
    target_user = random.choice(NORMAL_USERS)
    base_ts = random_timestamp()
    logs = []
    n_attempts = random.randint(8, 25)
    for i in range(n_attempts):
        ts = base_ts + timedelta(seconds=i * random.randint(2, 8))
        logs.append({
            "timestamp": ts.isoformat(),
            "log_type": "auth",
            "source_ip": ip,
            "user": target_user,
            "event": "login_failure",
            "message": f"Failed login attempt for user {target_user} from {ip} (repeated attempts detected)",
        })
    return logs


def make_port_scan_pattern() -> list[dict]:
    """Simule un scan de ports depuis une IP externe."""
    ip = random.choice(SUSPICIOUS_IPS)
    base_ts = random_timestamp()
    logs = []
    ports = random.sample(COMMON_PORTS, k=min(len(COMMON_PORTS), random.randint(5, 10)))
    for i, port in enumerate(ports):
        ts = base_ts + timedelta(seconds=i * random.randint(1, 3))
        logs.append({
            "timestamp": ts.isoformat(),
            "log_type": "network",
            "source_ip": ip,
            "user": None,
            "event": "port_scan",
            "port": port,
            "message": f"Connection attempt to port {port} from {ip} (possible port scan)",
        })
    return logs


def make_sensitive_endpoint_access() -> dict:
    """Simule un accès à un endpoint sensible depuis une IP externe."""
    ip = random.choice(SUSPICIOUS_IPS)
    ts = random_timestamp()
    endpoint = random.choice(SENSITIVE_ENDPOINTS)
    return {
        "timestamp": ts.isoformat(),
        "log_type": "access",
        "source_ip": ip,
        "user": None,
        "event": "sensitive_endpoint_access",
        "endpoint": endpoint,
        "status_code": random.choice([401, 403, 404]),
        "message": f"Unauthorized access attempt to {endpoint} from external IP {ip}",
    }


def make_struts_exploit_attempt() -> dict:
    """Log spécifique lié à une tentative d'exploitation Apache Struts (pour matcher les cas d'incident type)."""
    ip = random.choice(SUSPICIOUS_IPS)
    ts = random_timestamp()
    return {
        "timestamp": ts.isoformat(),
        "log_type": "access",
        "source_ip": ip,
        "user": None,
        "event": "suspicious_payload",
        "endpoint": "/struts2-showcase/index.action",
        "status_code": 500,
        "message": f"Suspicious Content-Type header detected in request from {ip}, possible Struts OGNL injection attempt",
    }


def generate_logs(count: int) -> list[dict]:
    logs: list[dict] = []

    # ~70% de trafic normal
    n_normal = int(count * 0.70)
    for _ in range(n_normal // 2):
        logs.append(make_normal_auth_log())
    for _ in range(n_normal - n_normal // 2):
        logs.append(make_normal_access_log())

    # Patterns d'attaque, mélangés dans le reste
    remaining = count - len(logs)
    while len(logs) < count:
        pattern_type = random.choice([
            "brute_force", "brute_force", "port_scan", "port_scan",
            "sensitive_access", "sensitive_access", "struts_exploit",
        ])
        if pattern_type == "brute_force":
            logs.extend(make_repeated_login_failure_pattern())
        elif pattern_type == "port_scan":
            logs.extend(make_port_scan_pattern())
        elif pattern_type == "sensitive_access":
            logs.append(make_sensitive_endpoint_access())
        elif pattern_type == "struts_exploit":
            logs.append(make_struts_exploit_attempt())

        if len(logs) >= count * 1.15:  # évite de dépasser trop largement la cible
            break

    logs.sort(key=lambda l: l["timestamp"])
    return logs


def main():
    parser = argparse.ArgumentParser(description="Génère des logs de sécurité synthétiques.")
    parser.add_argument("--count", type=int, default=300, help="Nombre approximatif de lignes de logs à générer.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/synthetic/security_logs.jsonl"),
        help="Chemin du fichier JSONL de sortie.",
    )
    args = parser.parse_args()

    logs = generate_logs(args.count)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as f:
        for log in logs:
            f.write(json.dumps(log, ensure_ascii=False) + "\n")

    print(f"{len(logs)} logs synthétiques écrits dans {args.output}")


if __name__ == "__main__":
    main()
