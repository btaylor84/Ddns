import json
import logging
import os
import sys
import time
from typing import Any, Dict, Optional

import requests


def env(name: str, default: Optional[str] = None) -> Optional[str]:
    value = os.getenv(name)
    return value if value is not None else default


def parse_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def get_public_ip(url: str, timeout: int) -> str:
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.text.strip()


def get_public_ip_with_fallback(
    primary_url: str,
    secondary_url: str,
    timeout: int,
    label: str,
    logger: logging.Logger,
) -> Optional[str]:
    primary_ip: Optional[str] = None
    secondary_ip: Optional[str] = None
    primary_err: Optional[Exception] = None
    secondary_err: Optional[Exception] = None

    try:
        primary_ip = get_public_ip(primary_url, timeout)
    except Exception as exc:
        primary_err = exc

    try:
        secondary_ip = get_public_ip(secondary_url, timeout)
    except Exception as exc:
        secondary_err = exc

    if primary_ip and secondary_ip:
        if primary_ip != secondary_ip:
            logger.error(
                "%s IP mismatch: primary=%s secondary=%s",
                label,
                primary_ip,
                secondary_ip,
            )
            return None
        return primary_ip

    if primary_ip and secondary_err:
        logger.warning("%s secondary IP check failed: %s", label, secondary_err)
        return primary_ip

    if secondary_ip and primary_err:
        logger.warning("%s primary IP check failed: %s", label, primary_err)
        return secondary_ip

    if primary_err and secondary_err:
        logger.error("%s IP checks failed: primary=%s secondary=%s", label, primary_err, secondary_err)
    return None


def cf_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def cf_get_zone_id(base_url: str, token: str, zone_name: str, timeout: int) -> str:
    resp = requests.get(
        f"{base_url}/zones",
        params={"name": zone_name, "status": "active"},
        headers=cf_headers(token),
        timeout=timeout,
    )
    resp.raise_for_status()
    data = resp.json()
    if not data.get("success") or not data.get("result"):
        raise RuntimeError(f"Zone not found or not active: {zone_name}")
    return data["result"][0]["id"]


def cf_get_record(base_url: str, token: str, zone_id: str, name: str, rtype: str, timeout: int) -> Optional[Dict[str, Any]]:
    resp = requests.get(
        f"{base_url}/zones/{zone_id}/dns_records",
        params={"name": name, "type": rtype},
        headers=cf_headers(token),
        timeout=timeout,
    )
    resp.raise_for_status()
    data = resp.json()
    if not data.get("success") or not data.get("result"):
        return None
    return data["result"][0]


def cf_update_record(
    base_url: str,
    token: str,
    zone_id: str,
    record_id: str,
    payload: Dict[str, Any],
    timeout: int,
) -> Dict[str, Any]:
    resp = requests.put(
        f"{base_url}/zones/{zone_id}/dns_records/{record_id}",
        headers=cf_headers(token),
        data=json.dumps(payload),
        timeout=timeout,
    )
    resp.raise_for_status()
    data = resp.json()
    if not data.get("success"):
        raise RuntimeError(f"Cloudflare update failed: {data}")
    return data["result"]


def cf_create_record(
    base_url: str,
    token: str,
    zone_id: str,
    payload: Dict[str, Any],
    timeout: int,
) -> Dict[str, Any]:
    resp = requests.post(
        f"{base_url}/zones/{zone_id}/dns_records",
        headers=cf_headers(token),
        data=json.dumps(payload),
        timeout=timeout,
    )
    resp.raise_for_status()
    data = resp.json()
    if not data.get("success"):
        raise RuntimeError(f"Cloudflare create failed: {data}")
    return data["result"]


def infer_zone_from_record(record_name: str) -> str:
    parts = record_name.split(".")
    if len(parts) < 2:
        raise ValueError("Record name must contain a zone, e.g. sub.example.com")
    return ".".join(parts[-2:])


def main() -> int:
    token = env("CLOUDFLARE_API_TOKEN") or env("CF_API_TOKEN")
    if not token:
        print("Missing CLOUDFLARE_API_TOKEN (or CF_API_TOKEN)", file=sys.stderr)
        return 2

    record_name = env("CF_RECORD_NAME", "sfc.taylor.md")
    record_types_raw = env("CF_RECORD_TYPES") or env("CF_RECORD_TYPE", "A")
    record_types = [t.strip().upper() for t in record_types_raw.split(",") if t.strip()]
    zone_id = env("CF_ZONE_ID")
    zone_name = env("CF_ZONE_NAME")
    if not zone_id and not zone_name:
        zone_name = infer_zone_from_record(record_name)

    interval_seconds = int(env("INTERVAL_SECONDS", "3600"))
    public_ip_url = env("PUBLIC_IP_URL", "https://api.ipify.org")
    public_ip_url_2 = env("PUBLIC_IP_URL_2", "https://ifconfig.me/ip")
    timeout_seconds = int(env("HTTP_TIMEOUT_SECONDS", "10"))
    run_once = parse_bool(env("RUN_ONCE"), False)

    log_file = env("LOG_FILE", "/logs/ddns.log")
    log_level = env("LOG_LEVEL", "INFO").upper()

    logger = logging.getLogger("ddns")
    logger.setLevel(log_level)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    logger.info("Starting ddns monitor")
    logger.info("Record: %s (%s)", record_name, ",".join(record_types))
    logger.info("Interval seconds: %s", interval_seconds)
    if zone_id:
        logger.info("Using zone id")
    else:
        logger.info("Using zone name: %s", zone_name)

    base_url = "https://api.cloudflare.com/client/v4"

    while True:
        try:
            ip = get_public_ip_with_fallback(
                public_ip_url,
                public_ip_url_2,
                timeout_seconds,
                "IPv4",
                logger,
            )
            if not ip:
                raise RuntimeError("Unable to determine IPv4 address")
            if zone_id:
                zid = zone_id
            else:
                zid = cf_get_zone_id(base_url, token, zone_name, timeout_seconds)

            for record_type in record_types:
                ip_to_use = ip
                if record_type == "AAAA":
                    ip_to_use = get_public_ip_with_fallback(
                        env("PUBLIC_IPV6_URL", "https://api64.ipify.org"),
                        env("PUBLIC_IPV6_URL_2", "https://ifconfig.me/ip"),
                        timeout_seconds,
                        "IPv6",
                        logger,
                    )
                    if not ip_to_use:
                        raise RuntimeError("Unable to determine IPv6 address")

                record = cf_get_record(base_url, token, zid, record_name, record_type, timeout_seconds)

                if record and record.get("content") == ip_to_use:
                    logger.info("No change. %s is still %s", record_type, ip_to_use)
                    continue

                ttl_env = env("CF_TTL")
                if ttl_env is None:
                    ttl = record.get("ttl", 1) if record else 1
                else:
                    ttl = int(ttl_env)

                proxied_env = env("CF_PROXIED")
                if proxied_env is None:
                    proxied = record.get("proxied", False) if record else False
                else:
                    proxied = parse_bool(proxied_env, False)

                payload = {
                    "type": record_type,
                    "name": record_name,
                    "content": ip_to_use,
                    "ttl": ttl,
                    "proxied": proxied,
                }

                if record:
                    cf_update_record(base_url, token, zid, record["id"], payload, timeout_seconds)
                    logger.info("Updated DNS %s (%s) -> %s", record_name, record_type, ip_to_use)
                else:
                    cf_create_record(base_url, token, zid, payload, timeout_seconds)
                    logger.info("Created DNS %s (%s) -> %s", record_name, record_type, ip_to_use)
        except Exception as exc:
            logger.error("Update failed: %s", exc)

        if run_once:
            break
        time.sleep(interval_seconds)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
