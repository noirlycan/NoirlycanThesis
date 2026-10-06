from __future__ import annotations

import ipaddress


def is_private_or_local_destination(value: str | None) -> bool:
    if not value:
        return True
    host = value.strip().lower()
    if host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local


def _matches_allowlist(value: str | None, allowlist: list[str] | None) -> bool:
    if not value or not allowlist:
        return False
    host = value.strip().lower()
    for entry in allowlist:
        item = str(entry).strip()
        if not item:
            continue
        try:
            network = ipaddress.ip_network(item, strict=False)
            address = ipaddress.ip_address(host)
            if address in network:
                return True
        except ValueError:
            if host == item.lower():
                return True
    return False


def is_external_beacon_candidate(
    destination_ip: str | None,
    destination_hostname: str | None,
    *,
    enabled: bool = True,
    allowlist: list[str] | None = None,
) -> bool:
    if not enabled:
        return False
    if _matches_allowlist(destination_ip, allowlist) or _matches_allowlist(destination_hostname, allowlist):
        return False
    if destination_ip and not is_private_or_local_destination(destination_ip):
        return True
    if destination_hostname and not is_private_or_local_destination(destination_hostname):
        lowered = destination_hostname.lower()
        if lowered.endswith(".local") or lowered.endswith(".lan"):
            return False
        return True
    return False
