from __future__ import annotations

import bisect
import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from .models import ProxyConfig, SourceResult, SourceSpec


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


@dataclass(frozen=True, slots=True)
class WhiteEvidence:
    networks: tuple[ipaddress.IPv4Network, ...]
    starts: tuple[int, ...]
    domains: frozenset[str]
    cidr_source: str
    domain_source: str | None

    def contains(self, value: str) -> bool:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        if not isinstance(address, ipaddress.IPv4Address):
            return False
        index = bisect.bisect_right(self.starts, int(address)) - 1
        return index >= 0 and address in self.networks[index]

    def contains_sni(self, value: str) -> bool:
        domain = _domain(value)
        if domain is None:
            return False
        labels = domain.split(".")
        return any(".".join(labels[index:]) in self.domains for index in range(len(labels) - 1))


def evidence_specs(config: dict[str, Any]) -> list[SourceSpec]:
    section = config.get("white_evidence", {})
    specs: list[SourceSpec] = []
    for kind in ("cidr_sources", "domain_sources"):
        content_type = "white-cidr" if kind == "cidr_sources" else "white-domains"
        for item in section.get(kind, []):
            specs.append(
                SourceSpec(
                    source_id=item["id"],
                    name=item.get("name", item["id"]),
                    url=item["url"],
                    lanes=set(),
                    content_type=content_type,
                )
            )
    return specs


def build_evidence(results: list[SourceResult]) -> WhiteEvidence:
    cidr_source = None
    networks: tuple[ipaddress.IPv4Network, ...] = ()
    for result in results:
        if result.source.content_type != "white-cidr" or result.error or not result.content.strip():
            continue
        try:
            networks = _networks(result.content)
        except ValueError:
            result.error = "INVALID_CIDR_FEED"
            continue
        cidr_source = result.source.source_id
        break
    if cidr_source is None:
        raise ValueError("WHITE_EVIDENCE_FAILED")

    domains: frozenset[str] = frozenset()
    domain_source = None
    for result in results:
        if (
            result.source.content_type != "white-domains"
            or result.error
            or not result.content.strip()
        ):
            continue
        parsed = frozenset(
            filter(None, (_domain(line.strip()) for line in result.content.splitlines()))
        )
        if len(parsed) < 50:
            result.error = "INVALID_DOMAIN_FEED"
            continue
        domains = parsed
        domain_source = result.source.source_id
        break

    return WhiteEvidence(
        networks=networks,
        starts=tuple(int(network.network_address) for network in networks),
        domains=domains,
        cidr_source=cidr_source,
        domain_source=domain_source,
    )


def evidence_for(config: ProxyConfig, evidence: WhiteEvidence) -> str | None:
    endpoint_allowed = bool(config.resolved_ip and evidence.contains(config.resolved_ip))
    server_name = _visible_server_name(config)
    sni_allowed = bool(server_name and evidence.contains_sni(server_name))
    if endpoint_allowed and sni_allowed:
        return "cidr+sni"
    if endpoint_allowed:
        return "cidr"
    if sni_allowed:
        return "sni"
    return None


def evidence_priority(signal: str) -> int:
    return {"cidr+sni": 3, "cidr": 2, "sni": 1}.get(signal, 0)


def _visible_server_name(config: ProxyConfig) -> str | None:
    security = str(config.options.get("security", "none"))
    always_tls = config.protocol in {"trojan", "hysteria2", "tuic"}
    if security not in {"tls", "reality"} and not always_tls:
        return None
    return str(config.options.get("sni") or config.host)


def _networks(content: str) -> tuple[ipaddress.IPv4Network, ...]:
    parsed: set[ipaddress.IPv4Network] = set()
    invalid = 0
    for line in content.splitlines():
        value = line.strip()
        if not value or value.startswith(("#", ";", "//")):
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            invalid += 1
            continue
        if not isinstance(network, ipaddress.IPv4Network) or not network.is_global:
            invalid += 1
            continue
        if network.prefixlen < 8:
            invalid += 1
            continue
        parsed.add(network)
    if len(parsed) < 100 or invalid > max(10, len(parsed) // 100):
        raise ValueError("invalid CIDR feed")
    collapsed = tuple(ipaddress.collapse_addresses(parsed))
    coverage = sum(network.num_addresses for network in collapsed) / 2**32
    if coverage > 0.05:
        raise ValueError("CIDR feed is implausibly broad")
    return collapsed


def _domain(value: str) -> str | None:
    value = value.strip().lower().rstrip(".")
    if not value or any(ord(character) < 32 for character in value):
        return None
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return value if DOMAIN_RE.fullmatch(value) else None
