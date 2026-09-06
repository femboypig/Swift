from __future__ import annotations

from swiftproxy.models import ProxyConfig


def validate_security(config: ProxyConfig) -> None:
    if config.options.get("insecure"):
        raise ValueError("certificate verification is disabled")
    security = config.options.get("security", "none")
    if config.protocol in {"vless", "trojan"} and security not in {"tls", "reality"}:
        raise ValueError("authenticated TLS is required")
    if (
        config.protocol == "vmess"
        and security == "none"
        and config.options.get("cipher") in {"none", "zero"}
    ):
        raise ValueError("unencrypted VMess is not publishable")
    if config.protocol == "ss" and config.options.get("method") in {"none", "plain", "table"}:
        raise ValueError("unencrypted Shadowsocks is not publishable")
