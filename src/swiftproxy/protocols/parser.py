from __future__ import annotations

from swiftproxy.models import ProxyConfig
from swiftproxy.protocols.quic import parse_hysteria, parse_hysteria2, parse_tuic
from swiftproxy.protocols.stream import parse_shadowsocks, parse_trojan, parse_vless, parse_vmess
from swiftproxy.protocols.validation import CONTROL_RE

SUPPORTED_PROXY_SCHEMES = frozenset(
    {"vless", "vmess", "trojan", "ss", "hysteria", "hysteria2", "hy2", "tuic"}
)


def parse_uri(uri: str) -> ProxyConfig:
    uri = uri.strip()
    if not uri or len(uri) > 8192 or CONTROL_RE.search(uri):
        raise ValueError("malformed URI")
    scheme = uri.split(":", 1)[0].lower()
    if scheme not in SUPPORTED_PROXY_SCHEMES or not uri.lower().startswith(f"{scheme}://"):
        raise ValueError("unsupported protocol")
    parsers = {
        "vless": parse_vless,
        "vmess": parse_vmess,
        "trojan": parse_trojan,
        "ss": parse_shadowsocks,
        "hysteria": parse_hysteria,
        "hysteria2": parse_hysteria2,
        "hy2": parse_hysteria2,
        "tuic": parse_tuic,
    }
    parser = parsers.get(scheme)
    if not parser:
        raise ValueError("unsupported protocol")
    return parser(uri)
