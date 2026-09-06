from __future__ import annotations

PROBE_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
    "https://connectivitycheck.platform.hicloud.com/generate_204",
]


DOWNLOAD_URL_R1 = "https://speed.cloudflare.com/__down?bytes=262144"


DOWNLOAD_URL_R2 = "https://speed.cloudflare.com/__down?bytes=262144"


DOWNLOAD_BYTES = 262144


MIN_THROUGHPUT_KBPS = 64.0


SERVICE_PROBES = {
    "yandex": "https://yandex.ru",
    "vk": "https://vk.com",
    "ozon": "https://ozon.ru",
    "telegram_api": "https://api.telegram.org",
}


RESULT_SCHEMA_VERSION = 1


HELD_EXIT_CODE = 2


TCP_PROTOCOLS = {"vless", "vmess", "trojan", "ss"}


TERMINAL_PASS = "PASS"
