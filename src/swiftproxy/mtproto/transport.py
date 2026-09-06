from __future__ import annotations

import ipaddress
import os
import socket
import struct
import time

from mtproxy_checker.attempts import effective_inner_mode
from mtproxy_checker.models import Mode
from mtproxy_checker.parser import decode_secret
from mtproxy_checker.protocol import (
    frame_message,
    make_obfuscated2_handshake,
    make_unencrypted_req_pq_multi,
    parse_res_pq,
    read_frame,
)
from mtproxy_checker.transports import FakeTlsTransport, PlainTransport

from swiftproxy.mtproto.models import TelegramProxy


def _connect(proxy: TelegramProxy, timeout: float) -> socket.socket:
    interface = os.environ.get("SWIFT_BIND_INTERFACE")
    if not interface or os.environ.get("SWIFT_DIRECT_SOCKS"):
        raise ValueError("MTProto checks require a physical interface without SOCKS detours")
    address = ipaddress.ip_address(proxy.resolved_ip or proxy.host)
    sock = socket.socket(socket.AF_INET6 if address.version == 6 else socket.AF_INET)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0")
        sock.settimeout(timeout)
        sock.connect((str(address), proxy.port))
        return sock
    except BaseException:
        sock.close()
        raise


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        chunk = sock.recv(length - len(output))
        if not chunk:
            raise OSError("connection closed")
        output.extend(chunk)
    return bytes(output)


def _check_once(
    proxy: TelegramProxy, mode: Mode, connect_timeout: float, response_timeout: float
) -> float:
    begin = time.monotonic()
    parsed_secret = decode_secret(proxy.secret)
    sock = _connect(proxy, connect_timeout)
    with sock:
        sock.settimeout(response_timeout)
        transport: FakeTlsTransport | PlainTransport
        if mode == Mode.FAKETLS:
            transport = FakeTlsTransport(
                sock, parsed_secret.raw_secret, parsed_secret.faketls_domain
            )
            transport.handshake()
        else:
            transport = PlainTransport(sock)
        inner_mode = effective_inner_mode(mode)
        init_packet, enc, dec = make_obfuscated2_handshake(parsed_secret.raw_secret, inner_mode, 2)
        transport.write(init_packet)
        nonce, request = make_unencrypted_req_pq_multi()
        transport.write(enc.update(frame_message(request, inner_mode)))
        parse_res_pq(read_frame(transport, dec, inner_mode), nonce)
    return (time.monotonic() - begin) * 1000


def _direct_telegram_check(endpoint: str, timeout: float) -> bool:
    host, separator, port_value = endpoint.rpartition(":")
    if not separator:
        return False
    nonce, message = make_unencrypted_req_pq_multi()
    proxy = TelegramProxy(host, int(port_value), "11" * 16, "raw", resolved_ip=host)
    with _connect(proxy, timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(b"\xef" + frame_message(message, Mode.ABRIDGED))
        first = _recv_exact(sock, 1)[0]
        if first < 127:
            length = first * 4
        else:
            length = struct.unpack("<I", _recv_exact(sock, 3) + b"\0")[0] * 4
        if not 0 < length <= 2 * 1024 * 1024:
            return False
        parse_res_pq(_recv_exact(sock, length), nonce)
    return True
