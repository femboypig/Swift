from __future__ import annotations

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


def _direct_socks() -> tuple[str, int] | None:
    value = os.environ.get("SWIFT_DIRECT_SOCKS", "").strip()
    if not value:
        return None
    host, separator, port = value.rpartition(":")
    if not separator or not host:
        raise ValueError("SWIFT_DIRECT_SOCKS must be host:port")
    try:
        port_number = int(port)
    except ValueError as exc:
        raise ValueError("SWIFT_DIRECT_SOCKS port must be an integer") from exc
    if not 1 <= port_number <= 65535:
        raise ValueError("SWIFT_DIRECT_SOCKS port is out of range")
    try:
        if not socket.inet_pton(socket.AF_INET, host) == b"\x7f\x00\x00\x01":
            raise ValueError("SWIFT_DIRECT_SOCKS must point to loopback")
    except OSError:
        if host != "localhost":
            raise ValueError("SWIFT_DIRECT_SOCKS must point to loopback") from None
    return host, port_number


def _connect(proxy: TelegramProxy, timeout: float) -> socket.socket:
    endpoint = proxy.resolved_ip or proxy.host
    direct = _direct_socks()
    if direct is None:
        return socket.create_connection((endpoint, proxy.port), timeout=timeout)
    sock = socket.create_connection(direct, timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2) != b"\x05\x00":
            raise OSError("SOCKS authentication negotiation failed")
        try:
            packed = socket.inet_pton(socket.AF_INET, endpoint)
            address = b"\x01" + packed
        except OSError:
            try:
                packed = socket.inet_pton(socket.AF_INET6, endpoint)
                address = b"\x04" + packed
            except OSError:
                encoded = endpoint.encode("idna")
                if len(encoded) > 255:
                    raise OSError("SOCKS destination is too long") from None
                address = b"\x03" + bytes([len(encoded)]) + encoded
        sock.sendall(b"\x05\x01\x00" + address + struct.pack("!H", proxy.port))
        head = _recv_exact(sock, 4)
        if head[:2] != b"\x05\x00":
            raise OSError("SOCKS connect failed")
        if head[3] == 1:
            _recv_exact(sock, 4)
        elif head[3] == 4:
            _recv_exact(sock, 16)
        elif head[3] == 3:
            _recv_exact(sock, _recv_exact(sock, 1)[0])
        else:
            raise OSError("SOCKS returned an invalid address type")
        _recv_exact(sock, 2)
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
