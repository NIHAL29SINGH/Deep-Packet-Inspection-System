#!/usr/bin/env python3
"""Generate the deterministic sample capture used by the demo, smoke test and benchmarks.

Unlike a random packet blaster, this produces realistic *bidirectional* sessions with valid
IP/TCP/UDP checksums, so the capture also opens cleanly in Wireshark:

* TCP three-way handshakes, data in both directions, FIN/ACK teardown
* TLS ClientHello with SNI - one quarter split across two TCP segments (needs reassembly)
* HTTP requests with real CRLF line endings
* DNS queries *and* responses
* QUIC-style UDP/443 traffic
* Scenario flows: Telnet, RDP, backdoor-style port, TLS without SNI, a large upload
  (outbound byte asymmetry), a non-first IPv4 fragment, an IPv6 packet, ICMP, a truncated frame

Usage:  python3 generate_sample_pcap.py [output.pcap|output.pcapng] [sessions]
The default output is sample_traffic.pcap next to this script. A .pcapng extension writes pcapng instead of
classic pcap. Output is identical on every run.
"""
import hashlib
import hmac
import random
import socket
import struct
import sys
from pathlib import Path

try:  # optional: only needed for real (encrypted) QUIC Initial packets
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTO = False

SEED = 1337
DEFAULT_SESSIONS = 600

DOMAINS = [
    ("www.google.com", 10), ("www.youtube.com", 8), ("www.facebook.com", 6), ("api.twitter.com", 5),
    ("www.instagram.com", 4), ("www.netflix.com", 5), ("github.com", 5), ("discord.com", 3),
    ("www.tiktok.com", 4), ("open.spotify.com", 4), ("www.amazon.com", 6), ("www.microsoft.com", 5),
    ("www.apple.com", 4), ("www.cloudflare.com", 3), ("zoom.us", 3), ("web.telegram.org", 2),
    ("web.whatsapp.com", 2), ("updates.example.org", 3), ("cdn.example.net", 3),
]
HTTP_HOSTS = ["detectportal.firefox.com", "connectivitycheck.example.org", "example.com"]

rng = random.Random(SEED)
packets = []  # (timestamp_us, frame bytes)
clock = [1_700_000_000_000_000]  # microseconds since epoch


def tick(low=40, high=900):
    clock[0] += rng.randint(low, high)
    return clock[0]


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def mac(last: int) -> bytes:
    return bytes([0x02, 0x00, 0x00, 0x00, 0x00, last & 0xFF])


def ip4(addr: str) -> bytes:
    return socket.inet_aton(addr)


def ipv4_header(src, dst, proto, payload_len, ident=0, flags_frag=0x4000):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + payload_len, ident, flags_frag, 64, proto, 0,
                         ip4(src), ip4(dst))
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:]


def frame(src_mac, dst_mac, ethertype, body):
    return dst_mac + src_mac + struct.pack("!H", ethertype) + body


def tcp_segment(src, dst, sport, dport, seq, ack, flags, payload=b""):
    header = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, 65535, 0, 0)
    pseudo = ip4(src) + ip4(dst) + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    csum = checksum(pseudo + header + payload)
    return header[:16] + struct.pack("!H", csum) + header[18:] + payload


def udp_datagram(src, dst, sport, dport, payload):
    length = 8 + len(payload)
    header = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = ip4(src) + ip4(dst) + struct.pack("!BBH", 0, 17, length)
    csum = checksum(pseudo + header + payload) or 0xFFFF
    return struct.pack("!HHHH", sport, dport, length, csum) + payload


def emit(src, dst, proto, l4, src_last, dst_last, ident=0, flags_frag=0x4000, gap=None):
    body = ipv4_header(src, dst, proto, len(l4), ident, flags_frag) + l4
    packets.append((tick(*(gap or (40, 900))), frame(mac(src_last), mac(dst_last), 0x0800, body)))


class TcpFlow:
    """One TCP connection; each call emits a correctly sequenced packet."""

    def __init__(self, client, server, sport, dport, client_last, server_last):
        self.c, self.s, self.sp, self.dp = client, server, sport, dport
        self.cl, self.sl = client_last, server_last
        self.cseq = rng.randint(1000, 2**31)
        self.sseq = rng.randint(1000, 2**31)

    def _send(self, from_client, flags, payload=b"", seq_override=None, gap=None):
        if from_client:
            seq = self.cseq if seq_override is None else seq_override
            seg = tcp_segment(self.c, self.s, self.sp, self.dp, seq, self.sseq, flags, payload)
            emit(self.c, self.s, 6, seg, self.cl, self.sl, gap=gap)
            if seq_override is None:
                self.cseq += len(payload) + (1 if flags & 0x03 else 0)
        else:
            seg = tcp_segment(self.s, self.c, self.dp, self.sp, self.sseq, self.cseq, flags, payload)
            emit(self.s, self.c, 6, seg, self.sl, self.cl, gap=gap)
            self.sseq += len(payload) + (1 if flags & 0x03 else 0)

    def handshake(self):
        self._send(True, 0x02)
        self._send(False, 0x12)
        self._send(True, 0x10)

    def client_data(self, payload, gap=None):
        self._send(True, 0x18, payload, gap=gap)
        self._send(False, 0x10, gap=gap)

    def server_data(self, payload, gap=None):
        self._send(False, 0x18, payload, gap=gap)

    def client_ack(self):
        self._send(True, 0x10)

    def close(self):
        self._send(True, 0x11)
        self._send(False, 0x11)
        self._send(True, 0x10)


# Client "families": each builds its ClientHello differently, so each has its own JA3 fingerprint.
#   0 browser-like (GREASE placeholders, TLS 1.3 offered)   1 curl-like (TLS 1.3, no GREASE)
#   2 scripting-library-like (TLS 1.2 only)                 3 legacy client (TLS 1.0)
GREASE = [0x0A0A, 0x2A2A, 0x4A4A, 0x6A6A, 0xAAAA, 0xCACA, 0xEAEA]


def _ext(ext_type, data):
    return struct.pack("!HH", ext_type, len(data)) + data


def client_hello(sni, pad=0, profile=0):
    random_bytes = bytes(rng.getrandbits(8) for _ in range(32))
    session = bytes(rng.getrandbits(8) for _ in range(32))
    g1, g2, g3 = rng.choice(GREASE), rng.choice(GREASE), rng.choice(GREASE)  # GREASE values vary per connection
    if profile == 0:
        version, cipher_ids = 0x0303, [g1, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8]
        groups, versions = [g2, 0x001D, 0x0017, 0x0018], [g3, 0x0304, 0x0303]
        order = ["grease", "sni", "groups", "pformats", "alpn", "versions"]
    elif profile == 1:
        version, cipher_ids = 0x0303, [0x1302, 0x1303, 0x1301, 0xC02C, 0xC030, 0x009F, 0xCCA9]
        groups, versions = [0x001D, 0x0017, 0x0018, 0x0019], [0x0304, 0x0303]
        order = ["sni", "pformats", "groups", "alpn", "versions"]
    elif profile == 2:
        version, cipher_ids = 0x0303, [0xC02F, 0xC02B, 0xC030, 0xC02C, 0x009E, 0x009C]
        groups, versions = [0x0017, 0x0018], []
        order = ["sni", "groups", "pformats"]
    else:
        version, cipher_ids = 0x0301, [0x002F, 0x0035, 0x000A]
        groups, versions = [], []
        order = ["sni", "pformats"]
    ciphers = b"".join(struct.pack("!H", c) for c in cipher_ids)
    parts = {}
    if sni:
        name = sni.encode()
        entry = b"\x00" + struct.pack("!H", len(name)) + name
        parts["sni"] = _ext(0x0000, struct.pack("!H", len(entry)) + entry)
    if groups:
        parts["groups"] = _ext(0x000A, struct.pack("!H", 2 * len(groups)) + b"".join(struct.pack("!H", x) for x in groups))
    parts["pformats"] = _ext(0x000B, b"\x01\x00")
    parts["alpn"] = _ext(0x0010, struct.pack("!H", 3) + b"\x02h2")
    if versions:
        parts["versions"] = _ext(0x002B, bytes([2 * len(versions)]) + b"".join(struct.pack("!H", v) for v in versions))
    parts["grease"] = _ext(g1 ^ 0x1010 if (g1 ^ 0x1010) in GREASE else 0x5A5A, b"")
    extensions = b"".join(parts[k] for k in order if k in parts)
    if pad:
        extensions += _ext(0x0015, b"\x00" * pad)  # padding extension
    body = (struct.pack("!H", version) + random_bytes + bytes([len(session)]) + session +
            struct.pack("!H", len(ciphers)) + ciphers + b"\x01\x00" +
            struct.pack("!H", len(extensions)) + extensions)
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def server_hello_and_data(size):
    return b"\x16\x03\x03" + struct.pack("!H", 90) + b"\x02" + b"\x00" * 89, b"\x17\x03\x03" + struct.pack("!H", size) + bytes(size)


def dns_query(name, txid):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack("!HH", 1, 1)


def dns_response(query, answer_ip):
    txid = query[:2]
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + ip4(answer_ip)
    return txid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + query[12:] + answer


def do_dns(client, cl, name, server_ip):
    txid = rng.randint(1, 65535)
    sport = rng.randint(20000, 60000)
    q = dns_query(name, txid)
    emit(client, "10.0.0.1", 17, udp_datagram(client, "10.0.0.1", sport, 53, q), cl, 1)
    emit("10.0.0.1", client, 17, udp_datagram("10.0.0.1", client, 53, sport, dns_response(q, server_ip)), 1, cl)


def server_ip_for(name):
    return "203.0.113.%d" % (1 + (sum(name.encode()) % 200))


def tls_session(client, cl, name):
    server = server_ip_for(name)
    do_dns(client, cl, name, server)
    flow = TcpFlow(client, server, rng.randint(20000, 60000), 443, cl, 200)
    flow.handshake()
    hello = client_hello(name, pad=rng.choice([0, 0, 0, 380]), profile=cl % 3)
    if rng.random() < 0.25 and len(hello) > 200:
        cut = rng.randint(60, 180)  # ClientHello split across two TCP segments
        flow.client_data(hello[:cut])
        flow.client_data(hello[cut:])
    else:
        flow.client_data(hello)
    sh, app = server_hello_and_data(1100)
    flow.server_data(sh)
    for _ in range(rng.randint(2, 7)):
        flow.server_data(app)
        flow.client_ack()
        if rng.random() < 0.4:
            flow.client_data(b"\x17\x03\x03\x00\x40" + bytes(64))
    flow.close()


def http_session(client, cl, host):
    server = server_ip_for(host)
    do_dns(client, cl, host, server)
    flow = TcpFlow(client, server, rng.randint(20000, 60000), 80, cl, 201)
    flow.handshake()
    request = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: DPI-Sample/1.0\r\nAccept: */*\r\n\r\n".encode()
    flow.client_data(request)
    body = b"<html><body>ok</body></html>" * 20
    flow.server_data(f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body)
    flow.client_ack()
    flow.close()


QUIC_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")


def _expand_label(secret, label, length):
    full = b"tls13 " + label.encode()
    info = struct.pack("!H", length) + bytes([len(full)]) + full + b"\x00"
    return hmac.new(secret, info + b"\x01", hashlib.sha256).digest()[:length]  # one HKDF block is enough


def _varint(value):
    if value < 64:
        return bytes([value])
    if value < 16384:
        return struct.pack("!H", 0x4000 | value)
    return struct.pack("!I", 0x80000000 | value)


def quic_initial(host):
    """A genuine QUIC v1 client Initial (RFC 9001): protected with keys derived from the public DCID."""
    dcid = bytes(rng.getrandbits(8) for _ in range(8))
    scid = bytes(rng.getrandbits(8) for _ in range(4))
    hello = client_hello(host)[5 + 0:]  # strip the 5-byte TLS record header; QUIC carries the bare handshake
    secret = _expand_label(hmac.new(QUIC_SALT_V1, dcid, hashlib.sha256).digest(), "client in", 32)
    key, iv, hp = (_expand_label(secret, "quic key", 16), _expand_label(secret, "quic iv", 12),
                   _expand_label(secret, "quic hp", 16))
    pn, pn_len = 0, 4
    crypto = b"\x06" + _varint(0) + _varint(len(hello)) + hello
    prefix = bytes([0xC0 | (pn_len - 1)]) + struct.pack("!I", 1) + bytes([len(dcid)]) + dcid + \
        bytes([len(scid)]) + scid + _varint(0)
    padding = max(0, 1200 - (len(prefix) + 2 + pn_len + 16 + len(crypto)))
    plaintext = crypto + b"\x00" * padding
    header = prefix + struct.pack("!H", 0x4000 | (pn_len + len(plaintext) + 16)) + struct.pack("!I", pn)
    nonce = bytes(a ^ b for a, b in zip(iv, b"\x00" * 4 + struct.pack("!Q", pn)))
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, header)
    mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(ciphertext[4 - pn_len:20 - pn_len])
    packet = bytearray(header + ciphertext)
    packet[0] ^= mask[0] & 0x0F
    for i in range(pn_len):
        packet[len(header) - pn_len + i] ^= mask[1 + i]
    return bytes(packet)


def quic_session(client, cl, name):
    server = server_ip_for(name)
    sport = rng.randint(20000, 60000)
    if HAVE_CRYPTO:
        initial = quic_initial(name)
    else:  # opaque stand-in; the engine then cannot read the SNI
        initial = b"\xc3\x00\x00\x00\x01" + bytes(rng.getrandbits(8) for _ in range(1100))
    emit(client, server, 17, udp_datagram(client, server, sport, 443, initial), cl, 202)
    for _ in range(rng.randint(2, 6)):
        emit(server, client, 17, udp_datagram(server, client, 443, sport, b"\x40" + bytes(900)), 202, cl)


def scenarios():
    # Telnet in cleartext
    flow = TcpFlow("10.0.0.12", "198.51.100.23", 40001, 23, 12, 210)
    flow.handshake()
    flow.client_data(b"admin\r\n")
    flow.server_data(b"Password: ")
    flow.client_data(b"hunter2\r\n")
    flow.close()
    # RDP and a backdoor-style port
    for port, last in ((3389, 211), (4444, 212)):
        flow = TcpFlow("10.0.0.13", "198.51.100.40", 41000 + port % 100, port, 13, last)
        flow.handshake()
        flow.client_data(bytes(100))
        flow.server_data(bytes(300))
        flow.close()
    # TLS 443 without any SNI extension, to a server that an earlier DNS answer resolved to a known name
    do_dns("10.0.0.14", 14, "stealth.example.org", "198.51.100.77")
    flow = TcpFlow("10.0.0.14", "198.51.100.77", 42000, 443, 14, 213)
    flow.handshake()
    flow.client_data(client_hello(None))
    sh, app = server_hello_and_data(800)
    flow.server_data(sh)
    flow.server_data(app)
    flow.close()
    # Large upload: ~420 KB outbound, tiny replies (outbound byte asymmetry)
    flow = TcpFlow("10.0.0.15", "203.0.113.250", 43000, 443, 15, 214)
    flow.handshake()
    flow.client_data(client_hello("backup.uploads-example.test"))
    for _ in range(300):
        flow._send(True, 0x18, b"\x17\x03\x03\x05\x00" + bytes(1395), gap=(20, 80))
        if rng.random() < 0.05:
            flow._send(False, 0x10)
    flow.close()
    # Legacy client that only offers TLS 1.0
    flow = TcpFlow("10.0.0.20", "198.51.100.88", 44000, 443, 20, 218)
    flow.handshake()
    flow.client_data(client_hello("legacy.example.com", profile=3))
    flow.server_data(server_hello_and_data(300)[0])
    flow.close()
    # DNS tunnelling: one client asks for many distinct, encoded-looking names under a single domain
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    for _ in range(30):
        label = "".join(rng.choice(alphabet) for _ in range(32))
        do_dns("10.0.0.19", 19, f"{label}.t.exfil-tunnel.example", "198.51.100.200")
    # Non-first IPv4 fragment (no transport header) and the first fragment of a UDP datagram
    first = udp_datagram("10.0.0.16", "198.51.100.5", 5000, 9999, bytes(1000))[:808]
    emit("10.0.0.16", "198.51.100.5", 17, first, 16, 215, ident=777, flags_frag=0x2000)
    emit("10.0.0.16", "198.51.100.5", 17, bytes(204), 16, 215, ident=777, flags_frag=101)
    # ICMP echo
    echo = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + bytes(56)
    echo = echo[:2] + struct.pack("!H", checksum(echo)) + echo[4:]
    emit("10.0.0.17", "198.51.100.9", 1, echo, 17, 216)
    # IPv6 TCP packet (parsed for visibility, not inspected)
    v6 = struct.pack("!IHBB16s16s", 0x60000000, 20, 6, 64, socket.inet_pton(socket.AF_INET6, "2001:db8::1"),
                     socket.inet_pton(socket.AF_INET6, "2001:db8::2")) + bytes(20)
    packets.append((tick(), frame(mac(18), mac(217), 0x86DD, v6)))
    # Truncated frame (shorter than an Ethernet header): counted as malformed
    packets.append((tick(), b"\x00" * 9))


def write_pcap(out):
    with open(out, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, data in packets:
            f.write(struct.pack("<IIII", ts // 1_000_000, ts % 1_000_000, len(data), len(data)))
            f.write(data)


def _ng_block(block_type, body):
    pad = (-len(body)) % 4
    total = 12 + len(body) + pad
    return struct.pack("<II", block_type, total) + body + b"\x00" * pad + struct.pack("<I", total)


def write_pcapng(out):
    """pcapng: section header, one Ethernet interface (explicit microsecond resolution), enhanced packet blocks."""
    shb = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
    idb = struct.pack("<HHI", 1, 0, 65535) + struct.pack("<HH", 9, 1) + b"\x06" + b"\x00" * 3 + struct.pack("<HH", 0, 0)
    with open(out, "wb") as f:
        f.write(_ng_block(0x0A0D0D0A, shb))
        f.write(_ng_block(1, idb))
        for ts, data in packets:
            epb = struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(data), len(data)) + data
            f.write(_ng_block(6, epb))


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("sample_traffic.pcap")
    sessions = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_SESSIONS
    names = [d for d, w in DOMAINS for _ in range(w)]

    for i in range(sessions):
        last = 10 + (i % 30)
        client = f"10.0.0.{last}"
        roll = rng.random()
        if roll < 0.62:
            tls_session(client, last, rng.choice(names))
        elif roll < 0.74:
            http_session(client, last, rng.choice(HTTP_HOSTS))
        elif roll < 0.86:
            name = rng.choice(names)
            do_dns(client, last, name, server_ip_for(name))
        else:
            quic_session(client, last, rng.choice(names))
        if i == sessions // 2:
            scenarios()

    packets.sort(key=lambda p: p[0])
    if out.suffix.lower() == ".pcapng":
        write_pcapng(out)
    else:
        write_pcap(out)
    print(f"wrote {len(packets)} packets to {out} ({out.stat().st_size / 1024:.0f} KiB)")


if __name__ == "__main__":
    main()
