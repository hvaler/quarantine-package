"""Quarantine Package sinkhole.

Runs inside the sinkhole container. The sandbox shares this container's network
namespace, and iptables rules (see entrypoint.sh) redirect every TCP connection
and every DNS query made by the sandbox uid to the listeners below, whatever
the destination (name or direct IP). Each attempt is written to stdout as one
JSON line. Nothing is forwarded anywhere: the container sits on an internal
Docker network with no route out.
"""

import json
import socket
import struct
import sys
import threading
import time
from datetime import datetime, timezone

TCP_PORT = 15001
DNS_PORT = 15353
UDP_OTHER_PORT = 15354
SO_ORIGINAL_DST = 80
FAKE_NET = (198, 18)  # RFC 2544 benchmark range, never routed

_lock = threading.Lock()
_names_by_ip = {}
_ip_by_name = {}
_next = [1]


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def emit(record):
    record["t"] = now()
    line = json.dumps(record, sort_keys=True)
    with _lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


def fake_ip_for(name):
    with _lock:
        if name in _ip_by_name:
            return _ip_by_name[name]
        n = _next[0]
        _next[0] += 1
        ip = "%d.%d.%d.%d" % (FAKE_NET[0], FAKE_NET[1] + (n >> 16), (n >> 8) & 255, n & 255)
        _ip_by_name[name] = ip
        _names_by_ip[ip] = name
        return ip


# ---------------------------------------------------------------- DNS

def parse_qname(data, off):
    labels = []
    while off < len(data):
        ln = data[off]
        if ln == 0:
            return ".".join(labels), off + 1
        if ln & 0xC0:
            return ".".join(labels), off + 2
        labels.append(data[off + 1: off + 1 + ln].decode("ascii", "replace"))
        off += 1 + ln
    raise ValueError("truncated qname")


def dns_answer(data):
    (tid, _flags, qd, _an, _ns, _ar) = struct.unpack("!HHHHHH", data[:12])
    if qd < 1:
        raise ValueError("no question")
    name, off = parse_qname(data, 12)
    qtype, qclass = struct.unpack("!HH", data[off: off + 4])
    question = data[12: off + 4]
    name = name.rstrip(".").lower()
    answer = b""
    ancount = 0
    resolved = None
    if qtype == 1 and qclass == 1:
        resolved = fake_ip_for(name)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 5, 4) + socket.inet_aton(resolved)
        ancount = 1
    header = struct.pack("!HHHHHH", tid, 0x8180, 1, ancount, 0, 0)
    return header + question + answer, name, qtype, resolved


def dns_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", DNS_PORT))
    while True:
        data, addr = s.recvfrom(4096)
        try:
            reply, name, qtype, resolved = dns_answer(data)
            emit({"type": "dns", "srcIp": addr[0], "srcPort": addr[1], "name": name, "qtype": qtype, "answer": resolved})
            s.sendto(reply, addr)
        except Exception as exc:  # malformed query: still an attempt
            emit({"type": "dns", "srcPort": addr[1], "name": None, "error": str(exc)[:80]})


# ---------------------------------------------------------------- UDP (non-DNS)

def udp_other_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", UDP_OTHER_PORT))
    while True:
        data, addr = s.recvfrom(65535)
        emit({"type": "udp", "srcIp": addr[0], "srcPort": addr[1], "payloadBytes": len(data),
              "note": "original destination not recoverable for UDP"})


# ---------------------------------------------------------------- TCP

def original_dst(conn):
    raw = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    port = struct.unpack("!H", raw[2:4])[0]
    ip = socket.inet_ntoa(raw[4:8])
    return ip, port


def parse_sni(hello):
    # TLS record header (5) + handshake header (4) + version (2) + random (32)
    try:
        if hello[0] != 0x16 or hello[5] != 0x01:
            return None
        p = 5 + 4 + 2 + 32
        sid_len = hello[p]
        p += 1 + sid_len
        cs_len = struct.unpack("!H", hello[p: p + 2])[0]
        p += 2 + cs_len
        cm_len = hello[p]
        p += 1 + cm_len
        ext_total = struct.unpack("!H", hello[p: p + 2])[0]
        p += 2
        end = p + ext_total
        while p + 4 <= end:
            etype, elen = struct.unpack("!HH", hello[p: p + 4])
            p += 4
            if etype == 0:
                q = p + 2
                name_type = hello[q]
                name_len = struct.unpack("!H", hello[q + 1: q + 3])[0]
                if name_type == 0:
                    return hello[q + 3: q + 3 + name_len].decode("ascii", "replace")
            p += elen
    except (IndexError, struct.error):
        return None
    return None


def recv_some(conn, limit, deadline):
    buf = b""
    while len(buf) < limit:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        conn.settimeout(remaining)
        try:
            chunk = conn.recv(min(4096, limit - len(buf)))
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        buf += chunk
        if b"\r\n\r\n" in buf and buf[:1] != b"\x16":
            head, _, body = buf.partition(b"\r\n\r\n")
            cl = 0
            for line in head.split(b"\r\n")[1:]:
                k, _, v = line.partition(b":")
                if k.strip().lower() == b"content-length":
                    try:
                        cl = int(v.strip())
                    except ValueError:
                        cl = 0
            if len(body) >= min(cl, limit):
                break
        if buf[:1] == b"\x16" and len(buf) >= 5:
            rec_len = struct.unpack("!H", buf[3:5])[0]
            if len(buf) >= 5 + rec_len:
                break
    return buf


def handle_tcp(conn, addr):
    try:
        try:
            dst_ip, dst_port = original_dst(conn)
        except OSError:
            dst_ip, dst_port = None, None
        rec = {"type": "tcp", "srcIp": addr[0], "srcPort": addr[1], "dstIp": dst_ip, "dstPort": dst_port,
               "dstName": _names_by_ip.get(dst_ip)}
        data = recv_some(conn, 65536, time.monotonic() + 2.0)
        rec["bytesReceived"] = len(data)
        if data[:1] == b"\x16":
            rec["protocol"] = "tls"
            rec["sni"] = parse_sni(data)
            rec["payloadBytes"] = None  # encrypted application data never sent: handshake refused
        elif data[:16].split(b" ")[0] in (b"GET", b"POST", b"PUT", b"PATCH", b"DELETE", b"HEAD", b"OPTIONS", b"CONNECT"):
            head, _, body = data.partition(b"\r\n\r\n")
            lines = head.split(b"\r\n")
            method, _, rest = lines[0].partition(b" ")
            path = rest.rpartition(b" ")[0]
            host = None
            chunked = False
            for line in lines[1:]:
                k, _, v = line.partition(b":")
                if k.strip().lower() == b"host":
                    host = v.strip().decode("ascii", "replace")
                if k.strip().lower() == b"transfer-encoding" and b"chunked" in v.lower():
                    chunked = True
            rec["chunked"] = chunked
            rec["protocol"] = "http"
            rec["method"] = method.decode("ascii", "replace")
            rec["path"] = path.decode("ascii", "replace")[:200]
            rec["host"] = host
            rec["payloadBytes"] = len(body)
            try:
                conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
        else:
            rec["protocol"] = "unknown" if data else "none"
            rec["payloadBytes"] = len(data)
        emit(rec)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def tcp_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", TCP_PORT))
    s.listen(128)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_tcp, args=(conn, addr), daemon=True).start()


def main():
    for fn in (dns_server, udp_other_server, tcp_server):
        threading.Thread(target=fn, daemon=True).start()
    time.sleep(0.2)
    emit({"type": "ready", "tcpPort": TCP_PORT, "dnsPort": DNS_PORT})
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
