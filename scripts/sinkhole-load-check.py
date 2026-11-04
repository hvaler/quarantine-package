"""AF-4 load check for the sinkhole, runnable without Docker.

Starts sinkhole.py's TCP server in-process, holds N connections open, then
sends an HTTP POST and checks that the POST is recorded with its payload
while the held connections are still open. (SO_ORIGINAL_DST is Linux-only;
off Linux the destination is recorded as unknown, which does not affect
this check.)
Then (AF-6) sends a payload 3 s after connecting on a connection that stays
open, requests the flush (SIGUSR1 path) and checks the payload is recorded.
Usage: python scripts/sinkhole-load-check.py [held=150]
"""
import importlib.util
import io
import json
import os
import socket
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("sinkhole", os.path.join(HERE, "..", "images", "sinkhole", "sinkhole.py"))
sink = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sink)

REAL_STDOUT = sys.stdout
captured = io.StringIO()
sink.sys.stdout = captured  # emit() writes JSON lines to stdout
sink.TCP_PORT = 25001
threading.Thread(target=sink.tcp_server, daemon=True).start()
time.sleep(0.3)

held_target = int(sys.argv[1]) if len(sys.argv) > 1 else 150
held = []
for _ in range(held_target):
    c = socket.create_connection(("127.0.0.1", sink.TCP_PORT), timeout=2)
    held.append(c)

body = json.dumps({"envCount": 12}).encode()
req = (b"POST /collect HTTP/1.1\r\nHost: recolector.example.com\r\nContent-Type: application/json\r\n"
       b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
p = socket.create_connection(("127.0.0.1", sink.TCP_PORT), timeout=3)
p.sendall(req)
reply = p.recv(100)
p.close()
time.sleep(0.5)

records = [json.loads(line) for line in captured.getvalue().splitlines() if line.strip()]
posts = [r for r in records if r.get("type") == "tcp" and r.get("method") == "POST"]
ok = bool(posts) and posts[0]["payloadBytes"] == len(body) and reply.startswith(b"HTTP/1.1 403")
print(json.dumps({"held": len(held), "postRecorded": bool(posts), "payloadBytes": posts[0]["payloadBytes"] if posts else None,
                  "replyStatus": reply[:12].decode(errors="replace"), "threads": threading.active_count(), "pass": ok}), file=REAL_STDOUT)
for c in held:
    c.close()
time.sleep(1.0)
records = [json.loads(line) for line in captured.getvalue().splitlines() if line.strip()]
after = sum(1 for r in records if r.get("type") == "tcp")
print(json.dumps({"recordsAfterClose": after, "expected": held_target + 1}), file=REAL_STDOUT)
ok = ok and after == held_target + 1

# AF-6: a payload sent well after the old 2 s cut, on a connection that is never
# completed or closed by the peer, is recorded with its bytes once the flush runs.
late = socket.create_connection(("127.0.0.1", sink.TCP_PORT), timeout=3)
silent = socket.create_connection(("127.0.0.1", sink.TCP_PORT), timeout=3)
time.sleep(3.0)
late.sendall(b"POST /late HTTP/1.1\r\nHost: late.example.com\r\nContent-Length: 999\r\n\r\nNPM_TOKEN-shaped-")
time.sleep(0.3)
sink.request_flush()
time.sleep(0.8)
records = [json.loads(line) for line in captured.getvalue().splitlines() if line.strip()]
lates = [r for r in records if r.get("type") == "tcp" and r.get("path") == "/late"]
flushed = [r for r in records if r.get("type") == "flushed"]
late_ok = bool(lates) and lates[0]["payloadBytes"] == 17 and lates[0]["method"] == "POST" and bool(flushed) and flushed[0]["closed"] == 2
print(json.dumps({"af6LateRecorded": bool(lates), "latePayloadBytes": lates[0]["payloadBytes"] if lates else None,
                  "flushedClosed": flushed[0]["closed"] if flushed else None, "pass": late_ok}), file=REAL_STDOUT)
late.close()
silent.close()
sys.exit(0 if ok and late_ok else 1)
