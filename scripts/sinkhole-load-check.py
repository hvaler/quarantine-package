"""AF-4 load check for the sinkhole, runnable without Docker.

Starts sinkhole.py's TCP server in-process, holds N connections open, then
sends an HTTP POST and checks that the POST is recorded with its payload
while the held connections are still open. (SO_ORIGINAL_DST is Linux-only;
off Linux the destination is recorded as unknown, which does not affect
this check.)
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
time.sleep(2.5)
records = [json.loads(line) for line in captured.getvalue().splitlines() if line.strip()]
print(json.dumps({"recordsAfterClose": sum(1 for r in records if r.get("type") == "tcp"), "expected": held_target + 1}), file=REAL_STDOUT)
sys.exit(0 if ok else 1)
