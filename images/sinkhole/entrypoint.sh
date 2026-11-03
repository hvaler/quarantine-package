#!/bin/sh
# Sinkhole entrypoint. The sandbox joins this container's network namespace, so
# these rules apply to its traffic. Every TCP connection and DNS query from the
# sandbox uid is redirected to the local sinkhole, whatever the destination;
# any other packet from that uid is dropped. Loopback traffic from the sandbox
# uid is redirected too, so nothing reaches another local listener.
set -eu
SANDBOX_UID="${QP_SANDBOX_UID:-10001}"

# An internal Docker network has no default route, so connect() to any
# outside address would fail with ENETUNREACH before netfilter sees it (and
# the attempt would never reach the sinkhole). A default route on the only
# interface lets every connection reach the OUTPUT nat rules below, which
# send it to the local sinkhole; nothing is forwarded (internal network).
ip route replace default dev eth0

iptables -t nat -I OUTPUT 1 -m owner --uid-owner "$SANDBOX_UID" -p udp --dport 53 -j REDIRECT --to-ports 15353
iptables -t nat -I OUTPUT 2 -m owner --uid-owner "$SANDBOX_UID" -p udp -j REDIRECT --to-ports 15354
iptables -t nat -I OUTPUT 3 -m owner --uid-owner "$SANDBOX_UID" -p tcp -j REDIRECT --to-ports 15001
# After NAT every redirected packet is addressed to 127.0.0.1 (delivered thanks
# to route_localnet=1, set by the orchestrator). Anything else from the sandbox
# uid (e.g. protocols other than TCP/UDP) is dropped.
iptables -I OUTPUT 1 -m owner --uid-owner "$SANDBOX_UID" ! -d 127.0.0.0/8 -j DROP
ip6tables -I OUTPUT 1 -m owner --uid-owner "$SANDBOX_UID" -j DROP 2>/dev/null || true

exec python3 -u /opt/sinkhole/sinkhole.py
