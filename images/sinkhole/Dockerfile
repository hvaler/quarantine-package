# Sinkhole and host-probe tools image. Base pinned by digest.
FROM python:3.12-alpine@sha256:e6dae589c1c05976188fd3bd019afd091445fc533ed2ea29001beddc7368a9c8
RUN apk add --no-cache iptables ip6tables tcpdump
COPY sinkhole.py entrypoint.sh /opt/sinkhole/
RUN chmod 0555 /opt/sinkhole/entrypoint.sh && chmod 0444 /opt/sinkhole/sinkhole.py
ENTRYPOINT ["/opt/sinkhole/entrypoint.sh"]
