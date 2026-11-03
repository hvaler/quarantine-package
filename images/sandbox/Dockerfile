# Sandbox and download image. Node 22 (>= 22.12) pinned by digest.
FROM node:22-bookworm-slim@sha256:4b150b48b4116e2a22f2c39cc27025fbf4f153e2078fd3b14d159fdb5c7279da
RUN apt-get update \
 && apt-get install -y --no-install-recommends strace \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 10001 qp && useradd -u 10001 -g 10001 -d /home/qp -s /bin/sh -M qp \
 && mkdir -p /work /in /out /home/qp /opt/qp \
 && chown 10001:10001 /work /in /out /home/qp
COPY runtime/ /opt/qp/
RUN chmod -R a-w /opt/qp && chmod 0555 /opt/qp/*.sh
ENV NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false \
    HOME=/home/qp
USER 10001:10001
WORKDIR /work
