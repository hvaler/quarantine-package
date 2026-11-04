# Deploying on a Vultr VM

This sets up the whole backend on one Vultr Cloud Compute VM:
- Caddy (TLS) on ports 80 and 443;
- the web app on `127.0.0.1:8080`;
- Docker for the sandboxes.

Every step can be pasted as-is and ends with a check. Run them as root on the VM unless a step says otherwise.

**Placeholders.** Replace these three before you paste. The values come with your deployment instructions (OPERATOR-3).

| Placeholder | Meaning |
|---|---|
| `<repo-url>` | the public GitHub URL of this repository |
| `<PINNED_SHA>` | the exact commit to deploy (40 hex characters) |
| `<your-dns-name>` | the DNS name of the VM, e.g. `qp.example.com` |

**The model key is never typed on a command line.** You paste it into one file with an editor (step 6).

## 0. The VM

- **Image and size:** Vultr Cloud Compute, Ubuntu 24.04 LTS x64, at least 2 vCPU, 4 GB RAM and 50 GB disk.
- **DNS:** an A record (for example `qp.example.com`) pointing at the VM's IPv4 address.
- **SSH:** log in as root.

## 1. Firewall: only 22, 80 and 443

```sh
ufw allow 22/tcp && ufw allow 80/tcp && ufw allow 443/tcp && ufw --force enable && ufw status
```
**Check:** `ufw status` lists exactly 22, 80 and 443 as ALLOW.

Docker does not open any port here: no container publishes a port, and the app listens on 127.0.0.1 only.

## 2. Docker Engine

```sh
apt-get update && apt-get install -y ca-certificates curl git
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list
apt-get update && apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin
docker info --format '{{.SecurityOptions}}'
```
**Check:** the output contains `name=seccomp,profile=builtin`.

## 3. Node.js 22

```sh
curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && apt-get install -y nodejs
node --version
```
**Check:** `v22.12` or later.

## 4. Service user and the code at a pinned commit

```sh
useradd --system --create-home --home-dir /home/qp --shell /usr/sbin/nologin qp
usermod -aG docker qp
git clone <repo-url> /opt/quarantine-package
cd /opt/quarantine-package && git checkout <PINNED_SHA> && git log -1 --format=%H
mkdir -p /var/lib/quarantine-package/receipts /opt/quarantine-package/state /opt/quarantine-package/evidence
chown -R qp:qp /opt/quarantine-package /var/lib/quarantine-package
```
**Check:** `git log -1` prints the pinned SHA.

The product has no npm dependencies, so `npm ci` has nothing to install and is not needed.

## 5. Build the images and run the tests

```sh
cd /opt/quarantine-package
sudo -u qp npm run build:images
sudo -u qp npm test
```
**Check:**
- the build ends with `built qp-sandbox:s1-<sha8>` and `built qp-sinkhole:s1-<sha8>`;
- `npm test` reports `fail 0`.

## 6. The model key (root-only file)

```sh
install -d -m 0700 -o root -g root /etc/quarantine-package
install -m 0600 -o root -g root /dev/null /etc/quarantine-package/env
nano /etc/quarantine-package/env
```
In the editor, type one line, `VULTR_INFERENCE_KEY=` followed by your key, then save.

**Check:** `stat -c '%U %a' /etc/quarantine-package/env` prints `root 600`. Do not `cat` the file.

systemd reads this file as root and passes the key only into the service's environment. It never appears in
`ps`, in logs, in a receipt, or in a sandbox.

## 7. The web app as a systemd service

```sh
cp /opt/quarantine-package/deploy/qp-web.service /etc/systemd/system/qp-web.service
systemctl daemon-reload && systemctl enable --now qp-web
sleep 2 && curl -fsS http://127.0.0.1:8080/healthz
```
**Check:** `{"ok":true,"queued":0,"running":0}`.

The service runs as `qp` (in the `docker` group) and listens on `127.0.0.1:8080`. The port must stay within
8080–8089. It trusts `X-Forwarded-For` only from Caddy on 127.0.0.1.

## 8. Caddy with automatic HTTPS

```sh
apt-get install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' > /etc/apt/sources.list.d/caddy-stable.list
apt-get update && apt-get install -y caddy
mkdir -p /var/log/caddy && chown caddy:caddy /var/log/caddy
sed 's/qp.example.com/<your-dns-name>/' /opt/quarantine-package/deploy/Caddyfile > /etc/caddy/Caddyfile
systemctl restart caddy
curl -fsS https://<your-dns-name>/healthz
```
**Check:** the public `/healthz` answers over HTTPS. The Caddyfile turns Caddy's local admin API off (`admin off`); after editing it, restart Caddy with `systemctl restart caddy`.

## 9. Verify (C15, C16)

**C15, from another network:** open `https://<your-dns-name>/` on another device (for example a phone on
mobile data).
1. Run the three demos.
2. Open each receipt link.

**C16, on the VM.** The checks run their own tasks under the run prefix `qpchk`, so they never count or touch the live
web service's tasks (prefix `qp`):
```sh
cd /opt/quarantine-package
sudo -u qp sh deploy/c16-checks.sh https://<your-dns-name>
```
**Check:** every line is `PASS`, and the script prints `evidence: evidence/c16-<utc>.json`. The checks are:
- the C2 host probe (nothing left the VM);
- the hostile fixture gets `do-not-install`;
- `/healthz` answered during the hostile run;
- C6 zero leftovers;
- the C7 secret scan;
- the public URL answers.

## Operating

| Task | Command |
|---|---|
| Logs | `journalctl -u qp-web -f` (never contains the key) |
| Stop | `systemctl stop qp-web`. Running tasks are interrupted and torn down within 10 s. |
| Leftover check / cleanup | `sudo -u qp node src/cli.js leftovers`. `cleanup` removes **every** object of the prefix, so run it only with the service stopped: `systemctl stop qp-web && sudo -u qp node src/cli.js cleanup` |
| Update | `git fetch && git checkout <NEW_SHA> && sudo -u qp npm run build:images && systemctl restart qp-web` |
