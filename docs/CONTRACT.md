# Quarantine Package — S1 contract (DEC-18)

This file fixes the interfaces the adversary and the auditor test against.
The basis is dispatch 1 plus decision revision 1 (DEC-2r1, DEC-5r1, DEC-11 to DEC-20).

## 1. CLI

From a clean clone (Node ≥ 22.12 on the host, Docker running):

```sh
npm run build:images                      # builds qp-sandbox:s1 and qp-sinkhole:s1 (bases pinned by digest)
node src/cli.js analyse <spec> [--host-probe]
node src/cli.js analyse --fixture <name> [--host-probe]
node src/cli.js leftovers
node src/cli.js cleanup
node src/cli.js scan-secrets [<path>...]
npm test                                  # unit tests (node:test)
```

| Command | Effect | Exit code |
|---|---|---|
| `analyse <spec>` | analyse a registry spec (`name`, `name@version`, `name@tag`, `@scope/name[@v]`) | 0 completed (any verdict), 2 invalid input, 3 aborted in the download phase, 4 infrastructure failure |
| `analyse --fixture <name>` | analyse `<repo>/fixtures/<name>`; only `[a-z0-9-]` directory names inside that folder, and the package must be `"private": true` | same |
| `--host-probe` | also run the C2 host probe during the task (result in `hostProbe`) | same |
| `leftovers` | list every container, network and volume of this `QP_RUN_PREFIX` | 0 none, 1 some |
| `cleanup` | remove every object of this `QP_RUN_PREFIX` | 0 |
| `scan-secrets` | pattern scan (default: the repo and the receipts dir); prints file, line and pattern name only | 0 clean, 1 hits |

`analyse` prints one JSON line on stdout: `{taskId, status, verdict, package, rulesFired, abortReason, hostProbePass, receipt}`.
`receipt` is the absolute path of the receipt file.

**Environment.**

| Variable | Meaning | Default |
|---|---|---|
| `QP_RUN_PREFIX` | run prefix, `^[a-z0-9]{1,16}$` | `qp` |
| `QP_RECEIPTS_DIR` | where receipts are written | `./receipts` (relative to the cwd) |
| `QP_SANDBOX_TIMEOUT_S` | sandbox wall clock | 60 |
| `QP_DOWNLOAD_TIMEOUT_S` | download wall clock | 120 |
| `QP_DOWNLOAD_MAX_BYTES` | unpacked download size | 52428800 |
| `QP_DOWNLOAD_MAX_PACKAGES` | packages in the tree | 300 |

Limit overrides are for tests; acceptance runs at the defaults. The receipt always records the applied values in `limits`.

**Input validation (DEC-19).** Rejected with exit 2 and `status: aborted`, `abortReason: invalid-input`:
`file:`, `git+`/`git:`, URLs, `npm:` aliases, paths, names starting with `-`, whitespace and shell metacharacters.
Ranges are limited to `^x.y.z` and `~x.y.z`; tags are allowed. The exact resolved version is in `package.version`.

## 2. Docker objects and lifecycle (DEC-7, DEC-14, DEC-15)

Every object the product creates is named `ar-<prefix>-<role>-<taskId>` (`taskId` = 10 hex characters) and labelled
`qp.managed=true`, `qp.run-prefix=<prefix>`, `qp.task-id=<taskId>` and `qp.owner-pid=<cli pid>`.

| Role word | Type | Purpose |
|---|---|---|
| `vol` | volume | download output, mounted read-only into the sandbox at `/in` |
| `download` | container | `npm install --ignore-scripts` (network on, scripts off) |
| `net` | network | per-task `--internal` network (IPv6 off) |
| `sinkhole` | container | DNS and TCP/UDP sink; owns the network namespace the sandbox joins |
| `sandbox` | container | `npm rebuild --offline` + harness, traced |
| `tracer` | container | `strace -f` attached to the sandbox |
| `probe`, `ctlnet`, `ctlin`, `ctlout` | container/network | only with `--host-probe` (C2) |

**Cleanup scope.** Cleanup and the reaper act only on objects labelled `qp.run-prefix=<prefix>`, or named
`^ar-<prefix>-(download|sinkhole|sandbox|tracer|probe|ctlin|ctlout|net|ctlnet|vol)-[a-f0-9]{10}$`. Nothing else is touched.

**Mechanisms.**
- Normal end, failure or timeout: the orchestrator removes every object of the task in `finally`. The receipt records it in `teardown`.
- Every container is `--rm` and runs under an in-container hard timeout:
  - sandbox: `timeout -s KILL <wall+5>`;
  - download: `timeout -s KILL <download+5>`;
  - probe: `timeout -s KILL <wall+120>`.
- CLI killed (hard kill, `taskkill /F /T` included): a watchdog started per task watches the CLI pid and removes the task's objects when it disappears.
  - It runs as a grandchild, so it is not in the CLI's process tree.
  - It polls every 500 ms, sweeps once, then sweeps again after 3 s.
- Ctrl+C: `SIGINT` does not interrupt `analyse`. The task tears down, writes its receipt, then exits. The watchdog also covers it.
- Every `analyse` first reaps objects of its own prefix whose `qp.owner-pid` is no longer alive. `cleanup` removes all objects of the prefix.
- **Host temp root:** none. The product writes no host-side temp files. A fixture is bind-mounted read-only from `<repo>/fixtures/<name>`, and the only host output is the receipt in `QP_RECEIPTS_DIR`.

## 3. Sandbox, tracer and sinkhole (C1, C2, DEC-12, DEC-13, DEC-16)

**Sandbox.**
- Image `qp-sandbox:s1`, from `node:22-bookworm-slim@sha256:4b150b48…7279da` (Node 22.23.4) plus `strace`.
- Flags: `--read-only --cap-drop ALL --security-opt no-new-privileges --user 10001:10001 --pids-limit 64 --memory 268435456 --memory-swap 268435456 --cpus 0.5`.
- tmpfs mounts, each `rw,exec,nosuid,nodev,uid=10001,gid=10001,mode=0700`:
  - `/work` 128 MiB;
  - `/tmp` 64 MiB;
  - `/home/qp` (HOME) 16 MiB.
- Volume `ar-…-vol-…` mounted at `/in` read-only.
- `--network container:<sinkhole>`: the sandbox has no network of its own and joins the sinkhole's namespace.
  - That namespace has exactly one interface, on the task's `--internal` network.
  - `HostConfig.NetworkMode` is therefore `container:<sinkhole id>`. The internal network is in `sandbox.network`, with `internal: true`.
- No docker.sock, no host pid/ipc/userns.

**Tracer.**
- Image `qp-sandbox:s1`, `--entrypoint /opt/qp/trace.sh`.
- Flags: `--pid container:<sandbox>` (shared pid namespace), `--network none`, `--read-only`, `--cap-drop ALL --cap-add SYS_PTRACE`, `--security-opt no-new-privileges`, `--user 0:0`, `--pids-limit 16`.
- Behaviour:
  - It runs `strace -f -qq -tt -y -s 4096` over execve/clone/fork, the file syscalls, socket/connect/send* and chdir, attached to the sandbox's pid 1.
  - The sandbox's pid 1 (`/opt/qp/run.sh`, uid 10001) does nothing until `/proc/self/status` shows a non-zero `TracerPid`. Only then does it copy `/in` to `/work` and exec the staged work.
  - The wait is bounded at 10 s (DEC-12r1). Past that it prints `QP-TRACER-MISSING` and exits 95, and no package code has run. The task then ends `status: aborted`, `abortReason: tracer-unavailable`, `verdict: null`, CLI exit 4. No limit is recorded.
  - If the tracer attaches but its stream ends more than 1 s before the sandbox exits, `completeness.kernel-trace` is `{ok: false, detail.state: "incomplete"}`, so the result is `review` (i).
- **Channel integrity:**
  - The trace exists only as the tracer container's stdout, read by the orchestrator over its `docker start -a` pipe. It is never written to a path in the sandbox.
  - The sandbox (uid 10001, no capabilities) cannot open `/proc/<tracer pid>/fd/*`, ptrace it or signal it, because those are a different uid.
  - So the package can neither forge nor truncate the trace.
- This replaces "strace as parent inside the sandbox" (DEC-12 example). The backstop is still kernel-level and covers every descendant of the sandbox's pid 1.

**Sinkhole.**
- Image `qp-sinkhole:s1`, from `python:3.12-alpine@sha256:e6dae5…a9c8` plus iptables and tcpdump.
- Flags: `--cap-drop ALL --cap-add NET_ADMIN --read-only --security-opt no-new-privileges`, `--sysctl net.ipv6.conf.all.disable_ipv6=1`, `--sysctl net.ipv4.conf.all.route_localnet=1`.
- Its entrypoint does three things:
  - adds a default route on its only interface;
  - redirects every TCP connection, DNS query (UDP 53, any destination including `1.1.1.1:53`) and other UDP datagram from uid 10001 to local listeners;
  - drops anything else from uid 10001.
- It logs one JSON line per attempt:
  - TCP: original destination via `SO_ORIGINAL_DST`, plus TLS SNI from the ClientHello (any port);
  - HTTP: method, host, path, body length and chunked flag;
  - DNS: query name and type. The answer is a per-name fake address in 198.18.0.0/15, never routed.
- It answers HTTP with 403 and refuses TLS after the ClientHello. Nothing is forwarded, since the network is internal.
- **Listeners in the shared namespace:** TCP `0.0.0.0:15001`, UDP `0.0.0.0:15353` (DNS), UDP `0.0.0.0:15354` (other UDP), plus Docker's embedded DNS on `127.0.0.11`. The sinkhole uses no unix sockets, abstract ones included.
- **What the sandbox can and cannot do in that namespace:**
  - Every TCP connection and UDP datagram from uid 10001 is redirected by the nat rules, loopback and the sinkhole's own ports included. So any direct attempt to reach a listener is itself logged as an attempt (`orig_dest` 127.0.0.1:<port>), never parsed as a sinkhole record.
  - uid 10001 can bind free ports in the namespace (Docker sets `ip_unprivileged_port_start=0`). But its own outbound traffic still goes to the sinkhole, and nothing else connects to it.
  - Sinkhole records are produced only by the sinkhole process. Package-supplied bytes appear only inside JSON-escaped fields (`path`, `host`, `sni`, DNS `name`) of a record whose type and destination the sinkhole sets.

**Trusted channels.**

| Source | Writable by the package? | Used for |
|---|---|---|
| tracer stdout (strace) | no | files, network attempts, processes and actors; markers `kernel-trace` and `ended-normally` |
| sinkhole stdout | no (package data appears only inside JSON-escaped fields) | destinations, SNI, payload, DNS names; marker `sinkhole-log` |
| sandbox stdout `QPEV <nonce> <json>` (preload/harness) | yes: can append, cannot remove | env-read and env-enumerate detail, heartbeats, load record |

The nonce is per task (`receipt.nonce`). Records with another nonce are dropped and counted in `sandbox.preloadForeignRecords`.
The nonce is readable by package code in the same process, so QPEV records are forgeable additions:
- A forged record can only add observations.
- A forged heartbeat cannot upgrade a verdict. The `instrumentation-heartbeat` marker is decided from the trace: for every node exec, the envp must carry `NODE_OPTIONS=--require=/opt/qp/preload.cjs` (the tracer prints exec envp) and the same pid must open `/opt/qp/preload.cjs`. The QPEV heartbeat is also required, but never sufficient. `kernel-trace` and `ended-normally` come from the tracer and the container exit status only.
- npm CLI processes (exact paths `/usr/local/bin/npm` or `.../npm/bin/npm-cli.js`) run with env unwrapped. Only the orchestrator's own npm (the trace's npm pid) is accepted that way. An npm CLI started by package code fails `instrumentation-heartbeat`, which gives (i). A script merely named `npm` is wrapped like any other node process.
- The load record can be forged by package code that already runs inside the harness. This is listed in `knownLimitations`.

## 4. Actors (DEC-2r1)

Actors are derived from the process tree in the trace (clone/fork return values, first record wins; threads join their process):
- `npm`: the process the stage script (`/opt/qp/stage.sh`) starts with `execve(".../npm")`, by pid. A process title or binary name elsewhere never confers it.
- `package`:
  - every descendant of that npm process (lifecycle `sh`, scripts, their children);
  - every descendant of the harness process;
  - inside the harness process (`node /opt/qp/harness.cjs`), every rule-relevant syscall (the harness itself does no writes, network or credential access).
  - Env reads inside the harness use the preload's stack: any frame under `/work/node_modules/` makes them `package`, otherwise `harness`.
- `harness`: the stage script, the in-sandbox scan (`/opt/qp/scan.cjs`), pid 1 and its helpers before the stage (`cp`, `sed`).
- `unattributed`: any pid with no process record. Unattributed counts against the package. So does any sinkhole record with no matching trace record.

## 5. Receipt (`<QP_RECEIPTS_DIR>/<taskId>.json`, schema `qp-receipt/1`)

| Field path | Content |
|---|---|
| `status` | `completed` or `aborted` |
| `verdict` | `install`, `review`, `do-not-install`, or `null` when aborted |
| `abortReason`, `abortDetail` | when aborted: `invalid-input`, `download-failed`, `download-time`, `download-size`, `download-deps`, `download-non-registry`, `infrastructure` |
| `rulesFired[]` | `{id, tier, text, observationIds[]}`, one per fired rule (`a`, `b`, `c1`, `d`, `e`, `f`, `g`, `h`, `i`) |
| `package` | `{requested, source: registry\|fixture, name, version}` (exact resolved version) |
| `limits` | applied limits (`downloadSeconds`, `downloadMaxBytes`, `downloadMaxPackages`, `sandboxSeconds`, `pids`, `memoryBytes`, `cpus`, `tmpfs*Bytes`) |
| `download` | `{container, hardening, seconds, exitCode, inventory: {name, version, packageCount, unpackedBytes, nonRegistry[], installScripts[]}, output}` |
| `sandbox.endedBy` | `exit`, `orchestrator-kill` or `kill` (end reason) |
| `sandbox.limitsHit[]` | `{reason: wall-clock\|pids\|memory, detail}` |
| `sandbox.hardening`, `sandbox.tracer.hardening`, `sandbox.sinkhole.hardening`, `download.hardening` | HostConfig snapshot from `docker inspect` after create: `User, ReadonlyRootfs, Privileged, CapDrop, CapAdd, SecurityOpt, PidsLimit, Memory, MemorySwap, NanoCpus, Tmpfs, Binds, Mounts, NetworkMode, PidMode, IpcMode, UsernsMode, AutoRemove` |
| `sandbox.containerId` | the new sandbox's container id; differs on every task |
| `sandbox.network` | `{name, internal, subnet, enableIPv6}` |
| `sandbox.roles` | `{stagePid, npmPid, harnessPid, scanPid}` |
| `completeness` | `{"instrumentation-heartbeat", "paths-resolved", "kernel-trace", "sinkhole-log", "ended-normally", "harness-ran"}`, each `{ok, detail}` (DEC-11). Rules for two of them: `instrumentation-heartbeat` needs, for every node process, a QPEV heartbeat AND a kernel-traced open of `/opt/qp/preload.cjs` by that pid. `paths-resolved` is false when the tracer could not resolve a path the package read, stat-ed, linked to or connected to (truncated string, unknown dirfd or cwd). `kernel-trace.detail.state` is `complete`, `incomplete` or `missing`. |
| `harness` | `{mode: "fallback-require (no model in S1)", loaded, detail}` |
| `explanation` | `{source: "none (no model in S1)", text: null}`; never an input to the verdict |
| `observations[]` | see below |
| `network.sinkholeLog[]` | the sinkhole's records for this task's sandbox |
| `secretScan.sandbox` | in-sandbox scan: `keyLikeEnvNames[]` (names only), `ignoredImageVars`, `dockerSockPresent[]`, `mounts[]`, `pass` |
| `secretScan.receipt` | pattern scan of the receipt itself: `{pass, hits[{line, pattern}]}` |
| `hostProbe` | with `--host-probe`: `{capturePoint, whyComplete, filter, sandboxSubnet, controlSubnet, sinkholeIp, nonceName, counts{sandboxLeaving, inSubnet, controlLeaving, dnsNonceLeaving, dnsNonceSeen}, samples, pass}` |
| `teardown` | `{removed{containers, networks, volumes}, leftoversForTask[], hostTempDirs: []}` |
| `knownLimitations[]` | stated blind spots |
| `logs.sandboxOutput` | package and phase output (data only, capped at 8 KB, pattern-redacted, QPEV lines removed) |

**Observation** (`observations[]`). Every entry has `id, kind, actor, pid, exe, dest, orig_dest, port, sni, proto, blocked, payload, path, nonce`, plus kind-specific fields:

| `kind` | Meaning | Extra fields |
|---|---|---|
| `fs-write` | open for write/create/truncate/append, creat, mkdir, rename/link (both paths), unlink, rmdir, symlink, truncate, chmod; successful or blocked | `syscall`, `errno` |
| `fs-access` | any access (open, stat, access, unix connect) to docker.sock or a credential path | `syscall`, `errno` |
| `proc-environ` | open of `/proc/<pid>/environ` | — |
| `env-read` | read of an env var whose name is key-like (preload) | `name` |
| `env-enumerate` | full env enumeration by package code, or exec of `env`/`printenv` (c2, observation only) | `rule`, `via` |
| `net-dns` | DNS attempt: UDP 53 to any address. TCP to port 53 is a `net-tcp` attempt and its payload is judged like any TCP | `queries[{name, qtype}]`, `sinkholeLogged` |
| `net-tcp` | TCP connect to any address and port. `proto` is `http`, `tls`, `unknown` or `none`; HTTP detail in `http{method, host, path, payloadBytes}` | `family`, `sinkholeLogged`, `http` |
| `net-udp` | UDP datagram other than DNS | `family`, `sinkholeLogged` |
| `spawn` | exec by package code (first 50) | `argv` |
| `pids-exhaustion` | fork/clone failed with EAGAIN | `failedForks` |
| `limit` | the task ended by a limit | `reason`, `detail` |
| `load` | harness result; `ok`, `mode` (`fallback-require`/`fallback-import`), `error`, `resolved` | |
| `completeness` | one per DEC-11 marker; `marker`, `ok`, `detail` | |

`payload` is `true` in two cases, both TCP only:
- plaintext HTTP with method POST, PUT or PATCH, or a body (Content-Length > 0), or chunked encoding;
- raw bytes on a non-HTTP, non-TLS TCP connection (any port, 53 included).

It is `false` for DNS, for TLS (the body is not inspected) and for a bodiless HTTP GET. It is `null` when the sinkhole has no matching record.
Rule (d) applies only to `net-tcp`. UDP, DNS included, is always (f) per DEC-2r1; the receipt still shows the bytes in the sinkhole log.

`printenv NAME` (exec by package code) is recorded as an `env-read` of `NAME`, so a key-like name fires (c1). This is pending the analyst's ruling on challenge point 5. Bare `env`/`printenv` is `env-enumerate` (c2).

**Path resolution.**
- The tracer runs `strace -y -s 4096`, so dirfd-relative paths resolve through the fd's directory.
- `/proc/<self|pid|thread-self>/root/X` is reported as `X`, and `/proc/self/cwd/X` as `<cwd>/X`.
- Paths through a symlink created during the task are reported as the path they reach.
- A symlink whose target is a credential path or docker.sock is itself an `fs-access`.
- An unresolvable write is recorded with path `unresolved:<raw>`, which counts as outside the allowed areas (a). An unresolvable read, stat, link target or unix connect sets the `paths-resolved` marker to false, which gives (i).

**Allowed write areas:** `/work` and `/tmp` (no rule). Writes to `/dev/null`, `/dev/tty`, `/dev/std*`, `/dev/fd/*` and `/proc/self/fd/*` are not file writes and are not recorded.

## 6. Verdict module (C4)

`src/verdict.js` exports `decide(input)` and `RULES`.
- `input` is `{ observations: Observation[] }`. Any other field (e.g. `explanation`, `model`, `verdict`) is ignored.
- It returns `{ verdict, rules: [{id, tier, text, observationIds}] }`.
- It is pure: no I/O, no clock, and it does not mutate its input.
- Tiers are evaluated in order (`do-not-install`, then `review`); the first tier with a fired rule wins.
- `install` needs no fired rule. A missing `load` observation fires (h).

**Named C4 test:** `test/verdict.test.js` → `C4 manipulated explanation does not change the verdict (test: manipulated-explanation)`.

## 7. Fixtures (`<repo>/fixtures/`, selected with `--fixture <dir>`)

| Dir | Package | Expected |
|---|---|---|
| `hostile` | `qp-fixture-hostile` | `do-not-install` (a, b, d; plus f, g) |
| `loop` | `qp-fixture-loop` | `do-not-install` (e: wall-clock) |
| `forkbomb` | `qp-fixture-forkbomb` | `do-not-install` (e: pids or wall-clock, with a `pids-exhaustion` observation) |
| `netprobe` | `qp-fixture-netprobe` | `review` (f): DNS name, direct IP 1.1.1.1:443, TLS SNI on 443 and 8443 |
| `netbenign` | `qp-fixture-netbenign` | `review` (f): bodiless HTTP GET |

## 8. Host probe (C2, DEC-5r1)

See `hostProbe` in the receipt.
- **Capture point:**
  - a helper container `ar-<prefix>-probe-<taskId>` with `--network host`, `NET_RAW` and `NET_ADMIN`, running `tcpdump -i any -nn -p`;
  - Docker Desktop/WSL2: the netns of the VM running dockerd, where the task's bridge and the VM's egress `eth0` both live;
  - plain Linux (S4): the host's root netns.
- **Why it sees everything:** the only interface of the sandbox's namespace is a veth on the task bridge. Any packet leaving it crosses that bridge here, with its original source address, before routing or NAT.
- **Filter:** `net <sandbox subnet> or net <control subnet> or port 53`.
- **Expectations:**
  - `sandboxLeaving` = 0;
  - `dnsNonceLeaving` = 0 (the sandbox resolves `qp-<nonce>.probe.invalid`);
  - positive controls `inSubnet` > 0 (`ctlin` talks to the sinkhole over the bridge) and `controlLeaving` > 0 (`ctlout`, on a non-internal `ar-` network, sends to 1.1.1.1:80).
