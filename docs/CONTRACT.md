# Quarantine Package — S1 contract (DEC-18)

This file fixes the interfaces the adversary and the auditor test against.
The basis is dispatch 1 plus decision revision 1 (DEC-2r1, DEC-5r1, DEC-11 to DEC-20).

## 1. CLI

From a clean clone (Node ≥ 22.12 on the host, Docker running):

```sh
npm run build:images                      # builds qp-sandbox:s1-<sha8> and qp-sinkhole:s1-<sha8> (bases pinned by digest)
node src/cli.js analyse <spec> [--host-probe]
node src/cli.js analyse --fixture <name> [--host-probe]
node src/cli.js leftovers
node src/cli.js cleanup
node src/cli.js scan-secrets [<path>...]
npm test                                  # unit tests (node:test)
```

| Command | Effect | Exit code |
|---|---|---|
| `analyse <spec>` | analyse a registry spec (`name`, `name@version`, `name@tag`, `@scope/name[@v]`) | 0 completed (any verdict), 2 invalid input, 3 aborted in the download phase, 4 infrastructure failure, 130 interrupted (Ctrl+C / SIGTERM) |
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
| `QP_IMAGE_TAG` | tag of the product images (`qp-sandbox:<tag>`, `qp-sinkhole:<tag>`); the receipt records tags and image ids (`images`, `*.hardening.imageId`) | `s1-<first 8 hex of the checkout HEAD>` |
| `QP_RECEIPTS_DIR` | where receipts are written | `./receipts` (relative to the cwd) |
| `QP_SANDBOX_TIMEOUT_S` | sandbox wall clock | 60 |
| `QP_DOWNLOAD_TIMEOUT_S` | download wall clock | 120 |
| `QP_DOWNLOAD_MAX_BYTES` | unpacked download size | 52428800 |
| `QP_DOWNLOAD_MAX_PACKAGES` | packages in the tree | 300 |

Limit overrides are for tests; acceptance runs at the defaults. The receipt always records the applied values in `limits`.

**Input validation (DEC-19).** Rejected with exit 2 and `status: aborted`, `abortReason: invalid-input`:
`file:`, `git+`/`git:`, URLs, `npm:` aliases, paths, names starting with `-`, whitespace and shell metacharacters.
Ranges are limited to `^x.y.z` and `~x.y.z`; tags are allowed. The exact resolved version is in `package.version`.

**Dependency specs (DEC-16, DEC-16r1).** The check runs before npm installs anything, inside the download container (`/opt/qp/precheck.cjs`):
- **Root first.** The root manifest's declared specs are classified before anything else: `dependencies`, `optionalDependencies`, `peerDependencies` and `overrides`, nested override keys included and `$ref` values skipped. The root manifest is the fixture's `package.json`, or the registry manifest of the requested spec.
  - If any root spec is not a registry spec, the walk stops there (`precheck.stage: "root"`, `manifestsFetched: 0`).
  - For a fixture nothing has been fetched at all, and npm never runs.
- **Then the tree.** Otherwise it walks the resolved tree breadth-first, reading `dependencies`, `optionalDependencies` and `peerDependencies` of every manifest.
  - Only registry metadata (packuments, never tarballs) is fetched, and only for specs already classified as registry specs.
  - A non-registry spec deeper in the tree is rejected before it is fetched (`stage: "tree"`). That is earlier than DEC-16r1 (2) requires.
- **Shrinkwrap.** A shrinkwrap can pin dependencies to any source, whatever the declared specs say.
  - A local fixture root that ships `npm-shrinkwrap.json` is rejected at the root stage.
  - For registry packages the gate is the **verified lock**. `npm install --package-lock-only --ignore-scripts` resolves the tree without extracting anything. `inventory.cjs lock` then requires every lock entry to resolve from `https://registry.npmjs.org/`, carry an `integrity` hash, not be a link, and declare only registry specs. On failure the result is `aborted` / `download-non-registry`, with details in `download.lockcheck`.
  - Only then does `npm ci --ignore-scripts` install exactly that verified lock.
- **Residual limitation:** the tree walk fetches registry metadata for the registry-spec dependencies it visits before reaching a rejected one. Download-container egress is not restricted to the registry host in S1 (recorded as S4 hardening). This is also listed in the receipt's `knownLimitations`.
- Each declared spec is classified with npm's own `npm-package-arg`. Only `version`, `range`, `tag`, or an `npm:` alias to one of these, is accepted. The host never matters.
- Rejected without being fetched: `git+*`, `git:`, github shorthand, `http(s)` tarball URLs (registry host included), `file:`, `link:`, `workspace:` and unparseable specs. Each is listed in `download.precheck.nonRegistry[]` as `{from, dependency, field, specType, spec}`, with the URL redacted.
- The task ends `status: aborted`, `abortReason: download-non-registry`, `verdict: null`, exit 3. The walk also enforces the package limit (`download-deps`).
- After `npm install --ignore-scripts`, `download.inventory.nonRegistry` re-checks the lock: every package must be resolved from the registry and must not be a link, and every declared spec must be a registry spec.

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

**Cleanup scope (ruling on S1-D2).** Several tasks can run at once under one prefix, and none touches another live task. Every object carries the labels `qp.run-prefix`, `qp.task-id`, `qp.owner-pid` (the CLI's pid) and `qp.created` (epoch ms).

| Actor | Removes | Never removes |
|---|---|---|
| Task teardown and its watchdog | only objects of its own task: label `qp.task-id=<taskId>`, or the exact name `ar-<prefix>-<role>-<taskId>` | anything of another task |
| Startup reaper (each `analyse`) | labelled objects of its prefix whose owner CLI is gone, or that are older than download + wall + 300 s (stale, e.g. pid reuse) | a live task of another CLI under the same prefix; unlabelled objects |
| `cleanup` (explicit command) | every object of the prefix: labelled `qp.run-prefix=<prefix>` or named `^ar-<prefix>-(download\|sinkhole\|sandbox\|tracer\|probe\|ctlin\|ctlout\|net\|ctlnet\|vol)-[a-f0-9]{10}$` | anything outside the prefix |

**Mechanisms.**
- Normal end, failure or timeout: the orchestrator removes every object of the task in `finally`. The receipt records it in `teardown`.
- Every container is `--rm` and runs under an in-container hard timeout:
  - sandbox: `timeout -s KILL <wall+5>`;
  - download: `timeout -s KILL <download+5>`;
  - probe: `timeout -s KILL <wall+120>`.
- CLI killed (hard kill, `taskkill /F /T` included): a watchdog started per task watches the CLI pid and removes the task's objects when it disappears.
  - It runs as a grandchild, so it is not in the CLI's process tree.
  - It polls every 500 ms, sweeps once, then sweeps again after 3 s.
- Ctrl+C / `SIGTERM` (AF-7): the first signal stops the task at once.
  - No new container, network or volume is created or started after it; in-flight docker clients are killed.
  - Every object of the task is removed (two sweeps, 1 s apart), the receipt is written with `status: aborted`, `abortReason: interrupted`, `verdict: null` and `interrupt: {signal, signalledAt, repeatedSignals, teardownSeconds}`, and the CLI exits 130. The receipt path is printed on stderr; the stdout JSON line, if the task flow reaches it before the exit, reports the same interrupted receipt.
  - Deadline: 9 s from the signal. If the teardown has not finished by then, the CLI exits anyway and the watchdog (left running) sweeps the task once the CLI is gone.
  - A second Ctrl+C while this runs is ignored: it never skips or restarts the teardown.
- Every `analyse` first runs the startup reaper (scope above). `cleanup` removes all objects of the prefix.
- **End reason from evidence only (ruling on S1-D2).** A limit (`sandbox.limitsHit`, rule e) is recorded only when one of these happened:
  - the orchestrator's own wall-clock timer fired (`wall-clock`);
  - Docker reported an OOM kill (`memory`);
  - the in-container hard timeout fired, which can only happen at or after wall + 5 s (`wall-clock`);
  - the trace shows fork/clone EAGAIN (`pids`).

  An **external stop** needs independent Docker evidence. Either Docker reports a `kill` or `stop` on the sandbox that the orchestrator did not issue, or the sinkhole is killed, stopped, removed or gone while the task runs. The result is `status: aborted`, `abortReason: killed-externally`, `verdict: null`, exit 4, with the Docker events in `sandbox.dockerEvents`. Rule (e) never fires for it.

  A non-zero exit alone is **not** external. Package code runs as the same uid as the sandbox's pid 1 and can kill it, so such a run is observed and decided normally. `ended-normally` is false, so it is at least (i), and any other evidence keeps its rules.
- **Host temp root:** none. The product writes no host-side temp files. A fixture is bind-mounted read-only from `<repo>/fixtures/<name>`, and the only host output is the receipt in `QP_RECEIPTS_DIR`.

## 3. Sandbox, tracer and sinkhole (C1, C2, DEC-12, DEC-13, DEC-16)

**Sandbox.**
- Image `qp-sandbox:s1-<sha8>`, from `node:22-bookworm-slim@sha256:4b150b48…7279da` (Node 22.23.4) plus `strace`.
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
- Image `qp-sandbox:s1-<sha8>`, `--entrypoint /opt/qp/trace.sh`.
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
- Image `qp-sinkhole:s1-<sha8>`, from `python:3.12-alpine@sha256:e6dae5…a9c8` plus iptables and tcpdump.
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
- **Capacity (AF-4).** The TCP sink is event-driven: one thread, a selector, no thread or process per connection, and `listen(4096)`. Every accepted connection is recorded when its request is complete, when the peer closes, at the task wall clock (`QP_CONN_DEADLINE_S` = sandbox seconds + 10), or at the flush.
- **Late payloads (AF-6).** A connection is attributed for its whole lifetime, not a fixed 2 s. When the sandbox ends, the orchestrator sends the sinkhole `SIGUSR1`; it drains every open connection, records it with all bytes received, and logs `{"type": "flushed"}` (receipt `sandbox.sinkhole.flushed`). If the flush is not confirmed within 5 s, a traced connect without a record still fails `sinkhole-log` (AF-4(a)), so a missed record never reads as "no payload".
- **Memory bound.** Buffered bytes across open connections are capped at 128 MB; over budget, the connection holding the most is recorded early with what it sent.
  - Its container limits (`--pids-limit 256`, `--memory 512m`, `nofile 65536`) sit far above what the sandbox can open. The sandbox has 64 pids, and held connections cost the sinkhole no process.
  - The orchestrator waits 2.5 s after the sandbox ends before reading the log, so in-flight connections are recorded.
  - Load check without Docker: `python scripts/sinkhole-load-check.py 150` holds 150 connections and then POSTs; the POST is recorded with its payload.
- **Backstop (AF-4).** `completeness.sinkhole-log` is ok only if the sinkhole reported ready **and** every kernel-traced package TCP connect or DNS query that reached the redirect has a matching sinkhole record.
  - Local failures before any packet do not count: ENETUNREACH, EAFNOSUPPORT, EADDRNOTAVAIL (e.g. IPv6).
  - Refused or unrecorded attempts do count, giving (i). Their observation ids are listed in `detail.unmatchedObservationIds`.
- **Listeners in the shared namespace:** TCP `0.0.0.0:15001`, UDP `0.0.0.0:15353` (DNS), UDP `0.0.0.0:15354` (other UDP), plus Docker's embedded DNS on `127.0.0.11`. The sinkhole uses no unix sockets, abstract ones included.
- **What the sandbox can and cannot do in that namespace:**
  - Every TCP connection and UDP datagram from uid 10001 is redirected by the nat rules, loopback and the sinkhole's own ports included. So any direct attempt to reach a listener is itself logged as an attempt (`orig_dest` 127.0.0.1:<port>), never parsed as a sinkhole record.
  - uid 10001 can bind free ports in the namespace (Docker sets `ip_unprivileged_port_start=0`). Its own outbound traffic still goes to the sinkhole and nothing else connects to it. Every such bind or listen is traced and recorded as a `net-listen` observation, giving (f) (ruling r2.7).
  - Sinkhole records reach the orchestrator only through the sinkhole container's stdout (`docker logs`), never over a socket the sandbox can reach.
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
- npm identity (ruling r2.4) is decided only from the trace. The preload leaves env unwrapped only in the process the stage script starts with `QP_ROLE=npm`; it then deletes `QP_ROLE`, so children never inherit it. No path, name or title is used. In the trace, two kinds of node exec fail `instrumentation-heartbeat`, giving (i):
  - an exec whose envp carries `QP_ROLE=npm` but whose pid is not the orchestrator's npm pid;
  - an npm CLI exec (`/usr/local/bin/npm`, `.../npm/bin/npm-cli.js`) by any pid other than that one.
  A package-started npm is package code.
- **Which execs must be instrumented (DEC-11r3).** Node is identified by the executed file, not its name.
  - The trace resolves every exec path against the cwd and through every symlink created during the task. So `ln -s /usr/local/bin/node /tmp/qpx; /tmp/qpx` is a node exec, and a hard link from a writable mount to the image's node is impossible (EXDEV).
  - Every node exec, and every exec by package code of any file on `/work`, `/tmp` or `/home/qp`, must show three kinds of instrumentation evidence: the preload flag in the traced envp, a traced open of `/opt/qp/preload.cjs` by that pid, and a heartbeat. Without it, `instrumentation-heartbeat` fails and the result is (i).
  - This covers copies of node and any other binary. Scripts executed directly from those mounts also fail closed, because the trace cannot tell a script from an ELF binary. That is stricter than DEC-11r3 (2).
  - **Cycle 3 (SR-1 to SR-3, ruling f1ebd3ab):**
    - A system binary reached through a symlink the task created is not trusted (`viaLink`). Links are forgotten when their path is unlinked, removed or renamed, and unlink, rename, link, symlink and lstat act on the link itself, never its target.
    - Only `/proc/self/exe` and `/proc/thread-self/exe` are resolved; `/proc/<other pid>/exe` stays opaque.
    - The envp of `execveat` is never trusted (`envp not traced`), so it always fails the marker.
  - **Allowlist (fail closed).** A package exec counts as observable only when it is node, or a binary from the image's read-only system directories `/usr`, `/bin` or `/sbin` (the dynamic loader `ld-linux*`/`ld-musl*`/`ld.so` excluded). Every other package exec must show the same instrumentation evidence, or the marker fails (i). That covers `/dev/fd/N`, `/proc/*/fd/N`, the loader, `execveat` (traced, identified by fd) and any other path. `/proc/<self|thread-self|pid>/exe` is first resolved to that process's current binary, so a node re-exec is a node exec.
  - `completeness.instrumentation-heartbeat.detail.reasons[<pid>]` names the cause and the path as executed.
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
| `abortReason`, `abortDetail` | when aborted: `invalid-input`, `download-failed`, `download-time`, `download-size`, `download-deps`, `download-non-registry`, `tracer-unavailable`, `killed-externally`, `infrastructure` |
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
| `net-listen` | bind to a fixed port or listen in the sandbox's network namespace (rule f) | `syscall` |
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

DEC-2r2 covers env and printenv executed by package code:
- `printenv NAME` is recorded as an `env-read` of `NAME`, as is `env NAME` when `NAME` is key-like (other `env` arguments are a command or assignments). A key-like name fires (c1).
- Bare `env` or `printenv` is `env-enumerate` (c2).
- Shell-builtin expansion (`$VAR`) is invisible and is listed in `knownLimitations`.

`net-listen` is a `bind` to a fixed port (>0) or a `listen` by package code in the sandbox's network namespace, giving (f). Ephemeral binds (port 0) are not recorded.

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
| `dep-tarball-url` | `qp-fixture-dep-tarball-url` | `aborted`, `abortReason: download-non-registry`, exit 3 (DEC-16: every declared spec in the resolved tree must be a registry version, range, tag or npm: alias to one) |
| `dep-git` | `qp-fixture-dep-git` | `aborted`, `download-non-registry` at the root stage, exit 3 |
| `dep-shrinkwrap` | `qp-fixture-dep-shrinkwrap` | `aborted`, `download-non-registry` (root ships npm-shrinkwrap.json), exit 3 |
| `node-symlink` | `qp-fixture-node-symlink` | `review` (i): uninstrumented node exec through a symlink (DEC-11r3) |
| `proc-self-exe` | `qp-fixture-proc-self-exe` | `review` (i): uninstrumented node via /proc/self/exe (SF-2) |

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
