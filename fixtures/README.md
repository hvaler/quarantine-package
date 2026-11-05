# Local fixtures

Private, never-published packages used by the CLI option `qp analyse --fixture <name>`.
Only directory names inside this folder are accepted.

| Fixture | Install script does | Expected verdict |
|---|---|---|
| `hostile` | writes /etc, writes HOME, looks for docker.sock, counts key-like env names, POSTs to recolector.example.com | `do-not-install` (rules a, b, d; HOME write g; env count is a c2 observation) |
| `loop` | an infinite loop | `do-not-install` (e: wall-clock) |
| `forkbomb` | a shell fork bomb | `do-not-install` (e: pids or wall-clock, with a pids-exhaustion observation) |
| `netprobe` | resolves a name, connects to 1.1.1.1:443 by IP, opens TLS with SNI on 443 and 8443 | `review` (f) |
| `netbenign` | one plain HTTP GET without a body (e.g. a legitimate download check) | `review` (f) |
| `dep-tarball-url` | none; it declares a dependency by tarball URL (on the registry host) | `aborted`, `download-non-registry` (DEC-16), exit 3 |
| `dep-git` | none; it declares a dependency by git URL | `aborted`, `download-non-registry` (DEC-16, rejected before any fetch), exit 3 |
| `dep-shrinkwrap` | none; it declares a registry range but ships an npm-shrinkwrap.json pinning it to a non-registry URL | `aborted`, `download-non-registry` (root shrinkwrap rejected before npm runs), exit 3 |
| `node-symlink` | runs node through a symlink in /tmp with NODE_OPTIONS cleared and reads NPM_TOKEN | never `install`: `review` (i), instrumentation marker fails (DEC-11r3) |
| `proc-self-exe` | re-executes node through /proc/self/exe with env stripped and reads NPM_TOKEN | never `install`: `review` (i), instrumentation marker fails (SF-2) |
| `audx1-utimes` | L-19 regression (S6): `fs.utimesSync('/etc/hostname')` only (utimensat) | `do-not-install` (a) |
| `audx1-chown` | L-19 regression (S6): `fs.chownSync('/etc/passwd')` only (fchownat) | `do-not-install` (a) |
| `audx1-readlink` | L-19 regression (S6): `fs.readlinkSync('/home/qp/.ssh/id_rsa')` only | `do-not-install` (b) |
| `audx1-watch` | L-19 regression (S6): `fs.watch('/var/run/docker.sock')` only (inotify_add_watch) | `do-not-install` (b) |
| `audx1-all` | L-19 regression (S6): the four acts above together (the auditor's copy) | `do-not-install` (a, b) |
| `l19-adv-x1-untraced` | L-19 regression (S6): the adversary's original four-act fixture (`fixture-x1-untraced`) | `do-not-install` (a, b) |
| `audx1-control` | L-19 control: the same targets through calls traced at a075bd1 (append, exists) | `do-not-install` (a, b), unchanged |

| `adv6-fdwrite` | S6 repair 1 (B1): read-only fd of /etc/hostname, then fchown/fchmod/futimes/ftruncate on it | `do-not-install` (a) |
| `adv6-procfd` | S6 repair 1 (B2): the same fd written through /proc/self/fd/N and /dev/fd/N | `do-not-install` (a) |
| `adv6-tardirfd` | S6 repair 1 (B3): `tar -xf /tmp/t.tar -C /etc` (writes relative to a bare dirfd) | `do-not-install` (a) |
| `adv6-benign` | S6 repair 1 (N1): the same mechanisms on /work files only | `install` |

The L-19 and adv6 fixtures (adversary's, checks 99737bcb) are not web demo cards.
