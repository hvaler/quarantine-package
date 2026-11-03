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
