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
