# Quarantine Package

Before you add an npm dependency, type its name and version: Quarantine Package downloads it **outside** a
sandbox without running any script, then installs and loads it **inside** a disposable, hardened, traced
sandbox whose only network ends at a logging sinkhole. You get a receipt with every observed attempt and a
deterministic verdict: `install`, `review` or `do-not-install`.

Stage S1 (this commit): the sandbox core as a CLI on local Docker. The model loop (S2), the web app (S3) and the
Vultr deployment and full documentation (S4) come later.

## Requirements

- Docker (Docker Desktop on Windows/macOS, or Docker Engine on Linux)
- Node.js >= 22.12 and npm on the host (the CLI has no npm dependencies)

## From a clean clone

```sh
npm run build:images                          # qp-sandbox:s1-<sha8> and qp-sinkhole:s1-<sha8> (base images pinned by digest)
npm test                                      # unit tests (verdict rules, trace parsing, attribution, inputs)
node src/cli.js analyse express@4.21.2        # registry package  -> install
node src/cli.js analyse --fixture hostile     # local fixture     -> do-not-install
node src/cli.js analyse --fixture netbenign --host-probe   # with the C2 host-side probe
node src/cli.js leftovers                     # expects count 0
node src/cli.js scan-secrets                  # pattern scan of the repo and receipts
```

Receipts are written to `./receipts/<taskId>.json` (override with `QP_RECEIPTS_DIR`). Docker objects are named
`ar-<QP_RUN_PREFIX>-<role>-<taskId>`; `QP_RUN_PREFIX` defaults to `qp`.

The full interface (CLI, exit codes, receipt schema, actors, trusted channels, limits) is in
[`docs/CONTRACT.md`](docs/CONTRACT.md).

## Default limits

| Phase | Limit |
|---|---|
| Download | 120 s, 50 MB unpacked, 300 packages, registry dependencies only |
| Sandbox | 60 s wall clock, 64 pids, 256 MB memory (no swap), 0.5 CPU, tmpfs 128 MB `/work`, 64 MB `/tmp`, 16 MB HOME |

## License

MIT, see [LICENSE](LICENSE). The CLI has no runtime npm dependencies; the images use the official `node` and
`python` images plus Debian/Alpine `strace`, `iptables` and `tcpdump`.
