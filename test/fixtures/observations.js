'use strict';
// Fixed observation fixtures for the verdict tests (C4).
let n = 0;
const id = () => `o${++n}`;
const base = (o) => ({ id: id(), actor: 'package', pid: 50, exe: '/usr/local/bin/node', dest: null, orig_dest: null, port: null, sni: null, proto: null, blocked: null, payload: null, path: null, nonce: 'test', ...o });

const write = (path, actor = 'package', blocked = false) => base({ kind: 'fs-write', path, actor, blocked });
const access = (path) => base({ kind: 'fs-access', path, blocked: true });
const envRead = (name) => base({ kind: 'env-read', name });
const envEnumerate = () => base({ kind: 'env-enumerate' });
const procEnviron = () => base({ kind: 'proc-environ', path: '/proc/self/environ' });
const tcp = (dest, actor = 'package', payload = false) => base({ kind: 'net-tcp', dest, actor, port: 80, proto: 'http', payload, orig_dest: '198.18.0.1:80' });
const dns = (dest) => base({ kind: 'net-dns', dest, port: 53, proto: 'udp', payload: false, orig_dest: '127.0.0.11:53' });
const limit = (reason) => base({ kind: 'limit', actor: null, reason });
const loadOk = () => base({ kind: 'load', actor: 'harness', ok: true, mode: 'fallback-require' });
const loadFail = () => base({ kind: 'load', actor: 'harness', ok: false, mode: 'fallback-require', error: 'MODULE_NOT_FOUND' });
const marker = (marker, ok) => base({ kind: 'completeness', actor: null, marker, ok });

function clean() {
  n = 0;
  return [
    base({ kind: 'env-enumerate' }),
    write('/work/node_modules/express/.cache', 'package'),
    tcp('registry.npmjs.org', 'npm', false),
    loadOk(),
    marker('instrumentation-heartbeat', true), marker('kernel-trace', true), marker('sinkhole-log', true),
    marker('ended-normally', true), marker('harness-ran', true),
  ];
}

function hostile() {
  n = 0;
  return [
    write('/etc/qp-fixture-marker', 'package', true),
    write('/home/qp/.qp-fixture-marker', 'package', false),
    access('/var/run/docker.sock'),
    envEnumerate(),
    dns('recolector.example.com'),
    tcp('recolector.example.com', 'package', true),
    loadOk(),
    marker('instrumentation-heartbeat', true), marker('kernel-trace', true), marker('sinkhole-log', true),
    marker('ended-normally', true), marker('harness-ran', true),
  ];
}

module.exports = { clean, hostile, write, access, envRead, envEnumerate, procEnviron, tcp, dns, limit, loadOk, loadFail, marker };
