// Parser for the tracer's strace stream (strace -f -qq -tt).
// Pure: text in, process table and syscall events out.
'use strict';

const LINE = /^(\d+)\s+(\d\d):(\d\d):(\d\d)\.(\d+)\s+(.*)$/;

function secondsOfDay(h, m, s, frac) {
  return Number(h) * 3600 + Number(m) * 60 + Number(s) + Number(`0.${frac}`);
}

// Split "name(args) = ret rest" into parts. Returns null for lines that are not calls.
function splitCall(text) {
  const open = text.indexOf('(');
  if (open <= 0) return null;
  const name = text.slice(0, open);
  if (!/^[a-z0-9_]+$/.test(name)) return null;
  const eq = text.lastIndexOf(') = ');
  if (eq < 0) return { name, args: text.slice(open + 1), ret: null, errno: null };
  const args = text.slice(open + 1, eq);
  const retPart = text.slice(eq + 4).trim();
  const m = /^(-?\d+|0x[0-9a-f]+|\?)(?:\s+([A-Z][A-Z0-9_]+))?/.exec(retPart);
  const ret = m ? (m[1] === '?' ? null : Number(m[1])) : null;
  return { name, args, ret, errno: m && m[2] ? m[2] : null };
}

// Extract quoted C strings from an argument list, in order.
function quotedStrings(args) {
  const out = [];
  const re = /"((?:[^"\\]|\\.)*)"(\.\.\.)?/g;
  let m;
  while ((m = re.exec(args))) {
    out.push(m[1].replace(/\\"/g, '"').replace(/\\\\/g, '\\'));
  }
  return out;
}

function parseLines(text) {
  const pending = new Map();
  const calls = [];
  for (const raw of String(text).split(/\r?\n/)) {
    const m = LINE.exec(raw);
    if (!m) continue;
    const pid = Number(m[1]);
    const t = secondsOfDay(m[2], m[3], m[4], m[5]);
    let body = m[6];
    if (body.endsWith('<unfinished ...>')) {
      pending.set(pid, { t, text: body.slice(0, -'<unfinished ...>'.length).trimEnd() });
      continue;
    }
    const resumed = /^<\.\.\. ([a-z0-9_]+) resumed>\s?(.*)$/.exec(body);
    if (resumed) {
      const p = pending.get(pid);
      pending.delete(pid);
      if (!p) continue;
      body = p.text + resumed[2];
      const c = splitCall(body);
      if (c) calls.push({ pid, t: p.t, ...c });
      continue;
    }
    const c = splitCall(body);
    if (c) calls.push({ pid, t, ...c });
  }
  return calls;
}

function resolvePath(cwd, p) {
  if (!p) return null;
  if (p.startsWith('/')) return normalize(p);
  if (!cwd) return null;
  return normalize(`${cwd}/${p}`);
}

function normalize(p) {
  const parts = [];
  for (const seg of p.split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') parts.pop();
    else parts.push(seg);
  }
  return `/${parts.join('/')}`;
}

const WRITE_FLAGS = /O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND/;

// Build process table and normalized events.
function analyse(text, opts = {}) {
  const calls = parseLines(text);
  const rootCwd = opts.initialCwd || '/work';
  const tgid = new Map([[1, 1]]);
  const parent = new Map();
  const exe = new Map();
  const argv = new Map();
  const cwd = new Map([[1, rootCwd]]);
  const sockType = new Map(); // `${tg}:${fd}` -> 'stream' | 'dgram'
  const events = [];
  const tg = (pid) => tgid.get(pid) || pid;

  for (const c of calls) {
    const p = tg(c.pid);
    if (!cwd.has(p)) cwd.set(p, null);
    const base = { pid: p, tid: c.pid, t: c.t, syscall: c.name, ret: c.ret, errno: c.errno };
    switch (c.name) {
      case 'clone': case 'clone3': case 'fork': case 'vfork': {
        if (c.ret && c.ret > 0) {
          const child = c.ret;
          if (/CLONE_THREAD/.test(c.args)) {
            if (!tgid.has(child)) tgid.set(child, p);
          } else if (!parent.has(child)) {
            parent.set(child, p);
            tgid.set(child, child);
            cwd.set(child, cwd.get(p));
            if (exe.has(p)) exe.set(child, exe.get(p));
            if (argv.has(p)) argv.set(child, argv.get(p));
          }
        } else if (c.ret === -1) {
          events.push({ ...base, type: 'fork-failed' });
        }
        break;
      }
      case 'execve': {
        const strs = quotedStrings(c.args);
        if (c.ret === 0) {
          exe.set(p, strs[0]);
          argv.set(p, strs.slice(1));
          events.push({ ...base, type: 'exec', path: strs[0], argv: strs.slice(1) });
        }
        break;
      }
      case 'chdir': {
        if (c.ret === 0) cwd.set(p, resolvePath(cwd.get(p), quotedStrings(c.args)[0]));
        break;
      }
      case 'fchdir': {
        if (c.ret === 0) cwd.set(p, null);
        break;
      }
      case 'socket': {
        if (c.ret >= 0) {
          const type = /SOCK_DGRAM/.test(c.args) ? 'dgram' : /SOCK_STREAM/.test(c.args) ? 'stream' : 'other';
          const fam = /AF_INET6/.test(c.args) ? 'inet6' : /AF_INET/.test(c.args) ? 'inet' : /AF_UNIX|AF_LOCAL/.test(c.args) ? 'unix' : 'other';
          sockType.set(`${p}:${c.ret}`, { type, fam });
        }
        break;
      }
      case 'connect': case 'sendto': case 'sendmsg': case 'sendmmsg': {
        const fd = Number(/^(\d+)/.exec(c.args)?.[1]);
        const st = sockType.get(`${p}:${fd}`) || { type: 'unknown', fam: 'unknown' };
        const unix = /sun_path="((?:[^"\\]|\\.)*)"/.exec(c.args);
        if (unix) {
          events.push({ ...base, type: 'net-unix', path: unix[1], blocked: c.ret === -1 });
          break;
        }
        const port = /sin6?_port=htons\((\d+)\)/.exec(c.args);
        const ip4 = /sin_addr=inet_addr\("([0-9.]+)"\)/.exec(c.args);
        const ip6 = /inet_pton\(AF_INET6,\s*"([^"]+)"/.exec(c.args);
        if (!port) break; // sendto on a connected socket: covered by its connect
        events.push({
          ...base,
          type: 'net',
          proto: st.type === 'dgram' ? 'udp' : st.type === 'stream' ? 'tcp' : 'unknown',
          family: ip6 ? 'inet6' : 'inet',
          ip: ip4 ? ip4[1] : ip6 ? ip6[1] : null,
          port: Number(port[1]),
          blocked: c.ret === -1 && c.errno !== 'EINPROGRESS',
        });
        break;
      }
      default: {
        const strs = quotedStrings(c.args);
        const atCwd = /^AT_FDCWD/.test(c.args);
        const relTo = (s) => (s && !s.startsWith('/') && !atCwd && /^(openat|mkdirat|unlinkat|renameat2?|symlinkat|linkat|fchmodat|faccessat2?|newfstatat|statx)$/.test(c.name) ? null : resolvePath(cwd.get(p), s));
        const blocked = c.ret === -1;
        if (c.name === 'openat' || c.name === 'open') {
          const path = relTo(strs[0]);
          const write = WRITE_FLAGS.test(c.args);
          events.push({ ...base, type: write ? 'fs-write' : 'fs-read', path, rawPath: strs[0], blocked });
        } else if (c.name === 'creat' || c.name === 'mkdir' || c.name === 'mkdirat' || c.name === 'truncate' || c.name === 'chmod' || c.name === 'fchmodat' || c.name === 'unlink' || c.name === 'unlinkat' || c.name === 'rmdir') {
          const path = relTo(strs[0]);
          events.push({ ...base, type: 'fs-write', path, rawPath: strs[0], blocked });
        } else if (/^(rename|renameat2?|link|linkat)$/.test(c.name)) {
          const path = relTo(strs[1]);
          events.push({ ...base, type: 'fs-write', path, rawPath: strs[1], blocked });
          const src = relTo(strs[0]);
          events.push({ ...base, type: 'fs-write', path: src, rawPath: strs[0], blocked });
        } else if (c.name === 'symlink' || c.name === 'symlinkat') {
          const path = relTo(strs[strs.length - 1]);
          events.push({ ...base, type: 'fs-write', path, rawPath: strs[strs.length - 1], blocked });
        } else if (/^(access|faccessat2?|newfstatat|statx|stat|lstat)$/.test(c.name)) {
          const path = relTo(strs[0]);
          if (path || strs[0]) events.push({ ...base, type: 'fs-stat', path, rawPath: strs[0], blocked });
        }
      }
    }
  }

  return { calls: calls.length, tgid, parent, exe, argv, events };
}

module.exports = { analyse, parseLines, splitCall, quotedStrings, normalize };
