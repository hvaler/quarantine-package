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

// Extract quoted C strings from an argument list, in order. A string strace
// truncated (trailing "...") is returned as null: never trusted as a path.
function quotedStrings(args) {
  return pathArgs(args).map((a) => a.str);
}

// Quoted strings with the directory they are relative to, from strace -y:
// `AT_FDCWD, "x"` -> base 'cwd'; `3</home/qp>, "x"` -> base '/home/qp'.
function pathArgs(args) {
  const out = [];
  const re = /(?:(AT_FDCWD|\d+<([^>]*)>),\s*)?"((?:[^"\\]|\\.)*)"(\.\.\.)?/g;
  let m;
  while ((m = re.exec(args))) {
    const str = m[4] ? null : m[3].replace(/\\"/g, '"').replace(/\\\\/g, '\\');
    const base = m[1] === undefined ? 'cwd' : m[1] === 'AT_FDCWD' ? 'cwd' : (m[2] && m[2].startsWith('/') ? m[2] : null);
    out.push({ str, base });
  }
  return out;
}

// execve("path", ["a", "b"], ["K=V", ...]) -> { path, argv, envp }.
// envp is null when strace abbreviated it (0x... /* n vars */).
function execArgs(args) {
  const groups = [[]];
  let depth = 0;
  let i = 0;
  const unq = (s) => s.replace(/\\"/g, '"').replace(/\\\\/g, '\\');
  while (i < args.length) {
    const ch = args[i];
    if (ch === '"') {
      let j = i + 1;
      while (j < args.length && args[j] !== '"') j += args[j] === '\\' ? 2 : 1;
      const truncated = args.slice(j + 1, j + 4) === '...';
      groups[groups.length - 1].push(truncated ? null : unq(args.slice(i + 1, j)));
      i = j + 1 + (truncated ? 3 : 0);
      continue;
    }
    if (ch === '[') { depth += 1; groups.push([]); }
    else if (ch === ']') depth -= 1;
    i += 1;
  }
  return { path: groups[0][0] ?? null, argv: groups[1] || [], envp: groups.length > 2 ? groups[2] : null };
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
  if (p.startsWith('/')) return normalize(p, cwd);
  if (!cwd) return null;
  return normalize(`${cwd}/${p}`, cwd);
}

function normalize(p, cwd) {
  const parts = [];
  for (const seg of p.split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') parts.pop();
    else parts.push(seg);
  }
  // /proc/<self|pid|thread-self>/root/X is X inside the sandbox (single mount namespace).
  if (parts[0] === 'proc' && parts[2] === 'root' && /^(self|thread-self|\d+)$/.test(parts[1] || '')) {
    return normalize(`/${parts.slice(3).join('/')}`, cwd);
  }
  // /proc/self/cwd/X is X relative to the caller's cwd, when known.
  if (parts[0] === 'proc' && parts[2] === 'cwd' && /^(self|thread-self)$/.test(parts[1] || '') && cwd) {
    return normalize(`${cwd}/${parts.slice(3).join('/')}`, null);
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
  // Symlinks created during the task: a later path through a link is reported
  // as the path it reaches (so /work/l/.npmrc with l -> /home/qp is /home/qp/.npmrc).
  const links = new Map();
  const canonical = (path) => {
    let cur = path;
    for (let i = 0; i < 16; i++) {
      let next = null;
      for (const [l, t] of links) {
        if (cur === l || cur.startsWith(`${l}/`)) { next = normalize(t + cur.slice(l.length)); break; }
      }
      if (!next || next === cur) return cur;
      cur = next;
    }
    return cur;
  };

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
        const { path, argv: av, envp } = execArgs(c.args);
        if (c.ret === 0) {
          exe.set(p, path);
          argv.set(p, av);
          events.push({ ...base, type: 'exec', path, argv: av, envp });
        }
        break;
      }
      case 'chdir': {
        if (c.ret === 0) cwd.set(p, resolvePath(cwd.get(p), quotedStrings(c.args)[0]));
        break;
      }
      case 'fchdir': {
        // strace -y prints the directory behind the fd: fchdir(3</work/x>)
        const d = /^\d+<([^>]*)>/.exec(c.args);
        if (c.ret === 0) cwd.set(p, d && d[1].startsWith('/') ? normalize(d[1]) : null);
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
        const unix = /sun_path=(@?)"((?:[^"\\]|\\.)*)"(\.\.\.)?/.exec(c.args);
        if (unix) {
          // Abstract sockets (@name) have no path; truncated or relative-without-cwd paths are unresolved.
          const raw = unix[3] ? null : unix[2];
          const path = unix[1] || raw === null ? null : resolvePath(cwd.get(p), raw);
          events.push({ ...base, type: 'net-unix', path, rawPath: raw, abstract: !!unix[1], unresolved: !unix[1] && path === null, blocked: c.ret === -1 });
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
        const args = pathArgs(c.args);
        // Resolve a path argument against its dirfd (strace -y) or the cwd.
        // Truncated strings and unknown dirfds give null: unresolved, never trusted.
        const at = (i) => {
          const a = args[i];
          if (!a || a.str === null) return { path: null, raw: a ? a.str : null };
          if (a.str.startsWith('/')) return { path: canonical(normalize(a.str, cwd.get(p))), raw: a.str };
          const dir = a.base === 'cwd' ? cwd.get(p) : a.base;
          return { path: dir ? canonical(normalize(`${dir}/${a.str}`, cwd.get(p))) : null, raw: a.str };
        };
        const blocked = c.ret === -1;
        const push = (type, r, extra = {}) => events.push({ ...base, type, path: r.path, rawPath: r.raw, unresolved: r.path === null, blocked, ...extra });
        if (c.name === 'openat' || c.name === 'open') {
          push(WRITE_FLAGS.test(c.args) ? 'fs-write' : 'fs-read', at(0));
        } else if (/^(creat|mkdir|mkdirat|truncate|chmod|fchmodat|unlink|unlinkat|rmdir)$/.test(c.name)) {
          push('fs-write', at(0));
        } else if (/^(rename|renameat2?|link|linkat)$/.test(c.name)) {
          push('fs-write', at(1));
          push('fs-write', at(0));
        } else if (c.name === 'symlink' || c.name === 'symlinkat') {
          // The link itself is a write; its target is an access to whatever it points at.
          const link = at(args.length - 1);
          push('fs-write', link);
          const target = args[0] && args[0].str !== null
            ? { path: args[0].str.startsWith('/') ? normalize(args[0].str, cwd.get(p)) : (link.path ? normalize(`${link.path}/../${args[0].str}`, cwd.get(p)) : null), raw: args[0].str }
            : { path: null, raw: null };
          push('fs-link-target', target);
          if (!blocked && link.path && target.path) links.set(link.path, target.path);
        } else if (/^(access|faccessat2?|newfstatat|statx|stat|lstat)$/.test(c.name)) {
          // fstat-style calls on an fd ("" with AT_EMPTY_PATH) are not path accesses.
          if (args[0] && args[0].str === '' && /AT_EMPTY_PATH/.test(c.args)) break;
          push('fs-stat', at(0));
        }
      }
    }
  }

  return { calls: calls.length, tgid, parent, exe, argv, events };
}

module.exports = { analyse, parseLines, splitCall, quotedStrings, normalize, execArgs };
