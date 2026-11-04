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

  const seen = new Set(); // pids (tgids) with at least one traced call
  const exeFromOwnExec = new Set(); // pids whose exe was set by their own successful execve
  for (const c of calls) {
    const p = tg(c.pid);
    seen.add(p);
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
            // AF-5: with strace -f the child's own events (e.g. its execve) can be
            // printed before the parent's clone return. Inherit state only for a
            // child that has not been seen yet; never overwrite what it set itself.
            if (!seen.has(child)) {
              cwd.set(child, cwd.get(p));
              if (exe.has(p)) { exe.set(child, exe.get(p)); exeFromOwnExec.delete(child); }
              if (argv.has(p)) argv.set(child, argv.get(p));
            }
          }
        } else if (c.ret === -1) {
          events.push({ ...base, type: 'fork-failed' });
        }
        break;
      }
      case 'execveat': {
        // fexecve / execveat: what runs is identified by an fd, not a checkable path.
        if (c.ret === 0) {
          // SR-3: the dirfd annotation is package-influenced text, so the argument
          // split is not trusted: envp is never taken from execveat (null = not
          // traced), so the instrumentation marker always fails for it.
          exe.set(p, '(execveat)');
          argv.set(p, []);
          events.push({ ...base, type: 'exec', path: '(execveat)', rawPath: c.args.slice(0, 120), argv: [], envp: null, opaque: true });
        }
        break;
      }
      case 'execve': {
        const { path: rawExe, argv: av, envp } = execArgs(c.args);
        if (c.ret === 0) {
          // DEC-11r3: identify what was executed, not its name. The path is resolved
          // against the cwd and through every symlink created during the task.
          // SR-2: only /proc/self/exe and /proc/thread-self/exe are resolved, to the
          // executing process's own current binary. Another pid's exe can change
          // under us (TOCTOU), so it stays an unresolved /proc path: opaque.
          let resolved = typeof rawExe === 'string' ? resolvePath(cwd.get(p), rawExe) : null;
          const procExe = resolved && /^\/proc\/(self|thread-self)\/exe$/.exec(resolved);
          // AF-5: resolve only from this pid's own traced execve; an inherited (or
          // order-dependent) value is not trusted, so the exec stays opaque.
          if (procExe) resolved = exeFromOwnExec.has(p) ? (exe.get(p) || null) : null;
          // SR-1: note whether reaching the target needed a symlink the task created.
          const path = resolved ? canonical(resolved) : rawExe;
          const viaLink = !!(resolved && path !== resolved);
          exe.set(p, path);
          exeFromOwnExec.add(p);
          argv.set(p, av);
          events.push({ ...base, type: 'exec', path, rawPath: rawExe, argv: av, envp, viaLink });
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
      case 'bind': case 'listen': {
        const fd = Number(/^(\d+)/.exec(c.args)?.[1]);
        const st = sockType.get(`${p}:${fd}`) || { type: 'unknown', fam: 'unknown' };
        if (c.name === 'listen') {
          events.push({ ...base, type: 'net-listen', proto: st.type === 'dgram' ? 'udp' : 'tcp', port: null, ip: null, blocked: c.ret === -1 });
          break;
        }
        const unixB = /sun_path=(@?)"((?:[^"\\]|\\.)*)"/.exec(c.args);
        if (unixB) { events.push({ ...base, type: 'net-bind', proto: 'unix', path: unixB[1] ? `@${unixB[2]}` : unixB[2], port: null, ip: null, blocked: c.ret === -1 }); break; }
        const port = /sin6?_port=htons\((\d+)\)/.exec(c.args);
        const ip4 = /sin_addr=inet_addr\("([0-9.]+)"\)/.exec(c.args);
        // An ephemeral bind (port 0, e.g. implicit UDP send) is not a listener.
        if (port && Number(port[1]) > 0) {
          events.push({ ...base, type: 'net-bind', proto: st.type === 'dgram' ? 'udp' : 'tcp', port: Number(port[1]), ip: ip4 ? ip4[1] : null, blocked: c.ret === -1 });
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
        // Calls that act on the final path component itself (unlink, rmdir,
        // rename, link, symlink, lstat) do not follow it: resolve the parent
        // directories through task-created links, but not the last component.
        const nofollow = (i) => {
          const a = args[i];
          if (!a || a.str === null) return { path: null, raw: a ? a.str : null };
          const dir = a.str.startsWith('/') ? '' : (a.base === 'cwd' ? cwd.get(p) : a.base);
          if (dir === null || dir === undefined) return { path: null, raw: a.str };
          const full = normalize(a.str.startsWith('/') ? a.str : `${dir}/${a.str}`, cwd.get(p));
          const cut = full.lastIndexOf('/');
          const parent = cut <= 0 ? '/' : canonical(full.slice(0, cut));
          return { path: normalize(`${parent}/${full.slice(cut + 1)}`), raw: a.str };
        };
        // SR-1: a link is forgotten once its path is unlinked, removed or renamed
        // (either side of a rename), so a stale mapping can never name a later file.
        const forget = (r) => { if (r.path) { for (const l of [...links.keys()]) if (l === r.path || l.startsWith(`${r.path}/`)) links.delete(l); } };
        const blocked = c.ret === -1;
        const push = (type, r, extra = {}) => events.push({ ...base, type, path: r.path, rawPath: r.raw, unresolved: r.path === null, blocked, ...extra });
        if (c.name === 'openat' || c.name === 'open') {
          push(WRITE_FLAGS.test(c.args) ? 'fs-write' : 'fs-read', at(0));
        } else if (/^(unlink|unlinkat|rmdir)$/.test(c.name)) {
          const r = nofollow(0);
          push('fs-write', r);
          if (!blocked) forget(r);
        } else if (/^(creat|mkdir|mkdirat|truncate|chmod|fchmodat)$/.test(c.name)) {
          push('fs-write', at(0));
        } else if (/^(rename|renameat2?)$/.test(c.name)) {
          const to = nofollow(1);
          const from = nofollow(0);
          push('fs-write', to);
          push('fs-write', from);
          if (!blocked) { forget(from); forget(to); }
        } else if (/^(link|linkat)$/.test(c.name)) {
          push('fs-write', nofollow(1));
          push('fs-write', at(0));
        } else if (c.name === 'symlink' || c.name === 'symlinkat') {
          // The link itself is a write; its target is an access to whatever it points at.
          const link = nofollow(args.length - 1);
          push('fs-write', link);
          const target = args[0] && args[0].str !== null
            ? { path: args[0].str.startsWith('/') ? normalize(args[0].str, cwd.get(p)) : (link.path ? normalize(`${link.path}/../${args[0].str}`, cwd.get(p)) : null), raw: args[0].str }
            : { path: null, raw: null };
          push('fs-link-target', target);
          if (!blocked && link.path && target.path) links.set(link.path, target.path);
        } else if (/^(access|faccessat2?|newfstatat|statx|stat|lstat)$/.test(c.name)) {
          // fstat-style calls on an fd ("" with AT_EMPTY_PATH) are not path accesses.
          if (args[0] && args[0].str === '' && /AT_EMPTY_PATH/.test(c.args)) break;
          push('fs-stat', c.name === 'lstat' || /AT_SYMLINK_NOFOLLOW/.test(c.args) ? nofollow(0) : at(0));
        }
      }
    }
  }

  return { calls: calls.length, tgid, parent, exe, argv, events };
}

module.exports = { analyse, parseLines, splitCall, quotedStrings, normalize, execArgs };
