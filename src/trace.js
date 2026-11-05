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
  // S6 repair 1 (B3): a bare numeric dirfd ("mkdirat(4, ...)": the production
  // tracer cannot annotate numeric fds) is never the cwd. Its base is null and
  // dirfd carries the number, which analyse() resolves through its fd table.
  // AT_FDCWD, annotated ("AT_FDCWD</work>") or not, is the tracked cwd.
  const re = /(?:(AT_FDCWD(?:<[^>]*>)?|(\d+)(?:<([^>]*)>)?),\s*)?"((?:[^"\\]|\\.)*)"(\.\.\.)?/g;
  let m;
  while ((m = re.exec(args))) {
    const str = m[5] ? null : m[4].replace(/\\"/g, '"').replace(/\\\\/g, '\\');
    let base;
    let dirfd;
    if (m[1] === undefined || m[1].startsWith('AT_FDCWD')) base = 'cwd';
    else if (m[3] !== undefined && m[3].startsWith('/')) base = m[3];
    else { base = null; if (m[3] === undefined) dirfd = Number(m[2]); }
    out.push(dirfd === undefined ? { str, base } : { str, base, dirfd });
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
  let seq = 0; // print position of each syscall line: entry/exit of a call as strace serialised them
  for (const raw of String(text).split(/\r?\n/)) {
    const m = LINE.exec(raw);
    if (!m) continue;
    seq += 1;
    const pid = Number(m[1]);
    const t = secondsOfDay(m[2], m[3], m[4], m[5]);
    let body = m[6];
    if (body.endsWith('<unfinished ...>')) {
      pending.set(pid, { t, entry: seq, text: body.slice(0, -'<unfinished ...>'.length).trimEnd() });
      continue;
    }
    const resumed = /^<\.\.\. ([a-z0-9_]+) resumed>\s?(.*)$/.exec(body);
    if (resumed) {
      const p = pending.get(pid);
      pending.delete(pid);
      if (!p) continue;
      body = p.text + resumed[2];
      const c = splitCall(body);
      if (c) calls.push({ pid, t: p.t, entry: p.entry, exit: seq, ...c });
      continue;
    }
    const c = splitCall(body);
    if (c) calls.push({ pid, t, entry: seq, exit: seq, ...c });
  }
  // A chdir/fchdir still unfinished when the trace ends may have taken effect:
  // keep it with an open interval and an unknown result (fail closed).
  // S6: the same for a file call still unfinished at the end: it was attempted,
  // and rules a and b count attempts (fail closed). Process and network calls keep
  // their earlier handling.
  for (const [pid, p] of pending) {
    const c = splitCall(p.text);
    if (c && (c.name === 'chdir' || c.name === 'fchdir' || !NOT_FILE_CALLS.has(c.name))) calls.push({ pid, t: p.t, entry: p.entry, exit: Infinity, ...c, ret: null, errno: null });
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
  // S6 repair 1: any other /proc/<x>/cwd/... (unknown cwd, or another pid's cwd)
  // cannot be read lexically: unresolved (null), never the literal /proc path.
  if (parts[0] === 'proc' && parts[2] === 'cwd' && /^(self|thread-self|\d+)$/.test(parts[1] || '')) return null;
  return `/${parts.join('/')}`;
}

const WRITE_FLAGS = /O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND/;

// L-19 (S6): every file syscall the tracer records has an explicit kind here,
// and test/trace-coverage.test.js checks the reference list against this table
// and against trace.sh. kind: 'write' -> fs-write (rule a; also checked by rule b),
// 'access' -> fs-probe (rule b). form says where the path is:
//   path     first quoted path, cwd-relative       (e.g. chown("/etc/passwd", ...))
//   lpath    same, but the last component is not followed (lchown, readlink, l*xattr)
//   dirfd    dirfd + path; a NULL path means the dirfd itself (utimensat(fd, NULL) = futimens)
//   ldirfd   dirfd + path, last component not followed (readlinkat, mknodat)
//   fd       the fd's path from strace -y (fchown(3</etc/passwd>, ...))
//   watch    inotify_add_watch(ifd, path): path is cwd-relative, the first fd is the inotify fd
//   fanotify fanotify_mark(ffd, flags, mask, dirfd, path|NULL)
//   opaque   no decodable path (mount fd + handle, or a syscall strace cannot name):
//            an unresolved fs-write, so rule a fires (fail closed)
// AT_SYMLINK_NOFOLLOW in the flags turns a following form into its nofollow variant.
const FS_SYSCALLS = Object.freeze({
  // writes and metadata changes
  utime: { kind: 'write', form: 'path' },
  utimes: { kind: 'write', form: 'path' },
  utimensat: { kind: 'write', form: 'dirfd' },
  futimesat: { kind: 'write', form: 'dirfd' },
  chown: { kind: 'write', form: 'path' },
  lchown: { kind: 'write', form: 'lpath' },
  fchownat: { kind: 'write', form: 'dirfd' },
  fchown: { kind: 'write', form: 'fd' },
  fchmod: { kind: 'write', form: 'fd' },
  fchmodat2: { kind: 'write', form: 'dirfd' },
  ftruncate: { kind: 'write', form: 'fd' },
  fallocate: { kind: 'write', form: 'fd' },
  mknod: { kind: 'write', form: 'lpath' },
  mknodat: { kind: 'write', form: 'ldirfd' },
  setxattr: { kind: 'write', form: 'path' },
  lsetxattr: { kind: 'write', form: 'lpath' },
  fsetxattr: { kind: 'write', form: 'fd' },
  removexattr: { kind: 'write', form: 'path' },
  lremovexattr: { kind: 'write', form: 'lpath' },
  fremovexattr: { kind: 'write', form: 'fd' },
  // privileged path calls (cap-drop ALL: they fail, but an attempt counts)
  chroot: { kind: 'write', form: 'path' },
  acct: { kind: 'write', form: 'path' },
  swapon: { kind: 'write', form: 'path' },
  swapoff: { kind: 'write', form: 'path' },
  uselib: { kind: 'write', form: 'path' },
  quotactl: { kind: 'write', form: 'path' },
  mount: { kind: 'write', form: 'opaque' },
  umount2: { kind: 'write', form: 'path' },
  pivot_root: { kind: 'write', form: 'path' },
  open_tree: { kind: 'write', form: 'dirfd' },
  move_mount: { kind: 'write', form: 'dirfd' },
  fspick: { kind: 'write', form: 'dirfd' },
  mount_setattr: { kind: 'write', form: 'dirfd' },
  fsconfig: { kind: 'write', form: 'opaque' },
  open_by_handle_at: { kind: 'write', form: 'opaque' },
  // reads, probes and watches
  readlink: { kind: 'access', form: 'lpath' },
  readlinkat: { kind: 'access', form: 'ldirfd' },
  statfs: { kind: 'access', form: 'path' },
  fstatfs: { kind: 'access', form: 'fd' },
  getxattr: { kind: 'access', form: 'path' },
  lgetxattr: { kind: 'access', form: 'lpath' },
  fgetxattr: { kind: 'access', form: 'fd' },
  listxattr: { kind: 'access', form: 'path' },
  llistxattr: { kind: 'access', form: 'lpath' },
  flistxattr: { kind: 'access', form: 'fd' },
  name_to_handle_at: { kind: 'access', form: 'dirfd' },
  inotify_add_watch: { kind: 'access', form: 'watch' },
  fanotify_mark: { kind: 'access', form: 'fanotify' },
});

// Syscalls analyse() handles in its own branches (process, cwd, network, and the
// file calls traced before S6). Together with FS_SYSCALLS this is the mapped set.
const LEGACY_SYSCALLS = Object.freeze([
  'clone', 'clone3', 'fork', 'vfork', 'execve', 'execveat', 'chdir', 'fchdir', 'getcwd',
  'close', 'close_range', 'dup', 'dup2', 'dup3', 'fcntl', 'unshare',
  'socket', 'connect', 'bind', 'listen', 'sendto', 'sendmsg', 'sendmmsg',
  'openat', 'open', 'openat2', 'creat', 'mkdir', 'mkdirat', 'truncate', 'chmod', 'fchmodat',
  'unlink', 'unlinkat', 'rmdir', 'rename', 'renameat', 'renameat2', 'link', 'linkat',
  'symlink', 'symlinkat', 'access', 'faccessat', 'faccessat2', 'newfstatat', 'statx', 'stat', 'lstat',
]);
// Repair 1 (P1): directory symlinks on the sandbox image's root filesystem, so
// "<link>/../x" is walked from the link's target as the kernel does. Listed from
// qp-sandbox:s1-683b3d47 with `find / -xdev -type l -xtype d` (26 entries; the
// image is pinned by digest, docs/TRACE-SET.md). /dev/fd, /dev/std* and /proc
// links are runtime links and are handled in walk() itself.
const IMAGE_DIR_LINKS = Object.freeze({
  '/bin': 'usr/bin', '/lib': 'usr/lib', '/lib64': 'usr/lib64', '/sbin': 'usr/sbin',
  '/usr/local/man': 'share/man',
  '/usr/share/doc/libgcc-s1': 'gcc-12-base', '/usr/share/doc/libstdc++6': 'gcc-12-base',
  ...Object.fromEntries(['Africa', 'America', 'Antarctica', 'Arctic', 'Asia', 'Atlantic', 'Australia', 'Brazil', 'Canada', 'Chile', 'Etc', 'Europe', 'Indian', 'Mexico', 'Pacific', 'US']
    .map((z) => [`/usr/share/zoneinfo/posix/${z}`, `../${z}`])),
  '/var/lock': '/run/lock', '/var/run': '/run', '/var/spool/mail': '../mail',
});

const NOT_FILE_CALLS = new Set(['unshare', 'close', 'close_range', 'dup', 'dup2', 'dup3', 'fcntl', 'clone', 'clone3', 'fork', 'vfork', 'execve', 'execveat', 'socket', 'connect', 'bind', 'listen', 'sendto', 'sendmsg', 'sendmmsg']);
const MAPPED_SYSCALLS = Object.freeze(new Set([...LEGACY_SYSCALLS, ...Object.keys(FS_SYSCALLS)]));

// The path behind an fd as strace -y prints it ("3</etc/passwd>"), or why there is none.
// Pipes, sockets, anon inodes and memfds are not filesystem paths.
function fdAnnotation(text) {
  const m = /^\s*(-?\d+)(?:<([^>]*)>)?/.exec(text);
  if (!m) return { kind: 'none' };
  if (m[2] === undefined) return { kind: 'none' };
  const p = m[2].replace(/ \(deleted\)$/, '');
  if (!p.startsWith('/') || p.startsWith('/memfd:')) return { kind: 'nonpath' };
  return { kind: 'path', path: normalize(p) };
}

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
  const ownCwd = new Set(); // pids that changed their cwd themselves (chdir/fchdir)
  // L-7 / F-D2-1 race: every successful chdir/fchdir with its print interval. A
  // thread is stopped at syscall entry until strace handles it, so a chdir can
  // only take effect between its entry and exit stops; one whose interval
  // overlaps a clone's interval (also one resumed later) may or may not be in
  // the child's cwd.
  // Counted unless it clearly failed: "= ?" (killed mid-call) or never resumed may have applied.
  const cwdChanges = calls.filter((x) => (x.name === 'chdir' || x.name === 'fchdir') && x.ret !== -1 && !(typeof x.ret === 'number' && x.ret < 0));
  // Dispatch 3 structural rule (AF-8 / L-7): independent of print order. Thread
  // membership comes from every CLONE_THREAD clone in the whole trace; a child
  // forked by a thread group in which any thread OTHER than the forking one ever
  // ran chdir/fchdir (before or after the fork, outcome unknown included) gets an
  // unresolved cwd. The forking thread's own chdir is inherited normally.
  const threadParent = new Map(); // tid -> tid that created it with CLONE_THREAD
  for (const x of calls) {
    if ((x.name === 'clone' || x.name === 'clone3') && x.ret > 0 && /CLONE_THREAD/.test(x.args)) threadParent.set(x.ret, x.pid);
  }
  const leader = (t) => {
    const hops = new Set();
    while (threadParent.has(t) && !hops.has(t)) { hops.add(t); t = threadParent.get(t); }
    return t;
  };
  const groupChdirTids = new Map(); // group leader -> tids that ran chdir/fchdir
  for (const d of cwdChanges) {
    const g = leader(d.pid);
    if (!groupChdirTids.has(g)) groupChdirTids.set(g, new Set());
    groupChdirTids.get(g).add(d.pid);
  }
  const otherThreadChdir = (forker) => {
    const tids = groupChdirTids.get(leader(forker));
    return !!tids && [...tids].some((t) => t !== forker);
  };
  // A non-thread clone with CLONE_FS shares cwd with its parent: a chdir by either
  // changes both, which the per-group model cannot follow. Pre-pass over the whole
  // trace (order-independent): every process on either side of such a clone has an
  // unresolved cwd for the whole trace.
  const fsShared = new Set();
  for (const x of calls) {
    if ((x.name === 'clone' || x.name === 'clone3') && x.ret > 0 && /CLONE_FS/.test(x.args) && !/CLONE_THREAD/.test(x.args)) {
      fsShared.add(leader(x.pid));
      fsShared.add(x.ret);
    }
  }
  // ---- S6 repair 1 (B1/B2/B3/N1): fd table, independent of strace -y.
  // The production tracer (uid 0, cap-drop ALL + SYS_PTRACE) cannot read
  // /proc/<pid>/fd, so strace -y annotates AT_FDCWD but never a numeric fd.
  // Per thread group: fd -> { k: 'path', path } | { k: 'nonpath' }, with a cloexec
  // flag. Filled from open/openat/openat2/creat/socket returns; close, close_range,
  // dup, dup2, dup3 and fcntl(F_DUPFD*, F_SETFD) are traced to keep it exact. A
  // fork/vfork/clone without CLONE_FILES copies the parent's table; a successful
  // exec drops the cloexec entries. Pid 1 starts with fds 0-2 as stdio (non-file).
  // An fd with no entry is UNKNOWN: a write through it (fd-only call, dirfd, or a
  // /proc/<pid>/fd/N or /dev/fd/N path) is an unresolved write (rule a).
  const parentOf = new Map(); // child tgid -> parent tgid (non-thread clones), whole trace
  const filesShared = new Set(); // both sides of a CLONE_FILES non-thread clone: table unknowable
  for (const x of calls) {
    // A thread created without CLONE_FILES, or any unshare(CLONE_FILES), splits a
    // table this per-group model shares: that group's table is unknowable.
    if (x.name === 'unshare' && /CLONE_FILES/.test(x.args) && x.ret !== -1) { filesShared.add(leader(x.pid)); continue; }
    if (/^(clone|clone3)$/.test(x.name) && x.ret > 0 && /CLONE_THREAD/.test(x.args) && !/CLONE_FILES/.test(x.args)) { filesShared.add(leader(x.pid)); continue; }
    if (!/^(clone|clone3|fork|vfork)$/.test(x.name) || !(x.ret > 0) || /CLONE_THREAD/.test(x.args)) continue;
    if (!parentOf.has(x.ret)) parentOf.set(x.ret, leader(x.pid));
    if (/CLONE_FILES/.test(x.args)) { filesShared.add(leader(x.pid)); filesShared.add(x.ret); }
  }
  const fdTables = new Map();
  const copyTable = (t) => new Map([...t].map(([fd, e]) => [fd, { ...e }]));
  const tableOf = (pid, depth = 0) => {
    const key = leader(pid);
    if (filesShared.has(key)) return null;
    if (fdTables.has(key)) return fdTables.get(key);
    let t;
    if (key === 1) t = new Map([0, 1, 2].map((fd) => [fd, { k: 'nonpath', cloexec: false }]));
    else if (parentOf.has(key) && depth < 64) { const pt = tableOf(parentOf.get(key), depth + 1); t = pt ? copyTable(pt) : new Map(); }
    else t = new Map();
    fdTables.set(key, t);
    return t;
  };
  // own = false: another process's fds. A lookup never creates that process's
  // table (security review): a pid with no table yet (no clone return, no call)
  // is unknown.
  const fdEntry = (pid, fd, own = true) => {
    if (!Number.isInteger(fd) || fd < 0) return { k: 'unknown' };
    if (!own && !fdTables.has(leader(pid))) return { k: 'unknown' };
    const t = tableOf(pid);
    return (t && t.get(fd)) || { k: 'unknown' };
  };
  const fdSet = (pid, fd, e) => { const t = tableOf(pid); if (t && Number.isInteger(fd) && fd >= 0) { if (e) t.set(fd, e); else t.delete(fd); } };
  // ---- Repair 1 (P1): component-by-component resolution, the way the kernel walks
  // a path (path_resolution(7)): at each prefix a link is followed BEFORE the next
  // ".." is applied. Links followed: task-created symlinks, the image's directory
  // symlinks (IMAGE_DIR_LINKS), /dev/fd and /dev/std*, /proc/<x>/root, /proc/<x>/cwd
  // and /proc/<x>/fd/N (through the fd table). A component whose real target is
  // unknown (unknown fd, unknown cwd, too many links) makes the path unresolved.
  // Returns { path } (path null = unresolved) or { sink: true } (a non-file fd).
  const procPid = (who, pid) => (who === 'self' || who === 'thread-self' ? pid : Number(who));
  // budget: one count of links followed, shared across the whole resolution
  // (the kernel's ELOOP limit is 40), so nested links cannot blow up the analysis.
  const walk = (pid, raw, baseDir, nofollowLast = false, budget = { follows: 0 }) => {
    if (typeof raw !== 'string' || budget.follows > 40) return { path: null };
    let cur;
    if (raw.startsWith('/')) cur = '/';
    else if (typeof baseDir === 'string' && baseDir.startsWith('/')) cur = baseDir;
    else return { path: null };
    const segs = raw.split('/').filter((s) => s && s !== '.');
    for (let i = 0; i < segs.length; i++) {
      const seg = segs[i];
      const last = i === segs.length - 1;
      if (seg === '..') { const cut = cur.lastIndexOf('/'); cur = cut <= 0 ? '/' : cur.slice(0, cut); continue; }
      cur = cur === '/' ? `/${seg}` : `${cur}/${seg}`;
      // fd and procfs magic links: followed even as the last component (fail closed).
      let m;
      if ((m = /^\/proc\/(self|thread-self|\d+)(?:\/task\/(\d+))?\/fd\/(\d+)$/.exec(cur))) {
        budget.follows += 1;
        const who = m[2] !== undefined ? Number(m[2]) : procPid(m[1], pid);
        const e = fdEntry(who, Number(m[3]), leader(who) === leader(pid));
        if (e.k === 'path') { cur = e.path; continue; }
        if (e.k === 'nonpath' && last) return { sink: true };
        return { path: null };
      }
      if (cur === '/dev/fd') { budget.follows += 1; const r = walk(pid, '/proc/self/fd', '/', false, budget); if (r.path === null || r.sink) return r; cur = r.path; continue; }
      if ((m = /^\/dev\/std(in|out|err)$/.exec(cur))) {
        const e = fdEntry(pid, { in: 0, out: 1, err: 2 }[m[1]]);
        if (e.k === 'path') { cur = e.path; continue; }
        if (e.k === 'nonpath' && last) return { sink: true };
        return { path: null };
      }
      if ((m = /^\/proc\/(self|thread-self|\d+)(?:\/task\/\d+)?\/root$/.exec(cur))) { cur = '/'; continue; }
      if ((m = /^\/proc\/(self|thread-self|\d+)(?:\/task\/(\d+))?\/cwd$/.exec(cur))) {
        const w = cwd.get(tg(m[2] !== undefined ? Number(m[2]) : procPid(m[1], pid)));
        if (typeof w !== 'string') return { path: null };
        cur = w; continue;
      }
      // Other procfs magic links (exe, map_files/*, ns/*) are not followed here:
      // walking past one is unresolved (fail closed).
      if (!last && /^\/proc\/(self|thread-self|\d+)(?:\/task\/\d+)?\/(exe|map_files\/[^/]+|ns\/[^/]+)$/.test(cur)) return { path: null };
      if (last && nofollowLast) break;
      // Task-created symlinks, then the image's directory symlinks.
      const target = links.has(cur) ? links.get(cur) : IMAGE_DIR_LINKS[cur];
      if (target !== undefined) {
        const parent = cur.slice(0, cur.lastIndexOf('/')) || '/';
        budget.follows += 1;
        const r = walk(pid, target, parent, false, budget);
        if (r.path === null || r.sink) return { path: null };
        cur = r.path;
      }
    }
    return { path: cur };
  };
  const dropCloexec = (pid) => { const t = tableOf(pid); if (t) for (const [fd, e] of [...t]) if (e.cloexec) t.delete(fd); };
  for (let ci = 0; ci < calls.length; ci++) {
    const c = calls[ci];
    const p = tg(c.pid);
    seen.add(p);
    if (!cwd.has(p) || fsShared.has(p)) cwd.set(p, null);
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
            // F-D2-1: cwd is not changed by exec, so it is inherited whenever the
            // child has not set its own (even if its exec was printed first);
            // exe/argv keep the seen guard (AF-5).
            // The child got the cwd the parent had when the clone was entered. If another
            // thread of the parent changed it while the clone was pending, that cwd is
            // not known here: unresolved (fail closed), never the later one.
            // Another thread of this group (or a thread not yet attributed) changing
            // cwd during the clone: the child's cwd is unknown (fail closed).
            const raced = otherThreadChdir(c.pid) || cwdChanges.some((d) => d.pid !== c.pid && d.pid !== child && (!tgid.has(d.pid) || tg(d.pid) === p) && d.entry <= c.exit && d.exit >= c.entry);
            if (!ownCwd.has(child)) cwd.set(child, raced ? null : cwd.get(p));
            if (fsShared.has(child)) cwd.set(child, null);
            // Repair 1: the child's fd table is the parent's at the clone return,
            // unless the child already acted (its table was then copied at its
            // first call, from the parent's table at that point).
            tableOf(child);
            if (!seen.has(child)) {
              if (exe.has(p)) { exe.set(child, exe.get(p)); exeFromOwnExec.delete(child); }
              if (argv.has(p)) argv.set(child, argv.get(p));
            }
          }
        } else if (c.ret === -1) {
          events.push({ ...base, type: 'fork-failed' });
        }
        break;
      }
      case 'getcwd': {
        // In strace's %file class but takes no path (it returns one): not an access.
        // Not traced by trace.sh; kept explicit so a %file widening cannot turn it
        // into an unmapped (fail-closed) write.
        break;
      }
      case 'execveat': {
        // fexecve / execveat: what runs is identified by an fd, not a checkable path.
        // A10 (S6): the attempt is also an access of the dirfd + path it names
        // ("" with AT_EMPTY_PATH = the fd itself). Unresolved -> paths-resolved fails.
        {
          const a = pathArgs(c.args)[0];
          let r = null;
          if (a && a.str !== null) {
            let dir = a.str.startsWith('/') ? '/' : (a.base === 'cwd' ? cwd.get(p) : a.base);
            if (dir === null && a.dirfd !== undefined) { const e = fdEntry(p, a.dirfd); dir = e.k === 'path' ? e.path : null; }
            if (dir) { const w = a.str === '' ? { path: dir } : walk(p, a.str, dir); r = w.path || null; }
          }
          events.push({ ...base, type: 'fs-probe', path: r, rawPath: a ? a.str : null, unresolved: !r, blocked: c.ret === -1 });
        }
        if (c.ret === 0) {
          // SR-3: the dirfd annotation is package-influenced text, so the argument
          // split is not trusted: envp is never taken from execveat (null = not
          // traced), so the instrumentation marker always fails for it.
          exe.set(p, '(execveat)');
          argv.set(p, []);
          dropCloexec(c.pid);
          events.push({ ...base, type: 'exec', path: '(execveat)', rawPath: c.args.slice(0, 120), argv: [], envp: null, opaque: true });
        }
        break;
      }
      case 'execve': {
        const { path: rawExe, argv: av, envp } = execArgs(c.args);
        // A10 (S6, DEC-D5-6): an exec attempt is also an access of the path it
        // names (spawn('/var/run/docker.sock') probes it), successful or not.
        {
          const w = typeof rawExe === 'string' ? walk(p, rawExe, cwd.get(p)) : { path: null };
          events.push({ ...base, type: 'fs-probe', path: w.path || null, rawPath: rawExe, unresolved: !w.path, blocked: c.ret === -1 });
        }
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
          dropCloexec(c.pid);
          events.push({ ...base, type: 'exec', path, rawPath: rawExe, argv: av, envp, viaLink });
        }
        break;
      }
      case 'chdir': {
        // A7 (S6, DEC-D5-4): chdir also probes its target (ENOENT vs ENOTDIR vs
        // success), so it is an access (rule b), attempted or not, resolved against
        // the cwd before the call.
        {
          const raw = quotedStrings(c.args)[0];
          const w = typeof raw === 'string' ? walk(p, raw, cwd.get(p)) : { path: null };
          events.push({ ...base, type: 'fs-probe', path: w.path || null, rawPath: raw ?? null, unresolved: !w.path, blocked: c.ret === -1 });
          // P1: the new cwd is the walked (link-followed) directory.
          if (c.ret === 0) { cwd.set(p, fsShared.has(p) ? null : (w.path || null)); ownCwd.add(p); }
        }
        if (c.ret === 0) { /* set above */ }
        else if (c.ret === null) { cwd.set(p, null); ownCwd.add(p); } // outcome unknown: may have applied
        break;
      }
      case 'fchdir': {
        // strace -y prints the directory behind the fd: fchdir(3</work/x>)
        const d = /^\d+<([^>]*)>/.exec(c.args);
        // A7 (S6, DEC-D5-4): fchdir into a directory is an access of that directory.
        if (d && d[1].startsWith('/')) events.push({ ...base, type: 'fs-probe', path: normalize(d[1]), rawPath: d[1], unresolved: false, blocked: c.ret === -1 });
        if (c.ret === 0) { cwd.set(p, d && d[1].startsWith('/') && !fsShared.has(p) ? normalize(d[1]) : null); ownCwd.add(p); }
        else if (c.ret === null) { cwd.set(p, null); ownCwd.add(p); } // outcome unknown: may have applied
        break;
      }
      case 'unshare': {
        // Traced only for the fd-table pre-pass (CLONE_FILES); no file event.
        break;
      }
      case 'close': {
        // Repair 1: the fd is gone whatever close returned (Linux frees it even on EINTR).
        const fd = Number(/^\s*(\d+)/.exec(c.args)?.[1]);
        fdSet(c.pid, fd, null);
        break;
      }
      case 'close_range': {
        // close_range(first, last|~0U, flags): CLOSE_RANGE_CLOEXEC only marks them.
        if (c.ret === 0) {
          const m = /^\s*(\d+),\s*(\d+|~0U?|4294967295|0xffffffff)/.exec(c.args);
          const t = tableOf(c.pid);
          if (m && t) {
            const lo = Number(m[1]);
            const hi = /^\d+$/.test(m[2]) ? Number(m[2]) : Infinity;
            for (const fd of [...t.keys()]) {
              if (fd < lo || fd > hi) continue;
              if (/CLOSE_RANGE_CLOEXEC/.test(c.args)) t.get(fd).cloexec = true; else t.delete(fd);
            }
          } else if (!m && t) {
            for (const fd of [...t.keys()]) t.delete(fd); // unparsable: forget all (unknown, fail closed)
          }
        }
        break;
      }
      case 'dup': case 'dup2': case 'dup3': {
        // dup(old) = new; dup2(old, new) = new; dup3(old, new, O_CLOEXEC) = new.
        if (typeof c.ret === 'number' && c.ret >= 0) {
          const old = Number(/^\s*(\d+)/.exec(c.args)?.[1]);
          const e = fdEntry(c.pid, old);
          fdSet(c.pid, c.ret, e.k === 'unknown' ? null : { ...e, cloexec: c.name === 'dup3' && /O_CLOEXEC/.test(c.args) });
        }
        break;
      }
      case 'fcntl': {
        const m = /^\s*(\d+),\s*(F_[A-Z_]+)/.exec(c.args);
        if (!m) break;
        if (/^F_DUPFD/.test(m[2]) && typeof c.ret === 'number' && c.ret >= 0) {
          const e = fdEntry(c.pid, Number(m[1]));
          fdSet(c.pid, c.ret, e.k === 'unknown' ? null : { ...e, cloexec: m[2] === 'F_DUPFD_CLOEXEC' });
        } else if (m[2] === 'F_SETFD' && c.ret === 0) {
          const t = tableOf(c.pid);
          const e = t && t.get(Number(m[1]));
          if (e) e.cloexec = /FD_CLOEXEC/.test(c.args.slice(m[0].length));
        }
        break;
      }
      case 'socket': {
        // Repair 1: a socket fd is not a file.
        if (typeof c.ret === 'number' && c.ret >= 0) fdSet(c.pid, c.ret, { k: 'nonpath', cloexec: /SOCK_CLOEXEC/.test(c.args) });
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
          const w = unix[1] || raw === null ? { path: null } : walk(p, raw, cwd.get(p));
          const path = w.path || null;
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
        // The directory a relative path is resolved against: the cwd, an annotated
        // dirfd, or (repair 1, B3) a bare numeric dirfd looked up in the fd table.
        // Unknown or non-file dirfd: null (unresolved), never the cwd.
        const dirOf = (a) => {
          if (a.base === 'cwd') return cwd.get(p);
          if (a.base !== null) return a.base;
          if (a.dirfd === undefined) return null;
          const e = fdEntry(p, a.dirfd);
          return e.k === 'path' ? e.path : null;
        };
        // P1: walked component by component (walk()), links followed before "..".
        const resolveArg = (i, nofollowLast) => {
          const a = args[i];
          if (!a || a.str === null) return { path: null, raw: a ? a.str : null };
          const dir = a.str.startsWith('/') ? '/' : dirOf(a);
          if (dir === null || dir === undefined) return { path: null, raw: a.str };
          const r = walk(p, a.str, dir, nofollowLast);
          return r.sink ? { path: null, raw: a.str, sink: true } : { path: r.path, raw: a.str };
        };
        const at = (i) => resolveArg(i, false);
        // Calls that act on the final path component itself (unlink, rmdir,
        // rename, link, symlink, lstat) do not follow it: the parent directories
        // are walked through links, the last component is not (fd and procfs magic
        // links still are: fail closed).
        const nofollow = (i) => resolveArg(i, true);
        // SR-1: a link is forgotten once its path is unlinked, removed or renamed
        // (either side of a rename), so a stale mapping can never name a later file.
        const forget = (r) => { if (r.path) { for (const l of [...links.keys()]) if (l === r.path || l.startsWith(`${r.path}/`)) links.delete(l); } };
        const blocked = c.ret === -1;
        const push = (type, r, extra = {}) => { if (!r.sink) events.push({ ...base, type, path: r.path, rawPath: r.raw, unresolved: r.path === null, blocked, ...extra }); };
        if (c.name === 'openat' || c.name === 'open' || c.name === 'openat2' || c.name === 'creat') {
          // openat2 prints its flags inside the how struct ({flags=O_WRONLY|O_CREAT, ...}).
          // RESOLVE_IN_ROOT/BENEATH only confine the lookup, so the path read here is
          // the widest one the call could reach (fail closed).
          const r = at(0);
          push(c.name === 'creat' || WRITE_FLAGS.test(c.args) ? 'fs-write' : 'fs-read', r);
          // Repair 1: the returned fd names this file (or a non-file, for a sink
          // such as /dev/stdout reopened); an unresolved path leaves it unknown.
          if (typeof c.ret === 'number' && c.ret >= 0) {
            const cloexec = /O_CLOEXEC/.test(c.args);
            fdSet(c.pid, c.ret, r.sink ? { k: 'nonpath', cloexec } : r.path ? { k: 'path', path: r.path, cloexec } : null);
          }
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
          // P1: the target is kept unresolved (absolute, ".." intact) and walked
          // each time the link is followed, so links created later in its chain count.
          const raw = args[0] && args[0].str !== null ? args[0].str : null;
          const linkDir = link.path ? (link.path.slice(0, link.path.lastIndexOf('/')) || '/') : null;
          const stored = raw === null ? null : raw.startsWith('/') ? raw : (linkDir ? `${linkDir === '/' ? '' : linkDir}/${raw}` : null);
          const tr = stored ? walk(p, stored, '/') : { path: null };
          const target = { path: tr.sink ? null : tr.path, raw };
          push('fs-link-target', target);
          if (!blocked && link.path && stored) links.set(link.path, stored);
        } else if (/^(access|faccessat2?|newfstatat|statx|stat|lstat)$/.test(c.name)) {
          // fstat-style calls on an fd ("" with AT_EMPTY_PATH) are not path accesses.
          if (args[0] && args[0].str === '' && /AT_EMPTY_PATH/.test(c.args)) break;
          push('fs-stat', c.name === 'lstat' || /AT_SYMLINK_NOFOLLOW/.test(c.args) ? nofollow(0) : at(0));
        } else if (FS_SYSCALLS[c.name]) {
          // L-19 (S6): the calls added to the traced set.
          const { kind, form } = FS_SYSCALLS[c.name];
          const type = kind === 'write' ? 'fs-write' : 'fs-probe';
          const noFollowFlag = /AT_SYMLINK_NOFOLLOW/.test(c.args);
          const fromFd = (text) => {
            const a = fdAnnotation(text);
            if (a.kind === 'path' && a.path) return { r: { path: a.path, raw: a.path } };
            if (a.kind === 'nonpath') return null; // pipe, socket, anon inode, memfd: not a file
            // Repair 1 (B1/N1): the production tracer prints no annotation for a
            // numeric fd, so the fd table names the file.
            const fdm = /^\s*(\d+)/.exec(text);
            const e = fdm ? fdEntry(p, Number(fdm[1])) : { k: 'unknown' };
            if (e.k === 'path') return { r: { path: e.path, raw: `fd ${fdm[1]}` } };
            if (e.k === 'nonpath') return null;
            // Unknown fd. EBADF: no fd, nothing was acted on. A write attempt,
            // successful or failed, is an unresolved write (rule a, fail closed).
            // A read or probe through an unknown fd is not recorded: getting an fd
            // to a credential file needs an open the tracer sees (rule b there).
            if (c.errno === 'EBADF') return null;
            return kind === 'write' ? { r: { path: null, raw: fdm ? `fd ${fdm[1]}` : null } } : null;
          };
          let target = null;
          if (form === 'fd') {
            target = fromFd(c.args);
          } else if (form === 'path' || form === 'lpath') {
            if (args.length) target = { r: form === 'lpath' ? nofollow(0) : at(0) };
          } else if (form === 'dirfd' || form === 'ldirfd') {
            if (args.length) {
              target = { r: form === 'ldirfd' || noFollowFlag ? nofollow(0) : at(0) };
            } else {
              // A NULL path acts on the dirfd itself: utimensat(3</etc/hostname>, NULL, ...).
              target = fromFd(c.args);
            }
          } else if (form === 'watch') {
            // The first fd is the inotify instance, not a directory: the path is cwd-relative.
            if (args.length) { args[0].base = 'cwd'; target = { r: at(0) }; }
          } else if (form === 'fanotify') {
            if (args.length) {
              target = { r: /FAN_MARK_DONT_FOLLOW/.test(c.args) ? nofollow(0) : at(0) };
            } else {
              const d = /(\d+<[^>]*>),\s*NULL\s*$/.exec(c.args);
              target = d ? fromFd(d[1]) : null;
            }
          } else {
            target = { r: { path: null, raw: null } }; // opaque
          }
          if (target) push(type, target.r);
        } else {
          // Fail closed: a traced call with no mapping (a name added to trace.sh
          // without one, a %file member this table does not know, or a syscall
          // strace prints only by number) is an unresolved write: rule a fires.
          // test/trace-coverage.test.js keeps every trace.sh name mapped, so this
          // branch is reached only by calls the tables do not know.
          push('fs-write', args.length ? at(0) : { path: null, raw: null }, { unmapped: true });
        }
      }
    }
  }

  return { calls: calls.length, tgid, parent, exe, argv, events };
}

module.exports = { analyse, parseLines, splitCall, quotedStrings, normalize, execArgs, FS_SYSCALLS, LEGACY_SYSCALLS, MAPPED_SYSCALLS };
