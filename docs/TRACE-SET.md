# Traced syscall set (S6, L-19)

This file records the evidence for the tracer's `-e trace=` set in
`images/sandbox/runtime/trace.sh`. The guard test `test/trace-coverage.test.js` enforces it.

## What changed and why

At a075bd1 the set was a hand-written list of 44 names. File syscalls outside it produced no record, so a package whose only forbidden acts used them got `install` (L-19). Examples are `utimensat`, `fchownat`, `readlink` and `inotify_add_watch`.

The S6 set had 88 names in d949e7de (95 after repair 1, see below), all listed explicitly:

| Group | Names |
|---|---|
| strace 6.1 `%file` class, minus `getcwd` | 66 |
| fd-only file calls (`%desc`; strace `-y` prints the path behind the fd) | ftruncate, fallocate, fchmod, fchown, fsetxattr, fremovexattr, fstatfs, fgetxattr, flistxattr, open_by_handle_at, fchdir |
| process (kept from a075bd1) | clone, clone3, fork, vfork; execve and execveat are also in `%file` |
| network (kept from a075bd1) | socket, connect, bind, listen, sendto, sendmsg, sendmmsg |

## Why explicit names and not `%file`

Mechanical comparison, using `comm` on the sorted lists:

- **`%file` (strace 6.1, x86_64) minus the traced set** is `getcwd` only. It takes no path; it returns one. If it were traced, the fail-closed default would misread its returned path as a write. `src/trace.js` maps it as a no-op in any case.
- **The traced set minus `%file`** is exactly the 11 fd-only calls and the process and network calls above.

So the explicit set is `%file` minus `getcwd`, plus extras. That is equivalent to `%file`, and wider.

Listing the names explicitly lets the guard test check membership by parsing `trace.sh`. A `%file` token would hide its expansion from the test.

## Where the `%file` list comes from

- **strace version in the tracer image:** `strace -- version 6.1`. This was checked in `qp-sandbox:impl6-wip` built from this tree, and the adversary checked it in `qp-sandbox:s1-a075bd1b`.
- **`%file` membership:** the `TF` flag in strace v6.1's `src/linux/x86_64/syscallent.h` and `src/linux/generic/syscallent-common.h`. The 67 names are in `test/reference/strace61-file-class.txt`, with the sha256 of each source table. The adversary and the auditor fetched the tables independently, and the hashes match.
- **strace accepts the set:** the image's strace 6.1 runs with the full 88-name set, and it traced a node probe of `utimensat` (path and fd), `readlink`, `fchmod`, `ftruncate`, `inotify_add_watch`, `statfs` and `chdir`.

## The guard test's oracle

The oracle is `test/reference/REFERENCE-SYSCALLS.md`, the adversary's list (DEC-D5-2). It was copied from checks commit `051a9d04`, and the test pins its sha256 `d0a9acdd…4712a`.

Section 5 of that file has 79 entries. For each entry, the test checks three things:
1. The name is in `trace.sh`.
2. The name has a mapping in `src/trace.js`.
3. A synthesized attempt yields the rule its kind needs:
   - fs-write on `/etc/…` must fire rule a;
   - fs-access, cwd+access, exec or net-unix on `/home/qp/.ssh/…` must fire rule b.

The test also fails if `trace.sh` traces a name that has no mapping.

Comparison of the traced set with the reference list:
- **reference minus traced:** none.
- **traced minus reference:** clone, clone3, fork, vfork, listen, socket, sendto, sendmsg, sendmmsg. These are process and network calls, all mapped.

## Mapping (`src/trace.js`, `FS_SYSCALLS`)

**fs-write** (rule a; it is also checked against rule b):
- utime, utimes, utimensat, futimesat;
- chown, lchown, fchownat, fchown;
- fchmod, fchmodat2, ftruncate, fallocate;
- mknod, mknodat;
- setxattr, lsetxattr, fsetxattr, removexattr, lremovexattr, fremovexattr;
- chroot, acct, swapon, swapoff, uselib, quotactl, mount, umount2, pivot_root;
- open_tree, move_mount, fspick, mount_setattr, fsconfig, open_by_handle_at.

**fs-probe** (an access; rule b):
- readlink, readlinkat;
- statfs, fstatfs;
- getxattr, lgetxattr, fgetxattr, listxattr, llistxattr, flistxattr;
- name_to_handle_at, inotify_add_watch, fanotify_mark.

**Existing calls with new access probes:**
- chdir and fchdir probe their target (A7, DEC-D5-4).
- execve and execveat probe the path they name (A10, DEC-D5-6).
- Their cwd and exec handling is unchanged.

**openat2** is mapped like openat, by the flags in its `how` struct. `RESOLVE_*` flags only confine the lookup, so the path read is the widest one the call could reach.

Some calls the reference list labels fs-access are mapped as fs-write: chroot, uselib, open_tree, fspick, fsconfig and open_by_handle_at. These are privileged or mount calls, and fs-write is the stricter mapping: it fires rule a, and rule b too on a credential path. The guard accepts a write mapping where an access is expected. It never accepts the reverse.

**Path forms:**
- **dirfd and cwd resolution is unchanged:** dirfd-relative paths, strace's `-y` dirfd paths, links created during the task, and an unknown cwd. An unknown cwd makes a write fire rule a and an access fail `paths-resolved` (review).
- **A NULL path means the fd itself.** For example, `utimensat(17</etc/hostname>, NULL, …)` is futimens on that file.
- **fd-only calls use the `-y` path of argument 0.** Pipes, sockets, anon inodes and memfds are not files.

## Fail-closed choice (F1b)

A traced call with no mapping becomes an **fs-write observation with an unresolved path**, so rule a fires (`do-not-install`). The same applies to a call strace prints only by number (`syscall_0x…`).

This was chosen over a completeness failure, which gives `review`, because an unknown file call can be a write, and `install` must never follow from one. A missing completeness marker would only downgrade the verdict to `review`.

The guard test keeps every name in `trace.sh` mapped, so this branch only catches calls the tables do not know.

**fd-only calls:**
- **A successful write on an fd with no `-y` path** is also an unresolved write, so rule a fires.
- **A failed call with no path** (EBADF) acted on nothing and is not recorded.

**Calls unfinished at the end of the trace:** a file call still unfinished when the trace ends is kept as an attempt. Process and network calls keep their a075bd1 handling.

## Limit: syscalls above 450 (README L-13 extension, DEC-D5-5)

strace 6.1 rejects the names and numbers of syscalls above 450 (adversary probe S-B). These are fchmodat2 (452), setxattrat, getxattrat, listxattrat and removexattrat (463–466), open_tree_attr (467), and file_getattr and file_setattr (468–469).

glibc 2.36 has no wrappers for them, and the image has no binary that uses them. So only a native `.node` addon can reach them. That is recorded as an extension of L-13 in the README and in the receipt's `knownLimitations`.

`fchmodat2` is in `FS_SYSCALLS`, so a future strace that names it is already mapped. A newer strace is out of S6 scope, because it means a new tracer image.

## Overhead

Measured on the implementer's working-tree build, end-to-end CLI wall time, `QP_MODEL_OFF=1`. The auditor's runs on the candidate are the official numbers.

| Package | a075bd1 median (auditor) | S6 tree median (implementer, 3 runs) |
|---|---|---|
| hostile | 29.2 s | 25.8 s |
| express@4.21.2 | 32.3 s | 30.5 s |

No measurable slowdown. The loop and forkbomb verdicts are unchanged: do-not-install, rule e.

## Repair 1 (after review 1 of d949e7de): the fd table

**Root fact.** The production tracer prints no `-y` annotation for a numeric fd. The adversary counted 0 `N</…>` annotations across 11 production traces, and the auditor confirmed it. `AT_FDCWD</…>` is annotated about 10,000 times per trace.
- The tracer container runs as uid 0 with `--cap-drop ALL --cap-add SYS_PTRACE`.
- Reading the target of `/proc/<pid>/cwd` needs only ptrace access. Traversing `/proc/<pid>/fd` (mode 0500, owned by uid 10001) needs DAC override, which the tracer lacks. That is the adversary's reasoned cause; I did not verify it separately.
- The `17</work/x>` example in handoff 1 was **not** produced by the production tracer. It came from a one-off probe:
  - `docker run --rm qp-sandbox:impl6-wip sh -c "strace -f -y ... node -e ..."`;
  - strace ran inside the sandbox image, as uid 10001, tracing its own child;
  - the same uid can read its own child's `/proc/<pid>/fd`.
- That probe proved the annotation format, not that the shipped tracer produces it. This was a gap in my evidence.

**Fix.** `src/trace.js` keeps its own fd table per thread group, independent of `-y`. An annotation is still used when one is present.

How the table is filled:
- The return values of open, openat, openat2 and creat (resolved path, or unknown) and of socket (not a file).
- Copy on `dup`, `dup2`, `dup3` and `fcntl(F_DUPFD[_CLOEXEC])`.
- Forget on `close`.
- `close_range` forgets, or only marks the entries with `CLOSE_RANGE_CLOEXEC`.
- `fcntl(F_SETFD)` sets the cloexec flag.
- A successful exec drops the cloexec entries.

How it is inherited:
- A fork, vfork or clone without `CLONE_FILES` copies the parent's table at the clone return, or at the child's first call if the child's lines come first.
- Threads share the table of their thread group.
- `CLONE_FILES` without `CLONE_THREAD` makes both sides' tables unknown for the whole trace (fail closed).
- Pid 1 starts with fds 0–2 as stdio, which is not a file.
- close, close_range, dup, dup2, dup3 and fcntl are added to the traced set (94 names; 95 with unshare, below). The guard test checks that each one is mapped.

How it is used:
- **B1:** an fd-only call takes its path from the table.
  - An unknown fd: a write attempt, successful or failed, is an unresolved write, so rule a fires.
  - EBADF is not recorded.
  - A read or probe through an unknown fd is not recorded. Getting an fd to a credential file needs a traced open, which already fires rule b.
- **B2:** `/proc/{self,thread-self,<pid>}/fd/N[/…]`, `/dev/fd/N[/…]` and `/dev/std{in,out,err}` resolve through the table (the named process's table for `<pid>`).
  - A non-file fd is a sink.
  - An unknown fd is unresolved.
  - `observe.js` no longer skips `/dev/fd`, `/proc/self/fd` or `/proc/thread-self/fd` as device sinks. It still skips `/dev/null`, `/dev/tty`, `/dev/stdout` and `/dev/stderr`.
- **B3:** a bare numeric dirfd (`mkdirat(4, "qpdir")`) resolves through the table. Unknown or non-file means unresolved, never the cwd.
- **Hardening:** `/proc/<x>/cwd/…` with an unknown cwd, or another pid's cwd, is unresolved instead of the literal path.

**Not done (should-fix):** using the `AT_FDCWD</path>` annotation as the base when the tracked cwd is unknown.
- In a printed annotation, `[^>]*` stops at the first `>`. A directory name containing `>` would therefore give a shorter, wrong base path.
- Trusting that text could turn today's unresolved (fail-closed) case into a resolved, allowed path.
- The unknown-cwd case stays unresolved.

**Verbatim tests.** `test/fdtable-s6.test.js` replays slices of the adversary's production traces: tasks 94c5fbb68f, 016cefc2ca, 9770eb7388 and 89c84b384a, from checks 99737bcb, on images `qp-sandbox:adv6-d949e7d`.
- The slices are in `test/fixtures/prod-traces/`, and no line is edited.
- On d949e7de these slices give no rule a for B1–B3, and a:2 for N1.
- On the repair they give rule a for B1–B3 (on `/etc/hostname` and `/etc/qpdir`), and no file rule for N1.

### P1 (adversary msg ab9905b7): `..` after a link

The kernel follows a symlink or magic link first, then walks `..` from its target (path_resolution(7)). Before this fix, `normalize()` collapsed `..` lexically first.

`walk()` in `src/trace.js` now resolves a path component by component. At each prefix it follows, before the next `..`:
- task-created symlinks. The target is kept unresolved and walked again each time the link is followed, so a link created later in the chain counts.
- the image's 26 directory symlinks (`IMAGE_DIR_LINKS`, listed from `qp-sandbox:s1-683b3d47` with `find / -xdev -type l -xtype d`), for example `/lib64 -> usr/lib64` and `/var/run -> /run`.
- `/dev/fd` and `/dev/std*`.
- `/proc/<x>/root`.
- `/proc/<x>/cwd`, through the tracked cwd.
- `/proc/<x>/fd/N`, through the fd table.

**Unresolved cases:** an unknown target makes the path unresolved. That covers an unknown fd, an unknown cwd, or more than 40 link hops.

**Where `walk()` is used:**
- every path argument in the file branches (`at()`, `nofollow()`);
- symlink targets;
- the chdir probe and the new cwd;
- execve and execveat probes;
- unix `connect` paths.

The exec identity (`exe`) keeps its lexical resolution, so roles and instrumentation markers are unchanged.

**Visible change:** paths through image links are now reported as their real path. For example, `/var/run/docker.sock` becomes `/run/docker.sock`. Both are in `DOCKER_SOCKETS`, so rule b fires as before. Two assertions in `test/observe.test.js` were updated to the real path.

### Automated security review of 683b3d47 (addressed)

1. **A thread created without `CLONE_FILES`, or a successful `unshare(CLONE_FILES)`, splits a table this model shares.** That group's table is now unknowable, so writes through its fds fire rule a.
   - `unshare` is added to the traced set (95 names). It has an explicit no-op mapping, because it creates no file event.
2. **An alias path was not followed through links.** `walk()` now covers it: links and fd aliases are substituted at every prefix.
3. **`/dev/stdout` and `/dev/stderr` reached through a link.** They are resolved through the fd table by `walk()`, and `observe.js` `DEVICE_SINKS` keeps only `/dev/null` and `/dev/tty`.

### Automated security review of 7a4fedaa (addressed)

1. **One shared link budget per resolution.** It caps link follows at 40, the kernel's ELOOP limit, across all recursion.
2. **More procfs paths covered.**
   - `/proc/<x>/task/<tid>/{fd/N,root,cwd}` are followed.
   - Walking past another procfs magic link (`exe`, `map_files/*` or `ns/*`) is unresolved.
3. **A lookup never creates another process's fd table.** A foreign pid with no table yet is unknown.

### Padded short lines (found in the implementer's adv7 pre-check on 10e3d056)

strace pads short calls to a column, for example `dup2(17, 1)       = 1` and `close(5)          = 0`.

**The bug:** `splitCall` only recognised `) = `, so every padded line had no return value. This predates S6.
- At a075bd1 it made, for example, a short successful `chdir("/tmp")` an "outcome unknown" chdir, which was fail-closed.
- With the fd table it dropped `dup2` and `dup` results. The adversary's adv7-benign2 (a spawn with a /work file as stdout) then got do-not-install a:3.

**The fix:** the separator is now `)` + spaces + `= `. A test covers it with verbatim lines from that production trace.

### P2 (adversary msg 19f47921): links that move (DEC-D5-7)

The tracer now tracks precisely:
- `rename` moves every task link and made-entry at or under the old path to the new path, including `RENAME_EXCHANGE`.
- `link` or `linkat` without `AT_SYMLINK_FOLLOW` of a known symlink copies it to the new name.
- `unlink` and `rmdir` forget them.

It also applies a fail-closed bound, as the analyst asked. In the writable mounts (`/work`, `/tmp`, `/home/qp`, `/dev/shm`), `walk()` refuses to apply `..` after a component that may be an untracked link: the path is then unresolved. A component may be an untracked link when:
- it, or an ancestor, has kind "unknown". For example, a pre-existing entry moved by `rename`, or the new name of a hard link to a non-link.
- the task ever created, renamed, linked or removed a path the tracer could not resolve. That is a global flag.

Directories made by `mkdir` stay resolvable, so ordinary task trees are not over-condemned.

**Limitation:** a symlink that already exists in `/work` before the trace is unknown to the tracer. The download phase uses `npm ci`, and pacote does not extract symlinks from registry tarballs, so this is not expected. If such a link exists, a `..` after it is collapsed lexically.

### Automated security review of 57ab9411 (addressed)

1. **Flag tests in the file branches ignore quoted strings.** They read a copy of the arguments with every quoted string blanked, so a path such as `/tmp/AT_SYMLINK_NOFOLLOW` cannot flip follow, nofollow, exchange or write decisions. `RENAME_EXCHANGE` counts only for `renameat2`.
2. **An unknown outcome counts as uncertain.** A rename, link, unlink, rmdir or symlink killed mid-call (`= ?`) or unfinished at the end is not treated as a success. It sets the untracked-links flag, so `..` in the writable mounts becomes unresolved.

### Automated security review of 845d9eed (addressed)

1. **Flag text from `-y` annotations is blanked too.** `<…>` annotations are removed along with quoted strings, so a cwd such as `/work/AT_SYMLINK_NOFOLLOW` cannot flip a flag.
2. **An uncertain rename, link or symlink is assumed to have happened** (and also not to have happened):
   - a rename copies the entries to the new name and keeps them at the old name;
   - a link copies a known symlink to the new name;
   - a symlink is recorded.
   - Each of these also sets the untracked-links flag.

### Automated security review of a6db84b9 (addressed)

1. **Uncertain changes no longer copy or overwrite tracked links.** A rename, link or symlink with an unknown outcome marks the names involved as `ambiguous` and sets the untracked-links flag. `walk()` treats following or walking past an `ambiguous` name as unresolved, so it is fail closed and never resolved through a guessed mapping.
2. **Flag text:** fd annotations (`AT_FDCWD<…>` and `N<…>`) are removed first, then quoted strings are blanked.
