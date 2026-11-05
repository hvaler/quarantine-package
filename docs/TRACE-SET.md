# Traced syscall set (S6, L-19)

This file records the evidence for the tracer's `-e trace=` set in
`images/sandbox/runtime/trace.sh`. The guard test `test/trace-coverage.test.js` enforces it.

## What changed and why

At a075bd1 the set was a hand-written list of 44 names. File syscalls outside it produced no record, so a package whose only forbidden acts used them got `install` (L-19). Examples are `utimensat`, `fchownat`, `readlink` and `inotify_add_watch`.

The S6 set has 88 names, all listed explicitly:

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
