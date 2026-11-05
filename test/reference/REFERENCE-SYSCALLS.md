# REFERENCE-SYSCALLS — the oracle for the S6 guard test (F1c, DEC-D5-2)

**Author:** adversary-qxrq. **Date:** 2026-11-05, about 05:50Z. **Arch:** x86_64.
**Baseline:** a075bd1, `images/sandbox/runtime/trace.sh:10`.
**Status:** paper only. No product code changed.

## Sources

- **S-A · strace 6.1 syscall table, the version in the image.**
  - `strace -V` → `strace -- version 6.1` in `qp-sandbox:s1-a075bd1b`.
  - The files are fetched from tag v6.1 of github.com/strace/strace:
    - `src/linux/x86_64/syscallent.h`, entries 0–334;
    - `src/linux/generic/syscallent-common.h`, entries 424–450.
  - The flag `TF` means the call is in `%file`, and `TD` means `%desc`. The `%file` column below is read directly from that table.
- **S-B · probes in throwaway containers.** Each ran `--rm` from the existing image `qp-sandbox:s1-a075bd1b` with label `qp.run-prefix=advd5`. No new image was pulled.
  - strace 6.1 rejects `fchmodat2`, `452`, `syscall_452` and `syscall_0x1c4` with "invalid system call". **It cannot trace any syscall above 450, by name or by number.**
  - Image: Debian 12, glibc 2.36, node v22.23.4. There is no python, no perl, and no `setfattr`/`getfattr`.
  - Present: `/usr/bin/{mount,umount,mknod,mkfifo,touch,chown,chgrp,chmod,stat,readlink,realpath,df,find,tar,cp,install,ln,truncate,fallocate,unshare,nsenter}` and `/usr/sbin/{chroot,swapon,swapoff,pivot_root,switch_root}`.
  - The host kernel is 6.18 (WSL2). The VM kernel was not checked (no VM access).
- **S-C · product code at a075bd1.**
  - `src/trace.js:281-403`: `chdir` only updates cwd; `default:` maps open/unlink/mkdir/rename/link/symlink/stat.
  - `src/observe.js:135`: access rule input.
  - `orchestrator.js:32,41,42`: L-2, L-11, L-13.

**Reachability, for column R:**
- **J** = a Node fs/process API.
- **B** = `child_process` of a system binary in the image. Not `review`, because the binary is not on a writable mount.
- **N** = a native `.node` addon only (L-13: loaded in-process, no exec, no `review`).
- **X** = native ELF executed from `/work`,`/tmp`,HOME, which already gives `review` (L-2).

**Column A**, whether a non-root, `cap-drop ALL` package can still attempt it:
- **Y** = it reaches the kernel; it may fail, but the attempt is real.
- **E** = it fails with EPERM before having any effect, but the syscall is still entered and visible to ptrace.

Rules (a) and (b) fire on attempts, so **Y** and **E** both need tracing.

## 1. Calls that must be traced AND mapped (the guard list)

| # | Syscall | Class | Expected kind | %file (S-A) | R | A | Traced at a075bd1? |
|---|---|---|---|---|---|---|---|
| 1 | open | path | by flags (fs-write if write flags, else fs-access) | TF | J | Y | yes |
| 2 | openat | dirfd+path | by flags | TF | J | Y | yes |
| 3 | openat2 | dirfd+path | by `how.flags`; any `RESOLVE_*` keeps the path | TF | N | Y | **no** |
| 4 | creat | path | fs-write | TF | J | Y | yes |
| 5 | truncate | path | fs-write | TF | B (`truncate`) | Y | yes |
| 6 | ftruncate | fd | fs-write (fd path via `-y`) | **TD only** | J (`fs.ftruncate`) | Y | **no** |
| 7 | fallocate | fd | fs-write (fd path) | **TD only** | B (`fallocate`) | Y | **no** |
| 8 | mkdir | path | fs-write | TF | J | Y | yes |
| 9 | mkdirat | dirfd+path | fs-write | TF | J | Y | yes |
| 10 | mknod | path | fs-write | TF | B (`mknod`,`mkfifo`) | Y | **no** |
| 11 | mknodat | dirfd+path | fs-write | TF | B | Y | **no** |
| 12 | rmdir | path | fs-write | TF | J | Y | yes |
| 13 | unlink | path | fs-write | TF | J | Y | yes |
| 14 | unlinkat | dirfd+path | fs-write | TF | J | Y | yes |
| 15 | rename | path×2 | fs-write ×2 | TF | J | Y | yes |
| 16 | renameat | dirfd+path×2 | fs-write ×2 | TF | J | Y | yes |
| 17 | renameat2 | dirfd+path×2 | fs-write ×2 | TF | J | Y | yes |
| 18 | link | path×2 | fs-write (new); old = fs-access | TF | J | Y | yes |
| 19 | linkat | dirfd+path×2 | same as link; `AT_EMPTY_PATH` uses an fd | TF | J | Y | yes |
| 20 | symlink | path×2 | fs-write (link) + target = fs-access | TF | J | Y | yes |
| 21 | symlinkat | path+dirfd+path | same as symlink | TF | J | Y | yes |
| 22 | chmod | path | fs-write | TF | J/B | Y | yes |
| 23 | fchmodat | dirfd+path | fs-write | TF | J/B | Y | yes |
| 24 | fchmod | fd | fs-write (fd path) | **TD only** | J (`fs.fchmod`) | Y | **no** |
| 25 | chown | path | fs-write | TF | J/B | Y | **no** |
| 26 | lchown | path | fs-write | TF | J (`fs.lchown`) | Y | **no** |
| 27 | fchownat | dirfd+path | fs-write | TF | J (`fs.chown`),B | Y | **no** (X1) |
| 28 | fchown | fd | fs-write (fd path) | **TD only** | J (`fs.fchown`) | Y | **no** |
| 29 | utime | path | fs-write | TF | N | Y | **no** |
| 30 | utimes | path | fs-write | TF | N | Y | **no** |
| 31 | futimesat | dirfd+path | fs-write | TF | N | Y | **no** |
| 32 | utimensat | dirfd+path, **or fd with path NULL** | fs-write; for `utimensat(3</p>, NULL, …)` the path is the fd's | TF | J (`fs.utimes`,`fs.lutimes`,`fs.futimes`),B (`touch`) | Y | **no** (X1) |
| 33 | setxattr | path | fs-write | TF | N | Y | **no** |
| 34 | lsetxattr | path | fs-write | TF | N | Y | **no** |
| 35 | fsetxattr | fd | fs-write (fd path) | **TD only** | N | Y | **no** |
| 36 | removexattr | path | fs-write | TF | N | Y | **no** |
| 37 | lremovexattr | path | fs-write | TF | N | Y | **no** |
| 38 | fremovexattr | fd | fs-write (fd path) | **TD only** | N | Y | **no** |
| 39 | access | path | fs-access | TF | J | Y | yes |
| 40 | faccessat | dirfd+path | fs-access | TF | J | Y | yes |
| 41 | faccessat2 | dirfd+path | fs-access | TF | J | Y | yes |
| 42 | stat | path | fs-access | TF | J | Y | yes |
| 43 | lstat | path | fs-access (nofollow) | TF | J | Y | yes |
| 44 | newfstatat | dirfd+path | fs-access (`"" + AT_EMPTY_PATH` = fd) | TF | J | Y | yes |
| 45 | statx | dirfd+path | fs-access (same `AT_EMPTY_PATH` rule) | TF | J | Y | yes |
| 46 | readlink | path | fs-access (nofollow) | TF | J (`fs.readlink`, `fs.realpath`),B | Y | **no** (X1) |
| 47 | readlinkat | dirfd+path | fs-access (nofollow) | TF | J/B | Y | **no** |
| 48 | statfs | path | fs-access | TF | J (`fs.statfs`),B (`df`,`stat -f`) | Y | **no** |
| 49 | fstatfs | fd | fs-access (fd path) | **TD only** | B (`df`, `stat -f`) | Y | **no** |
| 50 | getxattr | path | fs-access | TF | N | Y | **no** |
| 51 | lgetxattr | path | fs-access | TF | N | Y | **no** |
| 52 | fgetxattr | fd | fs-access (fd path) | **TD only** | N | Y | **no** |
| 53 | listxattr | path | fs-access | TF | N | Y | **no** |
| 54 | llistxattr | path | fs-access | TF | N | Y | **no** |
| 55 | flistxattr | fd | fs-access (fd path) | **TD only** | N | Y | **no** |
| 56 | inotify_add_watch | fd+path | fs-access (the path argument) | TF | J (`fs.watch`) | Y | **no** (X1) |
| 57 | fanotify_mark | fd+dirfd+path | fs-access | TF | N | E (needs fanotify_init) | **no** |
| 58 | name_to_handle_at | dirfd+path | fs-access | TF | N | Y | **no** |
| 59 | open_by_handle_at | mount fd + handle | fs-access (fd path) | **TD only** | N | E (CAP_DAC_READ_SEARCH) | **no** |
| 60 | **chdir** | path | **fs-access**, as well as the cwd update | TF | J (`process.chdir`) | Y | traced, **not mapped** (see A7) |
| 61 | fchdir | fd | cwd update; fs-access of the fd path | **TD only** | N | Y | traced, not mapped as access |
| 62 | chroot | path | fs-access | TF | B (`chroot`) | E | **no** |
| 63 | mount | path×2 | fs-write (target); source = fs-access | TF | B (`mount`) | E | **no** |
| 64 | umount2 | path | fs-write | TF | B (`umount`) | E | **no** |
| 65 | pivot_root | path×2 | fs-write | TF | B (`pivot_root`) | E | **no** |
| 66 | swapon | path | fs-write (it takes over the file) | TF | B (`swapon`) | E | **no** |
| 67 | swapoff | path | fs-write | TF | B (`swapoff`) | E | **no** |
| 68 | acct | path | fs-write (it appends to the file) | TF | N | E | **no** |
| 69 | quotactl | path (special) | fs-write | TF | N | E | **no** |
| 70 | uselib | path | fs-access | TF | N (ENOSYS on most kernels) | Y | **no** |
| 71 | open_tree | dirfd+path | fs-access | TF | N | E | **no** |
| 72 | move_mount | dirfd+path×2 | fs-write | TF | N | E | **no** |
| 73 | fsconfig | fd + path value | fs-access | TF | N | E | **no** |
| 74 | fspick | dirfd+path | fs-access | TF | N | E | **no** |
| 75 | mount_setattr | dirfd+path | fs-write | TF | N | E | **no** |
| 76 | execve | path | exec (existing handling) | TF | J | Y | yes |
| 77 | execveat | dirfd+path / fd | exec; fd form already opaque (`trace.js:247`) | TF | N | Y | yes |
| 78 | getcwd | — (output only) | none: no input path | TF | J | Y | **exclude**: returns a path and takes none |

**Network calls that carry a filesystem path** (unix `sun_path`) are already traced and mapped at a075bd1 (`trace.js:301-327`): `connect`, `sendto`, `sendmsg` → net-unix (fs-access); `bind` → net-listen (f). They stay as they are. The guard test should include `connect` and `bind` so a later edit can't drop them.

## 2. Calls strace 6.1 cannot see (no name, no number)

Kernel 6.18 implements these, and they take a path or a path fd. strace 6.1 rejects them (S-B). There is no glibc 2.36 wrapper, so they are reachable from **N** (native addon) only, never from **J** or **B**.

| Syscall (nr) | Class | Kind | Since |
|---|---|---|---|
| cachestat (451) | fd | fs-access (page-cache probe of an opened file) | 6.5 |
| **fchmodat2 (452)** | dirfd+path | fs-write | 6.6 |
| statmount (457) / listmount (458) | mount id | none: no path; mount information only | 6.8 |
| **setxattrat (463)** / **removexattrat (466)** | dirfd+path | fs-write | 6.13 |
| **getxattrat (464)** / **listxattrat (465)** | dirfd+path | fs-access | 6.13 |
| **open_tree_attr (467)** | dirfd+path | fs-access | 6.15 |
| **file_getattr (468)** / **file_setattr (469)** | dirfd+path | fs-access / fs-write | 6.17 |

**Finding A2 (for the implementer and auditor).** No `-e trace=` set on strace 6.1 can include these.
- Through a native addon, they are a **trace gap beyond L-13**: L-13 covers env reads only.
- Whether Docker's default seccomp profile allows each of them is **not verified**. Moby added fchmodat2 to its default profile; the xattrat and file_*attr calls are newer than most profiles.
- **Fail-closed options. The implementer decides with evidence:**
  - (i) a newer strace in the tracer image (Debian 13 ships 6.13+; still none for 466+);
  - (ii) `-e trace=!<noise>` negated sets, *if* strace 6.1 traces out-of-table numbers under negation (to be checked);
  - (iii) a seccomp profile for the sandbox that denies `nr >= 451` with EPERM (no effect, but the attempt stays invisible);
  - (iv) record it as a limitation: native addon + syscall ≥ 451, the same class as L-13.
- I will try to build a native fixture in A1-2 **only if** it can be done without a compiler or image download. Otherwise this stays a paper finding.

## 3. Excluded on purpose (with reason)

- **fd-only reads with no path effect** (`read`, `pread*`, `mmap`, `getdents64`, `sendfile`, `splice`, `copy_file_range`, `fstat`): the fd comes from an `open`/`openat` that is itself traced and mapped. What matters is the open.
- **`ioctl`** (FICLONE etc.): its dest fd also comes from a traced open.
- **`landlock_add_rule`**: takes an O_PATH fd from a traced open and restricts the caller only.
- **`quotactl_fd`**: needs CAP_SYS_ADMIN; its fd comes from a traced open.
- **`memfd_create` + `execveat`**: already opaque exec (`trace.js:247`).
- **`mq_open`**: the mqueue namespace, not filesystem paths.
- **`getcwd`**: output only.
- **io_uring path ops** (`IORING_OP_OPENAT/STATX/UNLINKAT/RENAMEAT/MKDIRAT/SYMLINKAT/LINKAT/…`): invisible to ptrace by design. This is already L-11; the auditor probes it at acceptance.
- **`inotify_init*`, `inotify_rm_watch`, `fanotify_init`**: no path.

## 4. Extra mapping findings for F1b (paper)

- **A7 · `chdir` is traced but not mapped as an access.**
  - At a075bd1, `trace.js:281-284` only updates cwd.
  - `process.chdir('/home/qp/.ssh')` probes the credential directory (ENOENT vs ENOTDIR vs success). It produces **no observation** if nothing relative follows. That makes it a pure-JS rule (b) miss that yields `install`.
  - Same for `fchdir` and `chroot` on a credential path.
  - **Expected:** chdir/fchdir/chroot → fs-access of the target as well as the cwd update. To be reproduced on the candidate in A1-2.
- **A8 · `utimensat` with a NULL path** (`fs.futimes`, glibc `futimens`), and every fd-only call:
  - strace prints `utimensat(3</etc/hostname>, NULL, …)` or `fchown(3</etc/passwd>, …)`.
  - `pathArgs` (`trace.js:36`) finds **no quoted string**, so a mapping through `at(0)` gives `path: null`.
  - **The fd-only calls (#6, 7, 24, 28, 35, 38, 49, 52, 55, 59, 61) need an fd-path helper that reads the `-y` annotation `N</path>` of argument 0.** Without it, two things go wrong:
    - **writes:** `observe.js:127` turns a null path into `unresolved:null`, and rule (a) fires. Fail-closed, but it **over-condemns** any legitimate fd write inside `/work` (for example `tar`'s `fchown`/`futimens` on extracted files). Watch this on express/fastify.
    - **accesses:** a null path fails `paths-resolved` (`observe.js:140`), so the verdict is `review`, not `install`. Also fail-closed, but a regression for clean packages.
  - The helper must fail closed when the annotation is missing, as today.
- **A9 · keep the fail-closed property for unresolved writes:** `observe.js:127` adds `unresolved:<raw>` as the fs-write path, and rule (a) fires because it is outside the allowed roots. The implementer should keep that for every new fs-write mapping, and add a test for it.
- **A10 · `execve` of a forbidden path** (`spawn('/home/qp/.ssh/id_rsa')`, `spawn('/var/run/docker.sock')`): exec events never reach the rule (b) input (`observe.js:135`). I will check in A1-2 whether this yields install or review.

## 5. Machine-readable list (for the F1c guard test)

Format: `name<TAB>kind`. Here `exec` and `cwd+access` are kinds the guard should accept for those calls. Section 2 calls are **not** listed, because strace 6.1 cannot name them; the guard should state that limit.

```
open	by-flags
openat	by-flags
openat2	by-flags
creat	fs-write
truncate	fs-write
ftruncate	fs-write
fallocate	fs-write
mkdir	fs-write
mkdirat	fs-write
mknod	fs-write
mknodat	fs-write
rmdir	fs-write
unlink	fs-write
unlinkat	fs-write
rename	fs-write
renameat	fs-write
renameat2	fs-write
link	fs-write
linkat	fs-write
symlink	fs-write
symlinkat	fs-write
chmod	fs-write
fchmodat	fs-write
fchmod	fs-write
chown	fs-write
lchown	fs-write
fchownat	fs-write
fchown	fs-write
utime	fs-write
utimes	fs-write
futimesat	fs-write
utimensat	fs-write
setxattr	fs-write
lsetxattr	fs-write
fsetxattr	fs-write
removexattr	fs-write
lremovexattr	fs-write
fremovexattr	fs-write
mount	fs-write
umount2	fs-write
pivot_root	fs-write
swapon	fs-write
swapoff	fs-write
acct	fs-write
quotactl	fs-write
move_mount	fs-write
mount_setattr	fs-write
access	fs-access
faccessat	fs-access
faccessat2	fs-access
stat	fs-access
lstat	fs-access
newfstatat	fs-access
statx	fs-access
readlink	fs-access
readlinkat	fs-access
statfs	fs-access
fstatfs	fs-access
getxattr	fs-access
lgetxattr	fs-access
fgetxattr	fs-access
listxattr	fs-access
llistxattr	fs-access
flistxattr	fs-access
inotify_add_watch	fs-access
fanotify_mark	fs-access
name_to_handle_at	fs-access
open_by_handle_at	fs-access
chroot	fs-access
uselib	fs-access
open_tree	fs-access
fsconfig	fs-access
fspick	fs-access
chdir	cwd+access
fchdir	cwd+access
execve	exec
execveat	exec
connect	net-unix
bind	net-listen
```

**Count:** 79 entries = the 67 `TF` names in S-A (60 from `x86_64/syscallent.h`, 7 from `syscallent-common.h`), minus `getcwd`, plus 11 TD-only fd calls, plus `connect` and `bind`. Checked mechanically: `comm` of this block against the TF set gives exactly `getcwd` missing and these 13 extra: bind, connect, fallocate, fchdir, fchmod, fchown, fgetxattr, flistxattr, fremovexattr, fsetxattr, fstatfs, ftruncate, open_by_handle_at.

**Check for the implementer:** `%file` on strace 6.1 = those 67 TF names. `%file` alone misses rows 6, 7, 24, 28, 35, 38, 49, 52, 55, 59 and 61 (fchdir is already traced at a075bd1). Those are the explicit extras. Socket calls are already traced.
