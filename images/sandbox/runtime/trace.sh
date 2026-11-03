#!/bin/sh
# Tracer container entry (root, CAP_SYS_PTRACE only, --pid container:<sandbox>,
# --network none). Attaches to the sandbox's pid 1 and follows every child.
# The strace record stream is this container's stdout.
# -y prints the path behind every fd argument (dirfds included), so
# dirfd-relative paths resolve; -s 4096 keeps whole paths (PATH_MAX).
# abbrev=!execve prints the full envp of every exec, so instrumentation
# (NODE_OPTIONS) is checked from the trace, not from package-writable stdout.
exec strace -f -qq -tt -y -s 4096 -e 'abbrev=!execve' -o /proc/self/fd/1 \
  -e trace=execve,clone,clone3,fork,vfork,chdir,fchdir,openat,open,creat,mkdir,mkdirat,rename,renameat,renameat2,unlink,unlinkat,rmdir,symlink,symlinkat,link,linkat,truncate,chmod,fchmodat,access,faccessat,faccessat2,newfstatat,statx,stat,lstat,socket,connect,sendto,sendmsg,sendmmsg \
  -e signal=none \
  -p 1
