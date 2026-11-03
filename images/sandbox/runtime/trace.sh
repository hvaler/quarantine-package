#!/bin/sh
# Tracer container entry (root, CAP_SYS_PTRACE only, --pid container:<sandbox>,
# --network none). Attaches to the sandbox's pid 1 and follows every child.
# The strace record stream is this container's stdout.
exec strace -f -qq -tt -s 200 -o /proc/self/fd/1 \
  -e trace=execve,clone,clone3,fork,vfork,chdir,fchdir,openat,open,creat,mkdir,mkdirat,rename,renameat,renameat2,unlink,unlinkat,rmdir,symlink,symlinkat,link,linkat,truncate,chmod,fchmodat,access,faccessat,faccessat2,newfstatat,statx,stat,lstat,socket,connect,sendto,sendmsg,sendmmsg \
  -e signal=none \
  -p 1
