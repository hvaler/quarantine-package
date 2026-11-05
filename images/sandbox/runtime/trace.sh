#!/bin/sh
# Tracer container entry (root, CAP_SYS_PTRACE only, --pid container:<sandbox>,
# --network none). Attaches to the sandbox's pid 1 and follows every child.
# The strace record stream is this container's stdout.
# -y prints the path behind every fd argument (dirfds included), so
# dirfd-relative paths resolve; -s 4096 keeps whole paths (PATH_MAX).
# abbrev=!execve prints the full envp of every exec, so instrumentation
# (NODE_OPTIONS) is checked from the trace, not from package-writable stdout.
#
# Traced set (S6, L-19). Every name is explicit, so test/trace-coverage.test.js
# can check it against test/reference/REFERENCE-SYSCALLS.md:
#   process and cwd:  execve execveat clone clone3 fork vfork chdir fchdir
#   file (path):      strace 6.1's whole %file class except getcwd (it takes no
#                     path, it returns one), listed by name; see
#                     docs/TRACE-SET.md for the comparison with %file
#   file (fd only):   ftruncate fallocate fchmod fchown fsetxattr fremovexattr
#                     fstatfs fgetxattr flistxattr open_by_handle_at (the path
#                     comes from src/trace.js's fd table; -y is used when present)
#   fd table:         close close_range dup dup2 dup3 fcntl (repair 1: src/trace.js
#                     follows fd -> path itself, because this tracer, uid 0 with
#                     only CAP_SYS_PTRACE, cannot read /proc/<pid>/fd, so -y
#                     annotates AT_FDCWD but never a numeric fd)
#   network:          socket connect bind listen sendto sendmsg sendmmsg
# strace 6.1 cannot name syscalls above 450 (fchmodat2, *xattrat, open_tree_attr,
# file_getattr/file_setattr), so they are not traced: README limitation L-13.
exec strace -f -qq -tt -y -s 4096 -e 'abbrev=!execve' -o /proc/self/fd/1 \
  -e trace=execve,execveat,clone,clone3,fork,vfork,chdir,fchdir,open,openat,openat2,creat,mkdir,mkdirat,mknod,mknodat,rename,renameat,renameat2,unlink,unlinkat,rmdir,symlink,symlinkat,link,linkat,truncate,ftruncate,fallocate,chmod,fchmodat,fchmod,chown,lchown,fchownat,fchown,utime,utimes,futimesat,utimensat,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,getxattr,lgetxattr,fgetxattr,listxattr,llistxattr,flistxattr,access,faccessat,faccessat2,newfstatat,statx,stat,lstat,readlink,readlinkat,statfs,fstatfs,inotify_add_watch,fanotify_mark,name_to_handle_at,open_by_handle_at,chroot,acct,swapon,swapoff,uselib,quotactl,mount,umount2,pivot_root,open_tree,move_mount,fspick,fsconfig,mount_setattr,close,close_range,dup,dup2,dup3,fcntl,socket,connect,bind,listen,sendto,sendmsg,sendmmsg \
  -e signal=none \
  -p 1
