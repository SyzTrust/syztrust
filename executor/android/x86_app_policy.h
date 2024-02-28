// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// File autogenerated by genseccomp.py from Android Q - edit at your peril!!

const struct sock_filter x86_app_filter[] = {
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 0, 0, 120),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 140, 59, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 75, 29, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 41, 15, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 24, 7, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 10, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 8, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 7, 113, 112), //restart_syscall|exit|fork|read|write|open|close
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 9, 112, 111), //creat
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 19, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 13, 110, 109), //unlink|execve|chdir
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 21, 109, 108), //lseek|getpid
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 33, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 26, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 25, 106, 105), //getuid
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 27, 105, 104), //ptrace
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 36, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 34, 103, 102), //access
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 40, 102, 101), //sync|kill|rename|mkdir
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 60, 7, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 54, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 45, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 44, 98, 97), //dup|pipe|times
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 46, 97, 96), //brk
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 57, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 56, 95, 94), //ioctl|fcntl
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 58, 94, 93), //setpgid
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 66, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 63, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 61, 91, 90), //umask
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 65, 90, 89), //dup2|getppid
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 68, 89, 88), //setsid|sigaction
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 114, 15, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 94, 7, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 85, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 77, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 76, 84, 83), //setrlimit
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 79, 83, 82), //getrusage|gettimeofday
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 90, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 86, 81, 80), //readlink
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 93, 80, 79), //mmap|munmap|truncate
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 102, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 96, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 95, 77, 76), //fchmod
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 98, 76, 75), //getpriority|setpriority
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 104, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 103, 74, 73), //socketcall
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 106, 73, 72), //setitimer|getitimer
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 125, 7, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 118, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 116, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 115, 69, 68), //wait4
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 117, 68, 67), //sysinfo
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 122, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 121, 66, 65), //fsync|sigreturn|clone
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 123, 65, 64), //uname
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 136, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 131, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 126, 62, 61), //mprotect
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 134, 61, 60), //quotactl|getpgid|fchdir
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 137, 60, 59), //personality
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 265, 29, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 207, 15, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 183, 7, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 168, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 150, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 149, 54, 53), //_llseek|getdents|_newselect|flock|msync|readv|writev|getsid|fdatasync
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 164, 53, 52), //mlock|munlock|mlockall|munlockall|sched_setparam|sched_getparam|sched_setscheduler|sched_getscheduler|sched_yield|sched_get_priority_max|sched_get_priority_min|sched_rr_get_interval|nanosleep|mremap
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 172, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 169, 51, 50), //poll
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 182, 50, 49), //prctl|rt_sigreturn|rt_sigaction|rt_sigprocmask|rt_sigpending|rt_sigtimedwait|rt_sigqueueinfo|rt_sigsuspend|pread64|pwrite64
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 199, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 190, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 188, 47, 46), //getcwd|capget|capset|sigaltstack|sendfile
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 198, 46, 45), //vfork|ugetrlimit|mmap2|truncate64|ftruncate64|stat64|lstat64|fstat64
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 205, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 203, 44, 43), //getuid32|getgid32|geteuid32|getegid32
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 206, 43, 42), //getgroups32
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 245, 7, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 218, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 211, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 210, 39, 38), //fchown32|setresuid32|getresuid32
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 212, 38, 37), //getresgid32
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 224, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 222, 36, 35), //mincore|madvise|getdents64|fcntl64
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 244, 35, 34), //gettid|readahead|setxattr|lsetxattr|fsetxattr|getxattr|lgetxattr|fgetxattr|listxattr|llistxattr|flistxattr|removexattr|lremovexattr|fremovexattr|tkill|sendfile64|futex|sched_setaffinity|sched_getaffinity|set_thread_area
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 254, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 252, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 250, 32, 31), //io_setup|io_destroy|io_getevents|io_submit|io_cancel
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 253, 31, 30), //exit_group
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 264, 30, 29), //epoll_create|epoll_ctl|epoll_wait|remap_file_pages|set_tid_address|timer_create|timer_settime|timer_gettime|timer_getoverrun|timer_delete
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 322, 15, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 295, 7, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 284, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 272, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 271, 25, 24), //clock_gettime|clock_getres|clock_nanosleep|statfs64|fstatfs64|tgkill
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 273, 24, 23), //fadvise64_64
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 291, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 285, 22, 21), //waitid
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 294, 21, 20), //inotify_init|inotify_add_watch|inotify_rm_watch
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 313, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 300, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 299, 18, 17), //openat|mkdirat|mknodat|fchownat
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 312, 17, 16), //fstatat64|unlinkat|renameat|linkat|symlinkat|readlinkat|fchmodat|faccessat|pselect6|ppoll|unshare|set_robust_list
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 318, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 317, 15, 14), //splice|sync_file_range|tee|vmsplice
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 321, 14, 13), //getcpu|epoll_pwait|utimensat
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 351, 7, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 344, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 340, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 337, 10, 9), //timerfd_create|eventfd|fallocate|timerfd_settime|timerfd_gettime|signalfd4|eventfd2|epoll_create1|dup3|pipe2|inotify_init1|preadv|pwritev|rt_tgsigqueueinfo|perf_event_open
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 341, 9, 8), //prlimit64
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 346, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 345, 7, 6), //syncfs
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 349, 6, 5), //setns|process_vm_readv|process_vm_writev
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 375, 3, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 358, 1, 0),
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 357, 3, 2), //sched_setattr|sched_getattr|renameat2|seccomp|getrandom|memfd_create
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 359, 2, 1), //execveat
BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 380, 1, 0), //membarrier|mlock2|copy_file_range|preadv2|pwritev2
BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
};

#define x86_app_filter_size (sizeof(x86_app_filter) / sizeof(struct sock_filter))
