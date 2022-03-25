# iTrustee TEE support for libc

------

| Header      | Supported | Comments                                                     |
| ----------- | --------- | ------------------------------------------------------------ |
| alloca.h    | Yes       | -                                                            |
| arpa/inet.h | Partial   | Unsupported functions: inet_neta(), inet_net_ntop(), inet_net_pton(), inet_nsap_addr(), inet_nsap_ntoa() |
| assert.h    | Yes       | -                                                            |
| ctype.h     | Partial   | Unsupported functions: isctype()                             |
| dlfcn.h     | Partial   | Unsupported functions: dlmopen(), dlvsym(), dladdr1()        |
| errno.h     | Yes       | -                                                            |
| fcntl.h     | Yes       | -                                                            |
| inttypes.h  | Partial   | supported functions: imaxabs(), imaxdiv(), strtoimax(), strtoumax(), wcstoimax(), wcstoumax() |
| locale.h    | Yes       | -                                                            |
| malloc.h    | Partial   | supported functions: malloc(), calloc(), realloc(), free(), valloc(), memalign(), malloc_usable_size() |
| netdb.h     | Partial   | Unsupported functions: gethostent_r(), getnetent_r(), getnetbyaddr_r(), getnetbyname_r(), getservent_r(), getprotoent_r(), getprotobyname_r(), getprotobynumber_r(), setnetgrent endnetgrent(), getnetgrent innetgr(), getnetgrent_r(), rcmd(), rcmd_af(), rexec(), rexec_af(), ruserok(), ruserok_af(), iruserok(), iruserok_af(), rresvport(), rresvport_af(), getaddrinfo_a(), gai_suspend gai_error(), gai_cancel() |
| poll.h      | Partial   | Unsupported functions: ppoll()                               |
| pthread.h   | Partial   | Unsupported functions: pthread_attr_getstackaddr(), pthread_attr_setstackaddr(), pthread_attr_setaffinity_np(), pthread_attr_getaffinity_np(), pthread_getname_np(), pthread_yield(), pthread_mutex_consistent_np(), pthread_mutexattr_getrobust_np(), pthread_mutexattr_setrobust_np(), pthread_rwlockattr_getkind_np(), pthread_rwlockattr_setkind_np() |
| sched.h     | Yes       | -                                                            |
| semaphore.h | Yes       | -                                                            |
| setjmp.h    | Yes       | -                                                            |
| signal.h    | Partial   | Unsupported functions: sysv_signal(), ssignal(), gsignal(), sigblock(), sigsetmask(), siggetmask(), sigreturn(), sigstack() |
| stdio.h     | Partial   | Unsupported functions: renameat2(), tmpnam_r(), fcloseall(), obstack_printf(), obstack_vprintf(),  uflow(), overflow() |
| stdlib.h    | Partial   | Unsupported functions: strtof16(), strtof32(),  strtof64(), strtof128(), strtof32x(), strtof64x(), strtof128x(), strtoq(), strtouq(), strfromd(), strfromf(),  strfroml(), strfromf16(), strfromf32(), strfromf64(), strfromf128(), strfromf32x(), strfromf64x(), strfromf128x(), strtol_l(), strtoul_l(), strtoll_l(), strtoull_l(), strtof16_l(), strtof32_l(), strtof64_l(), strtof128_l(), strtof32x_l(), strtof64x_l(), strtof128x_l(), random_r(), srandom_r(), initstate_r(), setstate_r(), drand48_r(), erand48_r(), lrand48_r(), nrand48_r(), mrand48_r(), jrand48_r(), srand48_r(), seed48_r(), lcong48_r(), reallocarray(), on_exit(), canonicalize_file_name(), qsort_r(), qecvt(), qfcvt(), qgcvt(), ecvt_r(), fcvt_r(), fcvt_r(), qfcvt_r(), rpmatch(), getpt(),ttyslot() |
| string.h    | Partial   | Unsupported functions: rawmemchr(), strfry(), memfrob()      |
| strings.h   | Yes       | -                                                            |
| time.h      | Partial   | Unsupported functions: strptime_l(), timelocal(), dysize(), timespec_get(), getdate_r() |
| unistd.h    | Partial   | Unsupported functions: lseek(), lseek64(), pread64(), pwrite64(), getwd(), group_member(), ttyslot(), setlogin(), revoke(), profil(), truncate64(), ftruncate64(), lockf(),  lockf64(), cuserid(), pthread_atfork() |
| wchar.h     | Partial   | Unsupported functions: wcschrnul(), wmempcpy(), wcstof16(), wcstof32(), wcstof64(), wcstof128(), wcstof32x(), wcstof64x(), wcstof128x(), wcstoq(), wcstouq(), wcstol_l(), wcstoul_l(), wcstod_l(), wcstof_l(), wcstold_l(),  wcstof16_l(), wcstof32_l(), wcstof64_l(), wcstof128_l(), wcstof32x_l(), wcstof64x_l(), wcstof128x_l() |
| wctype.h    | Yes       | -                                                            |