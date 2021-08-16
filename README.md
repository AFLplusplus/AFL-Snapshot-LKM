# AFL++ Snapshot LKM

A Linux Kernel Module that implements a fast snapshot mechanism for fuzzing.
Written by Andrea Fioraldi <andreafioraldi@gmail.com>.
First port to a LKM written by Nick "kallsyms" Gregory.
Originally inspired by https://github.com/sslab-gatech/perf-fuzz.

**!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!**

**PLEASE NOTE**: Due to syscall hooking and the never ending changes in the kernel we are unable to maintain it as we are busy working on libafl. If you would like to take over the development, just create an issue and let us start a discussion. We still accept pull requests in the mean time.

**!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!**

## Why?

fork() is slow and we want to fuzz faster.
The speed gain currently varies between 20-360% depending on the target.

Persistent mode in llvm_mode will give you a better performance bump though,
however adding this snapshot module will still be a small improvement.

## Speed comparison

|project|program|exec/s with snapshot|exec/s normal|speed factor|
|:-----:|:-----:|:------:|:-----:|:----------:|
|afl++|test-instr|25k|8234|x3|
|unrar|unrar|7044|1938|x3.6|
|jpeg|djpeg|1911|1502|x1.3|
|tiff|thumbnail|5058|3114|x1.6|
|libxml|xmllint|7835|3450|x2.3|
|afl++|test_persistent_new|106k|89k|x1.2|

## Usage

!WARNING! This LKM is in alpha testing state. DO NOT LOAD IT ON YOU'RE REAL MACHINE WITHOUT TESTING!!!
!DANGER!! It can crash the kernel and you will lose all you're unsaved data (open tabs, notes, etc.)

At the moment it builds and run ok on at least:
Debian buster Linux stand 4.19.160 #2 SMP Mon Dec 28 11:58:39 EET 2020 x86_64 GNU/Linux
Debian bullseye Linux l0c4lh05t 5.10.24 #8 SMP Sun Jun 13 01:31:09 EEST 2021 x86_64 GNU/Linux
Both on real hardware and under qemu vm.


While the module is loaded, [AFL++](https://github.com/AFLplusplus/AFLplusplus)
will detect it and automatically switch from fork() to snapshot mode.
(Note: currently llvm_mode only, available from v2.66d/v2.67c onwards)

## API

```c
int afl_snapshot_init();
```

This is the initialization routine that opens the ioctl device.

```c
void afl_snapshot_exclude_vmrange(void* start, void* end);
```

Add a range of addresses (with page granularity) in the blocklist.
These pages will not be snapshotted.

```c
void afl_snapshot_include_vmrange(void* start, void* end);
```

Add a range of addresses (with page granularity) in the allowlist.
These pages will be snapshotted.

```c
int afl_snapshot_take(int config);
```

Take the snapshot in this program point. Returns 1 when the snapshot is taken, if there is already one snapshot does nothing and return 0.

The config mask can have the following options OR-ed:

+ `AFL_SNAPSHOT_MMAP` Trace new mmaped ares and unmap them on restore.
+ `AFL_SNAPSHOT_BLOCK` Do not snapshot any page (by default all writeable not-shared pages are shanpshotted.
+ `AFL_SNAPSHOT_FDS` Snapshot file descriptor state, close newly opened descriptors
+ `AFL_SNAPSHOT_REGS` Snapshot registers state
+ `AFL_SNAPSHOT_EXIT` Perform a restore when exit_group is invoked
+ `AFL_SNAPSHOT_NOSTACK` Do not snapshot Stack pages

```c
void afl_snapshot_restore(void);
```

Restore the snapshot. If registers are snapshotted, this function never returns.

```c
void afl_snapshot_clean(void);
```

Remove the snapshot, you can not call `afl_snapshot_take` in another program point.

### TODOs

 + support for multithreaded applications
 + file descriptors state restore (lseek)
 + switch from ftrace to jmp for hooking (faster)
 + add support of tasks snapshot control from other process (can be achived via find_vpid(pid))

### Chandgelog

v1.1.0:
+	Add ftrace support
+	Add reflective symbols extractor (work on 5.10+)
+	Fix horrible bug which fault on do_exit_group() because of invalid return size (long/int) -- try make it universal (reflective)
+	Minimal security fixes like do NOT trying to insert LKM after building...

v1.0.0:
+	Initial release
