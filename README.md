# AFL++ Snapshot LKM

A Linux Kernel Module that implements a fast snapshot mechanism for fuzzing.

Based on https://github.com/sslab-gatech/perf-fuzz.

Written and maintained by Nick "kallsyms" Gregory and Andrea Fioraldi.

## Why?

fork() is slow and we want to fuzz faster.
The speed gain currently varies between 1-20% depending on the taget, but
this is WIP to be faster.

If your application is stateful, persistent mode in llvm_mode will give you
a better performance though.

## Build

Just `make`.

## Usage

Load it using `./load.sh`, unload it using `./unload.sh`.

While the module is loaded, [AFL++](https://github.com/AFLplusplus/AFLplusplus)
will detect it and automatically switch from fork() to snapshot mode.
(Note: currently llvm_mode only, available from v2.63c onwards)

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

 + switch from kprobe to ftrace for hooking (faster)
 + support for multithreaded applications
