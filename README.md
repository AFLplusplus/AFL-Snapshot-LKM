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

### TODOs

 + switch from kprobe to ftrace for hooking (faster)
 + implement pages blacklist/whitelist
 + API for fine grained snapshotting (e.g. add a new VMA outside the whitelist)
 + support for multithreaded applications
