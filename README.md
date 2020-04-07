# AFL++ Snapshot LKM

A Linux Kernel Module that implements a fast snapshot mechanism for fuzzing.

Based on https://github.com/sslab-gatech/perf-fuzz.

Written and maintained by Nick "kallsyms" Gregory and Andrea Fioraldi.

## Why?

fork() is slow and we want to fuzz faster.

If your application is stateful, give a look to persistent mode before.

## Build

Just make.

## Usage

Load it using load.sh, unload it using unload.sh.

While the module is loaded, AFL++ can detect it and automatically switch from fork() to snapshot mode.
