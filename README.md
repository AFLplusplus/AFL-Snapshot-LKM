# AFL++ Snapshot LKM

A Linux Kernel Module that implements a fast snapshot mechanism for fuzzing.

Based on https://github.com/sslab-gatech/perf-fuzz.

Written and maintained by Nick "kallsyms" Gregory and Andrea Fioraldi.

## Why?

fork() is slow and we want to fuzz faster.

If your application is stateful, give a look to persistent mode before.
