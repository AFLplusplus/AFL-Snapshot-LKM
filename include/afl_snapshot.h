#ifndef AFL_SNAPSHOT_H
#define AFL_SNAPSHOT_H

#include <linux/ioctl.h>

#define AFL_SNAPSHOT_FILE_NAME "/dev/afl_snapshot"

#define AFL_SNAPSHOT_IOCTL_MAGIC 44313

#define AFL_SNAPSHOT_IOCTL_DO _IO(AFL_SNAPSHOT_IOCTL_MAGIC, 1)
#define AFL_SNAPSHOT_IOCTL_CLEAN _IO(AFL_SNAPSHOT_IOCTL_MAGIC, 2)
#define AFL_SNAPSHOT_EXCLUDE_VMRANGE \
  _IOR(AFL_SNAPSHOT_IOCTL_MAGIC, 3, struct afl_snapshot_vmrange_args *)
#define AFL_SNAPSHOT_INCLUDE_VMRANGE \
  _IOR(AFL_SNAPSHOT_IOCTL_MAGIC, 4, struct afl_snapshot_vmrange_args *)
#define AFL_SNAPSHOT_IOCTL_TAKE _IOR(AFL_SNAPSHOT_IOCTL_MAGIC, 5, int)
#define AFL_SNAPSHOT_IOCTL_RESTORE _IO(AFL_SNAPSHOT_IOCTL_MAGIC, 6)

// Trace new mmaped ares and unmap them on restore.
#define AFL_SNAPSHOT_MMAP 1
// Do not snapshot any page (by default all writeable not-shared pages
// are shanpshotted.
#define AFL_SNAPSHOT_BLOCK 2
// Snapshot file descriptor state, close newly opened descriptors
#define AFL_SNAPSHOT_FDS 4
// Snapshot registers state
#define AFL_SNAPSHOT_REGS 8
// Perform a restore when exit_group is invoked
#define AFL_SNAPSHOT_EXIT 16
// TODO(andrea) allow not COW snapshots (high perf on small processes)
// Disable COW, restore all the snapshotted pages
#define AFL_SNAPSHOT_NOCOW 32
// Do not snapshot Stack pages
#define AFL_SNAPSHOT_NOSTACK 64

struct afl_snapshot_vmrange_args {

  unsigned long start, end;

};

#endif

