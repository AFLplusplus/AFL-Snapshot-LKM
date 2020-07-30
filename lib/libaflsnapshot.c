#include "libaflsnapshot.h"

#include <sys/ioctl.h>
#include <stdlib.h>
#include <fcntl.h>

static int dev_fd;

int afl_snapshot_init() {

  dev_fd = open(AFL_SNAPSHOT_FILE_NAME, 0);
  return dev_fd;

}

void afl_snapshot_exclude_vmrange(void *start, void *end) {

  struct afl_snapshot_vmrange_args args = {(unsigned long)start,
                                           (unsigned long)end};
  ioctl(dev_fd, AFL_SNAPSHOT_EXCLUDE_VMRANGE, &args);

}

void afl_snapshot_include_vmrange(void *start, void *end) {

  struct afl_snapshot_vmrange_args args = {(unsigned long)start,
                                           (unsigned long)end};
  ioctl(dev_fd, AFL_SNAPSHOT_INCLUDE_VMRANGE, &args);

}

int afl_snapshot_take(int config) {

  return ioctl(dev_fd, AFL_SNAPSHOT_IOCTL_TAKE, config);

}

int afl_snapshot_do(void) {

  return ioctl(dev_fd, AFL_SNAPSHOT_IOCTL_DO);

}

void afl_snapshot_restore(void) {

  ioctl(dev_fd, AFL_SNAPSHOT_IOCTL_RESTORE);

}

void afl_snapshot_clean(void) {

  ioctl(dev_fd, AFL_SNAPSHOT_IOCTL_CLEAN);

}

