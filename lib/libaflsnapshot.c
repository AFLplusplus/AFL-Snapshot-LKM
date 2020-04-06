#include "libaflsnapshot.h"

#include <sys/ioctl.h>
#include "afl_snapshot.h"

static int dev_fd;

int afl_snapshot_init() {

  dev_fd = open(AFL_SNAPSHOT_FILE_NAME, 0);
  return dev_fd;

}

int afl_snapshot_do(void) {

  return ioctl(dev_fd, AFL_SNAPSHOT_IOCTL_DO);

}

int afl_snapshot_clean(void) {

  return ioctl(dev_fd, AFL_SNAPSHOT_IOCTL_CLEAN);

}

