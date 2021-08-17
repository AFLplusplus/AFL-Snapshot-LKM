#ifndef __AFL_SNAPSHOT_TASK_DATA_H__
#define __AFL_SNAPSHOT_TASK_DATA_H__

#include "snapshot.h"
#include <linux/list.h>
#include <linux/sched.h>
#include "gears.h"

struct vmrange_node {

  unsigned long start;
  unsigned long end;

  struct vmrange_node *next;

};
#if 0
POSIX.1 also requires that threads share a range of other attributes (i.e., these attributes are process-wide rather than per-thread):

-  process ID

-  parent process ID

-  process group ID and session ID

-  controlling terminal

-  user and group IDs

-  open file descriptors

-  record locks (see fcntl(2))

-  signal dispositions

-  file mode creation mask (umask(2))

-  current directory (chdir(2)) and root directory (chroot(2))

-  interval timers (setitimer(2)) and POSIX timers (timer_create(2))

-  nice value (setpriority(2))

-  resource limits (setrlimit(2))

-  measurements of the consumption of CPU time (times(2)) and resources (getrusage(2))

As well as the stack, POSIX.1 specifies that various other attributes are distinct for each thread, including:

-  thread ID (the pthread_t data type)

-  signal mask (pthread_sigmask(3))

-  the errno variable

-  alternate signal stack (sigaltstack(2))

-  real-time scheduling policy and priority (sched(7))

The following Linux-specific features are also per-thread:

-  capabilities (see capabilities(7))

-  CPU affinity (sched_setaffinity(2))

#endif

struct thread_data {

  // what task_struct is this for?
  const struct task_struct *tsk;          // ptr to task_struct of certain thread
  const struct pid *pid;                  // ptr to pid struct of certain thread
  const struct mm_struct *mm;             // ptr to mm struct of certain thread
  const struct vm_area_struct *vma;       // ptr to vma struct of certain thread
  void *thread_pid_field_backup;          // backup of pointer needed to restore thread visibility in the system
  struct pt_regs regs;                    // backup of cpu-state per each thread

};

struct task_data {

  int threads_nr;                          // count of all process threads at the moment of snapshoting
  struct task_struct *leader;              // main task, present all process live
  long  config;                            // configuration flags captured from user request

  struct snapshot ss;
  unsigned long * snapshot_open_fds;
  struct vmrange_node *allowlist, *blocklist;

  struct list_head list;                   // will have sense when we do snapshots of few process
  struct rcu_head  rcu;                    // will have sense when we do snapshots of few process

  struct thread_data threads[];            // vector of all threads pf process at the moment of snapshotting

};

struct task_data *get_task_data(const struct task_struct *tsk);
struct task_data *ensure_task_data(const struct task_struct *tsk);
void              remove_task_data(struct task_data *data);

static inline void clear_snapshot(struct task_data *data) {

  data->ss.status &= ~SNAPSHOT_MADE;

}

static inline void set_had_snapshot(struct task_data *data) {

  data->ss.status |= SNAPSHOT_HAD;

}

static inline void set_snapshot(struct task_data *data) {

  data->ss.status |= SNAPSHOT_MADE;

}

static inline bool have_snapshot(struct task_data *data) {

  return (data->ss.status & SNAPSHOT_MADE) != 0;

}

static inline bool had_snapshot(struct task_data *data) {

  return (data->ss.status & SNAPSHOT_HAD) != 0;

}

#endif

