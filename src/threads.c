#include "hook.h"
#include "debug.h"
#include "task_data.h"
#include "snapshot.h"

static struct task_struct *next_tid(struct task_struct *start) {

  struct task_struct *pos = NULL;
  rcu_read_lock();
  if (pid_alive(start)) {

    pos = next_thread(start);
    if (thread_group_leader(pos))
      pos = NULL;
    else
      get_task_struct(pos);

  }

  rcu_read_unlock();
  put_task_struct(start);
  return pos;

}

/* void take_threads_snapshot(struct task_data * data) {

  struct task_struct* t = get_task_struct(data->tsk->group_leader);
  while (t) {

    if (t != data->tsk)
      add_snapshot_thread(data, t);
    t = next_tid(t);

  }

} */

void recover_threads_snapshot(struct task_data *data) {

  struct task_struct *t = get_task_struct(data->tsk->group_leader);
  while (t) {

    if (t != data->tsk) send_sig(SIGKILL, t, 1);
    t = next_tid(t);

  }

}

/* void clean_thareds_snapshot(struct task_data * data) {

} */

