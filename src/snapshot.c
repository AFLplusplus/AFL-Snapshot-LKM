#include "hook.h"
#include "debug.h"
#include "task_data.h"
#include "snapshot.h"

int exit_hook(struct kprobe *p, struct pt_regs *regs) {

  clean_snapshot();

  return 0;

}

void initialize_snapshot(struct task_data *data, int config) {

  struct pt_regs *regs = task_pt_regs(current);

  data->config = config;

  if (!had_snapshot(data)) {

    set_had_snapshot(data);
    hash_init(data->ss.ss_page);

  }

  set_snapshot(data);
  // INIT_LIST_HEAD(&(data->ss.ss_mmap));
  data->ss.ss_mmap = NULL;

  // copy current regs context
  data->ss.regs = *regs;

  // copy current brk
  data->ss.oldbrk = current->mm->brk;

}

int take_snapshot(int config) {

  struct task_data *data = ensure_task_data(current);

  if (!have_snapshot(data)) {  // first execution

    initialize_snapshot(data, config);
    take_memory_snapshot(data);
    take_files_snapshot(data);

    return 1;

  }

  return 0;

}

void recover_state(struct task_data *data) {

  if (data->config & AFL_SNAPSHOT_REGS) {

    struct pt_regs *regs = task_pt_regs(current);

    // restore regs context
    *regs = data->ss.regs;

  }

  // restore brk
  if (current->mm->brk > data->ss.oldbrk) current->mm->brk = data->ss.oldbrk;

}

void restore_snapshot(struct task_data *data) {

  recover_threads_snapshot(data);
  recover_memory_snapshot(data);
  recover_files_snapshot(data);
  recover_state(data);

}

void recover_snapshot(void) {

  struct task_data *data = get_task_data(current);
  restore_snapshot(data);

}

int exit_snapshot(void) {

  struct task_data *data = get_task_data(current);
  if (data && (data->config & AFL_SNAPSHOT_EXIT) && have_snapshot(data)) {

    restore_snapshot(data);
    return 0;

  }

  if (data && had_snapshot(data)) clean_snapshot();

  return 1;

}

void clean_snapshot(void) {

  struct task_data *data = get_task_data(current);
  if (!data) { return; }

  clean_memory_snapshot(data);
  clean_files_snapshot(data);
  clear_snapshot(data);

  remove_task_data(data);

}

