#include "hook.h"
#include "debug.h"
#include "task_data.h"
#include "snapshot.h"

void take_files_snapshot(struct task_data *data) {

  struct files_struct *files = current->files;
  struct fdtable *     fdt = rcu_dereference_raw(files->fdt);
  int                  size, i;

  size = (fdt->max_fds - 1) / BITS_PER_LONG + 1;

  if (data->snapshot_open_fds == NULL)
    data->snapshot_open_fds =
        (unsigned long *)kmalloc(size * sizeof(unsigned long), GFP_ATOMIC);

  for (i = 0; i < size; i++)
    data->snapshot_open_fds[i] = fdt->open_fds[i];

}

void recover_files_snapshot(struct task_data *data) {

  /*
   * assume the child process will not close any
   * father's fd?
   */

  struct files_struct *files = current->files;

  if (!data) {

    WARNF("Unable to find files_struct data in recover_files_snapshot");
    return;

  }

  struct fdtable *fdt = rcu_dereference_raw(files->fdt);

  int i, j = 0;
  for (;;) {

    unsigned long cur_set, old_set;
    i = j * BITS_PER_LONG;
    if (i >= fdt->max_fds) break;
    cur_set = fdt->open_fds[j];
    old_set = data->snapshot_open_fds[j++];
    DBG_PRINT("cur_set: 0x%08lx old_set: 0x%08lx\n", cur_set, old_set);
    while (cur_set) {

      if (cur_set & 1) {

        if (!(old_set & 1) && fdt->fd[i] != NULL) {

          struct file *file = fdt->fd[i];
          DBG_PRINT("find new fds %d file* 0x%08lx\n", i, (unsigned long)file);
          // fdt->fd[i] = NULL;
          // filp_close(file, files);
          __close_fd(files, i);

        }

      }

      i++;
      cur_set >>= 1;
      old_set >>= 1;

    }

  }

}

void clean_files_snapshot(struct task_data *data) {

  struct files_struct *files = current->files;

  if (!data) {

    WARNF("Unable to find files_struct data in clean_files_snapshot");
    return;

  }

  if (data->snapshot_open_fds != NULL) kfree(data->snapshot_open_fds);

}

