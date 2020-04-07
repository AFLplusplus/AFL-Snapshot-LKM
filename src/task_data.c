#include "task_data.h"
#include <linux/slab.h>

LIST_HEAD(task_datas);

struct task_data *get_task_data(const struct task_struct *tsk) {

  struct task_data *data = NULL;
  list_for_each_entry(data, &task_datas, l) {

    if (data->tsk == tsk) return data;

  }

  return NULL;

}

struct task_data *ensure_task_data(const struct task_struct *tsk) {

  struct task_data *data = get_task_data(tsk);
  if (data) return data;

  // XXX: this is academic code (tm) so if we run out of memory, too bad!
  data = kmalloc(sizeof(struct task_data), GFP_KERNEL | __GFP_ZERO);

  INIT_LIST_HEAD(&data->l);
  data->tsk = tsk;

  list_add(&data->l, &task_datas);

  return data;

}

void remove_task_data(struct task_data *data) {

  list_del(&data->l);
  kfree(data);

}
