#include "task_data.h"
#include <linux/slab.h>
#include "debug.h"

LIST_HEAD(task_datas);
static spinlock_t task_datas_lock;

static void task_data_free_callback(struct rcu_head *rcu) {

  struct task_data *data = container_of(rcu, struct task_data, rcu);
  // should probably free all the other stuff here too?
  struct vmrange_node *n = data->blocklist;
  while (n) {
    data->blocklist = n->next;
    kfree(n);
    n = data->blocklist;
  }
  data->blocklist = NULL;
  n = data->allowlist;
  while (n) {
    data->allowlist = n->next;
    kfree(n);
    n = data->allowlist;
  }
  data->allowlist = NULL;

  kfree(data);
}

struct task_data *get_task_data(const struct task_struct *tsk) {
  // SAYF("entered get_task_data(%p)\n", tsk);
  struct task_data *data = NULL;
  // return NULL;

  rcu_read_lock();
  // SAYF("rcu_read_lock ok\n");
  list_for_each_entry_rcu(data, &task_datas, list) {

    if (data->tsk == tsk) {

      rcu_read_unlock();
      return data;

    }

  }

  // SAYF("list_foreach_done\n");

  rcu_read_unlock();

  // SAYF("rcu_read_unlock ok\n");

  return NULL;

}

struct task_data *ensure_task_data(const struct task_struct *tsk) {

  struct task_data *data = get_task_data(tsk);
  if (data) return data;

  // XXX: this is academic code (tm) so if we run out of memory, too bad!
  data = kmalloc(sizeof(struct task_data), GFP_KERNEL | __GFP_ZERO);
  if (!data) return NULL;

  data->tsk = tsk;
  INIT_LIST_HEAD(&data->ss.dirty_pages);

  spin_lock(&task_datas_lock);
  list_add_rcu(&data->list, &task_datas);
  spin_unlock(&task_datas_lock);

  return data;

}

void remove_task_data(struct task_data *data) {

  spin_lock(&task_datas_lock);
  list_del_rcu(&data->list);
  spin_unlock(&task_datas_lock);

  call_rcu(&data->rcu, task_data_free_callback);

}

