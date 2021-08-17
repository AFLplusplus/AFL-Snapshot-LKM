#include "task_data.h"
#include <linux/slab.h>

LIST_HEAD(task_datas);
static spinlock_t task_datas_lock;

static void task_data_free_callback(struct rcu_head *rcu) {

  struct task_data *data = container_of(rcu, struct task_data, rcu);
  kfree(data);

}

struct task_data *get_task_data(const struct task_struct *leader) {

  struct task_data *data = NULL;

  rcu_read_lock();
  list_for_each_entry_rcu(data, &task_datas, list) {

    if (data->leader == leader) {
      rcu_read_unlock();
      return data;
    }

  }

  rcu_read_unlock();

  return NULL;

}

/*
 * add_thread_data -- add certain thread to global process structure
 * @data -- container of process snapshot, where to add thread
 * @thread -- certain thread's &task_struct
 * $rax -- ptr to certain offset in vector memory, or NULL in case of Err.
 */
struct thread_data *add_thread_data(struct task_data *data, struct task_struct *thread){
  if( !ISKADDR(data) || !ISKADDR(thread) ) return NULL;
  if( data->threads_nr >= 0x10 ) return NULL;

  /* extract free piece of memory */
  data->threads_nr++;
  struct thread_data *thr = &data->threads[data->threads_nr];

  /* filling the structure */
  thr->tsk = thread;
  thr->pid = get_task_pid(thread, );

  struct pt_regs *regs = task_pt_regs(thread);
  memcpy(&thr->regs, regs, sizeof(thr->regs));

}

/*
 * add_task_data -- allocate zeroed memory to place at least one threaded process
 *    put initial information (ptr to group leader task_struct) and increase thread counter
 * @leader -- ptr to group leader leader
 * $rax -- ptr to mem
 */
struct task_data *add_task_data(struct task_struct *leader){
  /* ensure */
  if( !ISKADDR(leader) || leader->group_leader != leader ) return NULL;

  // XXX: this is academic code (tm) so if we run out of memory, too bad!
  /* add place for 16 threads, including thread_leader. This should be enough in most cases */
  /* :TODO: Add realloc mechanism, or, maybe, count needed place amount before? */
  struct task_data *data = kzalloc(sizeof(*data) + sizeof(struct thread_data) * 0x10,
                                   GFP_KERNEL);
  if (!data) return NULL;

  data->leader = leader;
  data->threads_nr++;

  spin_lock(&task_datas_lock);
  list_add_rcu(&data->list, &task_datas);
  spin_unlock(&task_datas_lock);

  return data;
}

struct task_data *ensure_task_data(const struct task_struct *leader) {
  return get_task_data(leader) ? : NULL;
}

void remove_task_data(struct task_data *data) {

  spin_lock(&task_datas_lock);
  list_del_rcu(&data->list);
  spin_unlock(&task_datas_lock);

  call_rcu(&data->rcu, task_data_free_callback);

}

