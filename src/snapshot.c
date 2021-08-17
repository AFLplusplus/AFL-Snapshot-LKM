#include "hook.h"
#include "debug.h"
#include "task_data.h"
#include "snapshot.h"

/*int exit_hook(struct kprobe *p, struct pt_regs *regs) {*/
asmlinkage __naked long exit_hook(long rdi) {
  clean_snapshot();
  //  printk("do_exit_orig == %#llx\n", (long*)do_exit_orig);
  do_exit_orig(rdi);                   /* no return */
  return ((long (*)())(0xdeadbeef))(); /* to keep gcc happy */
}

void initialize_snapshot(struct task_data *data, unsigned long config) {


  data->config = config;

  if (!had_snapshot(data)) {
    set_had_snapshot(data);
    hash_init(data->ss.ss_page);
  }

  set_snapshot(data);
  // INIT_LIST_HEAD(&(data->ss.ss_mmap));
  data->ss.ss_mmap = NULL;

  // copy current brk
  data->ss.oldbrk = current->mm->brk;
}

#if 0
inline static dump_task_stuff(){
  initialize_snapshot(data, config);
  take_memory_snapshot(data);
  take_files_snapshot(data);
}
#endif

/*
 * thread_walk_cb -- search all threads of needle PID
 * $rax == &task_struct of thread, of found, or NULL;
 */
static struct task_struct *thread_walk_cb(struct task_struct *tsk, pid_t needle){
  pid_t pid_nr = tsk->pid;
  pid_t parrent_nr = tsk->parent ? tsk->parent->pid : 0x00;
  pid_t leader_nr = tsk->group_leader->pid;
  char name[TASK_COMM_LEN];

  get_task_comm(name, tsk); name[TASK_COMM_LEN] = 0x00;
  printk("I'm kernel_thread, my pid %d, my parent's pid %d, my name %s "
      "our group_leader pid is %d\n",
         pid_nr, parrent_nr, name, leader_nr);
  if( needle == parrent_nr ){
    printk("Found needed thread, returning &task_struct\n");
    return tsk;
  }
  return 0x00;
}
inline static int wpt_cb(struct task_struct *t, void *args){
  printk("%s, my name %s, my pid %d\n", __func__, t->comm, t->pid);
  return 0x00;
}

#if 0
[  105.169403] [AFL++] SAY: Entry to snapshot: requested pid 565, my name test4 my group_leader pid is 565
[  105.171610] Group thread founded!
               name test4, tid 565, pid 565
[  105.172717] I'm kernel_thread, my pid 565, my parent's pid 549, my name test4 our group_leader pid is 565
[  105.174309] Group thread founded!
               name test4, tid 567, pid 565
[  105.175460] I'm kernel_thread, my pid 565, my parent's pid 549, my name test4 our group_leader pid is 565
#endif

/*
 * take_snapshot -- handle ioctl request from userspace
 * @config -- this is [int][int]. Lowest part as it was,
 *    highest part == target pid_t, or 0x00 -- than current will be used
 */
long take_snapshot(unsigned long config) {
  /* reflective overloaded */
  struct task_struct *main_tsk = NULL;

  pid_t main_nr = (int)(config >> 0x20);

  struct pid *main_pid = (main_nr) ?
          find_get_pid(main_nr)    :
          get_task_pid((main_tsk = current->group_leader), PIDTYPE_PID);
  if( !main_pid ) return -1;

  struct task_data *data =
      ensure_task_data( (main_tsk) ?: /* already ptr to group leader */
          (main_tsk = (get_pid_task(main_pid, 0x00)->group_leader)) );
  /* above should be safe, coz &pid always have &task, and &task always have -> group_leader */

  SAYF("Entry to snapshot: requested pid %d, my name %s "
         "my group_leader pid is %d\n",
       main_nr, main_tsk->comm, main_pid->numbers->nr);

  if (!have_snapshot(data)) {  // first execution
    struct task_struct *p, *t;
    /* do not push read_lock, since we are in the void */
    //read_lock(k_tasklist_lock);
    for_each_process_thread(p, t) {
      if (p == main_tsk) {
        if (p == t) {
          printk(
              "Group leader founded!\n"
              "name %s, tid %d, pid %d\n",
              t->comm, t->pid, t->group_leader->pid);

        } else {
          printk(
              "Group thread founded!\n"
              "name %s, tid %d, pid %d\n",
              t->comm, t->pid, t->group_leader->pid);
          /* initialize snapshot data, etc */
          // thread_walk_cb(p, main_nr);
        }
      }
    }


    #warning "main_pid unneeded?"
    put_pid(main_pid);
    return 0x01;

    initialize_snapshot(data, config);
    take_memory_snapshot(data);
    take_files_snapshot(data);
    //read_unlock(k_tasklist_lock);

    /* :XXX: 0x00/-E conv. ? */
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

long exit_snapshot(void) {
  struct task_data *data = get_task_data(current);
  if (data && (data->config & AFL_SNAPSHOT_EXIT) && have_snapshot(data)) {
    restore_snapshot(data);
    return 0;
  }

  if (data && had_snapshot(data)) clean_snapshot();

  return 1;
}

/* :TODO: this should be static inline at least? */
void clean_snapshot(void) {
  struct task_data *data = get_task_data(current);
  if (!data) { return; }

  clean_memory_snapshot(data);
  clean_files_snapshot(data);
  clear_snapshot(data);

  remove_task_data(data);
}
