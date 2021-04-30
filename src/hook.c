#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/version.h>
#include "debug.h"
#include "ftrace_helper.h"
// TODO(andrea) switch from Kprobes to Ftrace

struct hook {

  struct kprobe    kp;
  struct ftrace_ops fops;
  struct list_head l;

};

LIST_HEAD(hooks);

int try_hook(const char *func_name, void *handler) {
  SAYF("Hooking function %s\n", func_name);
  struct hook *hook = kmalloc(sizeof(struct hook), GFP_KERNEL | __GFP_ZERO);
  INIT_LIST_HEAD(&hook->l);
  hook->kp.symbol_name = func_name;
  hook->kp.pre_handler = handler;
  hook->fops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY | FTRACE_OPS_FL_RECURSION;
  hook->fops.func = handler;
  ftrace_set_filter(&hook->fops, func_name, strlen(func_name), 0);
  int ret = register_ftrace_function(&hook->fops);
  SAYF("Hooked function: %d\n", ret);
  // int ret = register_kprobe(&hook->kp);
  if (!ret) { list_add(&hook->l, &hooks); }

  return true;

}

void unhook(const char *func_name) {

  struct hook *hook = NULL;
  list_for_each_entry(hook, &hooks, l) {

    if (!strcmp(hook->kp.symbol_name, func_name)) {

      // unregister_kprobe(&hook->kp);
      unregister_ftrace_function(&hook->fops);

    }

  }

}

void unhook_all(void) {

  struct hook *hook = NULL;
  list_for_each_entry(hook, &hooks, l) {

    // unregister_kprobe(&hook->kp);
    unregister_ftrace_function(&hook->fops);

  }

}
