#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/slab.h>

// TODO(andrea) switch from Kprobes to Ftrace

struct hook {

  struct kprobe    kp;
  struct list_head l;

};

LIST_HEAD(hooks);

int try_hook(const char *func_name, void *handler) {

  struct hook *hook = kmalloc(sizeof(struct hook), GFP_KERNEL | __GFP_ZERO);
  INIT_LIST_HEAD(&hook->l);
  hook->kp.symbol_name = func_name;
  hook->kp.pre_handler = handler;

  int ret = register_kprobe(&hook->kp);
  if (!ret) { list_add(&hook->l, &hooks); }

  return true;

}

void unhook(const char *func_name) {

  struct hook *hook = NULL;
  list_for_each_entry(hook, &hooks, l) {

    if (!strcmp(hook->kp.symbol_name, func_name)) {

      unregister_kprobe(&hook->kp);

    }

  }

}

void unhook_all(void) {

  struct hook *hook = NULL;
  list_for_each_entry(hook, &hooks, l) {

    unregister_kprobe(&hook->kp);

  }

}
