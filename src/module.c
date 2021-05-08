#include <linux/buffer_head.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/version.h>

#include "task_data.h"  // mm associated data
#include "hook.h"       // function hooking
#include "snapshot.h"   // main implementation
#include "debug.h"
// #include "symbols.h"
#include "ftrace_helper.h"

#include "afl_snapshot.h"

#define DEVICE_NAME "afl_snapshot"
#define CLASS_NAME "afl_snapshot"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kallsyms & andreafioraldi");
MODULE_DESCRIPTION("Fast process snapshots for fuzzing");
MODULE_VERSION("1.0.0");

void (*k_flush_tlb_mm_range)(struct mm_struct *mm, unsigned long start,
                             unsigned long end, unsigned int stride_shift,
                             bool freed_tables);

void (*k_zap_page_range)(struct vm_area_struct *vma, unsigned long start,
                         unsigned long size);

int            mod_major_num;
struct class * mod_class;
struct device *mod_device;

struct kobject *mod_kobj;

static char *mod_devnode(struct device *dev, umode_t *mode) {

  if (mode) *mode = 0644;
  return NULL;

}

long mod_dev_ioctl(struct file *filep, unsigned int cmd, unsigned long arg) {

  switch (cmd) {

    case AFL_SNAPSHOT_EXCLUDE_VMRANGE: {

      DBG_PRINT("Calling afl_snapshot_exclude_vmrange");

      struct afl_snapshot_vmrange_args args;
      if (copy_from_user(&args, (void *)arg,
                         sizeof(struct afl_snapshot_vmrange_args)))
        return -EINVAL;

      exclude_vmrange(args.start, args.end);
      return 0;

    }

    case AFL_SNAPSHOT_INCLUDE_VMRANGE: {

      DBG_PRINT("Calling afl_snapshot_include_vmrange");

      struct afl_snapshot_vmrange_args args;
      if (copy_from_user(&args, (void *)arg,
                         sizeof(struct afl_snapshot_vmrange_args)))
        return -EINVAL;

      include_vmrange(args.start, args.end);
      return 0;

    }

    case AFL_SNAPSHOT_IOCTL_TAKE: {

      DBG_PRINT("Calling afl_snapshot_take");

      return take_snapshot(arg);

    }

    case AFL_SNAPSHOT_IOCTL_DO: {

      DBG_PRINT("Calling afl_snapshot_do");

      return take_snapshot(AFL_SNAPSHOT_MMAP | AFL_SNAPSHOT_FDS |
                           AFL_SNAPSHOT_REGS | AFL_SNAPSHOT_EXIT);

    }

    case AFL_SNAPSHOT_IOCTL_RESTORE: {

      DBG_PRINT("Calling afl_snapshot_restore");

      recover_snapshot();
      return 0;

    }

    case AFL_SNAPSHOT_IOCTL_CLEAN: {

      DBG_PRINT("Calling afl_snapshot_clean");

      clean_snapshot();
      return 0;

    }

  }

  return -EINVAL;

}

static struct file_operations dev_fops = {

    .owner = THIS_MODULE,
    .unlocked_ioctl = mod_dev_ioctl,

};

#ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
typedef int (*syscall_handler_t)(struct pt_regs *);

// The original syscall handler that we removed to override exit_group()
syscall_handler_t orig_sct_exit_group = NULL;

// TODO: non-x86 architectures syscall_table entries don't take pt_regs,
// they take normal args
// https://grok.osiris.cyber.nyu.edu/xref/linux/include/linux/syscalls.h?r=83fa805b#235
// but x86 is (of course) different, taking a pt_regs, then passing extracted
// values to the actual __do_sys*
// https://grok.osiris.cyber.nyu.edu/xref/linux/arch/x86/include/asm/syscall_wrapper.h?r=6e484764#161

asmlinkage int sys_exit_group(struct pt_regs *regs) {

  // SAYF("hooked sys_exit_group(%p)\n", regs);
  // enum show_regs_mode print_kernel_regs;

	// show_regs_print_info(LOGLEVEL_INFO);

	// print_kernel_regs = user_mode(regs) ? SHOW_REGS_USER : SHOW_REGS_ALL;
	// __show_regs(regs, print_kernel_regs, LOGLEVEL_INFO);
  // int ret = exit_snapshot();
  // SAYF("exit_snapshot() = %d\n", ret);
  // return orig_sct_exit_group(regs);
  if (exit_snapshot()) return orig_sct_exit_group(regs);

  return 0;

}
#else
typedef long (*syscall_handler_t)(int error_code);

// The original syscall handler that we removed to override exit_group()
syscall_handler_t orig_sct_exit_group = NULL;

asmlinkage long sys_exit_group(int error_code) {

  if (exit_snapshot()) return orig_sct_exit_group(error_code);

  return 0;

}
#endif

static struct ftrace_hook syscall_hooks[] = {
    SYSCALL_HOOK("sys_exit_group", sys_exit_group, &orig_sct_exit_group),
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0) /* rename since Linux 5.8 */
#define probe_kernel_read copy_from_kernel_nofault
#endif

// TODO(galli-leo): we should be able to just use kallsyms_lookup_name now.
int snapshot_initialize_k_funcs() {

  k_flush_tlb_mm_range = (void *)kallsyms_lookup_name("flush_tlb_mm_range");
  k_zap_page_range = (void *)kallsyms_lookup_name("zap_page_range");

  if (!k_flush_tlb_mm_range || !k_zap_page_range) { return -ENOENT; }

  SAYF("All loaded");

  return 0;

}

void finish_fault_hook(unsigned long ip, unsigned long parent_ip,
                   struct ftrace_ops *op, ftrace_regs_ptr regs);

static int __init mod_init(void) {

  SAYF("Loading AFL++ snapshot LKM");

  mod_kobj = kobject_create_and_add("afl_snapshot", kernel_kobj);
  if (!mod_kobj) return -ENOMEM;

  mod_major_num = register_chrdev(0, DEVICE_NAME, &dev_fops);
  if (mod_major_num < 0) {

    FATAL("Failed to register a major number");
    return mod_major_num;

  }

  mod_class = class_create(THIS_MODULE, CLASS_NAME);
  if (IS_ERR(mod_class)) {

    FATAL("Failed to register device class");

    unregister_chrdev(mod_major_num, DEVICE_NAME);
    return PTR_ERR(mod_class);

  }

  mod_class->devnode = mod_devnode;

  mod_device = device_create(mod_class, NULL, MKDEV(mod_major_num, 0), NULL,
                             DEVICE_NAME);
  if (IS_ERR(mod_device)) {

    FATAL("Failed to create the device\n");

    class_destroy(mod_class);
    unregister_chrdev(mod_major_num, DEVICE_NAME);
    return PTR_ERR(mod_device);

  }

  SAYF("The major device number is %d", mod_major_num);

  int err;
  err = fh_install_hooks(syscall_hooks, ARRAY_SIZE(syscall_hooks));
  if(err)
      return err;

  // func hooks
  if (!try_hook("do_wp_page", &wp_page_hook)) {

    FATAL("Unable to hook do_wp_page");
    // unpatch_syscall_table();

    return -ENOENT;

  }

  if (!try_hook("page_add_new_anon_rmap", &do_anonymous_hook)) {

    FATAL("Unable to hook page_add_new_anon_rmap");

    unhook_all();
    // unpatch_syscall_table();
    return -ENOENT;

  }

  // return 0;

  if (!try_hook("do_exit", &exit_hook)) {

    FATAL("Unable to hook do_exit");

    unhook_all();
    // unpatch_syscall_table();
    return -ENOENT;

  }

  // if (!try_hook("finish_fault", &finish_fault_hook)) {
  //       FATAL("Unable to hook handle_pte_fault");

  //   unhook_all();
  //   // unpatch_syscall_table();
  //   return -ENOENT;
  // }

  // initialize snapshot non-exported funcs
  return snapshot_initialize_k_funcs();

}

static void __exit mod_exit(void) {

  SAYF("Unloading AFL++ snapshot LKM");

  kobject_put(mod_kobj);

  device_destroy(mod_class, MKDEV(mod_major_num, 0));
  class_unregister(mod_class);
  class_destroy(mod_class);
  unregister_chrdev(mod_major_num, DEVICE_NAME);

  unhook_all();
  fh_remove_hooks(syscall_hooks, ARRAY_SIZE(syscall_hooks));

}

module_init(mod_init);
module_exit(mod_exit);

