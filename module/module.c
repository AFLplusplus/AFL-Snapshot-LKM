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

#include "associated_data.h"  // mm associated data
#include "hook.h"             // function hooking
#include "snapshot.h"         // main implementation
#include "debug.h"

#include "afl_snapshot.h"

#define DEVICE_NAME "afl_snapshot"
#define CLASS_NAME "afl_snapshot"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("kallsyms & andreafioraldi");
MODULE_DESCRIPTION("Fast process snapshots for fuzzing");
MODULE_VERSION("1.0.0");

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

    case AFL_SNAPSHOT_IOCTL_START: {

      struct afl_snapshot_start_args args;
      if (copy_from_user(&args, (void *)arg, sizeof(struct afl_snapshot_start_args)))
        return -EINVAL;

      make_snapshot(args.cleanup_rtn, args.shm_addr, args.shm_size);
      return 0;
      
    }

    case AFL_SNAPSHOT_IOCTL_END: {
    
      recover_snapshot();
      return 0;
      
    }

  }

  return -EINVAL;

}

static struct file_operations dev_fops = {

    .owner = THIS_MODULE,
    .unlocked_ioctl = mod_dev_ioctl,

};

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

  struct mm_data *data = get_mm_data(current->mm);
  if (data && have_snapshot(data)) {

    snapshot_cleanup(current);
    return 0;

  }

  if (data && had_snapshot(data)) { clean_snapshot(); }

  return orig_sct_exit_group(regs);

}

static void **get_syscall_table(void) {

  void **syscall_table = NULL;

  syscall_table = kallsyms_lookup_name("sys_call_table");

  if (syscall_table) { return syscall_table; }

  int                i;
  unsigned long long s0 = kallsyms_lookup_name("__x64_sys_read");
  unsigned long long s1 = kallsyms_lookup_name("__x64_sys_write");

  unsigned long long *data =
      (unsigned long long *)((uint64_t)kallsyms_lookup_name("_etext") & ~0x7);
  for (i = 0; (unsigned long long)(&data[i]) < ULLONG_MAX; i++) {

    unsigned long long d;
    // use probe_kernel_read so we don't fault
    if (probe_kernel_read(&d, &data[i], sizeof(d))) { continue; }

    if (d == s0 && data[i + 1] == s1) {

      syscall_table = (void **)(&data[i]);
      break;

    }

  }

  return syscall_table;

}

static void _write_cr0(unsigned long val) {

  asm volatile("mov %0,%%cr0" : "+r"(val));

}

static void enable_write_protection(void) {

  _write_cr0(read_cr0() | (1 << 16));

}

static void disable_write_protection(void) {

  _write_cr0(read_cr0() & (~(1 << 16)));

}

static void **syscall_table_ptr;

static void patch_syscall_table(void) {

  disable_write_protection();
  orig_sct_exit_group = syscall_table_ptr[__NR_exit_group];
  syscall_table_ptr[__NR_exit_group] = &sys_exit_group;
  enable_write_protection();

}

static void unpatch_syscall_table(void) {

  disable_write_protection();
  syscall_table_ptr[__NR_exit_group] = orig_sct_exit_group;
  enable_write_protection();

}

static int __init mod_init(void) {

  SAYF("AFL++ snapshot LKM");

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

  // syscall_table overwrites
  syscall_table_ptr = get_syscall_table();
  if (!syscall_table_ptr) {

    FATAL("Unable to locate syscall_table");
    return -ENOENT;

  }

  patch_syscall_table();

  // func hooks
  if (!try_hook("do_wp_page", &wp_page_hook)) {

    FATAL("Unable to hook do_wp_page");
    unpatch_syscall_table();

    return -ENOENT;

  }

  if (!try_hook("page_add_new_anon_rmap", &do_anonymous_hook)) {

    FATAL("Unable to hook mem_cgroup_try_charge_delay");

    unhook_all();
    unpatch_syscall_table();
    return -ENOENT;

  }

  // initialize snapshot non-exported funcs
  return snapshot_initialize_k_funcs();

}

static void __exit mod_exit(void) {

  kobject_put(mod_kobj);

  device_destroy(mod_class, MKDEV(mod_major_num, 0));
  class_unregister(mod_class);
  class_destroy(mod_class);
  unregister_chrdev(mod_major_num, DEVICE_NAME);

  unhook_all();
  unpatch_syscall_table();

}

module_init(mod_init);
module_exit(mod_exit);

