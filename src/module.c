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
#include <linux/stop_machine.h>

#include "task_data.h"  // mm associated data
#ifdef USE_KPROBES
# include "hook.h"       // function hooking
#endif
#include "snapshot.h"   // main implementation
#include "debug.h"

#include "afl_snapshot.h"

#define DEVICE_NAME "afl_snapshot"
#define CLASS_NAME "afl_snapshot"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("andreafioraldi && Th3C4t");
MODULE_DESCRIPTION("Fast process snapshots for fuzzing");
MODULE_VERSION("1.1.0");
#ifndef __used
# define __used		__attribute__((used))
#endif
#ifndef __unused
# define __unused	__attribute__((unused))
#endif
#ifndef __weak
# define __weak		__attribute__((weak))
#endif

#ifdef WITHOUT_KERNEL_HEADERS
 extern  __weak uint64_t kallsyms_lookup_name;
#else
# if LINUX_VERSION_CODE > KERNEL_VERSION(4,19,0)
#  warning "Reflective mod enable"
# else
   extern  typeof(kallsyms_lookup_name) kallsyms_lookup_name;
# endif
#endif

typedef typeof(void *(*)(void *rdi, ...)) func_t;
func_t	_stop_machine = ((typeof(_stop_machine))&stop_machine);
func_t	_kallsyms_lookup_name = NULL;

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

typedef long (*syscall_handler_t)(long rdi);
syscall_handler_t orig_sct_exit_group = NULL;

asmlinkage long sys_exit_group(long rdi) {
  return exit_snapshot() ? orig_sct_exit_group(rdi) : 0x00;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0) /* rename since Linux 5.8 */
#define probe_kernel_read copy_from_kernel_nofault
#endif

static uint64_t *_sys_call_table = NULL;

/* :XXX: if this really needed? */
static void **get_syscall_table(void) {

  void **syscall_table = NULL;

  int                i;
  unsigned long long s0 = (typeof(s0))_kallsyms_lookup_name("sys_read") ?:
	 (typeof(s0))_kallsyms_lookup_name("__x64_sys_read");
  unsigned long long s1 = s0;
  if( !s1 || !s0 ) return NULL;

  unsigned long long *data = (uint64_t*)(((uint64_t)_kallsyms_lookup_name("_etext"))&~0x7);
  //      (unsigned long long *)(SYMADDR__etext & ~0x7);
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

static void __used disable_write_protection(volatile void *addr){
   unsigned int level;
   uint64_t *pte = (uint64_t*)lookup_address((unsigned long)addr, &level);
   if (pte[0x00] & ~((uint64_t)1<<1)) pte[0x00] |= ((unsigned long long int)1<<1);
}

static void __used enable_write_protection(volatile void *addr){
   unsigned int level;
   uint64_t *pte = (uint64_t*)lookup_address((unsigned long)addr, &level);
   pte[0x00] = pte[0x00] & ~((uint64_t)1<<1);
}

static void patch_syscall_table(void) {
  __asm__("cli;   \n\t");
  disable_write_protection(_sys_call_table);
  orig_sct_exit_group = (void*)_sys_call_table[__NR_exit_group];
  _sys_call_table[__NR_exit_group] = (uint64_t)&sys_exit_group;
  enable_write_protection(_sys_call_table);
  __asm__("sti;   \n\t");

}

static void unpatch_syscall_table(void) {
  __asm__("cli;   \n\t");
  disable_write_protection(_sys_call_table);
  _sys_call_table[__NR_exit_group] = (uint64_t)orig_sct_exit_group;
  enable_write_protection(_sys_call_table);
  __asm__("sti;   \n\t");
}
#ifndef USE_KPROBES
# include "ftrace_helper.c"
#endif

extern __weak __unused int do_wp_page(struct vm_fault *vmf); /* it doesn't have headers? */
asmlinkage typeof(&page_add_new_anon_rmap) page_add_new_anon_rmap_orig = NULL;
asmlinkage typeof(&do_wp_page) do_wp_page_orig = NULL;
asmlinkage typeof(&do_exit) do_exit_orig = NULL;
static struct ftrace_hook hooks[] = {
        HOOK("page_add_new_anon_rmap", do_anonymous_hook, &page_add_new_anon_rmap_orig),
        HOOK("do_wp_page", wp_page_hook, &do_wp_page_orig),
	HOOK("do_exit", exit_hook, &do_exit_orig),
};


int snapshot_initialize_k_funcs() {
  func_t chek_kaddr = (void*)_kallsyms_lookup_name("func_ptr_is_kernel_text") ?:
	(void*)_kallsyms_lookup_name("kernel_text_address");

  k_flush_tlb_mm_range = (void *)_kallsyms_lookup_name("flush_tlb_mm_range");
  k_zap_page_range = (void *)_kallsyms_lookup_name("zap_page_range");

  if (!chek_kaddr(k_flush_tlb_mm_range) ||
	!chek_kaddr(k_zap_page_range)) { return -ENOENT; }

  SAYF("All loaded :3");

  return 0;

}

#define NEEDLE "kallsyms_lookup_name+0x0"
/* pre_init -- func, which ask Mr. Torvald to give us needed adresses
 * $rax == ptr to kallsyms_lookup_name
***/
static void *pre_init(void){
	u_int64_t before = 0x00, after = 0x00;
	char kln2buf[0x200] = { 0x00 };

	before = (u_int64_t)sprint_symbol - 0x1000;
	after  = (u_int64_t)sprint_symbol + 0x1000;

	for ( u_int64_t now = before; now <= after; now++ ){
	        sprint_symbol(kln2buf, now);
	        if ( strncmp(kln2buf, NEEDLE, sizeof(NEEDLE)-1 ) == 0x00 ){
			SAYF("Thank you, Mr. Torvald :)");
                        /* is KLN() instrumented via 5b NOP for ftrace() in prologue? */
	                return ( *(uint32_t*)now == (uint32_t)0x00441f0f ) ?
	                        (((void*)now) + 0x05) : (void*)now;
	        } kln2buf[0x00] = 0x00;
	}
	return 0x00;
}

volatile static unsigned long long int __used slim_white_line(volatile void *args){
	/* doesn't work under the void state */
        //int ok = !!!fh_install_hooks(hooks, ARRAY_SIZE(hooks));
        //if( !ok ) return !ok;
        patch_syscall_table();
        return 0x00;//ok;
}
static int __attribute__((section(".text"))) mod_init(void) {

  int ok = 0x00;

  //printk("%#llx, %#llx, %#llx\n", &page_add_new_anon_rmap_orig, &do_wp_page_orig, &do_exit_orig);

  SAYF("Loading AFL++ snapshot LKM");
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,19,0)
  _kallsyms_lookup_name = pre_init();
#else
  _kallsyms_lookup_name = kallsyms_lookup_name;
#endif
  if( !_kallsyms_lookup_name ){ /* should not happend */
    printk("Very very bad, I don't have kallsyms_lookup_name()\n"
		"Don't look at me, go and do something!\n");
	 return -ENOENT;
  }
  _stop_machine = _kallsyms_lookup_name("stop_machine");

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

  // syscall_table prepare
  _sys_call_table = _kallsyms_lookup_name("sys_call_table") ?: get_syscall_table();
  if (!_sys_call_table) {

    FATAL("Unable to locate syscall_table");
    return -ENOENT;

  }

  /* breakpoint for GDB */
  //( ( void(*)(void) ) (long)(_kallsyms_lookup_name("sys_ni_syscall")) ) ();

  (ok = !!!_stop_machine(slim_white_line, NULL, NULL)) ?
	printk("Well done!\n") : printk("Failed :(\n");
  if( !ok ) return -ok;

  fh_install_hooks(hooks, ARRAY_SIZE(hooks));
  return snapshot_initialize_k_funcs();
  // initialize snapshot non-exported funcs
}
volatile static unsigned long long int __used fat_black_line(volatile void *args){
	//fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	unpatch_syscall_table();
	return 0x00;
}
static void __attribute__((section(".text"))) mod_exit(void) {

  SAYF("Unloading AFL++ snapshot LKM");
  fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
  _stop_machine(fat_black_line, NULL, NULL);

  kobject_put(mod_kobj);
  printk("Objects dropped\n");
  device_destroy(mod_class, MKDEV(mod_major_num, 0));
  printk("Devices dropped\n");
  class_unregister(mod_class);
  class_destroy(mod_class);
  printk("Classes dropped\n");
  unregister_chrdev(mod_major_num, DEVICE_NAME);
  printk("Chardev dropped\n");
  SAYF("[+] We're done here. Have a nice day!");

}

module_init(mod_init);
module_exit(mod_exit);

