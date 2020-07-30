#ifndef __AFL_SNAPSHOT_H__
#define __AFL_SNAPSHOT_H__

#include <asm/mmu.h>
#include <asm/page.h>
#include <linux/auxvec.h>
#include <linux/completion.h>
#include <linux/cpumask.h>
#include <linux/hashtable.h>
#include <linux/kprobes.h>
#include <linux/list.h>
#include <linux/page-flags-layout.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/spinlock.h>
#include <linux/threads.h>
#include <linux/types.h>
#include <linux/uprobes.h>
#include <linux/workqueue.h>
#include <linux/acct.h>
#include <linux/aio.h>
#include <linux/audit.h>
#include <linux/binfmts.h>
#include <linux/blkdev.h>
#include <linux/capability.h>
#include <linux/cgroup.h>
#include <linux/cn_proc.h>
#include <linux/compat.h>
#include <linux/compiler.h>
#include <linux/completion.h>
#include <linux/cpu.h>
#include <linux/delayacct.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/freezer.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/ftrace.h>
#include <linux/futex.h>
#include <linux/hugetlb.h>
#include <linux/init.h>
#include <linux/iocontext.h>
#include <linux/jiffies.h>
#include <linux/kcov.h>
#include <linux/key.h>
#include <linux/khugepaged.h>
#include <linux/ksm.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/magic.h>
#include <linux/memcontrol.h>
#include <linux/mempolicy.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/mmu_notifier.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/oom.h>
#include <linux/perf_event.h>
#include <linux/personality.h>
#include <linux/posix-timers.h>
#include <linux/proc_fs.h>
#include <linux/profile.h>
#include <linux/ptrace.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <linux/rmap.h>
#include <linux/seccomp.h>
#include <linux/security.h>
#include <linux/sem.h>
#include <linux/signalfd.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/syscalls.h>
#include <linux/sysctl.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/taskstats_kern.h>
#include <linux/tsacct_kern.h>
#include <linux/tty.h>
#include <linux/unistd.h>
#include <linux/uprobes.h>
#include <linux/user-return-notifier.h>
#include <linux/vmacache.h>
#include <linux/vmalloc.h>

#include <asm/cacheflush.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/pgtable_types.h>
#include <asm/tlb.h>
#include <asm/tlbflush.h>
#include <asm/uaccess.h>

#include "afl_snapshot.h"

struct task_data;

// TODO lock VMA restore
struct snapshot_vma {

  unsigned long        vm_start;
  unsigned long        vm_end;
  struct snapshot_vma *vm_next;

};

struct snapshot_thread {

  struct task_struct *tsk;

};

struct snapshot_page {

  unsigned long page_base;
  unsigned long page_prot;
  void *        page_data;

  bool has_been_copied;
  bool has_had_pte;
  bool dirty;

  struct hlist_node next;

};

#define SNAPSHOT_PRIVATE 0x00000001
#define SNAPSHOT_COW 0x00000002
#define SNAPSHOT_NONE_PTE 0x00000010

static inline bool is_snapshot_page_none_pte(struct snapshot_page *sp) {

  return sp->page_prot & SNAPSHOT_NONE_PTE;

}

static inline bool is_snapshot_page_cow(struct snapshot_page *sp) {

  return sp->page_prot & SNAPSHOT_COW;

}

static inline bool is_snapshot_page_private(struct snapshot_page *sp) {

  return sp->page_prot & SNAPSHOT_PRIVATE;

}

static inline void set_snapshot_page_none_pte(struct snapshot_page *sp) {

  sp->page_prot |= SNAPSHOT_NONE_PTE;

}

static inline void set_snapshot_page_private(struct snapshot_page *sp) {

  sp->page_prot |= SNAPSHOT_PRIVATE;

}

static inline void set_snapshot_page_cow(struct snapshot_page *sp) {

  sp->page_prot |= SNAPSHOT_COW;

}

#define SNAPSHOT_HASHTABLE_SZ 0x8

struct snapshot {

  unsigned int  status;
  unsigned long oldbrk;

  struct snapshot_vma *ss_mmap;

  struct pt_regs regs;

  DECLARE_HASHTABLE(ss_page, SNAPSHOT_HASHTABLE_SZ);

};

#define SNAPSHOT_NONE 0x00000000  // outside snapshot
#define SNAPSHOT_MADE 0x00000001  // in snapshot
#define SNAPSHOT_HAD 0x00000002   // once had snapshot

extern void (*k_flush_tlb_mm_range)(struct mm_struct *mm, unsigned long start,
                                    unsigned long end,
                                    unsigned int  stride_shift,
                                    bool          freed_tables);

extern void (*k_zap_page_range)(struct vm_area_struct *vma, unsigned long start,
                                unsigned long size);

void take_memory_snapshot(struct task_data *data);
void recover_memory_snapshot(struct task_data *data);
void clean_memory_snapshot(struct task_data *data);

void take_files_snapshot(struct task_data *data);
void recover_files_snapshot(struct task_data *data);
void clean_files_snapshot(struct task_data *data);

void recover_threads_snapshot(struct task_data *data);

int snapshot_initialize_k_funcs(void);

int wp_page_hook(struct kprobe *p, struct pt_regs *regs);
int do_anonymous_hook(struct kprobe *p, struct pt_regs *regs);
int exit_hook(struct kprobe *p, struct pt_regs *regs);

int  take_snapshot(int config);
void recover_snapshot(void);
void clean_snapshot(void);
int  exit_snapshot(void);

void exclude_vmrange(unsigned long start, unsigned long end);
void include_vmrange(unsigned long start, unsigned long end);

#endif

