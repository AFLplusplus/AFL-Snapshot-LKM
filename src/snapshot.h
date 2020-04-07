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

// mm stuff
struct snapshot_vma {

  unsigned long        vm_start;
  unsigned long        vm_end;
  struct snapshot_vma *vm_next;

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

  struct snapshot_vma * ss_mmap;
  
  struct pt_regs regs;

  DECLARE_HASHTABLE(ss_page, SNAPSHOT_HASHTABLE_SZ);

};

#define SNAPSHOT_NONE 0x00000000  // outside snapshot
#define SNAPSHOT_MADE 0x00000001  // in snapshot
#define SNAPSHOT_HAD 0x00000002   // once had snapshot

int snapshot_initialize_k_funcs(void);

int wp_page_hook(struct kprobe *p, struct pt_regs *regs);
int do_anonymous_hook(struct kprobe *p, struct pt_regs *regs);
int exit_hook(struct kprobe *p, struct pt_regs *regs);

int do_snapshot(void);
int exit_snapshot(void);
void clean_snapshot(void);

#endif

