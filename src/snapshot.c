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

#include "hook.h"
#include "debug.h"
#include "associated_data.h"
#include "snapshot.h"

void (*k_flush_tlb_mm_range)(struct mm_struct *mm, unsigned long start,
                             unsigned long end, unsigned int stride_shift,
                             bool freed_tables);

void (*k_zap_page_range)(struct vm_area_struct *vma, unsigned long start,
                         unsigned long size);

pmd_t *get_page_pmd(unsigned long addr) {

  pgd_t *pgd;
  p4d_t *p4d;
  pud_t *pud;
  pmd_t *pmd = NULL;

  struct mm_struct *mm = current->mm;

  pgd = pgd_offset(mm, addr);
  if (pgd_none(*pgd) || pgd_bad(*pgd)) {

    DBG_PRINT("Invalid pgd.");
    goto out;

  }

  p4d = p4d_offset(pgd, addr);
  if (p4d_none(*p4d) || p4d_bad(*p4d)) {

    DBG_PRINT("Invalid p4d.");
    goto out;

  }

  pud = pud_offset(p4d, addr);
  if (pud_none(*pud) || pud_bad(*pud)) {

    DBG_PRINT("Invalid pud.");
    goto out;

  }

  pmd = pmd_offset(pud, addr);
  if (pmd_none(*pmd) || pmd_bad(*pmd)) {

    DBG_PRINT("Invalid pmd.");
    pmd = NULL;
    goto out;

  }

out:
  return pmd;

}

pte_t *walk_page_table(unsigned long addr) {

  pgd_t *pgd;
  p4d_t *p4d;
  pud_t *pud;
  pmd_t *pmd;
  pte_t *ptep = NULL;

  struct mm_struct *mm = current->mm;

  pgd = pgd_offset(mm, addr);
  if (pgd_none(*pgd) || pgd_bad(*pgd)) {

    DBG_PRINT("Invalid pgd.");
    goto out;

  }

  p4d = p4d_offset(pgd, addr);
  if (p4d_none(*p4d) || p4d_bad(*p4d)) {

    DBG_PRINT("Invalid p4d.");
    goto out;

  }

  pud = pud_offset(p4d, addr);
  if (pud_none(*pud) || pud_bad(*pud)) {

    DBG_PRINT("Invalid pud.");
    goto out;

  }

  pmd = pmd_offset(pud, addr);
  if (pmd_none(*pmd) || pmd_bad(*pmd)) {

    DBG_PRINT("Invalid pmd.");
    goto out;

  }

  ptep = pte_offset_map(pmd, addr);
  if (!ptep) {

    DBG_PRINT("[NEW] Invalid pte.");
    goto out;

  }

out:
  return ptep;

}

void munmap_new_vmas(struct mm_data *mdata) {

  struct vm_area_struct *vma = mdata->mm->mmap;
  struct snapshot_vma *  ss_vma = mdata->ss.ss_mmap;

  unsigned long old_start = ss_vma->vm_start;
  unsigned long old_end = ss_vma->vm_end;
  unsigned long cur_start = vma->vm_start;
  unsigned long cur_end = vma->vm_end;

  /* we believe that normally, the original mappings of the father process
   * will not be munmapped by the child process when fuzzing.
   *
   * load library on-the-fly?
   */
  do {

    if (cur_start < old_start) {

      if (old_start >= cur_end) {

        DBG_PRINT("new: from 0x%08lx to 0x%08lx\n", cur_start, cur_end);
        vm_munmap(cur_start, cur_end - cur_start);
        vma = vma->vm_next;
        if (!vma) break;
        cur_start = vma->vm_start;
        cur_end = vma->vm_end;

      } else {

        DBG_PRINT("new: from 0x%08lx to 0x%08lx\n", cur_start, old_start);
        vm_munmap(cur_start, old_start - cur_start);
        cur_start = old_start;

      }

    } else {

      if (cur_end < old_end) {

        vma = vma->vm_next;
        if (!vma) break;
        cur_start = vma->vm_start;
        cur_end = vma->vm_end;

        old_start = cur_end;

      } else if (cur_end == old_end) {

        vma = vma->vm_next;
        if (!vma) break;
        cur_start = vma->vm_start;
        cur_end = vma->vm_end;

        ss_vma = ss_vma->vm_next;
        if (!ss_vma) break;
        old_start = ss_vma->vm_start;
        old_end = ss_vma->vm_end;

      } else if (cur_end > old_end) {

        cur_start = old_end;

        ss_vma = ss_vma->vm_next;
        if (!ss_vma) break;
        old_start = ss_vma->vm_start;
        old_end = ss_vma->vm_end;

      }

    }

  } while (true);

  if (vma) {

    DBG_PRINT("new: from 0x%08lx to 0x%08lx\n", cur_start, cur_end);
    vm_munmap(cur_start, cur_end - cur_start);
    while (vma->vm_next != NULL) {

      vma = vma->vm_next;
      DBG_PRINT("new: from 0x%08lx to 0x%08lx\n", vma->vm_start, vma->vm_end);
      vm_munmap(vma->vm_start, vma->vm_end - vma->vm_start);

    }

  }

}

void clean_snapshot_vmas(struct mm_data *mdata) {

  struct snapshot_vma *p = mdata->ss.ss_mmap;
  struct snapshot_vma *q;

  DBG_PRINT("freeing snapshot vmas");

  while (p != NULL) {

    DBG_PRINT("start: 0x%08lx end: 0x%08lx\n", p->vm_start, p->vm_end);
    q = p;
    p = p->vm_next;
    kfree(q);

  }

  remove_mm_data(mdata);

}

void do_recover_page(struct snapshot_page *sp) {

  DBG_PRINT(
      "found reserved page: 0x%08lx page_base: 0x%08lx page_prot: "
      "0x%08lx\n",
      (unsigned long)sp->page_data, (unsigned long)sp->page_base,
      sp->page_prot);

  copy_to_user((void __user *)sp->page_base, sp->page_data, PAGE_SIZE);

}

void do_recover_none_pte(struct snapshot_page *sp) {

  struct mm_struct *mm = current->mm;
  // struct mmu_gather tlb;
  /* pmd_t *pmd; */

  DBG_PRINT("found none_pte refreshed page_base: 0x%08lx page_prot: 0x%08lx\n",
            sp->page_base, sp->page_prot);

  // ghost
  /* /1* 1. find pmd of the page *1/ */
  /* pmd = get_page_pmd(sp->page_base); */
  /* if (!pmd) { */
  /* 	DBG_PRINT("invalid pmd for page base 0x%08lx\n", sp->page_base);
   */
  /* 	return; */
  /* } */

  /* /1* 2. with the help of zap_pte_range(?) to safely free a page *1/ */
  /* lru_add_drain(); // ? */
  /* tlb_gather_mmu(&tlb, mm, sp->page_base, sp->page_base + PAGE_SIZE); */
  /* zap_pte_range(&tlb, mm->mmap, pmd, sp->page_base, sp->page_base +
   * PAGE_SIZE, NULL); */
  /* tlb_finish_mmu(&tlb, sp->page_base, sp->page_base + PAGE_SIZE); */
  // ghost
  k_zap_page_range(mm->mmap, sp->page_base, PAGE_SIZE);

  /* check it again? */
  /*
  pte = walk_page_table(sp->page_base);
  if (!pte) {

          DBG_PRINT("re-checking addr 0x%08lx fail!\n", sp->page_base);
          return;

  }

  page = pte_page(*pte);
  DBG_PRINT("re-checking addr: 0x%08lx PTE: 0x%08lx Page: 0x%08lx
  PageAnon: %d\n", sp->page_base, pte->pte, (unsigned long)page, page ?
  PageAnon(page) : 0);
  */

}

void clean_memory_snapshot(struct mm_data *mdata) {

  struct snapshot_page *sp;
  int                   i;

  hash_for_each(mdata->ss.ss_page, i, sp, next) {

    if (sp->page_data != NULL) kfree(sp->page_data);

    kfree(sp);

  }

}

void recover_memory_snapshot(struct mm_data *mdata) {

  struct snapshot_page *sp, *prev_sp = NULL;
  pte_t *               pte, entry;
  int                   i;

  hash_for_each(mdata->ss.ss_page, i, sp, next) {

    if (sp->valid) {

      if (sp->has_been_copied) {  // it has been captured by page fault
        do_recover_page(sp);

      } else if (is_snapshot_page_private(

                     sp)) {  // private page that has not been captured
        pte = walk_page_table(sp->page_base);
        if (pte) {

          entry = pte_mkwrite(*pte);
          set_pte_at(mdata->mm, sp->page_base, pte, entry);
          // ghost
          // __flush_tlb_one(sp->page_base & PAGE_MASK);

        }

      } else if (is_snapshot_page_none_pte(sp) && sp->has_had_pte) {

        do_recover_none_pte(sp);

      }

      sp->valid = false;

    }

  }

}

void recover_brk(struct mm_data *mdata) {

  if (current->mm->brk > mdata->ss.oldbrk) {

    // ghost: since the memory mappings have been recovered it should be safe to
    // just do this
    current->mm->brk = mdata->ss.oldbrk;
    // ghost
    // sys_brk(mdata->ss.oldbrk);

  }

}

inline void init_snapshot(struct mm_data *mdata) {

  if (!had_snapshot(mdata)) {

    // printk("init snapshot...");
    set_had_snapshot(mdata);
    hash_init(mdata->ss.ss_page);

  }

  // multi-threading?
  set_snapshot(mdata);
  // INIT_LIST_HEAD(&(mdata->ss.ss_mmap));
  mdata->ss.ss_mmap = NULL;
  return;

}

struct snapshot_page *get_snapshot_page(struct mm_data *mdata,
                                        unsigned long   page_base) {

  struct snapshot_page *sp;

  // printk("in is_snapshot_page");
  hash_for_each_possible(mdata->ss.ss_page, sp, next, page_base) {

    // printk("try hash page: 0x%08lx\n", sp->page_base);
    if (sp->page_base == page_base) return sp;

  }

  return NULL;

}

struct snapshot_page *add_snapshot_page(struct mm_data *mdata,
                                        unsigned long   page_base) {

  struct snapshot_page *sp;

  sp = get_snapshot_page(mdata, page_base);
  if (sp == NULL) {

    sp = kmalloc(sizeof(struct snapshot_page), GFP_KERNEL);

    sp->page_base = page_base;
    sp->page_data = NULL;
    hash_add(mdata->ss.ss_page, &sp->next, sp->page_base);

  }

  sp->page_prot = 0;
  sp->has_been_copied = false;
  sp->valid = true;

  return sp;

}

void make_snapshot_page(struct vm_area_struct *vma, unsigned long addr) {

  pte_t *               pte;
  struct snapshot_page *sp;
  struct page *         page;

  pte = walk_page_table(addr);
  if (!pte) goto out;

  page = pte_page(*pte);

  DBG_PRINT(
      "making snapshot: 0x%08lx PTE: 0x%08lx Page: 0x%08lx "
      "PageAnon: %d\n",
      addr, pte->pte, (unsigned long)page, page ? PageAnon(page) : 0);

  sp = add_snapshot_page(ensure_mm_data(vma->vm_mm), addr);

  if (pte_none(*pte)) {

    /* empty pte */
    sp->has_had_pte = false;
    set_snapshot_page_none_pte(sp);

  } else {

    sp->has_had_pte = true;
    if (pte_write(*pte)) {

      /* Private rw page */
      DBG_PRINT("private writable addr: 0x%08lx\n", addr);
      ptep_set_wrprotect(vma->vm_mm, addr, pte);
      set_snapshot_page_private(sp);

      /* flush tlb to make the pte change effective */
      k_flush_tlb_mm_range(vma->vm_mm, addr & PAGE_MASK,
                           (addr & PAGE_MASK) + PAGE_SIZE, PAGE_SHIFT, false);
      DBG_PRINT("writable now: %d\n", pte_write(*pte));

    } else {

      /* COW ro page */
      DBG_PRINT("cow writable addr: 0x%08lx\n", addr);
      set_snapshot_page_cow(sp);

    }

  }

  pte_unmap(pte);

out:
  return;

}

void add_snapshot_vma(struct mm_data *mdata, unsigned long start,
                      unsigned long end) {

  struct snapshot_vma *ss_vma;
  struct snapshot_vma *p;

  DBG_PRINT("adding snapshot vmas start: 0x%08lx end: 0x%08lx\n", start, end);
  ss_vma =
      (struct snapshot_vma *)kmalloc(sizeof(struct snapshot_vma), GFP_ATOMIC);
  ss_vma->vm_start = start;
  ss_vma->vm_end = end;

  if (mdata->ss.ss_mmap == NULL) {

    mdata->ss.ss_mmap = ss_vma;

  } else {

    p = mdata->ss.ss_mmap;
    while (p->vm_next != NULL)
      p = p->vm_next;

    p->vm_next = ss_vma;

  }

  ss_vma->vm_next = NULL;

}

inline bool is_stack(struct vm_area_struct *vma) {

  return vma->vm_start <= vma->vm_mm->start_stack &&
         vma->vm_end >= vma->vm_mm->start_stack;

}

void do_memory_snapshot(unsigned long shm_addr, unsigned long shm_size) {

  struct task_struct *   tsk = current;
  struct mm_struct *     mm = tsk->mm;
  struct mm_data *       mdata = ensure_mm_data(mm);
  struct vm_area_struct *pvma = mm->mmap;
  unsigned long          addr;

  DBG_PRINT("shm_addr: 0x%08lx shm_size: 0x%08lx\n", shm_addr, shm_size);

  init_snapshot(mdata);

  do {

    // temporarily store all the vmas
    add_snapshot_vma(mdata, pvma->vm_start, pvma->vm_end);

    /* we only care about writable pages.
     * we do not care about all the stack pages (temporarily).
     */

    if (pvma->vm_flags & VM_WRITE && !is_stack(pvma) &&
        pvma->vm_start != shm_addr) {

      DBG_PRINT("make snapshot start: 0x%08lx end: 0x%08lx\n", pvma->vm_start,
                pvma->vm_end);

      for (addr = pvma->vm_start; addr < pvma->vm_end; addr += PAGE_SIZE) {

        make_snapshot_page(pvma, addr);

      }

    }

    pvma = pvma->vm_next;

  } while (pvma != NULL);

  return;

}

void recover_files_snapshot(void) {

  /*
   * assume the child process will not close any
   * father's fd?
   */

  struct files_struct *files = current->files;
  struct files_data *  fdata = get_files_data(files);

  if (!fdata) {

    WARNF("Unable to find files_struct data in recover_files_snapshot");
    return;

  }

  struct fdtable *fdt = rcu_dereference_raw(files->fdt);

  int i, j = 0;
  for (;;) {

    unsigned long cur_set, old_set;
    i = j * BITS_PER_LONG;
    if (i >= fdt->max_fds) break;
    cur_set = fdt->open_fds[j];
    old_set = fdata->snapshot_open_fds[j++];
    DBG_PRINT("cur_set: 0x%08lx old_set: 0x%08lx\n", cur_set, old_set);
    while (cur_set) {

      if (cur_set & 1) {

        if (!(old_set & 1) && fdt->fd[i] != NULL) {

          struct file *file = fdt->fd[i];
          DBG_PRINT("find new fds %d file* 0x%08lx\n", i, (unsigned long)file);
          // fdt->fd[i] = NULL;
          // filp_close(file, files);
          __close_fd(files, i);

        }

      }

      i++;
      cur_set >>= 1;
      old_set >>= 1;

    }

  }

}

void clean_files_snapshot(void) {

  struct files_struct *files = current->files;
  struct files_data *  fdata = get_files_data(files);

  if (!fdata) {

    WARNF("Unable to find files_struct data in clean_files_snapshot");
    return;

  }

  if (fdata->snapshot_open_fds != NULL) kfree(fdata->snapshot_open_fds);

  remove_files_data(fdata);
  kfree(fdata);

}

void do_files_snapshot(void) {

  struct files_struct *files = current->files;
  struct files_data *  fdata = ensure_files_data(files);
  struct fdtable *     fdt = rcu_dereference_raw(files->fdt);
  int                  size, i;

  size = (fdt->max_fds - 1) / BITS_PER_LONG + 1;

  if (fdata->snapshot_open_fds == NULL)
    fdata->snapshot_open_fds =
        (unsigned long *)kmalloc(size * sizeof(unsigned long), GFP_ATOMIC);

  for (i = 0; i < size; i++)
    fdata->snapshot_open_fds[i] = fdt->open_fds[i];

}

void reserve_context(unsigned long cleanup_rtn) {

  struct mm_data *         mdata = ensure_mm_data(current->mm);
  struct snapshot_context *sctx = mdata->ss.ucontext;

  if (sctx == NULL) {

    sctx = (struct snapshot_context *)kmalloc(sizeof(struct snapshot_context),
                                              GFP_ATOMIC);
    mdata->ss.ucontext = sctx;

  }

  sctx->cleanup = cleanup_rtn;

}

inline void reserve_brk(void) {

  struct mm_struct *mm = current->mm;
  struct mm_data *  mdata = ensure_mm_data(mm);
  mdata->ss.oldbrk = mm->brk;

}

void clean_context(struct mm_data *mdata) {

  if (mdata->ss.ucontext != NULL) kfree(mdata->ss.ucontext);
  mdata->ss.ucontext = NULL;

}

/*
 * hooks
 */
static long return_0_stub_func(void) {

  return 0;

}

int wp_page_hook(struct kprobe *p, struct pt_regs *regs) {

  struct vm_fault *vmf = (struct vm_fault *)regs->di;

  struct mm_struct *    mm = vmf->vma->vm_mm;
  struct mm_data *      data = get_mm_data(mm);
  struct snapshot_page *ss_page = NULL;
  struct page *         old_page;
  pte_t                 entry;
  char *                vfrom;

  if (data && have_snapshot(data)) {

    ss_page = get_snapshot_page(data, vmf->address & PAGE_MASK);

  } else {

    return 0;  // continue

  }

  if (!ss_page || !ss_page->valid) {

    /* not a snapshot'ed page */
    return 0;  // continue

  }

  /* the page has been copied?
   * the page becomes COW page again. we do not need to take care of it.
   */
  if (ss_page->has_been_copied) {

    return 0;  // continue

  }

  /* reserved old page data */
  if (ss_page->page_data == NULL) {

    ss_page->page_data = kmalloc(PAGE_SIZE, GFP_KERNEL);

  }

  old_page = pfn_to_page(pte_pfn(vmf->orig_pte));
  vfrom = kmap_atomic(old_page);
  memcpy(ss_page->page_data, vfrom, PAGE_SIZE);
  kunmap_atomic(vfrom);

  ss_page->has_been_copied = true;

  /* check if it is not COW/demand paging but the private page
   * whose prot is set from rw to ro by snapshot.
   */
  if (is_snapshot_page_private(ss_page)) {

    // printk("page fault! process: %s addr: 0x%08lx ptep: 0x%08lx pte:
    // 0x%08lx\n",
    //		current->comm, vmf->address, (unsigned long)vmf->pte,
    // vmf->orig_pte.pte);

    /* change the page prot back to ro from rw */
    entry = pte_mkwrite(vmf->orig_pte);
    set_pte_at(mm, vmf->address, vmf->pte, entry);
    // ghost
    // flush_tlb_page(vmf->vma, vmf->address & PAGE_MASK);
    // ghost
    unsigned long aligned_addr = vmf->address & PAGE_MASK;
    k_flush_tlb_mm_range(mm, aligned_addr, aligned_addr + PAGE_SIZE, PAGE_SHIFT,
                         false);

    /*
    printk("page_data: 0x%08lx +0xb0: 0x%08lx, pte: 0x%08lx\n",
                            (unsigned long)(ss_page->page_data),
                            *(unsigned long *)(ss_page->page_data + 0xb0),
                            vmf->pte->pte);
    */

    pte_unmap_unlock(vmf->pte, vmf->ptl);

    // skip original function
    regs->ip = &return_0_stub_func;
    return 1;

  }

  return 0;  // continue

}

// actually hooking page_add_new_anon_rmap, but we really only care about calls
// from do_anonymous_page
int do_anonymous_hook(struct kprobe *p, struct pt_regs *regs) {

  struct vm_area_struct *vma = (struct vm_area_struct *)regs->si;
  unsigned long          address = regs->dx;

  struct mm_struct *    mm = vma->vm_mm;
  struct mm_data *      data = get_mm_data(mm);
  struct snapshot_page *ss_page = NULL;

  if (data && have_snapshot(data)) {

    ss_page = get_snapshot_page(data, address & PAGE_MASK);

  } else {

    return 0;

  }

  if (!ss_page || !ss_page->valid) {

    /* not a snapshot'ed page */
    return 0;

  }

  // printk("do_anonymous_page address: 0x%08lx\n", fe->address);

  // HAVE PTE NOW
  ss_page->has_had_pte = true;

  return 0;

}

/*
 * module-called funcs
 */

int snapshot_initialize_k_funcs() {

  k_flush_tlb_mm_range = kallsyms_lookup_name("flush_tlb_mm_range");
  k_zap_page_range = kallsyms_lookup_name("zap_page_range");

  if (!k_flush_tlb_mm_range || !k_zap_page_range) { return -ENOENT; }

  SAYF("All loaded");

  return 0;

}

void make_snapshot(unsigned long cleanup_rtn, unsigned long shm_addr,
                   unsigned long shm_size) {

  reserve_context(cleanup_rtn);
  reserve_brk();
  do_memory_snapshot(shm_addr, shm_size);
  do_files_snapshot();

}

void recover_snapshot(void) {

  struct mm_data *data = get_mm_data(current->mm);
  if (!data) {

    WARNF("Unable to find mm data in recover_snapshot");
    return;

  }

  if (have_snapshot(data)) {

    clear_snapshot(data);
    recover_memory_snapshot(data);
    recover_brk(data);
    munmap_new_vmas(data);
    clean_snapshot_vmas(data);
    recover_files_snapshot();
    // clean_files_snapshot();
    // clean_context(current->mm);
    // clear_snapshot(current->mm);

  }

}

void snapshot_cleanup(struct task_struct *tsk) {

  struct pt_regs *regs = task_pt_regs(tsk);

  struct mm_data *data = get_mm_data(tsk->mm);
  if (!data) {

    WARNF("Unable to find mm data in snapshot_cleanup");
    return;

  }

  // printk("current ip: 0x%08lx bp: 0x%08lx sp: 0x%08lx\n", regs->ip, regs->bp,
  // regs->sp); printk("current ip: 0x%08lx\n", regs->ip);
  regs->ip = data->ss.ucontext->cleanup;
  // regs->cs = data->ss.regs->cs;
  // regs->sp = data->ss.ucontext->sp;
  // regs->ss = data->ss.regs->ss;
  // regs->bp = data->ss.ucontext->bp;
  // printk("after recover ip: 0x%08lx\n", regs->ip, regs->bp, regs->sp);
  // printk("after recover ip: 0x%08lx\n", regs->ip);

}

void clean_snapshot(void) {

  struct mm_data *data = get_mm_data(current->mm);
  if (!data) { return; }

  clean_memory_snapshot(data);
  clean_snapshot_vmas(data);
  clean_files_snapshot();
  clean_context(data);
  clear_snapshot(data);
  kfree(data);

}

