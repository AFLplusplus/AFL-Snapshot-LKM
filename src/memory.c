#include "hook.h"
#include "debug.h"
#include "task_data.h"
#include "snapshot.h"

static DEFINE_PER_CPU(struct task_struct *, last_task) = NULL;
static DEFINE_PER_CPU(struct task_data *, last_data) = NULL;

pmd_t *get_page_pmd(unsigned long addr) {

  pgd_t *pgd;
  p4d_t *p4d;
  pud_t *pud;
  pmd_t *pmd = NULL;

  struct mm_struct *mm = current->mm;

  pgd = pgd_offset(mm, addr);
  if (pgd_none(*pgd) || pgd_bad(*pgd)) {

    // DBG_PRINT("Invalid pgd.");
    goto out;

  }

  p4d = p4d_offset(pgd, addr);
  if (p4d_none(*p4d) || p4d_bad(*p4d)) {

    // DBG_PRINT("Invalid p4d.");
    goto out;

  }

  pud = pud_offset(p4d, addr);
  if (pud_none(*pud) || pud_bad(*pud)) {

    // DBG_PRINT("Invalid pud.");
    goto out;

  }

  pmd = pmd_offset(pud, addr);
  if (pmd_none(*pmd) || pmd_bad(*pmd)) {

    // DBG_PRINT("Invalid pmd.");
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

    // DBG_PRINT("Invalid pgd.");
    goto out;

  }

  p4d = p4d_offset(pgd, addr);
  if (p4d_none(*p4d) || p4d_bad(*p4d)) {

    // DBG_PRINT("Invalid p4d.");
    goto out;

  }

  pud = pud_offset(p4d, addr);
  if (pud_none(*pud) || pud_bad(*pud)) {

    // DBG_PRINT("Invalid pud.");
    goto out;

  }

  pmd = pmd_offset(pud, addr);
  if (pmd_none(*pmd) || pmd_bad(*pmd)) {

    // DBG_PRINT("Invalid pmd.");
    goto out;

  }

  ptep = pte_offset_map(pmd, addr);
  if (!ptep) {

    // DBG_PRINT("[NEW] Invalid pte.");
    goto out;

  }

out:
  return ptep;

}

// TODO lock thee lists

void exclude_vmrange(unsigned long start, unsigned long end) {

  struct task_data *data = ensure_task_data(current);

  struct vmrange_node *n = kmalloc(sizeof(struct vmrange_node), GFP_KERNEL);
  n->start = start;
  n->end = end;
  n->next = data->blocklist;
  data->blocklist = n;

}

void include_vmrange(unsigned long start, unsigned long end) {

  struct task_data *data = ensure_task_data(current);

  struct vmrange_node *n = kmalloc(sizeof(struct vmrange_node), GFP_KERNEL);
  n->start = start;
  n->end = end;
  n->next = data->allowlist;
  data->allowlist = n;

}

int intersect_blocklist(unsigned long start, unsigned long end) {

  struct task_data *data = ensure_task_data(current);

  struct vmrange_node *n = data->blocklist;
  while (n) {

    if (end > n->start && start < n->end) return 1;
    n = n->next;

  }

  return 0;

}

int intersect_allowlist(unsigned long start, unsigned long end) {

  struct task_data *data = ensure_task_data(current);

  struct vmrange_node *n = data->allowlist;
  while (n) {

    if (end > n->start && start < n->end) return 1;
    n = n->next;

  }

  return 0;

}

void add_snapshot_vma(struct task_data *data, unsigned long start,
                      unsigned long end) {

  struct snapshot_vma *ss_vma;
  struct snapshot_vma *p;

  DBG_PRINT("Adding snapshot vmas start: 0x%08lx end: 0x%08lx\n", start, end);

  ss_vma = kmalloc(sizeof(struct snapshot_vma), GFP_ATOMIC);
  ss_vma->vm_start = start;
  ss_vma->vm_end = end;

  if (data->ss.ss_mmap == NULL) {

    data->ss.ss_mmap = ss_vma;

  } else {

    p = data->ss.ss_mmap;
    while (p->vm_next != NULL)
      p = p->vm_next;

    p->vm_next = ss_vma;

  }

  ss_vma->vm_next = NULL;

}

struct snapshot_page *get_snapshot_page(struct task_data *data,
                                        unsigned long     page_base) {

  struct snapshot_page *sp;

  hash_for_each_possible(data->ss.ss_page, sp, next, page_base) {

    if (sp->page_base == page_base) return sp;

  }

  return NULL;

}

struct snapshot_page *add_snapshot_page(struct task_data *data,
                                        unsigned long     page_base) {

  struct snapshot_page *sp;

  sp = get_snapshot_page(data, page_base);
  if (sp == NULL) {

    sp = kmalloc(sizeof(struct snapshot_page), GFP_KERNEL);

    sp->page_base = page_base;
    sp->page_data = NULL;
    hash_add(data->ss.ss_page, &sp->next, sp->page_base);

  }

  sp->page_prot = 0;
  sp->has_been_copied = false;
  sp->dirty = false;

  return sp;

}

void make_snapshot_page(struct task_data *data, struct mm_struct *mm,
                        unsigned long addr) {

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

  sp = add_snapshot_page(data, addr);

  if (pte_none(*pte)) {

    /* empty pte */
    sp->has_had_pte = false;
    set_snapshot_page_none_pte(sp);

  } else {

    sp->has_had_pte = true;
    if (pte_write(*pte)) {

      /* Private rw page */
      DBG_PRINT("private writable addr: 0x%08lx\n", addr);
      ptep_set_wrprotect(mm, addr, pte);
      set_snapshot_page_private(sp);

      /* flush tlb to make the pte change effective */
      k_flush_tlb_mm_range(mm, addr & PAGE_MASK, (addr & PAGE_MASK) + PAGE_SIZE,
                           PAGE_SHIFT, false);
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

inline bool is_stack(struct vm_area_struct *vma) {

  return vma->vm_start <= vma->vm_mm->start_stack &&
         vma->vm_end >= vma->vm_mm->start_stack;

}

void take_memory_snapshot(struct task_data *data) {

  struct vm_area_struct *pvma = current->mm->mmap;
  unsigned long          addr;

  get_cpu_var(last_task) = NULL;
  put_cpu_var(last_task);
  get_cpu_var(last_data) = NULL;
  put_cpu_var(last_data);

  struct vmrange_node *n = data->allowlist;
  while (n) {

    DBG_PRINT("Allowlist: 0x%08lx - 0x%08lx\n", n->start, n->end);
    n = n->next;

  }

  n = data->blocklist;
  while (n) {

    DBG_PRINT("Blocklist: 0x%08lx - 0x%08lx\n", n->start, n->end);
    n = n->next;

  }

  do {

    // temporarily store all the vmas
    if (data->config & AFL_SNAPSHOT_MMAP)
      add_snapshot_vma(data, pvma->vm_start, pvma->vm_end);

    // We only care about writable pages. Shared memory pages are skipped
    // if notsack is specified, skip if this this the stack
    // Otherwise, look into the allowlist
    if (((pvma->vm_flags & VM_WRITE) && !(pvma->vm_flags & VM_SHARED) &&
         !((data->config & AFL_SNAPSHOT_NOSTACK) && is_stack(pvma))) ||
        intersect_allowlist(pvma->vm_start, pvma->vm_end)) {

      DBG_PRINT("Make snapshot start: 0x%08lx end: 0x%08lx\n", pvma->vm_start,
                pvma->vm_end);

      for (addr = pvma->vm_start; addr < pvma->vm_end; addr += PAGE_SIZE) {

        if (intersect_blocklist(addr, addr + PAGE_SIZE)) continue;
        if (((data->config & AFL_SNAPSHOT_BLOCK) ||
             ((data->config & AFL_SNAPSHOT_NOSTACK) && is_stack(pvma))) &&
            !intersect_allowlist(addr, addr + PAGE_SIZE))
          continue;

        make_snapshot_page(data, pvma->vm_mm, addr);

      }

    }

    pvma = pvma->vm_next;

  } while (pvma != NULL);

}

void munmap_new_vmas(struct task_data *data) {

  struct vm_area_struct *vma = data->tsk->mm->mmap;
  struct snapshot_vma *  ss_vma = data->ss.ss_mmap;

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

void do_recover_page(struct snapshot_page *sp) {

  DBG_PRINT(
      "found reserved page: 0x%08lx page_base: 0x%08lx page_prot: "
      "0x%08lx\n",
      (unsigned long)sp->page_data, (unsigned long)sp->page_base,
      sp->page_prot);

  if (copy_to_user((void __user *)sp->page_base, sp->page_data, PAGE_SIZE) != 0)
    DBG_PRINT("incomplete copy_to_user\n");
  sp->dirty = false;

}

void do_recover_none_pte(struct snapshot_page *sp) {

  struct mm_struct *mm = current->mm;

  DBG_PRINT("found none_pte refreshed page_base: 0x%08lx page_prot: 0x%08lx\n",
            sp->page_base, sp->page_prot);

  k_zap_page_range(mm->mmap, sp->page_base, PAGE_SIZE);

}

void recover_memory_snapshot(struct task_data *data) {

  struct snapshot_page *sp, *prev_sp = NULL;
  struct mm_struct *    mm = data->tsk->mm;
  pte_t *               pte, entry;
  int                   i;

  if (data->config & AFL_SNAPSHOT_MMAP) munmap_new_vmas(data);

  hash_for_each(data->ss.ss_page, i, sp, next) {

    if (sp->dirty &&
        sp->has_been_copied) {  // it has been captured by page fault

      do_recover_page(sp);  // copy old content
      sp->has_had_pte = true;

      pte = walk_page_table(sp->page_base);
      if (pte) {

        /* Private rw page */
        DBG_PRINT("private writable addr: 0x%08lx\n", sp->page_base);
        ptep_set_wrprotect(mm, sp->page_base, pte);
        set_snapshot_page_private(sp);

        /* flush tlb to make the pte change effective */
        k_flush_tlb_mm_range(mm, sp->page_base, sp->page_base + PAGE_SIZE,
                             PAGE_SHIFT, false);
        DBG_PRINT("writable now: %d\n", pte_write(*pte));

        pte_unmap(pte);

      }

    } else if (is_snapshot_page_private(sp)) {

      // private page that has not been captured
      // still write protected

    } else if (is_snapshot_page_none_pte(sp) && sp->has_had_pte) {

      do_recover_none_pte(sp);

      set_snapshot_page_none_pte(sp);
      sp->has_had_pte = false;

    }

  }

}

void clean_snapshot_vmas(struct task_data *data) {

  struct snapshot_vma *p = data->ss.ss_mmap;
  struct snapshot_vma *q;

  DBG_PRINT("freeing snapshot vmas");

  while (p != NULL) {

    DBG_PRINT("start: 0x%08lx end: 0x%08lx\n", p->vm_start, p->vm_end);
    q = p;
    p = p->vm_next;
    kfree(q);

  }

}

void clean_memory_snapshot(struct task_data *data) {

  struct snapshot_page *sp;
  int                   i;

  if (get_cpu_var(last_task) == current) {

    get_cpu_var(last_task) = NULL;
    get_cpu_var(last_data) = NULL;

  }

  put_cpu_var(last_task);
  put_cpu_var(last_data);

  if (data->config & AFL_SNAPSHOT_MMAP) clean_snapshot_vmas(data);

  hash_for_each(data->ss.ss_page, i, sp, next) {

    if (sp->page_data != NULL) kfree(sp->page_data);

    kfree(sp);

  }

}

static long return_0_stub_func(void) {

  return 0;

}

int wp_page_hook(struct kprobe *p, struct pt_regs *regs) {

  struct vm_fault *     vmf;
  struct mm_struct *    mm;
  struct task_data *    data;
  struct snapshot_page *ss_page;
  struct page *         old_page;
  pte_t                 entry;
  char *                vfrom;

  vmf = (struct vm_fault *)regs->di;
  mm = vmf->vma->vm_mm;
  ss_page = NULL;

  if (get_cpu_var(last_task) == mm->owner) {

    // fast path
    data = get_cpu_var(last_data);

  } else {

    // query the radix tree
    data = get_task_data(mm->owner);
    get_cpu_var(last_task) = mm->owner;
    get_cpu_var(last_data) = data;

  }

  put_cpu_var(last_task);
  put_cpu_var(last_data);  // not needed?

  if (data && have_snapshot(data)) {

    ss_page = get_snapshot_page(data, vmf->address & PAGE_MASK);

  } else

    return 0;  // continue

  if (!ss_page) {

    // not a snapshot'ed page
    return 0;  // continue

  }

  if (ss_page->dirty) return 0;

  ss_page->dirty = true;

  DBG_PRINT("wp_page_hook 0x%08lx", vmf->address);

  /* the page has been copied?
   * the page becomes COW page again. we do not need to take care of it.
   */
  if (!ss_page->has_been_copied) {

    /* reserved old page data */
    if (ss_page->page_data == NULL) {

      ss_page->page_data = kmalloc(PAGE_SIZE, GFP_KERNEL);

    }

    old_page = pfn_to_page(pte_pfn(vmf->orig_pte));
    vfrom = kmap_atomic(old_page);
    memcpy(ss_page->page_data, vfrom, PAGE_SIZE);
    kunmap_atomic(vfrom);

    ss_page->has_been_copied = true;

  }

  /* check if it is not COW/demand paging but the private page
   * whose prot is set from rw to ro by snapshot.
   */
  if (is_snapshot_page_private(ss_page)) {

    DBG_PRINT(
        "page fault! process: %s addr: 0x%08lx ptep: 0x%08lx pte: 0x%08lx",
        current->comm, vmf->address, (unsigned long)vmf->pte,
        vmf->orig_pte.pte);

    /* change the page prot back to ro from rw */
    entry = pte_mkwrite(vmf->orig_pte);
    set_pte_at(mm, vmf->address, vmf->pte, entry);
    // ghost
    // flush_tlb_page(vmf->vma, vmf->address & PAGE_MASK);
    // ghost
    unsigned long aligned_addr = vmf->address & PAGE_MASK;
    k_flush_tlb_mm_range(mm, aligned_addr, aligned_addr + PAGE_SIZE, PAGE_SHIFT,
                         false);

    pte_unmap_unlock(vmf->pte, vmf->ptl);

    // skip original function
    regs->ip = (long unsigned int)&return_0_stub_func;
    return 1;

  }

  return 0;  // continue

}

// actually hooking page_add_new_anon_rmap, but we really only care about calls
// from do_anonymous_page
int do_anonymous_hook(struct kprobe *p, struct pt_regs *regs) {

  struct vm_area_struct *vma;
  struct mm_struct *     mm;
  struct task_data *     data;
  struct snapshot_page * ss_page;
  unsigned long          address;

  vma = (struct vm_area_struct *)regs->si;
  address = regs->dx;
  mm = vma->vm_mm;
  ss_page = NULL;

  if (get_cpu_var(last_task) == mm->owner) {

    // fast path
    data = get_cpu_var(last_data);

  } else {

    // query the radix tree
    data = get_task_data(mm->owner);
    get_cpu_var(last_task) = mm->owner;
    get_cpu_var(last_data) = data;

  }

  put_cpu_var(last_task);
  put_cpu_var(last_data);  // not needed?

  if (data && have_snapshot(data)) {

    ss_page = get_snapshot_page(data, address & PAGE_MASK);

  } else {

    return 0;

  }

  if (!ss_page) {

    /* not a snapshot'ed page */
    return 0;

  }

  DBG_PRINT("do_anonymous_page 0x%08lx", address);

  // HAVE PTE NOW
  ss_page->has_had_pte = true;

  return 0;

}

