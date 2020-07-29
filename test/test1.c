#define _GNU_SOURCE
#include <fcntl.h>
#include <malloc.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "libaflsnapshot.h"

// gcc -I ../include -g test2.c ../lib/libaflsnapshot.o -o test2

int* shm_addr;
int* none_addr;

int pippo = 1;

void test2() {

  if (afl_snapshot_take(AFL_SNAPSHOT_NOSTACK) == 1)
    fprintf(stderr, "first time!\n");

loop:

  *none_addr += 1;
  *shm_addr += 1;
  fprintf(stderr, ">> %d     %p = %d    %p = %d\n", pippo, none_addr, *none_addr, shm_addr, *shm_addr);
  ++pippo;

  afl_snapshot_restore();
  goto loop;

}

int main() {

  afl_snapshot_init();
  
  shm_addr = mmap(0, 0x10000, PROT_READ | PROT_WRITE | PROT_EXEC,
             MAP_SHARED | MAP_ANONYMOUS, 0, 0);

  none_addr = mmap((void *)0, 0x1000, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  afl_snapshot_exclude_vmrange((unsigned long)none_addr, (unsigned long)(none_addr + (0x1000/4)));
  afl_snapshot_include_vmrange((unsigned long)shm_addr, (unsigned long)(shm_addr + (0x10000/4)));

  *shm_addr = 0;

  test2();

  return 0;

}


