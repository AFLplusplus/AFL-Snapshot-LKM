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

void* shm_addr;
int* none_addr;

int pippo = 1;

void test2() {

  afl_snapshot_do();

  *none_addr += 1;
  fprintf(stderr, ">> %d     %p = %d\n", pippo++, none_addr, *none_addr);
  
  exit(0);

}

int main() {

  afl_snapshot_init();
  
  shm_addr = mmap((void *)0xa000000, 0x10000, PROT_READ | PROT_WRITE | PROT_EXEC,
             MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, 0, 0);

  none_addr = shm_addr;

  test2();

  return 0;

}


