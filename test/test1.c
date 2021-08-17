#define _GNU_SOURCE
#include <stdint.h>
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

#include "../include/libaflsnapshot.h"

// gcc -I ../include -g test2.c ../lib/libaflsnapshot.o -o test2

int* shm_addr;
int* none_addr;
void *chunk;
int pippo = 1;
FILE *stdf = NULL;

void test2() {
  *shm_addr = 0xffffffff;
  if (afl_snapshot_take(getpid(), AFL_SNAPSHOT_REGS ) == 1)
    fprintf(stdf, "first time!\n");

loop:
  memset(chunk, 0x43, 0x1001);
  fprintf(stdf, "*chunk = %#lx\n", *(uint64_t*)chunk);
  *none_addr += 1;
  fprintf(stdf, ">> %d     %p = %#x    %p = %#x\n", pippo, none_addr, *none_addr, shm_addr, *shm_addr);
  *shm_addr = 0xdeadbeef;
  ++pippo;
  memset(chunk, 0x44, 0x1001);
  fprintf(stdf, "*chunk = %#lx\n", *(uint64_t*)chunk);
  afl_snapshot_restore();
  fprintf(stdf, "*chunk = %#lx\n", *(uint64_t*)chunk);
  if( *none_addr > 0x10000 ) exit(0x00);
  goto loop;

}

int main() {
  stdf = fopen("/dev/shm/log", "a");
  afl_snapshot_init();
  puts("1");
  shm_addr = mmap(0, 0x10000, PROT_READ | PROT_WRITE | PROT_EXEC,
             MAP_SHARED | MAP_ANONYMOUS, 0, 0);
  memset(shm_addr, 0x41, 0x10000);
  puts("2");
  none_addr = mmap((void *)0, 0x1000, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  memset(none_addr, 0xff, 0x1000);
  puts("3");
  afl_snapshot_exclude_vmrange((unsigned long)none_addr, (unsigned long)(none_addr + (0x1000/4)));
  puts("4");
  afl_snapshot_include_vmrange((unsigned long)shm_addr, (unsigned long)(shm_addr + (0x10000/4)));
  puts("5");
  *shm_addr = 0;
  puts("6");
  chunk = malloc(0x1001);
  memset(chunk, 0x41, 0x1001);
  fprintf(stdf, "*chunk = %#lx\n", *(uint64_t*)chunk);
  afl_snapshot_include_vmrange(chunk, chunk+0x1001);
  memset(chunk, 0x42, 0x1001);
  fprintf(stdf, "*chunk = %#lx\n", *(uint64_t*)chunk);
  puts("7");
  test2();
  return 0;

}


