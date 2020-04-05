/*
 * mallocinfo to check cow pages for libc
 * global variable a to check private pages of the binary
 *
 * wxu
 */

// gcc -I ../include -g test1.c ../lib/libaflsnapshot.o -o test1 
 
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

void *mmm;
unsigned long a;
unsigned long snapshot_arg[3];
jmp_buf env;

void procmap() {

  char buf[100];
  memset(buf, 0, sizeof(buf));
  sprintf(buf, "cat /proc/%d/maps", getpid());
  system(buf);

}

void filemap() {

  char buf[100];
  memset(buf, 0, sizeof(buf));
  sprintf(buf, "ls -al /proc/%d/fd", getpid());
  system(buf);

}

void worker() {

  void *p[0x20];
  unsigned long addr;
  struct mallinfo mi;
  int i, fd;

  *(unsigned long *)mmm = 0x4242424242424242;

  a = 0x87654321;
  printf("a: 0x%08lx\n", a);

  // *(unsigned long *)(0x602020) = reserved;

  // this will trigger demanding paging (do_anonymous_page)
  for (i = 0; i < 0x20; i++) {

    p[i] = malloc(0x100);
    printf("allocate: 0x%08lx\n", (unsigned long)p[i]);

  }

  for (i = 0; i < 0x20; i += 2)
    free(p[i]);
  mi = mallinfo();
  printf("[worker] allocated bytes: %d free chunks: %d\n", mi.uordblks,
         mi.ordblks);

  addr = (unsigned long)mmap((void *)0xa00000, 0x100000,
                             PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
  printf("mmap addr: 0x%08lx\n", addr);

  fd = open("file", O_CREAT, 0700);
  printf("fd: %d\n", fd);

  procmap();
  filemap();

  printf("start sleeping");
  fflush(stdout);

  /*
  while(1) {

          sleep(1);
          printf(".");
          fflush(stdout);

  }

  */

  exit(0);

  return;

}

void cleanup() {

  /* cleanup snapshot */
  afl_snapshot_end();

  /* jump back to the starting point */
  longjmp(env, 0);

}

void test1() {

  void *p;
  struct mallinfo mi;
  int i = 0;

  p = malloc(0x100);
  procmap();
  filemap();

  a = 0x12345678;
  printf("&a: 0x%08lx a: 0x%08lx\n", (unsigned long)(&a), a);
  mi = mallinfo();
  printf("allocated bytes: %d free chunks: %d\n", mi.uordblks, mi.ordblks);

  mmm = mmap((void *)0xa000000, 0x110000, PROT_READ | PROT_WRITE | PROT_EXEC,
             MAP_SHARED | MAP_FIXED | MAP_ANONYMOUS, 0, 0);
  printf("0x%08lx\n", (unsigned long)mmm);
  *(unsigned long *)mmm = 0x4141414141414141;

  setjmp(env);

  if (i > 5)
    goto out;
  i++;

  /***** start snapshot *****/
  afl_snapshot_start(&cleanup, mmm, 0x110000);

  /***** do fuzzing! *****/
  worker();

  /***** end snapshot *****/
  cleanup();

out:
  printf("mmm: 0x%08lx\n", *(unsigned long *)mmm);
  printf("&a: 0x%08lx a: 0x%08lx\n", (unsigned long)(&a), a);
  mi = mallinfo();
  printf("allocated bytes: %d free chunks: %d\n", mi.uordblks, mi.ordblks);
  procmap();
  filemap();

}

int main() {

  afl_snapshot_init();

  test1();

  unlink("file");

  return 0;

}


