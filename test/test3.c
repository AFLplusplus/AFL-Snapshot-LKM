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
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>

#include "libaflsnapshot.h"

#define PAGE_SIZE 0x1000

#define PAGE_ALIGN(addr) ((uint64_t)addr & (~(PAGE_SIZE-1)))

#define NUM_PAGES 0x2

#define NUM_WRITES 0x4

#define NUM_LOOPS 0x2

#define PRE_FORK_BASE 0x30000000
#define POST_FORK_BASE 0x40000000
#define POST_SNAP_BASE 0x50000000

void* pre_fork_pages[NUM_PAGES] = {0};
void* post_fork_pages[NUM_PAGES] = {0};
void* post_snapshot[NUM_PAGES] = {0};

// gcc -I ../include -g ../lib/libaflsnapshot.o test2.c -o test2

void randomly_map(void* pages[], void* base) {
    for (int i = 0; i < NUM_PAGES; i++) {
        void* fixed_addr = base + i * PAGE_SIZE;
        void* addr = mmap((void*)fixed_addr, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, 0, 0);
        if (addr != fixed_addr) {
            fprintf(stderr, "Failed to map page to %p\n", fixed_addr);
            exit(1);
        }
        memset(addr, 0x42, PAGE_SIZE);
        pages[i] = addr;
    }
}

void unmap_pages(void* pages[]) {
    for (int i = 0; i < NUM_PAGES; i++) {
        void* addr = pages[i];
        munmap(addr, PAGE_SIZE);
    }
}

void randomly_incl_excl(void* pages[]) {
    for (int i = 0; i < NUM_PAGES; i++) {
        long int result = random();
        void* addr = pages[i];
        if (i % 2 == 1) {
            afl_snapshot_exclude_vmrange(addr, addr + PAGE_SIZE);
        } else {
            afl_snapshot_include_vmrange(addr, addr + PAGE_SIZE);
        }
    }
}

void random_write()
{
    int rand_idx = random() % NUM_PAGES;
    int rand_page_off = random() % (PAGE_SIZE / 8); // we write a qword
    int rand_arr = random() % 3;
    void* page = 0;
    switch (rand_arr)
    {
    case 0:
        page = pre_fork_pages[rand_idx];
        break;
    case 1:
        page = post_fork_pages[rand_idx];
        break;
    case 2:
        page = post_snapshot[rand_idx];
        break;
    default:
        fprintf(stderr, "DAFUQ: %d\n", rand_arr);
        break;
    }
    void* rand_loc = page + rand_page_off;
    *((uint64_t*)rand_loc) = 0x6969696969696969;
}

void random_writes()
{
    for (int j = 0; j < NUM_WRITES; j++) {
        random_write();
    }
}

void check_page(void* page)
{
    uint64_t* conts = (uint64_t*)page;
    if (*conts != 0x4242424242424242) {
        fprintf(stderr, "ERROR (%p) not correctly restored: %p\n", page, *conts);
    }
}

void test3() {

  if (afl_snapshot_take(AFL_SNAPSHOT_BLOCK | AFL_SNAPSHOT_FDS) == 1)
    fprintf(stderr, "first time!\n");

  for (int i = 0; i < NUM_LOOPS; i++) {
    if (afl_snapshot_take(AFL_SNAPSHOT_BLOCK | AFL_SNAPSHOT_FDS) == 1)
        fprintf(stderr, "first time!\n");
      printf("Current Loop: %d\n", i);
      random_writes();
      afl_snapshot_restore();
      random_writes();
      afl_snapshot_restore();
      afl_snapshot_restore();
      random_write();
  }
}

void not_random_writes(void* pages[])
{
    for (int j = 0; j < NUM_PAGES; j++) {
        void* addr = pages[j];
        *(uint64_t*)addr = 0x6868686868686868;
    }
}

void not_random_writes_all()
{
    not_random_writes(pre_fork_pages);
    not_random_writes(post_fork_pages);
    not_random_writes(post_snapshot);
}

void test3b() {
      if (afl_snapshot_take(AFL_SNAPSHOT_BLOCK | AFL_SNAPSHOT_FDS) == 1)
    fprintf(stderr, "first time!\n");

  for (int i = 0; i < NUM_LOOPS; i++) {
    if (afl_snapshot_take(AFL_SNAPSHOT_BLOCK | AFL_SNAPSHOT_FDS) == 1)
        fprintf(stderr, "first time!\n");
      printf("Current Loop: %d\n", i);
      not_random_writes_all();
      afl_snapshot_restore();
      check_page(pre_fork_pages[0]);
      not_random_writes_all();
      afl_snapshot_restore();
      afl_snapshot_restore();
      not_random_writes_all();
  }
}

void print_maps()
{
    printf("\nMAPS\n\n");
    int fd = open("/proc/self/maps", O_RDONLY);
    char buf[4096];
    int size = 1;
    while (size > 0) {
        size = read(fd, buf, 4096);
        write(2, buf, size);
    }
    printf("\n\n");
}

int main() {
    randomly_map(pre_fork_pages, PRE_FORK_BASE);
    printf("First random page: %p\n", pre_fork_pages[0]);
    pid_t pid = fork();
    if (pid == 0) {
        printf("In child!\n");
        print_maps();
        afl_snapshot_init();
        randomly_map(post_fork_pages, POST_FORK_BASE);
        randomly_incl_excl(pre_fork_pages);
        randomly_incl_excl(post_fork_pages);
        void* data_start = &pre_fork_pages[0];
        void* data_end = &post_snapshot[NUM_PAGES-1];
        printf("DATA: %p - %p\n", data_start, data_end);
        data_start = PAGE_ALIGN(data_start);
        data_end = PAGE_ALIGN(data_end) + PAGE_SIZE;
        printf("DATA: %p - %p\n", data_start, data_end);
        afl_snapshot_exclude_vmrange(data_start, data_end);
        if (afl_snapshot_take(AFL_SNAPSHOT_NOSTACK) == 1)
            fprintf(stderr, "first time!\n");
        randomly_map(post_snapshot, POST_SNAP_BASE);
        randomly_incl_excl(post_snapshot);
        test3b();
        unmap_pages(pre_fork_pages);
        // test3b();
        // void* first_addr = pre_fork_pages[0];
        // *((uint64_t*)first_addr) = 0x6868686868686868;
        // print_maps();
    // test3();
    } else {
        printf("In parent, waiting on child...\n");
        int status = 0;
        waitpid(pid, &status, 0);
        printf("Child exited: %d, going as well\n", status);
    }

    return 0;
}


