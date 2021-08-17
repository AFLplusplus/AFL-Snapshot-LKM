/*
Manul - test file
-------------------------------------
Maksim Shudrak <mshudrak@salesforce.com> <mxmssh@gmail.com>

Copyright 2019 Salesforce.com, inc. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <signal.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "../include/afl_snapshot.h"
#include "../include/libaflsnapshot.h"

static int dev_fd;
void       LOG(const char *msg);
char *     log_name = "/dev/shm/stage4.log";

// static unsigned char *_buf = NULL;
static int  branch_1(int in, char *_buf);
static int  branch_2(char *buf);
void *      ThreadMain(void *argv);
static void p1w(void *addr) {
  LOG("Yes, General!\n");
  if (addr) ((volatile void (*)())addr)();
}

void LOG2WIN(const char *msg) {
  FILE *f = fopen("/dev/shm/WIN", "a");
  fprintf(f, "%s", msg);
  fclose(f);
}

void LOG(const char *msg) {
  FILE *f = fopen(log_name, "a");
  fprintf(f, "%s", msg);
  fclose(f);
}

void *open_file(char *name) {
  char *buf = NULL;
  int   size = 0;
  FILE *fp = fopen(name, "rb");
  if (!fp) {
    printf("Couldn't open file specified %s", name);
    return 0x00;
  }
  printf("Opening %s\n", name);
  // obtain file size:
  fseek(fp, 0, SEEK_END);
  size = ftell(fp);
  rewind(fp);

  // allocate memory to contain the whole file:
  buf = (char *)malloc(sizeof(char) * size);
  if (buf == NULL) {
    LOG("Unable to read file");
    exit(-1);
  }

  // copy the file into the buffer:
  fread(buf, 1, size, fp);
  fclose(fp);
  return buf;
}

int main() {
  dev_fd = afl_snapshot_init();
  printf("AFL-kit device opened %d\n", dev_fd);

  int stop = 0x00;

  signal(SIGPIPE, SIG_IGN);
  LOG("Initializing...\n");

  int server = socket(PF_INET, SOCK_STREAM, 0);
  if (server == -1) {
    printf("Could not create server socket: %d\n", errno);
    return 2;
  }
  LOG("[+]Socket \n");
  int retVal = 0;

  int enable = 1;
  if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) !=
      0) {
    printf("Could not set SO_REUSEADDR: %d\n", errno);
    retVal = 2;
    goto end;
  }
  LOG("[+]Socket opts\n");

  struct sockaddr_in addr = {0};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(8080);
  addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(server, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    printf("Could not bind: %d\n", errno);
    retVal = 3;
    goto end;
  }
  LOG("[+]Socket binded\n");
  if (listen(server, 20) != 0) {
    printf("Could not listen: %d\n", errno);
    retVal = 4;
    goto end;
  }
  LOG("[+]Going to point of __noreturn :3\n");
  while (!stop) {
    LOG("[I]main: loop prologue\n");
    struct sockaddr_storage theirAddr = {0};
    socklen_t               len = sizeof(theirAddr);
    int client = accept(server, (struct sockaddr *)&theirAddr, &len);
    if (client == -1) {
      printf("Accept returned %d\n", errno);
      continue;
    }
    stop = (int)(long)ThreadMain((void*)(long)client);
    LOG("[I]main: loop epilogue\n");
  }

end:
  close(server);
  return retVal;
}

#define HELLO "Hello, Fuzz!\n"
void *ThreadMain(void *argv) {
  char     name[0xff] = {0x00}, handshake[0xff] = {0x00}, *_buf = NULL;
  size_t   hssize = 0x00;
  uint32_t resp = 0x00;
  int      fd = (int)(long)argv;
  int      ok = 0x00;
  if (fd < 0) goto fall;

  ok = afl_snapshot_take(getpid(), AFL_SNAPSHOT_REGS | AFL_SNAPSHOT_FDS |
                         AFL_SNAPSHOT_MMAP);

  printf("snapshot taken %d\n", ok);

  strcat(handshake, HELLO);
  strcat(handshake, "\xff\x44\x33\x33\x00");
  hssize = strlen(handshake);

  ok = send(fd, handshake, hssize, 0x00);
  if (ok != hssize) goto fall;

  ok = recv(fd, (void *)&resp, sizeof(resp), 0x00);
  LOG2WIN("\n(1)|");
  LOG2WIN((void *)&resp);
  LOG2WIN("|\n");
  printf("recved data of %d is %s\n", ok, (char*)&resp);

  printf("Now, recovering snapshot\n");
  close(fd);
  afl_snapshot_restore();

  if (ok != sizeof(resp)) goto fall;
  if (resp != 0x333344ff) goto fall;
  ok = send(fd, "\x01", sizeof(char), 0x00);
  if (ok != sizeof(char)) goto fall;

  ok = recv(fd, name, 0xff - 1, 0x00);
  if (ok <= 0x00) goto fall;
  LOG2WIN("\n(2)|");
  LOG2WIN(name);
  LOG2WIN("|\n");
  name[ok] = 0x00;

  /* _buf = open_file(name); */
  _buf = malloc(0x1000);
  if (!_buf) return (void *)-1;

  recv(fd, _buf, 0x1000 - 1, MSG_DONTWAIT);
  if (_buf[0] == 0x01) p1w((void *)(long)branch_1(_buf[1], &(_buf[2])));

  if (malloc_usable_size(_buf)) {
    memset(_buf, 0x41, malloc_usable_size(_buf));
    free(_buf);
    _buf = NULL;
  }

  send(fd, "\x02", sizeof(char), 0x00);
  return NULL;

fall:
  printf("EXIT TRIGGERED!\n");
  close(fd);
  if (_buf) free(_buf);
  _buf = NULL;
  exit(0x00);
  return 0x00;
}

static int branch_1(int in, char *_buf) {
  int ret;
  LOG2WIN("Wiiiin");
  printf("in=%d, buf=%s\n", in, _buf);
  if (in % 0xae != 0x00) ret = 0x00;

  if (in % 17 == 0x00)
    if (_buf) ret = branch_2(_buf);
  return ret;
}

static int branch_2(char *buf) {
  LOG("hitted brach_2\n");
  if (buf[0] == 'P') {
    if (buf[1] == 'W') {
      if (buf[2] == 'N') {
        if (buf[3] == 'I') {
          LOG("Found it!\n");
          return 0xdeadbeef;
        }
      }
    }
  }
  return 0x00;
}
