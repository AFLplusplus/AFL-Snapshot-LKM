ifndef M
override M = $(PWD)
endif

ifndef LINUX_SYSTEM_MAP
override LINUX_SYSTEM_MAP = /proc/kallsyms
endif

obj-m += afl_snapshot.o
afl_snapshot-objs := memory.o files.o threads.o task_data.o snapshot.o hook.o module.o

ccflags-y := \
  -ggdb3 \
  -std=gnu99 \
  -Wframe-larger-than=1000000000 \
  -I$(M)/../include \
  -Wno-declaration-after-statement \
  $(CCFLAGS)

ifdef DEBUG
ccflags-y += -DDEBUG
endif

LINUX_DIR ?= /lib/modules/$(shell uname -r)/build

.PHONY: all

SUDO := $(shell which sudo)

all:
ifeq ($(SUDO),)
	env ARCH='$(ARCH)' LINUX_SYSTEM_MAP='$(LINUX_SYSTEM_MAP)' python3 lookup_symbols.py
else
	sudo env ARCH='$(ARCH)' LINUX_SYSTEM_MAP='$(LINUX_SYSTEM_MAP)' python3 lookup_symbols.py
endif

	$(MAKE) -C '$(LINUX_DIR)' M='$(M)' modules

clean:
	$(MAKE) -C '$(LINUX_DIR)' M='$(M)' clean
