ifndef M
override M = $(PWD)
endif

ifeq "$(shell uname -m)" "x86_64"
  ARCH := x64
else
  # not sure about this one
  ARCH := ia32
endif

MAP = /boot/System.map-$(shell uname -r)
SYMS = /proc/kallsyms

ifndef LINUX_SYSTEM_MAP
  ifdef KALLSYMS
    override LINUX_SYSTEM_MAP = /proc/kallsyms
  else
    ifeq "$(shell test -r $(MAP) && echo 1)" "1"
      override LINUX_SYSTEM_MAP = $(MAP)
    else
      ifeq "$(shell test -r $(SYMS) && echo 1)" "1"
        override LINUX_SYSTEM_MAP = $(SYMS)
      else
        $(error no readable $(MAP) and no readable $(SYMS) found)
      endif
    endif
  endif
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

all:
	env ARCH='$(ARCH)' LINUX_SYSTEM_MAP='$(LINUX_SYSTEM_MAP)' python3 lookup_symbols.py

	$(MAKE) -C '$(LINUX_DIR)' M='$(M)' modules

clean:
	$(MAKE) -C '$(LINUX_DIR)' M='$(M)' clean
