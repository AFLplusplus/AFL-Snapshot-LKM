ifndef M
override M = $(PWD)
endif

ifeq "$(shell uname -m)" "x86_64"
  ARCH := x64
else
  # not sure about this one
  ARCH := ia32
endif

#MAP = /opt/DEBIAN/fs/boot/System.map-4.19.160
#/boot/System.map-$(shell uname -r)
#SYMS = /opt/DEBIAN/fs/proc/kallsyms

obj-m += afl_snapshot.o
afl_snapshot-objs := memory.o files.o threads.o task_data.o snapshot.o hook.o module.o

ccflags-y := \
  -g3 -ggdb3 \
  -std=gnu99 \
  -Wframe-larger-than=100000000 \
  -I$(M)/../include \
  -Wno-declaration-after-statement \
  -fdata-sections \
  $(CCFLAGS)

ifdef DEBUG
  ccflags-y += -DDEBUG
endif

#LINUX_DIR ?= /lib/modules/$(shell uname -r)/build
LINUX_DIR ?= /opt/DEBIAN/stuff/linux-4.19.160
#/lib/modules/$(shell uname -r)/build

.PHONY: all

all:
	#env ARCH='$(ARCH)' LINUX_SYSTEM_MAP='$(LINUX_SYSTEM_MAP)' python3 lookup_symbols.py

	$(MAKE) -C '$(LINUX_DIR)' M='$(M)' modules

clean:
	$(MAKE) -C '$(LINUX_DIR)' M='$(M)' clean
