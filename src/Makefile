ifndef M
override M = $(PWD)
endif

obj-m += afl_snapshot.o
afl_snapshot-objs := associated_data.o snapshot.o hook.o module.o

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
	$(MAKE) -C '$(LINUX_DIR)' M='$(M)' modules

clean:
	$(MAKE) -C '$(LINUX_DIR)' M='$(M)' clean
