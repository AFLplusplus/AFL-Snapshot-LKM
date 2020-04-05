override CFLAGS += -I ../include -g

.PHONY: all

all: libaflsnapshot.so

libaflsnapshot.so: libaflsnapshot.o
	$(CC) -fPIC -shared libaflsnapshot.o -o libaflsnapshot.so $(LDFLAGS)

clean:
	rm -f libaflsnapshot.so
