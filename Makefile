
.PHONY: all

test: all
	sudo rmmod afl_snapshot || echo "Not loaded anyways..."
	sudo insmod src/afl_snapshot.ko
	./test/test3



all:
	cd src && $(MAKE)
	cd lib && $(MAKE)
	cd test && $(MAKE)

clean:
	cd src && $(MAKE) clean
	cd lib && $(MAKE) clean
	cd test && $(MAKE)

code-format:
	./.custom-format.py -i src/*.c
	./.custom-format.py -i src/*.h
	./.custom-format.py -i lib/*.c
	./.custom-format.py -i lib/*.h
	./.custom-format.py -i include/*.h
