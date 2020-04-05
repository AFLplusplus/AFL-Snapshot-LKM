
.PHONY: all

all:
	cd src && $(MAKE)
	cd lib && $(MAKE)

clean:
	cd src && $(MAKE) clean
	cd lib && $(MAKE) clean

code-format:
	./.custom-format.py -i src/*.c
	./.custom-format.py -i src/*.h
	./.custom-format.py -i lib/*.c
	./.custom-format.py -i lib/*.h
	./.custom-format.py -i include/*.h
