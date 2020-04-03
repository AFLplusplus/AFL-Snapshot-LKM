
.PHONY: all

all:
	cd module && $(MAKE)

clean:
	cd module && $(MAKE) clean

code-format:
	./.custom-format.py -i module/*.c
	./.custom-format.py -i module/*.h
	./.custom-format.py -i include/*.h
