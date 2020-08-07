
all:
	gcc -g -Wall -Werror src/fdlock.c src/kfifo.c src/ufifo.c example/bytestream.c -Iinc -lrt