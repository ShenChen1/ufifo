
all: bytestream record

clean:
	rm -rf bytestream record

test:
	./bytestream
	./record

bytestream: src/fdlock.c src/kfifo.c src/ufifo.c example/bytestream.c
	gcc -g -Wall -Werror -o $@ $^ -Iinc -lrt

record: src/fdlock.c src/kfifo.c src/ufifo.c example/record.c
	gcc -g -Wall -Werror -o $@ $^ -Iinc -lrt