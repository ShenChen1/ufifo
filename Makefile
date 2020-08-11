
all: bytestream record record-tag

clean:
	rm -rf bytestream record record-tag

test:
	./bytestream
	./record

bytestream: src/fdlock.c src/kfifo.c src/ufifo.c example/bytestream.c
	gcc -g -Wall -Werror -o $@ $^ -Iinc -lrt

record: src/fdlock.c src/kfifo.c src/ufifo.c example/record.c
	gcc -g -Wall -Werror -o $@ $^ -Iinc -lrt

record-tag: src/fdlock.c src/kfifo.c src/ufifo.c example/record-tag.c
	gcc -g -Wall -Werror -o $@ $^ -Iinc -lrt