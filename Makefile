CROSS_COMPILE ?=
CC := $(CROSS_COMPILE)-gcc
AR := $(CROSS_COMPILE)-ar
LD := $(CROSS_COMPILE)-g++
CFLAGS := -g -Wall -Werror -Os -Iinc
LDFLAGS := -lrt -lpthread

TARGET := bytestream record record-tag epoll

all: ufifo $(TARGET)

clean:
	rm -rf $(TARGET) obj

test: $(TARGET)
	./bytestream
	./record
	./record-tag
	./epoll

SRC := src/mutex.c src/fdlock.c src/kfifo.c src/ufifo.c
OBJ := $(addprefix obj/,$(notdir $(patsubst %.c, %.o, $(SRC))))

obj/%.o: src/%.c
	@mkdir -p obj
	$(CC) -c $(CFLAGS) -fPIC -o $@ $<

ufifo: $(OBJ)
	$(AR) -src obj/lib$@.a $^
	$(LD) -shared -fPIC -o obj/lib$@.so $^

bytestream: example/bytestream.c obj/libufifo.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

record: example/record.c obj/libufifo.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

record-tag: example/record-tag.c obj/libufifo.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

epoll: example/epoll.c obj/libufifo.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)