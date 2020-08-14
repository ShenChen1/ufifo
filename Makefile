CROSS_COMPILE ?=
CC := $(CROSS_COMPILE)-gcc
AR := $(CROSS_COMPILE)-ar
LD := $(CROSS_COMPILE)-gcc
CFLAGS := -g -Os -Wall -Werror -Iinc
LDFLAGS := -lrt -lpthread

ifeq ($(SANITIZER), 1)
CFLAGS += -fsanitize=address -fno-omit-frame-pointer -fno-common
LDFLAGS += -fsanitize=address
endif

TARGET := pressure bytestream nolock record record-tag

all: ufifo $(TARGET)

clean:
	rm -rf $(TARGET) obj

test: $(TARGET)
	@for bin in $(TARGET); do ./$$bin || exit 1; done

SRC := src/mutex.c src/fdlock.c src/kfifo.c src/ufifo.c
OBJ := $(addprefix obj/,$(notdir $(patsubst %.c, %.o, $(SRC))))

obj/%.o: src/%.c
	@mkdir -p obj
	$(CC) -c $(CFLAGS) -fPIC -o $@ $<

ufifo: $(OBJ)
	$(AR) -src obj/lib$@.a $^
	$(LD) -shared -fPIC -o obj/lib$@.so $^

pressure: example/pressure.c obj/libufifo.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

bytestream: example/bytestream.c obj/libufifo.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

nolock: example/nolock.c obj/libufifo.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

record: example/record.c obj/libufifo.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

record-tag: example/record-tag.c obj/libufifo.a
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)