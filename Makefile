CFLAGS  =-std=gnu99 -fPIC -O0 -ggdb3 -Wall -Wextra -fvisibility=hidden
CPPFLAGS=-Iinclude
LDLIBS  =-lffi -ldl

.PHONY: clean

all: ctypes.so ctypes.sh

ctypes.so: ctypes.o util.o callback.o types.o unpack.o
	$(CC) $(LDFLAGS) $(CFLAGS) -shared -o $@ $^ $(LDLIBS)

ctypes.sh: ctypes.so
	nm -D --defined $< | grep _struct | sed 's#.* D \(.*\)_struct#enable -f $(abspath $<) \1#g' > $@

clean:
	rm -f ctypes.so *.o ctypes.sh
