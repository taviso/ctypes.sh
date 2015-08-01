CFLAGS  = -std=gnu99 -fPIC -O0 -ggdb3 -Wall -Wextra -fvisibility=hidden
CPPFLAGS= -Iinclude $(shell pkg-config --cflags libffi)
UNAME   = $(shell uname -s)
LDLIBS  = $(shell pkg-config --libs libffi)
PREFIX	= /usr/local
SOEXT	= so
LDFLAGS =

ifeq ($(UNAME), Linux)
	LDLIBS 	+= -ldl
	LDFLAGS	+= -shared
endif

ifeq ($(UNAME), Darwin)
	SOEXT	 = bundle
	LDFLAGS	+= -bundle -undefined dynamic_lookup
endif

.PHONY: clean install

all: ctypes.$(SOEXT) ctypes.sh

ctypes.$(SOEXT): ctypes.o util.o callback.o types.o unpack.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f ctypes.$(SOEXT) *.o

install: ctypes.$(SOEXT) ctypes.sh
	install ctypes.sh $(PREFIX)/bin
	install ctypes.$(SOEXT) $(PREFIX)/lib
