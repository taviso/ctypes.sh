CFLAGS  := -std=gnu99 -fPIC -O0 -ggdb3 -Wall -Wextra -fvisibility=hidden
CPPFLAGS:= -Iinclude $(shell pkg-config --cflags libffi)
LDLIBS  := $(shell pkg-config --libs libffi)
PREFIX	:= /usr/local
UNAME    = $(shell uname -s)
SOEXT   := so

ifeq ($(UNAME), Linux)
	LDLIBS += -ldl
else ifeq ($(UNAME), Darwin)
	LDFLAGS += -bundle -undefined dynamic_lookup
	SOEXT = bundle
else
	LDFLAGS += -shared
  ifeq ($(shell uname -o), Msys)
	SOEXT = dll
  else ifeq ($(shell uname -o), Cygwin)
	SOEXT = dll
  endif
endif
ifeq ($(SOEXT), dll)
# TODO: Windows needs to link to the bash .dll or .exe
	LDLIBS  += bash.dll
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
