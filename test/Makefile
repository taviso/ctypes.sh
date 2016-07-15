CFLAGS	=-g

all: test

structs.so: structs.o
	$(CC) $(CFLAGS) $(LDFLAGS) -shared -o $@ $^

test: structs.so
	bash dlopen.sh
	bash alarm.sh
	bash math.sh
	bash stat.sh
	bash qsort.sh
	bash strfry.sh
	bash wget.sh
	bash structs.sh

clean:
	rm -f *.o *.so core *.core
