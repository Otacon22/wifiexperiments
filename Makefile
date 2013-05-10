CFLAGS=-O2

all: witest

witest: witest.c
	$(CC) -o $@ $< -lpcap $(CFLAGS)

clean:
	rm -f witest.o witest
