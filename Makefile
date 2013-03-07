all: test

test: test.c
	$(CC) -o $@ $< -lpcap

clean:
	rm -f test.o test
