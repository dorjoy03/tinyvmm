CC=gcc
CFLAGS=-Wall -Wextra -O2
SOURCES=tinyvmm.c ttyS0.c
HEADERS=linux_params.h ttyS0.h
OBJECTS=$(SOURCES:.c=.o)

tinyvmm: $(OBJECTS)
	$(CC) $^ -o $@

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f tinyvmm $(OBJECTS)
