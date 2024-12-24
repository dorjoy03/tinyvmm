CC=gcc
CFLAGS=-Wall -Wextra -O2
SOURCES=tinyvmm.c ttyS0.c uart.c
HEADERS=linux_params.h ttyS0.h uart.h
OBJECTS=$(SOURCES:.c=.o)

tinyvmm: $(OBJECTS)
	$(CC) $^ -o $@

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f tinyvmm $(OBJECTS)
