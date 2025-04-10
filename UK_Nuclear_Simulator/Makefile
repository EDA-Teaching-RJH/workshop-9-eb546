CC = gcc
CFLAGS = -Wall -Wextra -O2 -I.
LDFLAGS = -lssl -lcrypto -lpthread

all: nuclearControl missileSilo submarine radar satellite

nuclearControl: nuclearControl.c common.c globals.c common.h
	$(CC) $(CFLAGS) -o $@ nuclearControl.c common.c globals.c $(LDFLAGS)

missileSilo: missileSilo.c common.c globals.c common.h
	$(CC) $(CFLAGS) -o $@ missileSilo.c common.c globals.c $(LDFLAGS)

# Similar rules for other components...

clean:
	rm -f nuclearControl missileSilo submarine radar satellite
	rm -f nuclear_log.txt targets.dat

test: all
	./nuclearControl --test &
	./missileSilo &
	./submarine &
	./radar &
	./satellite &

.PHONY: all clean test

