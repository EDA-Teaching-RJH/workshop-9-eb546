CC = gcc
CFLAGS = -Wall -Wextra -O2 -I.
LDFLAGS = -lpthread

all: nuclearControl missileSilo submarine radar satellite

nuclearControl: nuclearControl.c common.c common.h
	$(CC) $(CFLAGS) -o $@ nuclearControl.c common.c $(LDFLAGS)

missileSilo: missileSilo.c common.c common.h
	$(CC) $(CFLAGS) -o $@ missileSilo.c common.c $(LDFLAGS)

submarine: submarine.c common.c common.h
	$(CC) $(CFLAGS) -o $@ submarine.c common.c $(LDFLAGS)

radar: radar.c common.c common.h
	$(CC) $(CFLAGS) -o $@ radar.c common.c $(LDFLAGS)

satellite: satellite.c common.c common.h
	$(CC) $(CFLAGS) -o $@ satellite.c common.c $(LDFLAGS)

clean:
	rm -f nuclearControl missileSilo submarine radar satellite nuclear_log.txt targets.dat

test: all
	./nuclearControl --test &
	./missileSilo &
	./submarine &
	./radar &
	./satellite &

.PHONY: all clean test

