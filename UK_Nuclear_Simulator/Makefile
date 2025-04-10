CC = gcc
CFLAGS = -Wall -Wextra -O2 -I.
LDFLAGS = -lssl -lcrypto -lpthread

all: nuclearControl missileSilo submarine radar satellite

nuclearControl: nuclearControl.c common.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

missileSilo: missileSilo.c common.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

submarine: submarine.c common.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

radar: radar.c common.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

satellite: satellite.c common.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f nuclearControl missileSilo submarine radar satellite nuclear_log.txt

.PHONY: all clean

