CC = gcc
CFLAGS = -Wall -Wextra -O2 -I. $(shell pkg-config --cflags openssl)
LDFLAGS = $(shell pkg-config --libs openssl) -lpthread

TARGETS = control_center missile_silo radar_station satellite submarine

all: $(TARGETS)

nuclearControl: nuclearControl.c common.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

missileSilo: missileSilo.c common.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

radar: radar.c common.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

satellite: satellite.c common.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

submarine: submarine.c common.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGETS) nuclear_log.txt

.PHONY: all clean