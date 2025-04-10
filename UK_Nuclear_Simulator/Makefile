CC = gcc 
CFLAGS = -Wall -Wextra -O2 -I. -DENCRYPT_LOGS=1  # Set to 0 to disable log encryption

all: nuclearControl missileSilo submarine radar satellite

nuclearControl: nuclearControl.c common.c common.h
	$(CC) $(CFLAGS) -o $@ nuclearControl.c common.c $(LDFLAGS)

missileSilo: missileSilo.c
	$(CC) $(CFLAGS) -o missileSilo missileSilo.c

submarine: submarine.c
	$(CC) $(CFLAGS) -o submarine submarine.c

radar: radar.c
	$(CC) $(CFLAGS) -o radar radar.c

satellite: satellite.c
	$(CC) $(CFLAGS) -o satellite satellite.c

clean:
	rm -f nuclearControl missileSilo submarine radar satellite

