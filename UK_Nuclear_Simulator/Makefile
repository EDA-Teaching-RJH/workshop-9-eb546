CC = gcc CFLAGS = -Wall -Wextra

all: nuclearControl missileSilo submarine radar satellite

nuclearControl: nuclearControl.c
	$(CC) $(CFLAGS) -o nuclearControl nuclearControl.c

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

	