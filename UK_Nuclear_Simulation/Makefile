CC = gcc
CFLAGS = -Wall -Wextra -O2 -I.
LDFLAGS = -lssl -lcrypto -lpthread

all: nuclearControl missileSilo submarine radar satellite

nuclearControl: nuclearControl.c common.c common.h
	$(CC) $(CFLAGS) -o $@ $< common.c $(LDFLAGS)

missileSilo: missileSilo.c common.c common.h
	$(CC) $(CFLAGS) -o $@ $< common.c $(LDFLAGS)

submarine: submarine.c common.c common.h
	$(CC) $(CFLAGS) -o $@ $< common.c $(LDFLAGS)

radar: radar.c common.c common.h
	$(CC) $(CFLAGS) -o $@ $< common.c $(LDFLAGS)

satellite: satellite.c common.c common.h
	$(CC) $(CFLAGS) -o $@ $< common.c $(LDFLAGS)

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

