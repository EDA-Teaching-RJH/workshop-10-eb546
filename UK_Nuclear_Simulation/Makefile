CC = gcc
CFLAGS = -Wall -Wextra -O2 -I.
LDFLAGS = -lssl -lcrypto -lpthread

all: nuclearControl missileSilo submarine radar satellite

nuclearControl: nuclearControl.c common.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

missileSilo: missileSilo.c common.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

submarine: submarine.c common.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

radar: radar.c common.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

satellite: satellite.c common.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

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
