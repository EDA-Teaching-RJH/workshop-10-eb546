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

CFLAGS = -Wall -Wextra -O2 -I. -DENCRYPT_LOGS=1  # Set to 0 to disable log encryption


SecureMessage msg;
// ... receive message ...
if (verify_message(&msg, key)) {
    if (decrypt_message(&msg, key)) {
        printf("Decrypted: %s\n", msg.payload);
    }
}

decrypt_log_file("nuclear_log.txt", control_key);



