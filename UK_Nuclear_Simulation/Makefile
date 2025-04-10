# Simple Makefile for UK Nuclear Simulation Platform

CC = gcc
CFLAGS = -Wall -Wextra -g -I. # Include current dir for headers, add -g for debugging
LDFLAGS = -pthread          # Link pthreads library for nuclearControl

# List of source files
SRCS = nuclearControl.c missileSilo.c submarine.c radar.c satellite.c utils.c
# List of executables to build
TARGETS = nuclearControl missileSilo submarine radar satellite

# Default target: build all executables
all: $(TARGETS)

# Rule to build nuclearControl (needs pthreads)
nuclearControl: nuclearControl.c utils.c common.h utils.h
	$(CC) $(CFLAGS) nuclearControl.c utils.c -o nuclearControl $(LDFLAGS)

# Rule to build missileSilo
missileSilo: missileSilo.c utils.c common.h utils.h
	$(CC) $(CFLAGS) missileSilo.c utils.c -o missileSilo

# Rule to build submarine
submarine: submarine.c utils.c common.h utils.h
	$(CC) $(CFLAGS) submarine.c utils.c -o submarine

# Rule to build radar
radar: radar.c utils.c common.h utils.h
	$(CC) $(CFLAGS) radar.c utils.c -o radar

# Rule to build satellite
satellite: satellite.c utils.c common.h utils.h
	$(CC) $(CFLAGS) satellite.c utils.c -o satellite

# Rule to create the logs directory
logs:
	mkdir -p logs

# Clean up object files and executables
clean:
	rm -f $(TARGETS) *.o core.* core

# Phony targets (targets that don't represent files)
.PHONY: all clean logs

