# SPDX-License-Identifier: MIT
CC      ?= gcc
CFLAGS  ?= -O2 -std=gnu11 -Wall -Wextra -Isrc
LDFLAGS ?= -static -lz -lpthread

SRC := $(wildcard src/*.c)
BIN := forge

.PHONY: all clean
all: $(BIN)

$(BIN): $(SRC) src/*.h
	$(CC) $(CFLAGS) $(SRC) -o $(BIN) $(LDFLAGS)

clean:
	rm -f $(BIN)
