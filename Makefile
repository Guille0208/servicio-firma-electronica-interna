CC = gcc
CFLAGS = -std=c11 -O2 -Wall -Wextra -Wpedantic
PKG = $(shell pkg-config --cflags --libs openssl jansson)

.PHONY: all clean
all: firmad
firmad: src/firmad.c
	$(CC) $(CFLAGS) -o $@ $< $(PKG)
clean:
	rm -f firmad
