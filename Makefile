CC := gcc
CFLAGS := -g -Wall -Wextra -02
LDFLAGES := -static

BINDIR := bin
SRCDIR := src
TARGET := $(BINDIR)/binmon

SOURCES := $(wildcard $(SRCDIR)/*.c)
OBJECTS := $(SOURCES:$(SRCDIR)/%.c=$(BINDIR)/%.o)

all: $(BINDIR) $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGES) -o $@ $^

$(BINDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BINDIR)/*

.PHONY: clean
