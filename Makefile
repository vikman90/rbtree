CFLAGS = -O2 -pipe -Wall -Wextra -Wpedantic
TARGET = rbtree

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(wildcard *.c)

clean:
	$(RM) $(TARGET)
