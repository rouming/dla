# Makefile for dla tool

# XXX
LIBUNWIND_INC     = $(HOME)/devel/libunwind/include
LIBUNWIND_LIBPATH = $(HOME)/devel/libunwind/src/.libs
LIBUNWIND_LIBS    = -lunwind-x86_64 -lunwind -lunwind-ptrace

CC = $(CROSS_COMPILE)gcc
DEFINES=-D_GNU_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -D_XOPEN_SOURCE=600

CFLAGS = -std=gnu99 -MD -g -Wall -Werror -Wextra $(DEFINES) -I$(LIBUNWIND_INC)
LFLAGS = -L$(LIBUNWIND_LIBPATH) $(LIBUNWIND_LIBS) -lpthread -lrt

TOOLS  = dla filter-deadlock test-deadlock

SRCS = $(wildcard *.c)
DEPS = $(SRCS:.c=.d)
-include $(DEPS)

all: $(TOOLS)

dla: dla.o proto.o
	$(CC) -o $@ $^ $(LFLAGS)

test-deadlock: test-deadlock.o
	$(CC) -o $@ $^ $(LFLAGS)

filter-deadlock: filter-deadlock.o
	$(CC) -o $@ $^ $(LFLAGS)

clean:
	$(RM) $(TOOLS) *~ *.o *.d
