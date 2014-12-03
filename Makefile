# Makefile for dla tool

# XXX
LIBUNWIND_INC     = $(HOME)/devel/libunwind/include
LIBUNWIND_LIBPATH = $(HOME)/devel/libunwind/src/.libs
LIBUNWIND_LIBS    = -lunwind-x86_64 -lunwind -lunwind-ptrace

CC = $(CROSS_COMPILE)gcc
DEFINES=-D_GNU_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -D_XOPEN_SOURCE=600

CFLAGS = -std=gnu99 -g -Wall -Wextra $(DEFINES) -I$(LIBUNWIND_INC)
LFLAGS = -L$(LIBUNWIND_LIBPATH) $(LIBUNWIND_LIBS) -lpthread

all: dla test-deadlock
%: %.c
	$(CC) $(CFLAGS) -o $@ $^ $(LFLAGS)

clean:
	$(RM) dla test-deadlock *~
