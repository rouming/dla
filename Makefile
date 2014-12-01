# Makefile for dla tool

# XXX
LIBUNWIND_INC     = $(HOME)/devel/libunwind-1.1/include
LIBUNWIND_LIBPATH = $(HOME)/roman/devel/libunwind-1.1/src/.libs
LIBUNWIND_LIBS    = -lunwind-x86_64 -lunwind -lunwind-ptrace

CC = $(CROSS_COMPILE)gcc
DEFINES=-D_GNU_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -D_XOPEN_SOURCE=600

CFLAGS = -std=gnu99 -g -Wall -Wextra $(DEFINES) -I$(LIBUNWIND_INC)
LFLAGS = -L$(LIBUNWIND_LIBPATH) $(LIBUNWIND_LIBS)

all: dla
%: %.c
	$(CC) $(CFLAGS) -o $@ $^ $(LFLAGS)

clean:
	$(RM) dla *~
