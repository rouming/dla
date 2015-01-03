# Makefile for dla tool

CC = $(CROSS_COMPILE)gcc
MACHINE = $(shell $(CC) -dumpmachine)

DEFINES=-D_GNU_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -D_XOPEN_SOURCE=600

LIBUNWIND            = 3rdparty/libunwind
LIBUNWIND_INC        = $(LIBUNWIND)/include
LIBUNWIND_MAIN_LIB   = $(LIBUNWIND)/src/.libs/libunwind.a
LIBUNWIND_PTRACE_LIB = $(LIBUNWIND)/src/.libs/libunwind-ptrace.a

# ARM
ifneq (, $(findstring arm, $(MACHINE)))
	LIBUNWIND_ARCH_LIB = $(LIBUNWIND)/src/.libs/libunwind-arm.a
# x86-64
else
	LIBUNWIND_ARCH_LIB = $(LIBUNWIND)/src/.libs/libunwind-x86_64.a
endif

LIBUNWIND_LIBS = $(LIBUNWIND_PTRACE_LIB) $(LIBUNWIND_ARCH_LIB) $(LIBUNWIND_MAIN_LIB)

CFLAGS = -std=gnu99 -MD -g -Wall -Werror -Wextra $(DEFINES) -I$(LIBUNWIND_INC)
LFLAGS = -lpthread -lrt

# x86-64
ifneq (, $(findstring x86, $(MACHINE)))
	LFLAGS += -llzma
endif

TOOLS  = dla filter-deadlock test-deadlock

all:
	$(MAKE) libunwind
	$(MAKE) build

libunwind: $(LIBUNWIND)/src/.libs/libunwind.a
build: $(TOOLS)

dla: dla.o proto.o $(LIBUNWIND_LIBS)
	$(CC) -o $@ $^ $(LFLAGS)

test-deadlock: test-deadlock.o
	$(CC) -o $@ $^ $(LFLAGS)

filter-deadlock: filter-deadlock.o
	$(CC) -o $@ $^

$(LIBUNWIND)/configure.ac:
	tar -xf $(LIBUNWIND).tar.gz -C 3rdparty
$(LIBUNWIND)/configure: $(LIBUNWIND)/configure.ac
	autoreconf -i $(LIBUNWIND)
$(LIBUNWIND)/Makefile: $(LIBUNWIND)/configure
	(cd $(LIBUNWIND); ./configure --disable-shared --target=$(MACHINE) --host=$(MACHINE))
$(LIBUNWIND)/src/.libs/libunwind.a: $(LIBUNWIND)/Makefile
	$(MAKE) -C $(LIBUNWIND)
$(LIBUNWIND)/src/.libs/libunwind-x86_64.a: $(LIBUNWIND)/Makefile
	$(MAKE) -C $(LIBUNWIND)
$(LIBUNWIND)/src/.libs/libunwind-arm.a: $(LIBUNWIND)/Makefile
	$(MAKE) -C $(LIBUNWIND)
$(LIBUNWIND)/src/.libs/libunwind-ptrace.a: $(LIBUNWIND)/Makefile
	$(MAKE) -C $(LIBUNWIND)

clean:
	$(RM) -r $(TOOLS) *~ *.o *.d $(LIBUNWIND)

.PHONY: clean all

SRCS = $(wildcard *.c)
DEPS = $(SRCS:.c=.d)
-include $(DEPS)
