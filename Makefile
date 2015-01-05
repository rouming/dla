# Makefile for dla tool

VERSION=0.1

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
	(cd $(LIBUNWIND); ./configure --disable-shared \
								  --disable-minidebuginfo \
								  --target=$(MACHINE) \
								  --host=$(MACHINE))
$(LIBUNWIND)/src/.libs/libunwind.a: $(LIBUNWIND)/Makefile
	$(MAKE) -C $(LIBUNWIND)
$(LIBUNWIND)/src/.libs/libunwind-x86_64.a: $(LIBUNWIND)/Makefile
	$(MAKE) -C $(LIBUNWIND)
$(LIBUNWIND)/src/.libs/libunwind-arm.a: $(LIBUNWIND)/Makefile
	$(MAKE) -C $(LIBUNWIND)
$(LIBUNWIND)/src/.libs/libunwind-ptrace.a: $(LIBUNWIND)/Makefile
	$(MAKE) -C $(LIBUNWIND)

rpm:
	mkdir -p ~/rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
	rm -rf ~/rpmbuild/SOURCES/dla-$(VERSION).tar.gz
	cp -r . ~/rpmbuild/SOURCES/dla-$(VERSION)

	(cd ~/rpmbuild/SOURCES/dla-$(VERSION); \
	 rm -rf .git; \
	 make clean)
	(cd ~/rpmbuild/SOURCES/; \
	 tar -czf ./dla-$(VERSION).tar.gz ./dla-$(VERSION); \
	 rm -rf ./dla-$(VERSION))

	rpmbuild --clean \
			 --target=$(MACHINE) \
			 --define "_version $(VERSION)" \
			 -ba ./packaging/dla.spec
	rm -f ~/rpmbuild/SOURCES/dla-$(VERSION).tar.gz

install:
	for tool in $(TOOLS); do \
		mkdir -p $(DESTDIR)/usr/bin; \
		install -m 0755 $$tool $(DESTDIR)/usr/bin/$$tool; \
    done

clean:
	$(RM) -r $(TOOLS) *~ *.o *.d $(LIBUNWIND)

.PHONY: clean all install rpm

SRCS = $(wildcard *.c)
DEPS = $(SRCS:.c=.d)
-include $(DEPS)
