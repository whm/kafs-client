CFLAGS		= -g -O2 -Wall -Wsign-compare
MKDIR		= mkdir
INSTALL		= install
DESTDIR		=
ETCDIR		= /etc
BINDIR		= /usr/bin
LIBEXECDIR	= /usr/libexec
MANDIR		= /usr/share/man
DATADIR		= /usr/share/kafs-client
UNITDIR		= /usr/lib/systemd/system
SPECFILE	= redhat/kafs-client.spec

LNS		:= ln -sf

###############################################################################
#
# Determine the current package version from the specfile
#
###############################################################################
VERSION		:= $(word 2,$(shell grep "^Version:" $(SPECFILE)))

###############################################################################
#
# Guess at the appropriate word size
#
###############################################################################
BUILDFOR	:= $(shell file /usr/bin/make | sed -e 's!.*ELF \(32\|64\)-bit.*!\1!')-bit

ifeq ($(BUILDFOR),32-bit)
CFLAGS		+= -m32
else
ifeq ($(BUILDFOR),64-bit)
CFLAGS		+= -m64
endif
endif

###############################################################################
#
# Build stuff
#
###############################################################################
all:
	$(MAKE) -C src all

###############################################################################
#
# Clean up
#
###############################################################################
clean:
	$(MAKE) -C src clean
	$(RM) debugfiles.list debugsources.list

distclean: clean
	$(MAKE) -C src distclean
