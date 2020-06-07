CFLAGS		= -g -Wall -Wsign-compare

include Makefile.config

all: lib progs

CPPFLAGS	+= -Iinclude -DETCDIR=\"$(ETCDIR)\"

###############################################################################
#
# Build a library to do config parsing and other stuff.
#
###############################################################################
lib: $(DEVELLIB)

$(DEVELLIB): $(SONAME)
	$(LNS) $< $@

$(SONAME): $(LIBNAME)
	$(LNS) $< $@

LIB_HEADERS	:= $(wildcard include/kafs/*.h)
LIB_FILES	:= \
	lib_cell_lookup.c \
	lib_cellserv.c \
	lib_dns_lookup.c \
	lib_object.c \
	lib_profile.c

LIBVERS		:= -shared -Wl,-soname,$(SONAME) -Wl,--version-script,version.lds
LIB_OBJS	:= $(patsubst %.c,%.os,$(LIB_FILES))

%.os: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -o $@ -c $<

$(LIBNAME): $(LIB_OBJS) version.lds Makefile
	$(CC) $(CFLAGS) -fPIC $(LDFLAGS) $(LIBVERS) -o $@ $(LIB_OBJS) $(LIBLIBS) \
		-lresolv

$(LIB_OBJS) : $(LIB_HEADERS) Makefile

LIB_DEPENDENCY	:= $(DEVELLIB)
LDFLAGS		+= -L.

#%.o: %.c $(LIB_HEADERS) Makefile
#	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ -c $<

###############################################################################
#
# Build stuff
#
###############################################################################
progs: \
	aklog-kafs \
	kafs-check-config \
	kafs-preload \
	kafs-dns

aklog-kafs: aklog-kafs.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< -lkrb5 -lkeyutils

kafs-check-config: kafs-check-config.o $(DEVELLIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ kafs-check-config.o -lkafs_client

kafs-preload: preload-cells.o $(DEVELLIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ preload-cells.o -lkafs_client

KAFS_DNS_OBJS := dns_main.o dns_afsdb_text.o dns_afsdb_v1.o
kafs-dns: $(KAFS_DNS_OBJS) $(DEVELLIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(KAFS_DNS_OBJS) \
		-lkafs_client -lkeyutils

kafs-check-config.o: $(LIB_HEADERS)
preload-cells.o: $(LIB_HEADERS)
$(KAFS_DNS_OBJS): $(LIB_HEADERS)

###############################################################################
#
# Install everything
#
###############################################################################
install: all
	mkdir -p $(DESTDIR)$(INCLUDEDIR)/kafs
	$(INSTALL) -D -m 0644 $(LIB_HEADERS) $(DESTDIR)$(INCLUDEDIR)/kafs/
	$(INSTALL) -D -m 0755 $(LIBNAME) $(DESTDIR)$(LIBDIR)/$(LIBNAME)
	$(LNS) $(LIBNAME) $(DESTDIR)$(LIBDIR)/$(SONAME)
	$(LNS) $(LIBDIR)/$(SONAME) $(DESTDIR)$(LIBDIR)/$(DEVELLIB)
	$(INSTALL) -D -m 0755 aklog-kafs $(DESTDIR)$(BINDIR)/aklog-kafs
	$(INSTALL) -D -m 0755 kafs-check-config $(DESTDIR)$(SBINDIR)/kafs-check-config
	$(INSTALL) -D -m 0755 kafs-preload $(DESTDIR)$(LIBEXECDIR)/kafs-preload
	$(INSTALL) -D -m 0755 kafs-dns $(DESTDIR)$(LIBEXECDIR)/kafs-dns

###############################################################################
#
# Clean up
#
###############################################################################
clean:
	$(RM) aklog-kafs kafs-check-config kafs-preload kafs-dns
	$(RM) $(DEVELLIB) $(SONAME) $(LIBNAME)
	$(RM) *.o *~ *.os

distclean: clean

###############################################################################
#
# Build debugging
#
###############################################################################
show_vars:
	@echo VERSION=$(VERSION)
