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
TARBALL		:= kafs-client-$(VERSION).tar
ZTARBALL	:= $(TARBALL).bz2

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
# Install everything
#
###############################################################################
MAN1	:= $(MANDIR)/man1
MAN5	:= $(MANDIR)/man5
MAN7	:= $(MANDIR)/man7
MAN8	:= $(MANDIR)/man8

install: all
	$(MAKE) -C src install
	$(MKDIR) -p -m755 $(DESTDIR)$(MAN1)/
	$(MKDIR) -p -m755 $(DESTDIR)$(MAN5)/
	$(MKDIR) -p -m755 $(DESTDIR)$(MAN7)/
	$(MKDIR) -p -m755 $(DESTDIR)$(MAN8)/
	$(INSTALL) -D -m 0644 man/*.1 $(DESTDIR)$(MAN1)/
	$(INSTALL) -D -m 0644 man/*.5 $(DESTDIR)$(MAN5)/
	$(INSTALL) -D -m 0644 man/*.7 $(DESTDIR)$(MAN7)/
	$(INSTALL) -D -m 0644 man/*.8 $(DESTDIR)$(MAN8)/
	$(INSTALL) -D -m 0644 conf/cellservdb.conf $(DESTDIR)$(DATADIR)/cellservdb.conf
	$(INSTALL) -D -m 0644 conf/etc.conf $(DESTDIR)$(ETCDIR)/kafs/client.conf
	$(INSTALL) -D -m 0644 conf/kafs_dns.conf $(DESTDIR)$(ETCDIR)/request-key.d/kafs_dns.conf
	$(INSTALL) -D -m 0644 conf/kafs-config.service $(DESTDIR)$(UNITDIR)/kafs-config.service
	$(INSTALL) -D -m 0644 conf/afs.mount $(DESTDIR)$(UNITDIR)/afs.mount
	$(MKDIR) -m755 $(DESTDIR)$(ETCDIR)/kafs/client.d

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
	$(RM) -r rpmbuild $(TARBALL)

###############################################################################
#
# Generate a tarball
#
###############################################################################
$(ZTARBALL):
	git archive --prefix=kafs-client-$(VERSION)/ --format tar HEAD | \
	bzip2 -9 >$(ZTARBALL)

tarball: $(ZTARBALL)

###############################################################################
#
# Generate an RPM
#
###############################################################################
SRCBALL	:= rpmbuild/SOURCES/$(TARBALL)
ZSRCBALL := rpmbuild/SOURCES/$(ZTARBALL)

BUILDID	:= .local
rpmver0	:= $(shell rpmspec -q ./redhat/kafs-client.spec --define "buildid $(BUILDID)")
rpmver1	:= $(word 1,$(rpmver0))
rpmver2	:= $(subst ., ,$(rpmver1))
rpmver3	:= $(lastword $(rpmver2))
rpmver4	:= $(patsubst %.$(rpmver3),%,$(rpmver1))
rpmver	:= $(patsubst kafs-client-%,%,$(rpmver4))
SRPM	:= rpmbuild/SRPMS/kafs-client-$(rpmver).src.rpm

RPMBUILDDIRS := \
	--define "_srcrpmdir $(CURDIR)/rpmbuild/SRPMS" \
	--define "_rpmdir $(CURDIR)/rpmbuild/RPMS" \
	--define "_sourcedir $(CURDIR)/rpmbuild/SOURCES" \
	--define "_specdir $(CURDIR)/rpmbuild/SPECS" \
	--define "_builddir $(CURDIR)/rpmbuild/BUILD" \
	--define "_buildrootdir $(CURDIR)/rpmbuild/BUILDROOT"

RPMFLAGS := \
	--define "buildid $(BUILDID)"

rpm: tarball
	mkdir -p rpmbuild
	chmod ug-s rpmbuild
	mkdir -p rpmbuild/{SPECS,SOURCES,BUILD,BUILDROOT,RPMS,SRPMS}
	cp $(ZTARBALL) $(ZSRCBALL)
	rpmbuild -ts $(ZSRCBALL) --define "_srcrpmdir rpmbuild/SRPMS" $(RPMFLAGS)
	rpmbuild --rebuild $(SRPM) $(RPMBUILDDIRS) $(RPMFLAGS)

rpmlint: rpm
	rpmlint $(SRPM) $(CURDIR)/rpmbuild/RPMS/*/kafs-client-{,debuginfo-}$(rpmver).*.rpm

.PHONY: rpmlint rpm tarball $(ZTARBALL)

###############################################################################
#
# Build debugging
#
###############################################################################
show_vars:
	@echo VERSION=$(VERSION)
	@echo TARBALL=$(TARBALL)
	@echo BUILDFOR=$(BUILDFOR)
