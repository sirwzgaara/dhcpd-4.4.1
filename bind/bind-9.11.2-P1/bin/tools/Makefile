# Copyright (C) 2009, 2010, 2012-2017  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

srcdir =	.

top_srcdir =	../..

VERSION=9.11.2-P1

# Copyright (C) 1999-2001, 2004, 2005, 2007, 2012, 2014, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# $Id: includes.in,v 1.21 2007/06/19 23:47:24 tbox Exp $

# Search for machine-generated header files in the build tree,
# and for normal headers in the source tree (${top_srcdir}).
# We only need to look in OS-specific subdirectories for the
# latter case, because there are no machine-generated OS-specific
# headers.

ISC_INCLUDES = -I/usr/src/dhcp-4.4.1/bind/bind-9.11.2-P1/lib/isc/include \
	-I${top_srcdir}/lib/isc \
	-I${top_srcdir}/lib/isc/include \
	-I${top_srcdir}/lib/isc/unix/include \
	-I${top_srcdir}/lib/isc/nothreads/include \
	-I${top_srcdir}/lib/isc/x86_32/include

ISCCC_INCLUDES = -I/usr/src/dhcp-4.4.1/bind/bind-9.11.2-P1/lib/isccc/include \
       -I${top_srcdir}/lib/isccc/include

ISCCFG_INCLUDES = -I/usr/src/dhcp-4.4.1/bind/bind-9.11.2-P1/lib/isccfg/include \
       -I${top_srcdir}/lib/isccfg/include

DNS_INCLUDES = -I/usr/src/dhcp-4.4.1/bind/bind-9.11.2-P1/lib/dns/include \
	-I${top_srcdir}/lib/dns/include

IRS_INCLUDES = -I/usr/src/dhcp-4.4.1/bind/bind-9.11.2-P1/lib/irs/include \
	-I${top_srcdir}/lib/irs/include

LWRES_INCLUDES = -I/usr/src/dhcp-4.4.1/bind/bind-9.11.2-P1/lib/lwres/include \
	-I${top_srcdir}/lib/lwres/unix/include \
	-I${top_srcdir}/lib/lwres/include

BIND9_INCLUDES = -I/usr/src/dhcp-4.4.1/bind/bind-9.11.2-P1/lib/bind9/include \
	-I${top_srcdir}/lib/bind9/include

TEST_INCLUDES = \
	-I${top_srcdir}/lib/tests/include

CINCLUDES =	${DNS_INCLUDES} ${ISC_INCLUDES} \
		${ISCCFG_INCLUDES} ${LWRES_INCLUDES} \
		${OMAPI_INCLUDES} ${BIND9_INCLUDES} 

CDEFINES =	 -DVERSION=\"${VERSION}\"
CWARNINGS =

DNSLIBS =	../../lib/dns/libdns.a 
BIND9LIBS =	../../lib/bind9/libbind9.a
ISCLIBS =	../../lib/isc/libisc.a 
ISCNOSYMLIBS =	../../lib/isc/libisc-nosymtbl.a
ISCCFGLIBS = 	../../lib/isccfg/libisccfg.a
LWRESLIBS =	../../lib/lwres/liblwres.a

DNSDEPLIBS =	../../lib/dns/libdns.a
BIND9DEPLIBS =	../../lib/bind9/libbind9.a
ISCDEPLIBS =	../../lib/isc/libisc.a
ISCCFGDEPLIBS = ../../lib/isccfg/libisccfg.a
LWRESDEPLIBS =	../../lib/lwres/liblwres.a

LIBS =		${ISCLIBS} -ldl -lz -lrt 
NOSYMLIBS =	${ISCNOSYMLIBS} -ldl -lz -lrt 

SUBDIRS =

DNSTAPTARGETS =	dnstap-read
NZDTARGETS =	named-nzd2nzf
TARGETS =	arpaname named-journalprint \
		named-rrchecker  nsec3hash \
		genrandom isc-hmac-fixup mdig \
		 

DNSTAPSRCS  =	dnstap-read.c
NZDSRCS  =	named-nzd2nzf.c
SRCS =		arpaname.c named-journalprint.c named-rrchecker.c \
		nsec3hash.c genrandom.c isc-hmac-fixup.c mdig.c \
		 

MANPAGES =	arpaname.1 dnstap-read.1 genrandom.8 \
		isc-hmac-fixup.8 mdig.1 named-journalprint.8 \
		named-nzd2nzf.8 named-rrchecker.1 nsec3hash.8

HTMLPAGES =	arpaname.html dnstap-read.html genrandom.html \
		isc-hmac-fixup.html mdig.html named-journalprint.html \
		named-nzd2nzf.html named-rrchecker.html nsec3hash.html

MANOBJS =	${MANPAGES} ${HTMLPAGES}

# Copyright (C) 1998-2009, 2011-2017  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

###
### Common Makefile rules for BIND 9.
###

###
### Paths
###
### Note: paths that vary by Makefile MUST NOT be listed
### here, or they won't get expanded correctly.

prefix =	/usr/local
exec_prefix =	${prefix}
bindir =	${exec_prefix}/bin
sbindir =	${exec_prefix}/sbin
includedir =	/usr/local/dhcp-4.4.1/include
libdir =	/usr/local/dhcp-4.4.1/lib
sysconfdir =	/etc
localstatedir =	/var
mandir =	${datarootdir}/man
datarootdir =   ${prefix}/share

DESTDIR =



top_builddir =	/usr/src/dhcp-4.4.1/bind/bind-9.11.2-P1

###
### All
###
### Makefile may define:
###	PREREQS
###	TARGETS

all: ${PREREQS} subdirs ${TARGETS} testdirs

###
### Subdirectories
###
### Makefile may define:
###	SUBDIRS
###	DEPDIRS

ALL_SUBDIRS = ${SUBDIRS} nulldir
ALL_TESTDIRS = ${TESTDIRS} nulldir

#
# We use a single-colon rule so that additional dependencies of
# subdirectories can be specified after the inclusion of this file.
# The "depend" and "testdirs" targets are treated the same way.
#
subdirs:
	@for i in ${ALL_SUBDIRS}; do \
		if [ "$$i" != "nulldir" -a -d $$i ]; then \
			echo "making all in `pwd`/$$i"; \
			(cd $$i; ${MAKE} ${MAKEDEFS} DESTDIR="${DESTDIR}" all) || exit 1; \
		fi; \
	done

#
# Tests are built after the targets instead of before
#
testdirs:
	@for i in ${ALL_TESTDIRS}; do \
		if [ "$$i" != "nulldir" -a -d $$i ]; then \
			echo "making all in `pwd`/$$i"; \
			(cd $$i; ${MAKE} ${MAKEDEFS} DESTDIR="${DESTDIR}" all) || exit 1; \
		fi; \
	done

install:: all

install uninstall clean distclean maintainer-clean doc docclean man manclean::
	@for i in ${ALL_SUBDIRS} ${ALL_TESTDIRS}; do \
		if [ "$$i" != "nulldir" -a -d $$i ]; then \
			echo "making $@ in `pwd`/$$i"; \
			(cd $$i; ${MAKE} ${MAKEDEFS} DESTDIR="${DESTDIR}" $@) || exit 1; \
		fi; \
	done

###
### C Programs
###
### Makefile must define
###	CC
### Makefile may define
###	CFLAGS
###	LDFLAGS
###	CINCLUDES
###	CDEFINES
###	CWARNINGS
### User may define externally
###     EXT_CFLAGS

CC = 		gcc
CFLAGS =	-g -O2  -fPIC
LDFLAGS =	
STD_CINCLUDES =	
STD_CDEFINES =	 -D_GNU_SOURCE
STD_CWARNINGS =	 -W -Wall -Wmissing-prototypes -Wcast-qual -Wwrite-strings -Wformat -Wpointer-arith -fno-strict-aliasing -fno-delete-null-pointer-checks

BUILD_CC = gcc
BUILD_CFLAGS = -g -O2  -fPIC
BUILD_CPPFLAGS =  -D_GNU_SOURCE 
BUILD_LDFLAGS = 
BUILD_LIBS = -ldl -lz -lrt 

.SUFFIXES:
.SUFFIXES: .c .o

ALWAYS_INCLUDES = -I${top_builddir} -I${top_srcdir}
ALWAYS_DEFINES = 
ALWAYS_WARNINGS =

ALL_CPPFLAGS = \
	${ALWAYS_INCLUDES} ${CINCLUDES} ${STD_CINCLUDES} \
	${ALWAYS_DEFINES} ${CDEFINES} ${STD_CDEFINES}

ALL_CFLAGS = ${EXT_CFLAGS} ${ALL_CPPFLAGS} ${CFLAGS} \
	${ALWAYS_WARNINGS} ${STD_CWARNINGS} ${CWARNINGS}

.c.o:
	${LIBTOOL_MODE_COMPILE} ${CC} ${ALL_CFLAGS} -c $<

SHELL = /bin/sh
LIBTOOL = 
LIBTOOL_MODE_COMPILE = ${LIBTOOL} 
LIBTOOL_MODE_INSTALL = ${LIBTOOL} 
LIBTOOL_MODE_LINK = ${LIBTOOL} 
LIBTOOL_MODE_UNINSTALL = ${LIBTOOL} 
PURIFY = 

MKDEP = ${SHELL} ${top_builddir}/make/mkdep

###
### This is a template compound command to build an executable binary with
### an internal symbol table.
### This process is tricky.  We first link all objects including a tentative
### empty symbol table, then get a tentative list of symbols from the resulting
### binary ($@tmp0).  Next, we re-link all objects, but this time with the
### symbol table just created ($tmp@1).  The set of symbols should be the same,
### but the corresponding addresses would be changed due to the difference on
### the size of symbol tables.  So we create the symbol table and re-create the
### objects once again.  Finally, we check the symbol table embedded in the
### final binaryis consistent with the binary itself; otherwise the process is
### terminated.
###
### To minimize the overhead of creating symbol tables, the autoconf switch
### --enable-symtable takes an argument so that the symbol table can be created
### on a per application basis: unless the argument is set to "all", the symbol
### table is created only when a shell (environment) variable "MAKE_SYMTABLE" is
### set to a non-null value in the rule to build the executable binary.
###
### Each Makefile.in that uses this macro is expected to define "LIBS" and
### "NOSYMLIBS"; the former includes libisc with an empty symbol table, and
### the latter includes libisc without the definition of a symbol table.
### The rule to make the executable binary will look like this
### binary: ${OBJS}
###     #export MAKE_SYMTABLE="yes"; \  <- enable if symtable is always needed
###	export BASEOBJS="${OBJS}"; \
###	${FINALBUILDCMD}
###
### Normally, ${LIBS} includes all necessary libraries to build the binary;
### there are some exceptions however, where the rule lists some of the
### necessary libraries explicitly in addition to (or instead of) ${LIBS},
### like this:
### binary: ${OBJS}
###     cc -o $@ ${OBJS} ${OTHERLIB1} ${OTHERLIB2} ${lIBS}
### in order to modify such a rule to use this compound command, a separate
### variable "LIBS0" should be deinfed for the explicitly listed libraries,
### while making sure ${LIBS} still includes libisc.  So the above rule would
### be modified as follows:
### binary: ${OBJS}
###	export BASEOBJS="${OBJS}"; \
###	export LIBS0="${OTHERLIB1} ${OTHERLIB2}"; \
###     ${FINALBUILDCMD}
### See bin/check/Makefile.in for a complete example of the use of LIBS0.
###
FINALBUILDCMD = if [ X"${MKSYMTBL_PROGRAM}" = X -o X"$${MAKE_SYMTABLE:-${ALWAYS_MAKE_SYMTABLE}}" = X ] ; then \
		${LIBTOOL_MODE_LINK} ${PURIFY} ${CC} ${ALL_CFLAGS} ${LDFLAGS} \
		-o $@ $${BASEOBJS} $${LIBS0} ${LIBS}; \
	else \
		rm -f $@tmp0; \
		${LIBTOOL_MODE_LINK} ${PURIFY} ${CC} ${ALL_CFLAGS} ${LDFLAGS} \
		-o $@tmp0 $${BASEOBJS} $${LIBS0} ${LIBS} || exit 1; \
		rm -f $@-symtbl.c $@-symtbl.o; \
		${MKSYMTBL_PROGRAM} ${top_srcdir}/util/mksymtbl.pl \
		-o $@-symtbl.c $@tmp0 || exit 1; \
		$(MAKE) $@-symtbl.o || exit 1; \
		rm -f $@tmp1; \
		${LIBTOOL_MODE_LINK} ${PURIFY} ${CC} ${ALL_CFLAGS} ${LDFLAGS} \
		-o $@tmp1 $${BASEOBJS} $@-symtbl.o $${LIBS0} ${NOSYMLIBS} || exit 1; \
		rm -f $@-symtbl.c $@-symtbl.o; \
		${MKSYMTBL_PROGRAM} ${top_srcdir}/util/mksymtbl.pl \
		-o $@-symtbl.c $@tmp1 || exit 1; \
		$(MAKE) $@-symtbl.o || exit 1; \
		${LIBTOOL_MODE_LINK} ${PURIFY} ${CC} ${ALL_CFLAGS} ${LDFLAGS} \
		-o $@tmp2 $${BASEOBJS} $@-symtbl.o $${LIBS0} ${NOSYMLIBS}; \
		${MKSYMTBL_PROGRAM} ${top_srcdir}/util/mksymtbl.pl \
		-o $@-symtbl2.c $@tmp2; \
		count=0; \
		until diff $@-symtbl.c $@-symtbl2.c > /dev/null ; \
		do \
			count=`expr $$count + 1` ; \
			test $$count = 42 && exit 1 ; \
			rm -f $@-symtbl.c $@-symtbl.o; \
			${MKSYMTBL_PROGRAM} ${top_srcdir}/util/mksymtbl.pl \
			-o $@-symtbl.c $@tmp2 || exit 1; \
			$(MAKE) $@-symtbl.o || exit 1; \
			${LIBTOOL_MODE_LINK} ${PURIFY} ${CC} ${ALL_CFLAGS} \
			${LDFLAGS} -o $@tmp2 $${BASEOBJS} $@-symtbl.o \
			$${LIBS0} ${NOSYMLIBS}; \
			${MKSYMTBL_PROGRAM} ${top_srcdir}/util/mksymtbl.pl \
			-o $@-symtbl2.c $@tmp2; \
		done ; \
		mv $@tmp2 $@; \
		rm -f $@tmp0 $@tmp1 $@tmp2 $@-symtbl2.c; \
	fi

cleandir: distclean
superclean: maintainer-clean

clean distclean maintainer-clean::
	rm -f *.o *.o *.lo *.la core *.core *-symtbl.c *tmp0 *tmp1 *tmp2
	rm -rf .depend .libs

distclean maintainer-clean::
	rm -f Makefile

depend:
	@for i in ${ALL_SUBDIRS} ${ALL_TESTDIRS}; do \
		if [ "$$i" != "nulldir" -a -d $$i ]; then \
			echo "making depend in `pwd`/$$i"; \
			(cd $$i; ${MAKE} ${MAKEDEFS} DESTDIR="${DESTDIR}" $@) || exit 1; \
		fi; \
	done
	@if [ X"${srcdir}" != X. ] ; then \
		if [ X"${SRCS}" != X -a X"${PSRCS}" != X ] ; then \
			echo ${MKDEP} -vpath ${srcdir} ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${SRCS}; \
			${MKDEP} -vpath ${srcdir} ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${SRCS}; \
			echo ${MKDEP} -vpath ${srcdir} -ap ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${PSRCS}; \
			${MKDEP} -vpath ${srcdir} -ap ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${PSRCS}; \
			${DEPENDEXTRA} \
		elif [ X"${SRCS}" != X ] ; then \
			echo ${MKDEP} -vpath ${srcdir} ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${SRCS}; \
			${MKDEP} -vpath ${srcdir} ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${SRCS}; \
			${DEPENDEXTRA} \
		elif [ X"${PSRCS}" != X ] ; then \
			echo ${MKDEP} -vpath ${srcdir} ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${PSRCS}; \
			${MKDEP} -vpath ${srcdir} -p ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${PSRCS}; \
			${DEPENDEXTRA} \
		fi \
	else \
		if [ X"${SRCS}" != X -a X"${PSRCS}" != X ] ; then \
			echo ${MKDEP} ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${SRCS}; \
			${MKDEP} ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${SRCS}; \
			echo ${MKDEP} -ap ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${PSRCS}; \
			${MKDEP} -ap ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${PSRCS}; \
			${DEPENDEXTRA} \
		elif [ X"${SRCS}" != X ] ; then \
			echo ${MKDEP} ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${SRCS}; \
			${MKDEP} ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${SRCS}; \
			${DEPENDEXTRA} \
		elif [ X"${PSRCS}" != X ] ; then \
			echo ${MKDEP} ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${PSRCS}; \
			${MKDEP} -p ${ALL_CPPFLAGS} ${ALL_CFLAGS} ${PSRCS}; \
			${DEPENDEXTRA} \
		fi \
	fi

FORCE:

###
### Libraries
###

AR =		/usr/bin/ar
ARFLAGS =	cruv
RANLIB =	ranlib

###
### Installation
###

INSTALL =		/usr/bin/install -c
INSTALL_PROGRAM =	${INSTALL}
LINK_PROGRAM =		ln -s
INSTALL_SCRIPT =	${INSTALL}
INSTALL_DATA =		${INSTALL} -m 644
INSTALL_LIBRARY =	${INSTALL_DATA}

###
### Programs used when generating documentation.  It's ok for these
### not to exist when not generating documentation.
###

XSLTPROC =		/usr/bin/xsltproc --novalid --xinclude --nonet
XMLLINT =		/usr/bin/xmllint
PERL =			/usr/bin/perl
LATEX =			latex
PDFLATEX =		pdflatex
DBLATEX =		dblatex
W3M =			w3m
PANDOC =		pandoc

###
### Script language program used to create internal symbol tables
###
MKSYMTBL_PROGRAM =	/usr/bin/perl

###
### Switch to create internal symbol table selectively
###
ALWAYS_MAKE_SYMTABLE =	

###
### DocBook -> HTML
### DocBook -> man page
###

.SUFFIXES: .docbook .html .1 .2 .3 .4 .5 .6 .7 .8

.docbook.html:
	${XSLTPROC} -o $@ ${top_srcdir}/doc/xsl/isc-docbook-html.xsl $<

.docbook.1:
	${XSLTPROC} -o $@ ${top_srcdir}/doc/xsl/isc-manpage.xsl $<

.docbook.2:
	${XSLTPROC} -o $@ ${top_srcdir}/doc/xsl/isc-manpage.xsl $<

.docbook.3:
	${XSLTPROC} -o $@ ${top_srcdir}/doc/xsl/isc-manpage.xsl $<

.docbook.4:
	${XSLTPROC} -o $@ ${top_srcdir}/doc/xsl/isc-manpage.xsl $<

.docbook.5:
	${XSLTPROC} -o $@ ${top_srcdir}/doc/xsl/isc-manpage.xsl $<

.docbook.6:
	${XSLTPROC} -o $@ ${top_srcdir}/doc/xsl/isc-manpage.xsl $<

.docbook.7:
	${XSLTPROC} -o $@ ${top_srcdir}/doc/xsl/isc-manpage.xsl $<

.docbook.8:
	${XSLTPROC} -o $@ ${top_srcdir}/doc/xsl/isc-manpage.xsl $<


arpaname: arpaname.o ${ISCDEPLIBS} ${DNSDEPLIBS}
	${LIBTOOL_MODE_LINK} ${PURIFY} ${CC} ${CFLAGS} ${LDFLAGS} \
		-o $@ arpaname.o ${ISCLIBS} ${LIBS}

named-journalprint: named-journalprint.o ${ISCDEPLIBS} ${DNSDEPLIBS}
	export BASEOBJS="named-journalprint.o"; \
	export LIBS0="${DNSLIBS}"; \
	${FINALBUILDCMD}

named-rrchecker: named-rrchecker.o ${ISCDEPLIBS} ${DNSDEPLIBS}
	export BASEOBJS="named-rrchecker.o"; \
	export LIBS0="${DNSLIBS}"; \
	${FINALBUILDCMD}

nsec3hash: nsec3hash.o ${ISCDEPLIBS} ${DNSDEPLIBS}
	export BASEOBJS="nsec3hash.o"; \
	export LIBS0="${DNSLIBS}"; \
	${FINALBUILDCMD}

isc-hmac-fixup: isc-hmac-fixup.o ${ISCDEPLIBS}
	export BASEOBJS="isc-hmac-fixup.o"; \
	export LIBS0="${ISCLIBS}"; \
	${FINALBUILDCMD}

genrandom: genrandom.o
	${LIBTOOL_MODE_LINK} ${PURIFY} ${CC} ${CFLAGS} ${LDFLAGS} \
		-o $@ genrandom.o  ${LIBS}

mdig: mdig.o ${ISCDEPLIBS} ${DNSDEPLIBS} ${BIND9DEPLIBS}
	export BASEOBJS="mdig.o"; \
	export LIBS0="${DNSLIBS} ${BIND9LIBS}"; \
	${FINALBUILDCMD}

dnstap-read: dnstap-read.o ${ISCDEPLIBS} ${DNSDEPLIBS}
	export BASEOBJS="dnstap-read.o"; \
	export LIBS0="${DNSLIBS}"; \
	${FINALBUILDCMD}

named-nzd2nzf: named-nzd2nzf.o ${NZDDEPLIBS}
	export BASEOBJS="named-nzd2nzf.o"; \
	export LIBS0="${ISCCFGLIBS} ${ISCCCLIBS} ${BIND9LIBS} ${DNSLIBS}"; \
	${FINALBUILDCMD}

doc man:: ${MANOBJS}

docclean manclean maintainer-clean::
	rm -f ${MANOBJS}

installdirs:
	$(SHELL) ${top_srcdir}/mkinstalldirs ${DESTDIR}${bindir}
	$(SHELL) ${top_srcdir}/mkinstalldirs ${DESTDIR}${sbindir}
	$(SHELL) ${top_srcdir}/mkinstalldirs ${DESTDIR}${mandir}/man1
	$(SHELL) ${top_srcdir}/mkinstalldirs ${DESTDIR}${mandir}/man8

nzd:
	${LIBTOOL_MODE_INSTALL} ${INSTALL_PROGRAM} named-nzd2nzf \
		${DESTDIR}${sbindir}
	${INSTALL_DATA} ${srcdir}/named-nzd2nzf.8 ${DESTDIR}${mandir}/man8

dnstap:
	${LIBTOOL_MODE_INSTALL} ${INSTALL_PROGRAM} dnstap-read \
		${DESTDIR}${bindir}
	${INSTALL_DATA} ${srcdir}/dnstap-read.1 ${DESTDIR}${mandir}/man1

install:: ${TARGETS} installdirs  
	${LIBTOOL_MODE_INSTALL} ${INSTALL_PROGRAM} arpaname \
		${DESTDIR}${bindir}
	${LIBTOOL_MODE_INSTALL} ${INSTALL_PROGRAM} named-journalprint \
		${DESTDIR}${sbindir}
	${LIBTOOL_MODE_INSTALL} ${INSTALL_PROGRAM} named-rrchecker \
		${DESTDIR}${bindir}
	${LIBTOOL_MODE_INSTALL} ${INSTALL_PROGRAM} nsec3hash \
		${DESTDIR}${sbindir}
	${LIBTOOL_MODE_INSTALL} ${INSTALL_PROGRAM} genrandom \
		${DESTDIR}${sbindir}
	${LIBTOOL_MODE_INSTALL} ${INSTALL_PROGRAM} isc-hmac-fixup \
		${DESTDIR}${sbindir}
	${LIBTOOL_MODE_INSTALL} ${INSTALL_PROGRAM} mdig \
		${DESTDIR}${bindir}
	${INSTALL_DATA} ${srcdir}/arpaname.1 ${DESTDIR}${mandir}/man1
	${INSTALL_DATA} ${srcdir}/isc-hmac-fixup.8 ${DESTDIR}${mandir}/man8
	${INSTALL_DATA} ${srcdir}/named-journalprint.8 ${DESTDIR}${mandir}/man8
	${INSTALL_DATA} ${srcdir}/named-rrchecker.1 ${DESTDIR}${mandir}/man1
	${INSTALL_DATA} ${srcdir}/nsec3hash.8 ${DESTDIR}${mandir}/man8
	${INSTALL_DATA} ${srcdir}/genrandom.8 ${DESTDIR}${mandir}/man8
	${INSTALL_DATA} ${srcdir}/mdig.1 ${DESTDIR}${mandir}/man1

uninstall::
	rm -f ${DESTDIR}${mandir}/man1/mdig.1
	rm -f ${DESTDIR}${mandir}/man8/genrandom.8
	rm -f ${DESTDIR}${mandir}/man8/nsec3hash.8
	rm -f ${DESTDIR}${mandir}/man1/named-rrchecker.1
	rm -f ${DESTDIR}${mandir}/man8/named-journalprint.8
	rm -f ${DESTDIR}${mandir}/man8/isc-hmac-fixup.8
	rm -f ${DESTDIR}${mandir}/man1/arpaname.1
	${LIBTOOL_MODE_UNINSTALL} rm -f \
		${DESTDIR}${bindir}/mdig
	${LIBTOOL_MODE_UNINSTALL} rm -f \
		${DESTDIR}${sbindir}/isc-hmac-fixup
	${LIBTOOL_MODE_UNINSTALL} rm -f \
		${DESTDIR}${sbindir}/genrandom
	${LIBTOOL_MODE_UNINSTALL} rm -f \
		${DESTDIR}${sbindir}/nsec3hash
	${LIBTOOL_MODE_UNINSTALL} rm -f \
		${DESTDIR}${bindir}/named-rrchecker
	${LIBTOOL_MODE_UNINSTALL} rm -f \
		${DESTDIR}${sbindir}/named-journalprint
	${LIBTOOL_MODE_UNINSTALL} rm -f \
		${DESTDIR}${bindir}/arpaname
	rm -f ${DESTDIR}${mandir}/man1/dnstap-read.1
	${LIBTOOL_MODE_UNINSTALL} rm -f \
		${DESTDIR}${bindir}/dnstap-read
	rm -f ${DESTDIR}${mandir}/man8/named-nzd2nzf.8
	${LIBTOOL_MODE_UNINSTALL} rm -f \
		${DESTDIR}${sbindir}/named-nzd2nzf

clean distclean::
	rm -f ${TARGETS}
