# src/bin/pg_waldump/Makefile

PGFILEDESC = "pg_undo_dump - decode and display UNDO log"
PGAPPICON=win32

subdir = src/bin/pg_undo_dump
top_builddir = ../../..
include $(top_builddir)/src/Makefile.global

OBJS = pg_undo_dump.o $(RMGRDESCOBJS) $(WIN32RES)

override CPPFLAGS := -DFRONTEND $(CPPFLAGS)


all: pg_undo_dump

pg_undo_dump: $(OBJS) | submake-libpgport
	$(CC) $(CFLAGS) $^ $(LDFLAGS) $(LDFLAGS_EX) $(LIBS) -o $@$(X)

xlogreader.c: % : $(top_srcdir)/src/backend/access/transam/%
	rm -f $@ && $(LN_S) $< .

undorecordset_xlog.c: % : $(top_srcdir)/src/backend/access/undo/%
	rm -f $@ && $(LN_S) $< .

install: all installdirs
	$(INSTALL_PROGRAM) pg_undo_dump$(X) '$(DESTDIR)$(bindir)/pg_undo_dump$(X)'

installdirs:
	$(MKDIR_P) '$(DESTDIR)$(bindir)'

uninstall:
	rm -f '$(DESTDIR)$(bindir)/pg_undo_dump$(X)'

clean distclean maintainer-clean:
	rm -f pg_undo_dump$(X) $(OBJS)
	rm -rf tmp_check

check:
	$(prove_check)

installcheck:
	$(prove_installcheck)
