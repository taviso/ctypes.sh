lib_LTLIBRARIES       = ctypes.la
noinst_HEADERS        = types.h util.h
noinst_LTLIBRARIES    = libstruct.la
ctypes_la_SOURCES     = callback.c ctypes.c types.c unpack.c util.c 
ctypes_la_LDFLAGS     = -module -avoid-version -shared -export-symbols-regex '^.*_struct'
ctypes_la_CPPFLAGS    = -I../include
ctypes_la_CFLAGS      = -std=gnu99 $(FFI_CFLAGS)
ctypes_la_LIBADD      = $(FFI_LIBS) libstruct.la $(LTLIBOBJS)
libstruct_la_SOURCES  = struct/dutil.c struct/dwarves.c struct/gobuffer.c struct/struct.c struct/strings.c struct/dwarf_loader.c struct/dwarves_fprintf.c struct/elf_symtab.c struct/rbtree.c
libstruct_la_CFLAGS   = -std=gnu99 -D_GNU_SOURCE
libstruct_la_CPPFLAGS = -I../include -I../lib
