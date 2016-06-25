lib_LTLIBRARIES  	= ctypes.la
noinst_HEADERS		= types.h util.h
ctypes_la_SOURCES   = callback.c ctypes.c types.c unpack.c util.c struct/dutil.c struct/dwarves.c struct/gobuffer.c struct/pahole.c struct/strings.c struct/ctf_loader.c struct/dwarf_loader.c struct/dwarves_fprintf.c struct/elf_symtab.c struct/libctf.c struct/rbtree.c
ctypes_la_LDFLAGS   = -module -avoid-version -shared -export-symbols-regex '^.*_struct'
ctypes_la_CPPFLAGS  = -I../include
ctypes_la_CFLAGS    = -std=gnu99 $(FFI_CFLAGS)
ctypes_la_LIBADD    = $(FFI_LIBS)
