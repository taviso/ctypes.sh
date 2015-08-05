lib_LTLIBRARIES  	= ctypes.la
ctypes_la_SOURCES   = callback.c ctypes.c types.c unpack.c util.c
ctypes_la_LDFLAGS   = -module -avoid-version -shared -export-symbols-regex '^.*_struct'
ctypes_la_CPPFLAGS  = -I../include
ctypes_la_CFLAGS    = -std=gnu99 $(FFI_CFLAGS)
ctypes_la_LIBADD    = $(FFI_LIBS)
