AC_PREREQ([2.59])
AC_INIT([ctypes.sh], [1.1], [ctypesdotsh@googlegroups.com])
AC_CONFIG_SRCDIR([src/callback.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_LIBOBJ_DIR([lib])
AM_INIT_AUTOMAKE([subdir-objects])
LT_INIT([disable-static])
AC_SEARCH_LIBS(dlopen, [dl c])
AC_CHECK_LIB([elf], [gelf_getehdr], [], [
    disable_struct_support=yes;
    AC_MSG_WARN([libelf is not available, struct support will not be available])
])
AC_CHECK_LIB([dw], [dwfl_version], [], [
    disable_struct_support=yes;
    AC_MSG_WARN([elfutils is not available, struct support will not be available])
])
AC_CONFIG_HEADERS([config.h])
PKG_CHECK_MODULES([FFI], [libffi >= 3])
PKG_CHECK_MODULES([ZLIB], [zlib])
AC_CHECK_HEADERS([dlfcn.h fcntl.h inttypes.h limits.h memory.h stdint.h stdlib.h string.h strings.h sys/param.h sys/time.h unistd.h], [], [
    AC_MSG_ERROR([a critical header could not be found])
])
AC_CHECK_HEADERS([dwarf.h libelf.h link.h elfutils/libdwfl.h], [], [
    disable_struct_support=yes;
    AC_MSG_WARN([a header needed for struct support was not found])
])
AC_CHECK_FUNCS([strchr strdup strrchr strtol strtoul malloc realloc strtod], [], [
    AC_MSG_ERROR([a critical standard function could not be found])
])
AC_CHECK_FUNCS([gelf_getehdr dwfl_version dl_iterate_phdr], [], [
    disable_struct_support=yes;
    AC_MSG_WARN([a function needed for struct support was not found])
])
AC_CHECK_HEADER_STDBOOL
AC_PROG_CC
AC_FUNC_ALLOCA

AS_IF([test "x$disable_struct_support" == "xyes"], [
    AC_FUNC_OBSTACK
])

# Debian split libtool into multiple packages, so LT_INIT is not enough to
# be certain some LT_* macro is available.
m4_ifndef([LT_SYS_DLSEARCH_PATH], [m4_fatal([You may need to install libltdl-dev])])
m4_ifndef([LT_SYS_MODULE_EXT], [m4_fatal([You may need to install libltdl-dev])])

LT_SYS_DLSEARCH_PATH
LT_SYS_MODULE_EXT

SAVED_CPPFLAGS="${CPPFLAGS}"
SAVED_LDFLAGS="${LDFLAGS}"

# temporarily configure my build flags
CPPFLAGS="${CPPFLAGS} -I${srcdir}/include"

# locate the bash binary so we can test if it works.
AC_PATH_PROG([BASH_ABS_PATH], [bash])

# Verify I can see bash structure definitions
AC_CHECK_MEMBER([struct builtin.name],
                [],
                [AC_MSG_FAILURE([builtin structure not available])],
                [[#include "builtins.h"]])

AM_CONDITIONAL([ENABLE_STRUCTS], [test "x$disable_struct_support" != "xyes"])

# Does enable -f work with a very simple plugin?
LDFLAGS="${LDFLAGS} -shared -fPIC"

AC_MSG_CHECKING([whether a minimal bash plugin compiles])
AC_LINK_IFELSE([AC_LANG_SOURCE([[
    #include <stddef.h>
    #include <unistd.h>

    #include "builtins.h"

    int conftest_function(WORD_LIST *list)
    {
        exit(EXIT_SUCCESS);
    }

    struct builtin conftest_struct = {
        .name       = "conftest",
        .function   = conftest_function,
        .flags      = BUILTIN_ENABLED,
        .long_doc   = NULL,
        .short_doc  = NULL,
        .handle     = NULL,
    };
]])], [
    AC_MSG_RESULT([yes])
    AC_MSG_CHECKING([loading simple plugin])
    if bash -c "enable -f ./conftest${ac_exeext} conftest && conftest || exit 1"; then
        AC_MSG_RESULT([yes])
    else
        AC_MSG_RESULT([no])
        AC_MSG_FAILURE([bash plugins do not appear to work], 1)
    fi
], [
    AC_MSG_RESULT([no])
    AC_MSG_FAILURE([unable to build a test extension], 1)
])

# If this test fails, the distribution has built bash incorrectly and may need
# to append -Wl,-export-dynamic to the linker command line. Without exported
# symbols, plugins cannot interact with bash.
AC_MSG_CHECKING([whether bash symbols are exported])
AC_LINK_IFELSE([AC_LANG_SOURCE([[
    #include <stddef.h>
    #include <unistd.h>

    #include "builtins.h"

    int conftest_function(WORD_LIST *list)
    {
        exit(num_shell_builtins
                ? EXIT_SUCCESS
                : EXIT_FAILURE);
    }

    struct builtin conftest_struct = {
        .name       = "conftest",
        .function   = conftest_function,
        .flags      = BUILTIN_ENABLED,
        .long_doc   = NULL,
        .short_doc  = NULL,
        .handle     = NULL,
    };
]])], [
    AC_MSG_RESULT([yes])
    AC_MSG_CHECKING([loading plugin with external references])
    if bash -c "enable -f ./conftest${ac_exeext} conftest && conftest || exit 1"; then
        AC_MSG_RESULT([yes])
    else
        AC_MSG_RESULT([no])
        AC_MSG_FAILURE([report this bug to your distribution; bash may be built incorrectly], 1)
    fi
], [
    AC_MSG_RESULT([no])
    AC_MSG_FAILURE([unable to build a test extension], 1)
])

LDFLAGS="${SAVED_LDFLAGS}"
CPPFLAGS="${SAVED_CPPFLAGS}"

AS_IF([test "x$disable_struct_support" == "xyes"], [
      AS_BOX([!!! AUTOMATIC STRUCT SUPPORT IS DISABLED DUE TO MISSING DEPENDENCIES !!!], [*])
      AC_SUBST([struct], [])
      AC_SUBST([sizeof], [])
], [
      AC_SUBST([struct], [struct])
      AC_SUBST([sizeof], [sizeof])
])

AC_SUBST([soext], [$shrext_cmds])
AC_CONFIG_FILES([Makefile src/Makefile ctypes.sh])
AC_OUTPUT
