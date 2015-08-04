AC_INIT(ctypes.sh, 0.02, taviso@cmpxchg8b.com)
AC_PROG_CC
AC_CONFIG_SRCDIR([callback.c])
AC_CONFIG_HEADERS([config.h])
PKG_CHECK_MODULES(FFI, libffi >= 3)
AC_SEARCH_LIBS(dlopen, [dl c])
AC_CHECK_HEADERS([dlfcn.h fcntl.h inttypes.h limits.h memory.h stdint.h stdlib.h string.h strings.h sys/param.h sys/time.h unistd.h])
AC_CHECK_FUNCS([mempcpy strchr strdup strrchr strtol strtoul alloca malloc realloc strtod])
AC_CHECK_HEADER_STDBOOL

# temporarily configure my build flags
CPPFLAGS="${CPPFLAGS} -I${srcdir}/include"

# locate the bash binary so we can test if it works.
AC_PATH_PROG([BASH_ABS_PATH], [bash])

# If this test fails, the distribution has built bash incorrectly and may need
# to append -Wl,-export-dynamic to the linker command line. Without exported
# symbols, plugins cannot interact with bash.
AC_MSG_CHECKING([whether bash symbols are exported])
AC_RUN_IFELSE([AC_LANG_SOURCE([[
        #ifdef HAVE_DLFCN_H
        # include <dlfcn.h>
        #endif

        int main() {
            void *handle = dlopen(]["${BASH_ABS_PATH}"][, RTLD_LAZY);

            if (handle && dlsym(handle, "bind_int_variable"))
                return 0;

        return 1;
    }
]])], [
    AC_MSG_RESULT([yes])
], [
    AC_MSG_RESULT([no])
    AC_MSG_WARN([bash may have been built incorrectly])
])

# Verify I can see bash structure definitions
AC_CHECK_MEMBER([struct builtin.name],
                [],
                [AC_MSG_FAILURE([builtin structure not available])],
                [[#include <builtins.h>]])

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
    if `bash -c "enable -f ./conftest${ac_exeext} conftest; conftest; exit 1"`; then
        AC_MSG_RESULT([yes])
    else
        AC_MSG_RESULT([no])
        AC_MSG_FAILURE([bash plugins do not appear to work], 1)
    fi
], [AC_MSG_RESULT([no])])

soext=so
AC_MSG_CHECKING([extension of plugins])
if test $(uname -s) == Darwin; then
    soext=bundle
fi
AC_MSG_RESULT([${soext}])
AC_SUBST(soext)

AC_OUTPUT([Makefile ctypes.sh])
