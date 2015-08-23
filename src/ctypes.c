#define _GNU_SOURCE
#include <dlfcn.h>
#include <libgen.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <stdbool.h>
#include <ffi.h>
#include <inttypes.h>

#include "builtins.h"
#include "variables.h"
#include "arrayfunc.h"
#include "common.h"
#include "bashgetopt.h"
#include "util.h"
#include "types.h"
#include "shell.h"

static void __attribute__((constructor)) init(void)
{
    char handle[128];

    find_or_make_array_variable("DLHANDLES", 3);

    // RTLD_NEXT and RTLD_DEFAULT are special handles for dlsym. These are
    // stored as strings rather than integers, as otherwise they can
    // be interpreted as flags (they are small negative integers cast to
    // void*).
    snprintf(handle, sizeof handle, "%p", RTLD_NEXT);
    bind_variable("RTLD_NEXT", handle, 0);

    snprintf(handle, sizeof handle, "%p", RTLD_DEFAULT);
    bind_variable("RTLD_DEFAULT", handle, 0);
}

// Decode a single rtld flag into a string. This is used to convert symbolic
// parameters to dlopen to integer flags.
static const char * rtld_flags_encode(uint32_t n)
{
    static struct rtldname {
        uint32_t value;
        const char *name;
    } flags[] = {
        { RTLD_LAZY, "RTLD_LAZY" },
        { RTLD_NOW, "RTLD_NOW" },
        { RTLD_NOLOAD,  "RTLD_NOLOAD" },
        { RTLD_GLOBAL, "RTLD_GLOBAL" },
        { RTLD_NODELETE, "RTLD_NODELETE" },
#ifdef RTLD_DEEPBIND
        { RTLD_DEEPBIND, "RTLD_DEEPBIND" },
#endif
        { 0 },
    };
    struct rtldname *p = flags;

    // This routine handles only single flags.
    assert(__builtin_popcount(n) == 1);

    // Lookup string in the table.
    do {
        if (p->value == n) {
            return p->name;
        }
        ++p;
    } while (p->name);

    // Flag doesn't exist, or I don't know about it.
    return "RTLD_INVALID";
}

// Return the value of the single rtld flag specified.
static uint32_t rtld_flags_decode(const char *flag) {
    unsigned long result;

    // Enumerate through all flags to find the one specified, this is
    // suboptimal but there are only 32 possible flags.
    for (uint32_t i = 0; i < 31; i++) {
        if (strcmp(rtld_flags_encode(1 << i), flag) == 0) {
            return 1 << i;
        }
    }

    // Perhaps it was specified numerically?
    if (check_parse_ulong(flag, &result)) {
        return result;
    }

    builtin_warning("invalid or unrecognised rtld flag ignored: %s", flag);

    return 0;
}

static int close_dynamic_library(WORD_LIST *list)
{
    void *handle;

    if (!list) {
        builtin_usage();
        return EX_USAGE;
    }

    while (list) {
        if (!check_parse_ulong(list->word->word, (unsigned long *) &handle)) {
            builtin_warning("could not parse handle identifier %s", list->word->word);
        } else {
            if (dlclose(handle) != 0) {
                builtin_warning("dlclose set an error for %s, %s", list->word->word, dlerror());
            }
        }

        list = list->next;
    }

    return 0;
}

// Usage:
//
//  dlopen [-N] [-t] [-d] [-g] [-n] [library] [RTLD_NODELETE|RTLD_GLOBAL|...] [...]
//
static int open_dynamic_library(WORD_LIST *list)
{
    char varname[1024];
    char value[1024];
    uint32_t flags;
    void *handle;
    int opt;

    reset_internal_getopt();

    flags   = RTLD_LAZY | RTLD_GLOBAL;
    handle  = NULL;

    // Options can either be specified as bash-like flags, or as a list. The
    // bash-like flags look like this:
    //
    // $ dlopen -tg libc.so
    //
    while ((opt = internal_getopt(list, "lNtdgn")) != -1) {
        switch (opt) {
                // RTLD_LAZY and RTLD_NOW are mutually exclusive.
            case 'l':
                flags = (flags & ~RTLD_NOW) | RTLD_LAZY;
                break;
            case 'N':
                flags = (flags & ~RTLD_LAZY) | RTLD_NOW;
                break;
            case 't':
                flags |= RTLD_NOLOAD;
                break;
            case 'd':
#ifdef RTLD_DEEPBIND
                flags |= RTLD_DEEPBIND;
#else
                builtin_warning("RTLD_DEEPBIND is not supported on this platform");
#endif

                break;
            case 'g':
                flags &= ~RTLD_GLOBAL;
                break;
            case 'n':
                flags |= RTLD_NODELETE;
                break;
            default:
                builtin_usage();
                return EX_USAGE;
        }
    }

    // Skip past any options.
    if ((list = loptend) == NULL) {
        builtin_usage();
        return 1;
    }

    // Check and decode parameters, which can be specified as strings.
    //
    // $ dlopen libc.so RTLD_LAZY RTLD_NODELETE
    //
    // or, as an integer
    //
    // $ dlopen libc.so 0x10101
    //
    if (list->next) {
        WORD_LIST *flaglist = list->next;

        // Caller wants more control over flags, so reset and decode the flags
        // specified.
        for (flags = 0; flaglist; flaglist = flaglist->next) {
            flags |= rtld_flags_decode(flaglist->word->word);
        }
    }

    // Now list->word is the library name.
    if (!(handle = dlopen(list->word->word, flags))) {
        builtin_error("dlopen(\"%s\", %#x) failed, %s", list->word->word, flags, dlerror());
        return 1;
    }

    // Print the handle.
    if (interactive_shell) {
        printf("%p\n", handle);
    }

    snprintf(varname, sizeof varname, "DLHANDLES[\"%s\"]", basename(list->word->word));
    snprintf(value, sizeof value, "%p", handle);

    // Make the handle available programmatically.
    if (assign_array_element(varname, value, 4) == NULL) {
        builtin_error("failed to append element to $DLHANDLES array");
        return 1;
    }

    return 0;
}

// Usage:
//
// dlsym $RTLD_DEFAULT "errno"
//
static int get_symbol_address(WORD_LIST *list)
{
    int opt;
    void *handle;
    void *symbol;
    char *resultname;
    char retval[256];

    handle = RTLD_DEFAULT;
    resultname = "DLRETVAL";

    reset_internal_getopt();

    // $ dlsym [-n name] [-h handle] symbol
    while ((opt = internal_getopt(list, "h:n:")) != -1) {
        switch (opt) {
            case 'n':
                resultname = list_optarg;
                break;
            case 'h':
                if (check_parse_ulong(list_optarg, (void *) &handle) == 0) {
                    builtin_warning("handle %s %p is not well-formed", list_optarg, handle);
                    return EXECUTION_FAILURE;
                }
                break;
            default:
                builtin_usage();
                return EX_USAGE;
        }
    }

    // Skip past any options.
    if ((list = loptend) == NULL) {
        builtin_usage();
        return EX_USAGE;
    }

    if (!(symbol = dlsym(handle, list->word->word))) {
        builtin_warning("failed to resolve symbol %s, %s", list->word->word, dlerror());
        return EXECUTION_FAILURE;
    }

    snprintf(retval, sizeof retval, "pointer:%p", symbol);
    
    if (interactive_shell) {
        fprintf(stderr, "%s\n", retval);
    }
    
    bind_variable(resultname, retval, 0);

    return EXECUTION_SUCCESS;
}

// Usage:
//
// dlcall "printf" "hello %s %u %c" $USER 123 int:10
//
static int call_foreign_function(WORD_LIST *list)
{
    unsigned nargs;
    unsigned i;
    int opt;
    ffi_cif cif;
    ffi_type **argtypes;
    ffi_type *rettype;
    void **values;
    void *handle;
    void *func;
    char *prefix;
    char *format;
    char *resultname;

    nargs       = 0;
    argtypes    = NULL;
    values      = NULL;
    format      = NULL;
    prefix      = NULL;
    rettype     = &ffi_type_void;
    resultname  = "DLRETVAL";
    handle      = RTLD_DEFAULT;

    reset_internal_getopt();

    // $ dlcall [-a abi] [-r type] [-n name] [-h handle] symbol args...
    while ((opt = internal_getopt(list, "h:a:r:n:")) != -1) {
        switch (opt) {
            case 'a':
                builtin_warning("FIXME: only abi %u is currently supported", FFI_DEFAULT_ABI);
                return 1;
                break;
            case 'r':
                if (decode_type_prefix(prefix = list_optarg, NULL, &rettype, NULL, &format) != true) {
                    builtin_warning("failed to parse return type");
                    return 1;
                }
                break;
            case 'n':
                resultname = list_optarg;
                break;
            case 'h':
                if (check_parse_ulong(list_optarg, (void *) &handle) == 0) {
                    builtin_warning("handle %s %p is not well-formed", list_optarg, handle);
                    return EXECUTION_FAILURE;
                }
                break;
            default:
                builtin_usage();
                return EX_USAGE;
        }
    }

    // Skip past any options.
    if ((list = loptend) == NULL) {
        builtin_usage();
        return EX_USAGE;
    }

    if (!(func = dlsym(handle, list->word->word))) {
        builtin_warning("failed to resolve symbol %s, %s", list->word->word, dlerror());
        return 1;
    }

    // Skip to optional parameters
    list = list->next;

    while (list) {
        argtypes = realloc(argtypes, (nargs + 1) * sizeof(ffi_type *));
        values   = realloc(values, (nargs + 1) * sizeof(void *));

        if (decode_primitive_type(list->word->word, &values[nargs], &argtypes[nargs]) != true) {
            builtin_error("failed to decode type from parameter %s", list->word->word);
            goto error;
        }

        nargs++;
        list = list->next;
    }

    if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, nargs, rettype, argtypes) == FFI_OK) {
        char *retval;
        void *rc = alloca(rettype->size);

        // Do the call.
        ffi_call(&cif, func, rc, values);

        // Decode the result.
        if (format) {
            retval = encode_primitive_type(format, rettype, rc);

            // If this is an interactive shell, print the output.
            if (interactive_shell) {
                fprintf(stderr, "%s\n", retval);
            }

            // Save the result to the requested location.
            bind_variable(resultname, retval, 0);

            // Bash maintains it's own copy of this string, so we can throw it away.
            free(retval);
        }
    }

    for (i = 0; i < nargs; i++)
        free(values[i]);
    free(values);
    free(argtypes);
    return 0;

  error:
    for (i = 0; i < nargs; i++)
        free(values[i]);
    free(values);
    free(argtypes);
    return 1;
}

static char *dlcall_usage[] = {
    "Call an exported symbol.",
    "Lookup symbol using dlsym, then call it with the parameters specified.",
    "",
    "By default, RTLD_DEFAULT is assumed which searches for symbols at global",
    "scope. Optionally, you may specify another handle, which will usually",
    "either be an element from the associative array DLHANDLES, or one of the",
    "pseudo-handles $RTLD_DEFAULT or $RTLD_NEXT. Note that this is not",
    "enforced, and you can use any value for handle, although this may crash",
    "your shell if done incorrectly.",
    "",
    "The return value is stored in DLRETVAL, unless otherwise specified."
    "",
    "Usage:",
    "In very simple cases, dlcall is quite easy to use",
    "",
    "    $ dlcall puts \"hello world\"",
    "",
    "    or",
    "",
    "    $ dlopen libc.so.6",
    "    $ dlcall -h ${DLHANDLES[\"libc.so.6\"]} printf %s%c \"hello\" 10",
    "",
    "It gets more complex if the parameters are not obvious. By default dlcall",
    "assumes all parameters specified are C strings, *unless* they can be parsed",
    "perfectly as integers. If that is not what you want, you need to specify",
    "the type with a prefix. The following prefixes are recognised:",
    "",
    "uint8, int8, uint16, int16, uint32, int32, uint64, int64, float, double, char",
    "uchar, ushort, short, unsigned, int, ulong, long, longdouble, pointer, string",
    "void",
    "",
    "These are specified followed by a ':' then the type.",
    "",
    "    $ dlopen libc.so.6",
    "    $ dlcall lchown string:/tmp/foo int:$UID int:-1",
    "",
    "Options:",
    "    -a abi      Use the specifed ABI rather than the default.",
    "    -r type     The function returns the specified type (default: long).",
    "    -n var      Use var instead of DLRETVAL to store the result.",
    "    -h handle   Use handle instead of RTLD_DEFAULT (Usually ${DLRETVAL[soname]})."
    "",
    NULL,
};

static char *dlsym_usage[] = {
    "Lookup an exported symbol.",
    "Lookup symbol in using dlsym, and return it's value.",
    "",
    "By default, the pseudo-handle RTLD_DEFAULT is assumed. Optionally you may",
    "specify the handle, which will usually be an element from the associative array",
    "DLHANDLES, or $RTLD_NEXT. Note that this is not enforced, and you can use",
    "any value for handle, although this may crash your shell if done incorrectly.",
    "",
    "The return value is stored in DLRETVAL, unless otherwise specified."
    "",
    "Usage:",
    "",
    "    $ dlopen libc.so.6",
    "    $ dlsym -h ${DLHANDLES[libc.so.6]} errno",
    "",
    "   Access bash internal state:",
    "",
    "   $ dlsym last_asynchronous_pid",
    "   pointer:0x6ecf14",
    "   $ pid=(int)",
    "   $ sleep 100 &",
    "   [2] 57271",
    "   $ unpack pointer:0x6ecf14 pid",
    "   $ echo ${pid##*:}",
    "   57271",
    "",
    "Options:",
    "    -n var      Use var instead of DLRETVAL to store the result.",
    "    -h handle   Use handle instead of RTLD_DEFAULT (Usually ${DLRETVAL[soname]})."
    "",
    NULL,
};
static char *dlclose_usage[] = {
    "Close a dynamic shared object handle.",
    "",
    "Closes the specified handle, which would usually be an element of the",
    "associative array DLHANDLES. Improper usage may cause your shell to crash.",
    "",
    "Usage:",
    "",
    "   $ dlclose ${DLHANDLES[libc.so.6]}"
    "",
    "   Close all open handles:",
    "",
    "   $ dlclose ${DLHANDLES[*]}",
    "",
    NULL,
};

static char *dlopen_usage[] = {
    "Load a dynamic shared object into the current shell.",
    "Load the library specified from the standard search path, and make it",
    "accessible to future calls to dlcall or dlget. The default flags should",
    "work in general, but if more control is required the flags can be",
    "specified as switches, or by name. To close a handle, use dlclose.",
    "",
    "If library is an absolute path, the standard search path is not used.",
    "",
    "On success, the handle is added to the associative array DLHANDLES.",
    "Needless to say, it is possible to break or crash your shell in strange",
    "ways using this interface.",
    "",
    "Usage:",
    "It might be tempting to write this:",
    "",
    "    $ handle=$(dlopen libc.so.6) # DONT DO THIS, BROKEN",
    "",
    "But this won't work, because the handle will only exist in the subshell.",
    "Instead, you should do this:",
    "",
    "    $ dlopen libc.so.6",
    "    $ handle=${DLHANDLES[\"libc.so.6\"]}",
    "",
    "Options:",
    "    -l      Perform lazy binding.",
    "    -N      Resolve all undefined symbols immediately.",
    "    -t      Don't load, but return handle if already loaded.",
    "    -d      Place the lookup scope ahead of global scope.",
    "    -g      Don't make symbols available for global symbol resolution.",
    "    -n      Do not unload library after dlclose.",
    "",
    "Alternatively, for very precise control of flags, you can specify dlfcn",
    "flags on the commandline. For example:",
    "",
    "    $ dlopen libc.so.6 RTLD_GLOBAL RTLD_LAZY",
    "",
    "Or for very unusual flags, you can specify them numerically.",
    "",
    "    $ dlopen libc.so.6 0x232",
    "",
    "Or combine the two:",
    "",
    "    $ dlopen libc.so.6 RTLD_LAZY $((1 << 8))",
    "",
    "Exit Status:",
    "The return code is zero, unless dlopen returns error.",
    NULL
};

struct builtin __attribute__((visibility("default"))) dlopen_struct = {
    .name       = "dlopen",
    .function   = open_dynamic_library,
    .flags      = BUILTIN_ENABLED,
    .long_doc   = dlopen_usage,
    .short_doc  = "dlopen [-N|-l] [-t] [-d] [-g] [-n] library [flags|...]",
    .handle     = NULL,
};

struct builtin __attribute__((visibility("default"))) dlcall_struct = {
    .name       = "dlcall",
    .function   = call_foreign_function,
    .flags      = BUILTIN_ENABLED,
    .long_doc   = dlcall_usage,
    .short_doc  = "dlcall [-n name] [-a abi] [-r type] [-h handle] symbol [parameters...]",
    .handle     = NULL,
};

struct builtin __attribute__((visibility("default"))) dlsym_struct = {
    .name       = "dlsym",
    .function   = get_symbol_address,
    .flags      = BUILTIN_ENABLED,
    .long_doc   = dlsym_usage,
    .short_doc  = "dlsym [-n name] [-h handle] symbol",
    .handle     = NULL,
};

struct builtin __attribute__((visibility("default"))) dlclose_struct = {
    .name       = "dlclose",
    .function   = close_dynamic_library,
    .flags      = BUILTIN_ENABLED,
    .long_doc   = dlclose_usage,
    .short_doc  = "dlclose handle [handle ...]",
    .handle     = NULL,
};
