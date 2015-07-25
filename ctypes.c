#define _GNU_SOURCE
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <stdbool.h>
#include <link.h>
#include <ffi.h>
#include <inttypes.h>

#include "builtins.h"
#include "variables.h"
#include "arrayfunc.h"
#include "common.h"
#include "bashgetopt.h"
#include "util.h"

static bool decode_type_prefix(const char *prefix, const char *value, ffi_type **type, void **result, char **pformat);

static void __attribute__((constructor)) init(void)
{
    find_or_make_array_variable("DLHANDLES", 3);
    bind_int_variable("RTLD_NEXT", "-1");
    bind_int_variable("RTLD_DEFAULT", "0");
}

// Decode a single rtld flag into a string.
static const char * rtld_flags_encode(uint32_t n)
{
    static const char * const flags[32] = {
        [__builtin_ffs(RTLD_LAZY)]     = "RTLD_LAZY",
        [__builtin_ffs(RTLD_NOW)]      = "RTLD_NOW",
        [__builtin_ffs(RTLD_NOLOAD)]   = "RTLD_NOLOAD",
        [__builtin_ffs(RTLD_DEEPBIND)] = "RTLD_DEEPBIND",
        [__builtin_ffs(RTLD_GLOBAL)]   = "RTLD_GLOBAL",
        [__builtin_ffs(RTLD_NODELETE)] = "RTLD_NODELETE",
    };

    // This routine only handles single flags.
    assert(__builtin_popcount(n) == 1);

    // Lookup string in the table.
    return flags[__builtin_ffs(n)] ? flags[__builtin_ffs(n)] : "RTLD_INVALID";
}

// Return the value of the single rtld flag specified.
static uint32_t rtld_flags_decode(const char *flag) {
    intmax_t result;

    // Enumerate through all flags to find the one specified, this is
    // suboptimal but there are only 32 possible flags.
    for (uint32_t i = 0; i < 31; i++) {
        if (strcmp(rtld_flags_encode(1 << i), flag) == 0) {
            return 1 << i;
        }
    }

    // Perhaps it was specified numerically?
    if (check_parse_long(flag, &result)) {
        return result;
    }

    builtin_warning("invalid or unrecognised rtld flag ignored: %s", flag);

    return 0;
}

static int close_dynamic_library(WORD_LIST *list)
{
    void *handle;

    if (!list)
        builtin_usage();

    while (list) {
        if (!check_parse_long(list->word->word, (long *) &handle)) {
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

    flags   = RTLD_LAZY;
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
                flags |= RTLD_DEEPBIND;
                break;
            case 'g':
                flags |= RTLD_GLOBAL;
                break;
            case 'n':
                flags |= RTLD_NODELETE;
                break;
            default:
                builtin_usage();
                return 1;
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

    // Print the handle, although this is not usable unless being used interactively.
    printf("%p\n", handle);

    snprintf(varname, sizeof varname, "DLHANDLES[\"%s\"]", basename(list->word->word));
    snprintf(value, sizeof value, "%p", handle);

    // Make the handle available programmatically.
    if (assign_array_element(varname, value, 4) == NULL) {
        builtin_error("failed to append element to $DLHANDLES array");
        return 1;
    }

    return 0;
}

static int decode_primitive_type(const char *parameter, void **value, ffi_type **type)
{
    const char *prefix;

    prefix  = NULL;
    *value  = NULL;
    *type   = NULL;

    // If a colon exists, then everything before it is a type
    if (strchr(parameter, ':')) {
        // Extract the two components.
        prefix    = strndupa(parameter, strchr(parameter, ':') - parameter);
        parameter = strchr(parameter, ':') + 1;
    } else {
        intmax_t n;
        char *string;

        // No type was specified, so there are only two possibilities,
        // If this is a legal number, then it's an int. Otherwise, this is a
        // string.
        if (check_parse_long(parameter, &n)) {
            *type   = &ffi_type_sint;
            *value  = malloc(ffi_type_sint.size);

            memcpy(*value, &n, ffi_type_sint.size);
            return 0;
        }

        // This must be a string.
        *type   = &ffi_type_pointer;
        *value  = malloc(ffi_type_pointer.size);
        string  = strdup(parameter);

        memcpy(*value, &string, ffi_type_pointer.size);
        return 0;
    }

    if (decode_type_prefix(prefix, parameter, type, value, NULL) != true) {
        builtin_warning("parameter decoding failed");
        return 1;
    }

    return 0;
}

static bool decode_type_prefix(const char *prefix, const char *value, ffi_type **type, void **result, char **pformat)
{
    static struct {
        char     *prefix;
        ffi_type *type;
        char     *sformat;
        char     *pformat;
    } types[] = {
        { "uint8", &ffi_type_uint8, "%" SCNu8, "%" PRIu8 },
        { "int8", &ffi_type_sint8, "%" SCNd8, "%" PRId8 },
        { "uint16", &ffi_type_uint16, "%" SCNu16, "%" PRIu16 },
        { "int16", &ffi_type_sint16, "%" SCNd16, "%" PRId16 },
        { "uint32", &ffi_type_uint32, "%" SCNu32, "%" PRIu32 },
        { "int32", &ffi_type_sint32, "%" SCNd32, "%" PRId32 },
        { "uint64", &ffi_type_uint64, "%" SCNu64, "%" PRIu64 },
        { "int64", &ffi_type_sint64, "%" SCNd64, "%" PRId64 },
        { "float", &ffi_type_float, "%f", "%f" },
        { "double", &ffi_type_double, "%lf", "%lf" },
        { "char", &ffi_type_schar, "%c", "%c" },
        { "uchar", &ffi_type_uchar, "%c", "%c" },
        { "ushort", &ffi_type_ushort, "%hu", "%hu" },
        { "short", &ffi_type_sshort, "%hd", "%hd", },
        { "unsigned", &ffi_type_uint, "%u", "%u" },
        { "int", &ffi_type_sint, "%d", "%d" },
        { "ulong", &ffi_type_ulong, "%lu", "%lu" },
        { "long", &ffi_type_slong, "%ld", "%ld" },
        { "longdouble", &ffi_type_longdouble, "%llg", "%llg" },
        { "pointer", &ffi_type_pointer, "%p", "%p" },
        { "string", &ffi_type_pointer, "%ms", "%s" },
        { "void", &ffi_type_void, "", "" },
        { NULL },
    };

    for (int i = 0; types[i].prefix; i++) {
        if (strcmp(types[i].prefix, prefix) == 0) {
            // Prefix matched type, return information user requested.
            if (type) {
                *type = types[i].type;
            }

            if (pformat) {
                *pformat = types[i].pformat;
            }

            // Caller wants us to decode it, lets go ahead.
            if (result) {
                *result = malloc(types[i].type->size);

                if (sscanf(value, types[i].sformat, *result) != 1) {
                    builtin_warning("failed to parse %s as a %s", value, prefix);
                    free(*result);
                    return false;
                }
            }
            return true;
        }
    }

    builtin_warning("unrecognised type prefix %s", prefix);
    return false;
}

// Usage:
//
// dlcall $RTLD_DEFAULT "printf" "hello %s %u %c" $USER 123 int:10
//
static int call_foreign_function(WORD_LIST *list)
{
    unsigned nargs;
    int opt;
    ffi_cif cif;
    ffi_type **argtypes;
    ffi_type *rettype;
    void **values;
    void *handle;
    void *func;
    char *prefix;
    char *format;

    nargs       = 0;
    argtypes    = NULL;
    values      = NULL;
    format      = NULL;
    prefix      = NULL;
    rettype     = &ffi_type_void;

    reset_internal_getopt();

    // $ dlcall [-a abi] [-r type]
    while ((opt = internal_getopt(list, "a:r:")) != -1) {
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
            default:
                builtin_usage();
                return 1;
        }
    }

    // Skip past any options.
    if ((list = loptend) == NULL || list->next == NULL) {
        builtin_usage();
        return 1;
    }

    if (check_parse_long(list->word->word, (void *) &handle) == 0) {
        builtin_warning("handle %s %p is not well-formed", list->word->word, handle);
        return 1;
    }

    if (!(func = dlsym(handle, list->next->word->word))) {
        builtin_warning("failed to resolve symbol %s, %s", list->next->word->word, dlerror());
        return 1;
    }

    // Skip to optional parameters
    list = list->next->next;

    while (list) {
        argtypes = realloc(argtypes, (nargs + 1) * sizeof(ffi_type *));
        values   = realloc(values, (nargs + 1) * sizeof(void *));

        if (decode_primitive_type(list->word->word, &values[nargs], &argtypes[nargs]) != 0) {
            builtin_error("failed to decode type from parameter %s", list->word->word);
            goto error;
        }

        nargs++;
        list = list->next;
    }

    if (ffi_prep_cif(&cif, FFI_DEFAULT_ABI, nargs, rettype, argtypes) == FFI_OK) {
        char retval[1024];
        void *rc = alloca(rettype->size);

        // Do the call.
        ffi_call(&cif, func, rc, values);

        // Print the result.
        if (format) {
            snprintf(retval, sizeof retval, "%s:", prefix);
            snprintf(retval + strlen(retval), sizeof retval, format, *(uintptr_t *) rc);
            fprintf(stderr, "%s\n", retval);
            bind_variable("DLRETVAL", retval, 0);
        }
    }

    for (unsigned i = 0; i < nargs; i++)
        free(values[i]);
    free(values);
    free(argtypes);
    return 0;

  error:
    for (unsigned i = 0; i < nargs; i++)
        free(values[i]);
    free(values);
    free(argtypes);
    return 1;
}

static char *dlcall_usage[] = {
    "Call an exported symbol from the handle specified.",
    "Lookup symbol in the specified handle using dlsym, then call it with the",
    "parameters specified.",
    "",
    "The handle will usually either be an element from the associative array",
    "DLHANDLES, or one of the pseudo-handles $RTLD_DEFAULT or $RTLD_NEXT. Note",
    "that this is not enforced, and you can use any value for handle, although",
    "this may crash your shell if done incorrectly.",
    "",
    "The return value is stored in DLRETVAL, unless otherwise specified."
    "",
    "Usage:",
    "In very simple cases, dlcall is quite easy to use",
    "",
    "    $ dlcall $RTLD_DEFAULT puts \"hello world\"",
    "",
    "    or",
    "",
    "    $ dlopen libc.so.6",
    "    $ dlcall ${DLHANDLES[\"libc.so.6\"]} printf %s%c \"hello\" 10",
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
    "    $ dlcall ${DLHANDLES[libc.so.6]} lchown string:/tmp/foo int:$UID int:-1",
    "",
    "Options:",
    "    -a abi      Use the specifed ABI rather than the default.",
    "    -r type     The function returns the specified type (default: long).",
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
    "    -g      Make symbols available for global symbol resolution.",
    "    -n      Do not unload library after dlclose.",
    "",
    "Alternatively, for very precise control of flags, you can specify dlfcn",
    "flags on the commandline. For example:",
    "",
    "    $ dlopen libc.so.6 RTLD_LOCAL RTLD_DEEPBIND",
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
    "dlopen",
    open_dynamic_library,
    0x01,
    dlopen_usage,
    "dlopen [-N|-l] [-t] [-d] [-g] [-n] [library] [RTLD_NODELETE|RTLD_GLOBAL|...]",
    0x00
};

struct builtin __attribute__((visibility("default"))) dlcall_struct = {
    "dlcall",
    call_foreign_function,
    0x01,
    dlcall_usage,
    "dlcall [-a abi] [-r type] handle symbol [parameters...]",
    0x00
};

struct builtin __attribute__((visibility("default"))) dlclose_struct = {
    "dlclose",
    close_dynamic_library,
    0x01,
    dlclose_usage,
    "dlclose handle [handle ...]",
    0x00
};
