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
#include "make_cmd.h"
#include "execute_cmd.h"
#include "util.h"
#include "types.h"
#include "shell.h"

static int execute_bash_trampoline(ffi_cif *cif, void *retval, void **args, char **proto)
{
    SHELL_VAR *function;
    WORD_LIST *params;
    char *result;

    // Decode parameters
    // callback hello pointer pointer int int
    // FIXME this is really ugly, do it properly and check cif->argtypes
    //
    if (!(function = find_function(*proto))) {
        fprintf(stderr, "error: unable to resolve function %s in thunk", *proto);
        return -1;
    }

    params = NULL;

    for (unsigned i = 0; i < cif->nargs; i++) {
        char parameter[1024];
        ffi_raw *p = args[i];

        // Decode the parameters
        snprintf(parameter, sizeof parameter, proto[i+1], p->ptr);

        params = make_word_list(make_word(parameter), params);
    }

    // The first parameter should be the return location
    asprintf(&result, "pointer:%p", retval);

    params = make_word_list(make_word(result), params);
    params = make_word_list(make_word(*proto), params);

    execute_shell_function(function, params);

    free(result);
    return 0;
}

static int generate_native_callback(WORD_LIST *list)
{
    int nargs;
    void *callback;
    ffi_cif *cif;
    ffi_closure *closure;
    ffi_type **argtypes;
    ffi_type *rettype;
    char **proto;
    char *resultname = "DLRETVAL";
    char opt;
    reset_internal_getopt();

    // $ dlcall [-a abi] [-r type] [-n name]
    while ((opt = internal_getopt(list, "a:r:n:")) != -1) {
        switch (opt) {
            case 'n':
                resultname = list_optarg;
                break;
            default:
                builtin_usage();
                return EX_USAGE;
        }
    }

    // Skip past any options.
    if ((list = loptend) == NULL || !list->next) {
        builtin_usage();
        return EX_USAGE;
    }

    closure     = ffi_closure_alloc(sizeof(ffi_closure), &callback);
    cif         = malloc(sizeof(ffi_cif));
    argtypes    = NULL;
    proto       = malloc(sizeof(char *));
    proto[0]    = strdup(list->word->word);
    nargs       = 0;
    list        = list->next;

    // Second parameter must be the return type
    if (decode_type_prefix(list->word->word,
                           NULL,
                           &rettype,
                           NULL,
                           NULL) != true) {
        builtin_warning("couldnt parse the return type %s", list->word->word);
        return EXECUTION_FAILURE;
    }

    // Skip past return type
    list = list->next;

    while (list) {
        argtypes        = realloc(argtypes, (nargs + 1) * sizeof(ffi_type *));
        proto           = realloc(proto, (nargs + 1 + 1) * sizeof(char *));

        if (decode_type_prefix(list->word->word, NULL, &argtypes[nargs], NULL, &proto[nargs+1]) != true) {
            builtin_error("failed to decode type from parameter %s", list->word->word);
            goto error;
        }

        list = list->next;
        nargs++;
    }

    if (ffi_prep_cif(cif, FFI_DEFAULT_ABI, nargs, rettype, argtypes) == FFI_OK) {
        // Initialize the closure.
        if (ffi_prep_closure_loc(closure, cif, execute_bash_trampoline, proto, callback) == FFI_OK) {
            char retval[1024];
            snprintf(retval, sizeof retval, "pointer:%p", callback);
            fprintf(stderr, "%s\n", retval);
            bind_variable(resultname, retval, 0);
        }
    }

    //free(argtypes);
    return 0;

  error:
    //free(argtypes);
    return 1;
}


static char *callback_usage[] = {
    "Generate a native callable function pointer",
    "",
    "It is sometimes necessary to provide a callback function to library",
    "routines, for example bsearch and qsort. Given a bash function name and a",
    "list of type prefixes, this routine will return a function pointer that",
    "can be called from native code.",
    "",
    "functions in bash can only return integers <= 255. If you require a",
    "greater range of values, use the setreturn command.",
    "",
    "",
    "Usage:",
    "",
    " $ function bash_callback() {",
    " > echo hello from bash",
    " > return 1",
    " > }",
    " $ callback bash_callback int int int",
    " pointer:0x123123",
    "",
    NULL,
};

struct builtin __attribute__((visibility("default"))) callback_struct = {
    .name       = "callback",
    .function   = generate_native_callback,
    .flags      = BUILTIN_ENABLED,
    .long_doc   = callback_usage,
    .short_doc  = "dlopen [-N|-l] [-t] [-d] [-g] [-n] [library] [RTLD_NODELETE|RTLD_GLOBAL|...]",
    .handle     = NULL,
};

