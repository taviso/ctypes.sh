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

static int execute_bash_trampoline(ffi_cif *cif, int *ret, void **args, char **proto)
{
    SHELL_VAR *function;
    WORD_LIST *params;

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

    params = make_word_list(make_word(*proto), params);

    *ret = execute_shell_function(function, params);

    return 0;
}

static int generate_native_callback(WORD_LIST *list)
{
    int nargs;
    void *callback;
    ffi_cif *cif;
    ffi_closure *closure;
    ffi_type **argtypes;
    char **proto;

    closure     = ffi_closure_alloc(sizeof(ffi_closure), &callback);
    cif         = malloc(sizeof(ffi_cif));
    argtypes    = NULL;
    proto       = malloc(sizeof(char *));
    proto[0]    = strdup(list->word->word);
    nargs       = 0;
    list        = list->next;

    while (list) {
        argtypes        = realloc(argtypes, (nargs + 1) * sizeof(ffi_type *));
        proto           = realloc(proto, (nargs + 1 + 1) * sizeof(char *));

        if (decode_type_prefix(list->word->word, NULL, &argtypes[nargs], NULL, &proto[nargs+1]) != true) {
            builtin_error("failed to decode type from parameter %s", list->word->word);
            goto error;
        }

        nargs++;
        list = list->next;
    }

    if (ffi_prep_cif(cif, FFI_DEFAULT_ABI, nargs, &ffi_type_sint, argtypes) == FFI_OK) {
        // Initialize the closure.
        if (ffi_prep_closure_loc(closure, cif, execute_bash_trampoline, proto, callback) == FFI_OK) {
            char retval[1024];
            snprintf(retval, sizeof retval, "pointer:%p", callback);
            fprintf(stderr, "%s\n", retval);
            bind_variable("DLRETVAL", retval, 0);
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
    "routines. Given a bash function name and a list of type prefixes, this",
    "routine will return a function pointer.",
    "",
    "functions in bash can only return an integer, this limitation will be",
    "resolved in a future release, perhaps by using $retval instead.",
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

