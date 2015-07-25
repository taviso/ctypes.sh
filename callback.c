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
#include "util.h"

static int generate_native_callback(WORD_LIST *list)
{
    SHELL_VAR *function;
    WORD_LIST *params;
    int result;

    // Decode parameters
    // callback hello pointer pointer int int
    // closure to 
    //
    function = find_function("hello");
    params   = make_word_list(make_word("pop"), NULL);
    params   = make_word_list(make_word("hello"), params);

    result = execute_shell_function(function, params);
    printf("returned %d\n", result);


    return 0;
}

static char *callback_usage[] = {
    "Generate a native callable function pointer",
    "",
    "It is sometimes necessary to provide a callback function to library"
    "routines. Given a bash function name and a list of type prefixes, this
    "routine will return a function pointer."
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
    "callback",
    generate_native_callback,
    0x01,
    callback_usage,
    "dlopen [-N|-l] [-t] [-d] [-g] [-n] [library] [RTLD_NODELETE|RTLD_GLOBAL|...]",
    0x00
};

