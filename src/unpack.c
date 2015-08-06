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
#include <ffi.h>
#include <inttypes.h>

#include "builtins.h"
#include "variables.h"
#include "arrayfunc.h"
#include "common.h"
#include "bashgetopt.h"
#include "make_cmd.h"
#include "util.h"
#include "types.h"
#include "shell.h"

#if !defined(__GLIBC__) && !defined(__NEWLIB__)
static inline void *mempcpy(void *dest, const void *src, size_t n)
{
    memcpy(dest, src, n);
    return ((char *)dest + n);
}
#endif

struct pack_context {
    ffi_type *ptrtype;
    WORD_LIST *list;
    uint8_t *source;
    int retval;
};

// Callback for each array element.
int pack_decode_element(ARRAY_ELEMENT *element, void *user)
{
    struct pack_context *ctx;
    void **value;

    ctx = user;

    if (decode_primitive_type(element->value,
                              (void **)&value,
                              &ctx->ptrtype) == false) {

        // You can exit from an array_walk early by returning -1, so set
        // failure and do that here.
        ctx->retval = EXECUTION_FAILURE;

        // Give a hint about what failed to parse.
        builtin_warning("aborted pack at bad type prefix %s (%s[%lu])",
                        element->value,
                        ctx->list->word->word,
                        element->ind);

        return -1;
    }

    // Extract the data into the destination buffer.
    ctx->source = mempcpy(ctx->source, value, ctx->ptrtype->size);

    // No longer needed.
    free(value);
    return 0;
}

static int pack_prefixed_array(WORD_LIST *list)
{
    SHELL_VAR *dest_v;
    ARRAY *dest_a;
    void **value;
    struct pack_context ctx = { 0 };

    // Assume success by default.
    ctx.retval = EXECUTION_SUCCESS;

    // Verify we have two parameters.
    if (!list || !list->next) {
        builtin_usage();
        goto error;
    }

    // Fetch the source pointer.
    if (decode_primitive_type(list->word->word,
                              (void **)&value,
                              &ctx.ptrtype) != true) {
        builtin_error("the destination parameter %s could not parsed", list->word->word);
        goto error;
    }

    // Verify that it was a pointer.
    if (ctx.ptrtype != &ffi_type_pointer) {
        builtin_error("the destination parameter must be a pointer");
        goto error;
    }

    // Skip to next parameter.
    list        = list->next;
    ctx.source  = *value;
    ctx.list    = list;

    GET_ARRAY_FROM_VAR(list->word->word, dest_v, dest_a);

    array_walk(dest_a, pack_decode_element, &ctx);

    return ctx.retval;

error:
    return EXECUTION_FAILURE;
}

struct unpack_context {
    ffi_type *ptrtype;
    WORD_LIST *list;
    uint8_t *source;
    int retval;
};

// Callback for each array element.
int unpack_decode_element(ARRAY_ELEMENT *element, void *user)
{
    struct unpack_context *ctx;
    char *format;

    ctx = user;

    // Truncate it if there's already a value, e.g.
    // a=(int:0 int:0) is accceptable to initialize a buffer.
    if ((format = strchr(element->value, ':')))
        *format = '\0';

    if (decode_type_prefix(element->value,
                           NULL,
                           &ctx->ptrtype,
                           NULL,
                           &format) == false) {
        // You can exit from an array_walk early by returning -1, so set
        // failure and do that here.
        ctx->retval = EXECUTION_FAILURE;

        // Give a hint about what failed to parse.
        builtin_warning("aborted unpack at bad type prefix %s (%s[%lu])",
                        element->value,
                        ctx->list->word->word,
                        element->ind);

        return -1;
    }

    // Discard previous value
    FREE(element->value);

    // Decode the type.
    element->value = encode_primitive_type(format, ctx->ptrtype, ctx->source);

    // Skip to next element.
    ctx->source += ctx->ptrtype->size;

    return 0;
}

static int unpack_prefixed_array(WORD_LIST *list)
{
    SHELL_VAR *dest_v;
    ARRAY *dest_a;
    void **value;
    struct unpack_context ctx = { 0 };

    // Assume success by default.
    ctx.retval = EXECUTION_SUCCESS;

    // Verify we have two parameters.
    if (!list || !list->next) {
        builtin_usage();
        goto error;
    }

    // Fetch the source pointer.
    if (decode_primitive_type(list->word->word,
                              (void **)&value,
                              &ctx.ptrtype) != true) {
        builtin_error("the source parameter %s could not parsed", list->word->word);
        goto error;
    }

    // Verify that it was a pointer.
    if (ctx.ptrtype != &ffi_type_pointer) {
        builtin_error("the source parameter must be a pointer");
        goto error;
    }

    // Skip to next parameter.
    list        = list->next;
    ctx.source  = *value;
    ctx.list = list;

    GET_ARRAY_FROM_VAR(list->word->word, dest_v, dest_a);

    array_walk(dest_a, unpack_decode_element, &ctx);

    return ctx.retval;

error:
    return EXECUTION_FAILURE;
}

static char *unpack_usage[] = {
    "Unpack memory into a bash array.",
    "",
    "Bash provides no convenient mechanism for dealing with binary data, this",
    "interface allows for converting between prefixed, native, primitive types.",
    "",
    "$ struct=(pointer char int long)",
    "$ unpack pointer:0x1234 struct",
    "$ echo ${struct[*]}",
    "pointer:0x1234 char:a int:1234 long:-1",
    "  pack pointer:01234 struct",
    "",
/*
    But perhaps a more usable way to deal with structures in bash is to map
    members to indexes, like this:

    $ let n=0
    $ declare -a stat
    $ { 
    >       stat[st_dev     = n++]="long"
    >       stat[st_ino     = n++]="long"
    >       stat[st_nlink   = n++]="long"
    >       stat[st_mode    = n++]="int"
    >       stat[st_uid     = n++]="int"
    >       stat[st_gid     = n++]="int"
    >       stat[             n++]="int"    # padding
    >       stat[st_rdev    = n++]="long"
    >       stat[st_size    = n++]="long"
    >       stat[st_blksize = n++]="long"
    >       stat[st_blocks  = n++]="long"
    > }
    $ unpack pointer:0x1234 stat
    $ printf "%o\n" ${stat[st_mode]}
    0644
*/
    NULL,
};

static char *pack_usage[] = {
    "Convert data from a prefixed bash array into native memory.",
    NULL,
};

struct builtin __attribute__((visibility("default"))) unpack_struct = {
    .name       = "unpack",
    .function   = unpack_prefixed_array,
    .flags      = BUILTIN_ENABLED,
    .long_doc   = unpack_usage,
    .short_doc  = "unpack pointer array",
    .handle     = NULL,
};

struct builtin __attribute__((visibility("default"))) pack_struct = {
    .name       = "pack",
    .function   = pack_prefixed_array,
    .flags      = BUILTIN_ENABLED,
    .long_doc   = pack_usage,
    .short_doc  = "pack pointer array",
    .handle     = NULL,
};

