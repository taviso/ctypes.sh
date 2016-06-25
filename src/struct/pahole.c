/*
  Copyright (C) 2006 Mandriva Conectiva S.A.
  Copyright (C) 2006 Arnaldo Carvalho de Melo <acme@mandriva.com>
  Copyright (C) 2007-2008 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <argp.h>
#include <assert.h>
#include <stdio.h>
#include <dwarf.h>
#include <search.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <ffi.h>

#include "dwarves.h"
#include "dutil.h"
#include "builtins.h"
#include "variables.h"
#include "arrayfunc.h"
#include "common.h"
#include "bashgetopt.h"
#include "util.h"
#include "types.h"
#include "shell.h"

static char *class_name;
static struct conf_fprintf conf;
static struct conf_load conf_load;

// We don't use the libctf stuff, silence loader.
struct debug_fmt_ops ctf__ops;

// This gets called once for every compilation unit, and we're expected to
// search it to see if it contains something we're interested in.
static enum load_steal_kind pahole_stealer(struct cu *cu, struct conf_load *conf_load __unused)
{
    static uint16_t class_id;
    struct tag *tag;
    struct class *class;
    struct class_member *member;

    if (!(tag = cu__find_struct_by_name(cu, "stat", false, &class_id)))
        return LSK__DELETE;

    class  = tag__class(tag);
    member = type__last_member(&class->type);

    type__for_each_data_member(&class->type, member) {
        struct tag *type = cu__type(cu, member->tag.type);

        printf("member %s size %u, tag? %s\n",
               class_member__name(member, cu),
               member->byte_size,
               dwarf_tag_name(type->tag));

        while (tag__is_typedef(type)) {
            printf("\ttypedef %s...\n", type__name(tag__type(type), cu));
            type = cu__type(cu, type->type);
        }

        if (type->tag == DW_TAG_base_type) {
            char buf[64] = {0};

            tag__name(type, cu, buf, sizeof(buf), &conf);

            printf("\tbase! so %s is a %s\n", class_member__name(member, cu), buf);
        }

        if (tag__is_struct(type) || tag__is_union(type) || tag__is_enumeration(type)) {
            printf("sorry, this isn't supported yet, soon!\n");
        }

        if (type->tag == DW_TAG_array_type) {
            printf("sorry, this isn't supported yet, soon!\n");
        }
    }

    return LSK__STOP_LOADING;
}

static int generate_standard_struct(WORD_LIST *list)
{
    struct cus *cus = cus__new();

    char *filenames[] = {
        "/usr/lib/debug/lib/x86_64-linux-gnu/libc-2.19.so",
        NULL
    };

    conf.expand_types = 1;
    conf.emit_stats = 0;
    conf.suppress_comments = 1;
    conf.flat_arrays = 1;

    class_name = "stat";

    dwarves__init(0);

    conf_load.steal = pahole_stealer;
    cus__load_files(cus, &conf_load, filenames);

    cus__delete(cus);
    dwarves__exit();
    return 0;
}

static char *struct_usage[] = {
    "Generate a bash array for a standard structure.",
    NULL,
};

struct builtin __attribute__((visibility("default"))) struct_struct = {
    .name       = "struct",
    .function   = generate_standard_struct,
    .flags      = BUILTIN_ENABLED,
    .long_doc   = struct_usage,
    .short_doc  = "generate array for matching structure",
    .handle     = NULL,
};
