#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#include "util.h"

bool check_parse_long(const char *number, long *result)
{
    char *endptr;

    if (strlen(number) == 0)
        return false;

    *result = strtol(number, &endptr, 0);

    return *endptr == '\0';
}
