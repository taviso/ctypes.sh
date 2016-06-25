#ifndef _STRINGS_H_
#define _STRINGS_H_ 1
/*
  Copyright (C) 2008 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include "gobuffer.h"

typedef unsigned int strings_t;

struct strings {
	void		*tree;
	struct gobuffer	gb;
};

struct strings *strings__new(void);

void strings__delete(struct strings *strings);

strings_t strings__add(struct strings *strings, const char *str);
strings_t strings__find(struct strings *strings, const char *str);

int strings__cmp(const struct strings *strings, strings_t a, strings_t b);

static inline const char *strings__ptr(const struct strings *strings, strings_t s)
{
	return gobuffer__ptr(&strings->gb, s);
}

static inline const char *strings__entries(const struct strings *strings)
{
	return gobuffer__entries(&strings->gb);
}

static inline unsigned int strings__nr_entries(const struct strings *strings)
{
	return gobuffer__nr_entries(&strings->gb);
}

static inline strings_t strings__size(const struct strings *strings)
{
	return gobuffer__size(&strings->gb);
}

static inline const char *strings__compress(struct strings *strings,
					    unsigned int *size)
{
	return gobuffer__compress(&strings->gb, size);
}

#endif /* _STRINGS_H_ */
