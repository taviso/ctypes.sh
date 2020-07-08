#ifndef _GOBUFFER_H_
#define _GOBUFFER_H_ 1
/*
  SPDX-License-Identifier: GPL-2.0-only

  Copyright (C) 2008 Arnaldo Carvalho de Melo <acme@redhat.com>
*/

struct gobuffer {
	char		*entries;
	unsigned int	nr_entries;
	unsigned int	index;
	unsigned int	allocated_size;
};

struct gobuffer *gobuffer__new(void);

void gobuffer__init(struct gobuffer *gb);
void gobuffer__delete(struct gobuffer *gb);
void __gobuffer__delete(struct gobuffer *gb);

void gobuffer__copy(const struct gobuffer *gb, void *dest);

int gobuffer__add(struct gobuffer *gb, const void *s, unsigned int len);
int gobuffer__allocate(struct gobuffer *gb, unsigned int len);

static inline const void *gobuffer__entries(const struct gobuffer *gb)
{
	return gb->entries;
}

static inline unsigned int gobuffer__nr_entries(const struct gobuffer *gb)
{
	return gb->nr_entries;
}

static inline unsigned int gobuffer__size(const struct gobuffer *gb)
{
	return gb->index;
}

void *gobuffer__ptr(const struct gobuffer *gb, unsigned int s);

const void *gobuffer__compress(struct gobuffer *gb, unsigned int *size);

#endif /* _GOBUFFER_H_ */
