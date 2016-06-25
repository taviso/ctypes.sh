/*
  Copyright (C) 2008 Arnaldo Carvalho de Melo <acme@redhat.com>

  Grow only buffer, add entries but never delete

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include "gobuffer.h"

#include <search.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <zlib.h>
#include <errno.h>

#include "dutil.h"

#define GOBUFFER__BCHUNK (8 * 1024)
#define GOBUFFER__ZCHUNK (8 * 1024)

void gobuffer__init(struct gobuffer *gb)
{
	gb->entries = NULL;
	gb->nr_entries = gb->allocated_size = 0;
	/* 0 == NULL */
	gb->index = 1;
}

struct gobuffer *gobuffer__new(void)
{
	struct gobuffer *gb = malloc(sizeof(*gb));

	if (gb != NULL)
		gobuffer__init(gb);

	return gb;
}

void __gobuffer__delete(struct gobuffer *gb)
{
	free(gb->entries);
}

void gobuffer__delete(struct gobuffer *gb)
{
	__gobuffer__delete(gb);
	free(gb);
}

void *gobuffer__ptr(const struct gobuffer *gb, unsigned int s)
{
	return s ? gb->entries + s : NULL;
}

int gobuffer__allocate(struct gobuffer *gb, unsigned int len)
{
	const unsigned int rc = gb->index;
	const unsigned int index = gb->index + len;

	if (index >= gb->allocated_size) {
		unsigned int allocated_size = (gb->allocated_size +
					       GOBUFFER__BCHUNK);
		if (allocated_size < index)
			allocated_size = index + GOBUFFER__BCHUNK;
		char *entries = realloc(gb->entries, allocated_size);

		if (entries == NULL)
			return -ENOMEM;

		gb->allocated_size = allocated_size;
		gb->entries = entries;
	}

	gb->index = index;
	return rc;
}

int gobuffer__add(struct gobuffer *gb, const void *s, unsigned int len)
{
	const int rc = gobuffer__allocate(gb, len);

	if (rc >= 0) {
		++gb->nr_entries;
		memcpy(gb->entries + rc, s, len);
	}
	return rc;
}

void gobuffer__copy(const struct gobuffer *gb, void *dest)
{
	memcpy(dest, gb->entries, gobuffer__size(gb));
}

const void *gobuffer__compress(struct gobuffer *gb, unsigned int *size)
{
	z_stream z = {
		.zalloc	  = Z_NULL,
		.zfree	  = Z_NULL,
		.opaque	  = Z_NULL,
		.avail_in = gobuffer__size(gb),
		.next_in  = (Bytef *)gobuffer__entries(gb),
	};
	void *bf = NULL;
	unsigned int bf_size = 0;

	if (deflateInit(&z, Z_BEST_COMPRESSION) != Z_OK)
		goto out_free;

	do {
		const unsigned int new_bf_size = bf_size + GOBUFFER__ZCHUNK;
		void *nbf = realloc(bf, new_bf_size);

		if (nbf == NULL)
			goto out_close_and_free;

		bf = nbf;
		z.avail_out = GOBUFFER__ZCHUNK;
		z.next_out  = (Bytef *)bf + bf_size;
		bf_size	    = new_bf_size;
		if (deflate(&z, Z_FINISH) == Z_STREAM_ERROR)
			goto out_close_and_free;
	} while (z.avail_out == 0);

	deflateEnd(&z);
	*size = bf_size - z.avail_out;
out:
	return bf;

out_close_and_free:
	deflateEnd(&z);
out_free:
	free(bf);
	bf = NULL;
	goto out;
}
