/*
  Copyright (C) 2007 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/


#include "dutil.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *zalloc(const size_t size)
{
	void *s = malloc(size);
	if (s != NULL)
		memset(s, 0, size);
	return s;
}

struct str_node *str_node__new(const char *s, bool dupstr)
{
	struct str_node *snode = malloc(sizeof(*snode));

	if (snode != NULL){
		if (dupstr) {
			s = strdup(s);
			if (s == NULL)
				goto out_delete;
		}
		snode->s = s;
	}

	return snode;

out_delete:
	free(snode);
	return NULL;
}

static void str_node__delete(struct str_node *snode, bool dupstr)
{
	if (dupstr)
		free((void *)snode->s);
	free(snode);
}

int strlist__add(struct strlist *slist, const char *new_entry)
{
        struct rb_node **p = &slist->entries.rb_node;
        struct rb_node *parent = NULL;
	struct str_node *sn;

        while (*p != NULL) {
		int rc;

                parent = *p;
                sn = rb_entry(parent, struct str_node, rb_node);
		rc = strcmp(sn->s, new_entry);

		if (rc > 0)
                        p = &(*p)->rb_left;
                else if (rc < 0)
                        p = &(*p)->rb_right;
		else
			return -EEXIST;
        }

	sn = str_node__new(new_entry, slist->dupstr);
	if (sn == NULL)
		return -ENOMEM;

        rb_link_node(&sn->rb_node, parent, p);
        rb_insert_color(&sn->rb_node, &slist->entries);

	return 0;
}

int strlist__load(struct strlist *slist, const char *filename)
{
	char entry[1024];
	int err = -1;
	FILE *fp = fopen(filename, "r");

	if (fp == NULL)
		return -1;

	while (fgets(entry, sizeof(entry), fp) != NULL) {
		const size_t len = strlen(entry);

		if (len == 0)
			continue;
		entry[len - 1] = '\0';

		if (strlist__add(slist, entry) != 0)
			goto out;
	}

	err = 0;
out:
	fclose(fp);
	return err;
}

struct strlist *strlist__new(bool dupstr)
{
	struct strlist *slist = malloc(sizeof(*slist));

	if (slist != NULL) {
		slist->entries = RB_ROOT;
		slist->dupstr = dupstr;
	}

	return slist;
}

void strlist__delete(struct strlist *slist)
{
	if (slist != NULL) {
		struct str_node *pos;
		struct rb_node *next = rb_first(&slist->entries);

		while (next) {
			pos = rb_entry(next, struct str_node, rb_node);
			next = rb_next(&pos->rb_node);
			strlist__remove(slist, pos);
		}
		slist->entries = RB_ROOT;
		free(slist);
	}
}

void strlist__remove(struct strlist *slist, struct str_node *sn)
{
	rb_erase(&sn->rb_node, &slist->entries);
	str_node__delete(sn, slist->dupstr);
}

bool strlist__has_entry(struct strlist *slist, const char *entry)
{
        struct rb_node **p = &slist->entries.rb_node;
        struct rb_node *parent = NULL;

        while (*p != NULL) {
		struct str_node *sn;
		int rc;

                parent = *p;
                sn = rb_entry(parent, struct str_node, rb_node);
		rc = strcmp(sn->s, entry);

		if (rc > 0)
                        p = &(*p)->rb_left;
                else if (rc < 0)
                        p = &(*p)->rb_right;
		else
			return true;
        }

	return false;
}

Elf_Scn *elf_section_by_name(Elf *elf, GElf_Ehdr *ep,
			     GElf_Shdr *shp, const char *name, size_t *index)
{
	Elf_Scn *sec = NULL;
	size_t cnt = 1;

	while ((sec = elf_nextscn(elf, sec)) != NULL) {
		char *str;

		gelf_getshdr(sec, shp);
		str = elf_strptr(elf, ep->e_shstrndx, shp->sh_name);
		if (!strcmp(name, str)) {
			if (index)
				*index = cnt;
			break;
		}
		++cnt;
	}

	return sec;
}
