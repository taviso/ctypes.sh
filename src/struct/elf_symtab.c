/*
  Copyright (C) 2009 Red Hat Inc.
  Copyright (C) 2009 Arnaldo Carvalho de Melo <acme@redhat.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.
*/

#include <malloc.h>
#include <stdio.h>
#include <string.h>

#include "dutil.h"
#include "elf_symtab.h"

#define HASHSYMS__BITS 8
#define HASHSYMS__SIZE (1UL << HASHSYMS__BITS)

struct elf_symtab *elf_symtab__new(const char *name, Elf *elf, GElf_Ehdr *ehdr)
{
	if (name == NULL)
		name = ".symtab";

	GElf_Shdr shdr;
	Elf_Scn *sec = elf_section_by_name(elf, ehdr, &shdr, name, NULL);

	if (sec == NULL)
		return NULL;

	if (gelf_getshdr(sec, &shdr) == NULL)
		return NULL;

	struct elf_symtab *symtab = malloc(sizeof(*symtab));
	if (symtab == NULL)
		return NULL;

	symtab->name = strdup(name);
	if (symtab->name == NULL)
		goto out_delete;

	symtab->syms = elf_getdata(sec, NULL);
	if (symtab->syms == NULL)
		goto out_free_name;

	sec = elf_getscn(elf, shdr.sh_link);
	if (sec == NULL)
		goto out_free_name;

	symtab->symstrs = elf_getdata(sec, NULL);
	if (symtab->symstrs == NULL)
		goto out_free_name;

	symtab->nr_syms = shdr.sh_size / shdr.sh_entsize;

	return symtab;
out_free_name:
	free(symtab->name);
out_delete:
	free(symtab);
	return NULL;
}

void elf_symtab__delete(struct elf_symtab *symtab)
{
	if (symtab == NULL)
		return;
	free(symtab->name);
	free(symtab);
}
