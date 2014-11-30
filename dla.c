/*
 * dla - Futex deadlock analyser
 *
 * Copyright (C) 2014 Roman Pen <r.peniaev@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <getopt.h>
#include <limits.h>
#include <malloc.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

struct list_head prev_scan;
struct list_head curr_scan;

struct hash_table hash_tasks;

unsigned int jhash(const char *key, size_t len)
{
	unsigned int hash, i;
	for (hash = i = 0; i < len; ++i) {
		hash += key[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);
	return hash;
}

#define MAX_HASHSIZE 128

struct hash_entry {
	unsigned int     h_key;
	struct list_head h_list;
};

struct hash_table {
	struct list_head *h_tbl;
	unsigned int      h_sz;
};

static int hash_init(struct hash_table *hash)
{
	hash->h_sz = MAX_HASHSIZE;
	hash->h_tbl = malloc(sizeof(*hash->h_tbl) * hash->h_sz);

	return (hash->h_tbl ? 0 : -ENOMEM);
}

static int hash_insert(struct hash_table *h, struct hash_entry *e)
{
	unsigned int hash;

	hash = jhash(&e->key, sizeof(e->key));
	list_add(&e->h_list, &hash->h_tbl[hash & (hash->h_sz - 1)]);
}

static int hash_remove(struct hash_entry *e)
{
	list_remove(&e->h_list);
}

static struct hash_entry *hash_lookup(struct hash_table *h, unsigned int key)
{
	struct hash_entry *e;
	struct list_head *l;
	unsigned int hash;

	hash = jhash(&e->key, sizeof(e->key));
	l = &hash->h_tbl[hash & (hash->h_sz - 1)];
	for_each_list(e, l)
		if (e->key == key)
			return e;
	return NULL;
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	while (1) {
		do_scan(&hash_tasks, &prev_scan);
		
	}

	return 0;
}
