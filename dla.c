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
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <libunwind-ptrace.h>

struct UPT_info;

#include "list.h"

#define MAX_HASHSIZE 1024

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

unsigned int jhash(const void *key_, size_t len)
{
	unsigned int hash, i;
	const unsigned char *key = key_;
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

struct hash_entry {
	void             *h_key;
	unsigned int      h_key_sz;
	struct list_head  h_list;
	void (*h_free)(struct hash_entry *);
};

struct hash_table {
	struct list_head *h_tbl;
	unsigned int      h_sz;
};

struct task {
	struct hash_entry h_entry;
	struct list_head  l_entry;
	struct list_head  l_stuck;


	pid_t tgid;
	pid_t tid;

	unsigned long      diff_vol_ctxt_sw;
	unsigned long      diff_nonvol_ctxt_sw;

	unsigned long long vol_ctxt_sw;
	unsigned long long nonvol_ctxt_sw;
	unsigned long long check_ms;

	struct {
		int           nr;
		unsigned long arg1;
		unsigned long arg2;
		unsigned long arg3;
	} syscall;
};

static inline unsigned long long msecs_epoch()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return ((unsigned long long)tv.tv_sec * 1000) +
		((unsigned long long)tv.tv_usec / 1000);
}

static void __task_free(struct hash_entry *e)
{
	struct task *t = container_of(e, struct task, h_entry);
	list_del(&t->l_entry);
	list_del(&t->l_stuck);
	free(t);
}

static struct task *task_new(pid_t tgid, pid_t tid)
{
	struct task *t;

	t = calloc(1, sizeof(*t));
	if (!t)
		return NULL;

	t->tgid             = tgid;
	t->tid              = tid;
	t->h_entry.h_key    = &t->tid;
	t->h_entry.h_key_sz = sizeof(t->tid);
	t->h_entry.h_free   = __task_free;

	INIT_LIST_HEAD(&t->l_entry);
	INIT_LIST_HEAD(&t->l_stuck);

	return t;
}

static void task_fill_ctxt_sw(struct task *task)
{
	FILE *fp;
	char path[32];
	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	snprintf(path, sizeof(path), "/proc/%u/status", task->tid);

	fp = fopen(path, "r");
	if (!fp) {
		perror("open /proc/*/status failed");
		goto out;
	}

	while ((read = getline(&line, &len, fp)) != -1) {
		unsigned long long vol_sw, nonvol_sw;

		if (1 == sscanf(line, "voluntary_ctxt_switches: %llu", &vol_sw)) {
			task->diff_vol_ctxt_sw = vol_sw - task->vol_ctxt_sw;
			task->vol_ctxt_sw      = vol_sw;
		}
		if (1 == sscanf(line, "nonvoluntary_ctxt_switches: %llu", &nonvol_sw)) {
			task->diff_nonvol_ctxt_sw = nonvol_sw - task->nonvol_ctxt_sw;
			task->nonvol_ctxt_sw      = nonvol_sw;
		}
	}

	free(line);

out:
	if (fp)
		fclose(fp);
}

static int task_fill_syscall(struct task *task)
{
	FILE *fp;
	char path[32];
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	int res = 0;

	snprintf(path, sizeof(path), "/proc/%u/syscall", task->tid);

	fp = fopen(path, "r");
	if (!fp) {
		perror("open /proc/*/syscall failed");
		goto out;
	}

	while ((read = getline(&line, &len, fp)) != -1) {
		res = (4 == sscanf(line, "%u %lx %lx %lx",
				   &task->syscall.nr,
				   &task->syscall.arg1,
				   &task->syscall.arg2,
				   &task->syscall.arg3));
		break;
	}

	free(line);

out:
	if (fp)
		fclose(fp);

	return res;
}

static int is_task_stuck(const struct task *task)
{
	return !task->diff_nonvol_ctxt_sw && !task->diff_vol_ctxt_sw;
}

static int is_task_stuck_in_futex(struct task *task)
{
	if (!task_fill_syscall(task))
		return 0;
	if (task->syscall.nr != SYS_futex)
		return 0;
	/* Here we handle only 'pthread_mutex_lock', which has '2' as lock value, */
	if (task->syscall.arg3 != 2)
		return 0;

	return 1;
}

static int hash_init(struct hash_table *h)
{
	unsigned int i;

	h->h_sz = MAX_HASHSIZE;
	h->h_tbl = malloc(sizeof(*h->h_tbl) * h->h_sz);
	if (!h->h_tbl)
		return -ENOMEM;

	for (i = 0; i < h->h_sz; i++) {
		struct list_head *head = &h->h_tbl[i];
		INIT_LIST_HEAD(head);
	}

	return 0;
}

static void hash_free(struct hash_table *h)
{
	unsigned int i;

	for (i = 0; i < h->h_sz; i++) {
		struct hash_entry *e;
		struct list_head *head = &h->h_tbl[i];
		list_for_each_entry(e, head, h_list) {
			e->h_free(e);
		}
	}
}

static void hash_insert(struct hash_table *h, struct hash_entry *e)
{
	unsigned int hash;

	hash = jhash(e->h_key, e->h_key_sz);
	list_add_tail(&e->h_list, &h->h_tbl[hash & (h->h_sz - 1)]);
}

static void hash_remove(struct hash_entry *e)
{
	list_del(&e->h_list);
	e->h_free(e);
}

static struct hash_entry *hash_lookup(struct hash_table *h,
				      const void *key, unsigned int key_sz)
{
	struct hash_entry *e;
	struct list_head *l;
	unsigned int hash;

	hash = jhash(key, key_sz);
	l = &h->h_tbl[hash & (h->h_sz - 1)];
	list_for_each_entry(e, l, h_list) {
		if (e->h_key_sz != key_sz)
			continue;
		if (!memcmp(e->h_key, key, key_sz))
			return e;
	}
	return NULL;
}

static int is_dot_dot_file(const char *p)
{
	return !strcmp(p, ".") || !strcmp(p, "..");
}

static int is_tgid_tid(const char *p, pid_t *tgid, pid_t *tid)
{
	return (2 == sscanf(p, "/proc/%u/task/%u", tgid, tid));
}

struct {
	struct hash_table *tasks;
	struct list_head  *list;
	struct list_head  *stuck_list;
} __nftw_ctx;

static int nftw_proc_scan(const char *fpath, const struct stat *sb,
			  int tflag, struct FTW *ftwbuf)
{
	struct hash_entry *h_entry;
	struct task *task;
	pid_t tgid, tid;

	(void)sb;

	if (tflag != FTW_D)
		return 0;
	if (ftwbuf->level != 3)
		return 0;
	if (is_dot_dot_file(fpath))
		return 0;
	if (!is_tgid_tid(fpath, &tgid, &tid))
		return 0;

	h_entry = hash_lookup(__nftw_ctx.tasks, &tid, sizeof(tid));
	if (!h_entry) {
		task = task_new(tgid, tid);
		if (!task) {
			printf("memory problems\n");
			return -1;
		}
		hash_insert(__nftw_ctx.tasks, &task->h_entry);
	} else {
		task = container_of(h_entry, struct task, h_entry);
		list_del(&task->l_entry);
	}

	list_add_tail(&task->l_entry, __nftw_ctx.list);

	task->check_ms = msecs_epoch();
	task_fill_ctxt_sw(task);

	if (is_task_stuck(task) && is_task_stuck_in_futex(task))
		list_add(&task->l_stuck, __nftw_ctx.stuck_list);

	return 0;
}

static int do_tasks_scan(struct hash_table *hash_tasks, struct list_head *list,
			 struct list_head *stuck_list)
{
	/* What we can do? Nothing, just do not use threads */
	__nftw_ctx.tasks      = hash_tasks;
	__nftw_ctx.list       = list;
	__nftw_ctx.stuck_list = stuck_list;

	if (nftw("/proc", nftw_proc_scan, 32, FTW_PHYS) == -1) {
		perror("nftw");
		return -1;
	}

	return 0;
}

struct backtrace_frame {
	unw_word_t ip;
	unw_word_t ip_off;
	unw_word_t sp;
	char       f_name[32];
};

static int do_backtrace(struct backtrace_frame *bt, unsigned int max_bt_sz,
			 unw_addr_space_t as, struct UPT_info *ui)
{
	unw_word_t start_ip = 0;
	int n = 0, ret;
	unw_cursor_t c;

	ret = unw_init_remote(&c, as, ui);
	if (ret < 0) {
		printf("unw_init_remote() failed: ret=%d\n", ret);
		return ret;
	}

	do {
		struct backtrace_frame *frame = &bt[n];

		/* Get registers */
		if ((ret = unw_get_reg(&c, UNW_REG_IP, &frame->ip)) < 0 ||
		    (ret = unw_get_reg(&c, UNW_REG_SP, &frame->sp)) < 0)
			printf("unw_get_reg/unw_get_proc_name() failed: ret=%d\n", ret);

		if (n == 0)
			start_ip = frame->ip;

		/* Get function name */
		unw_get_proc_name(&c, frame->f_name, sizeof(frame->f_name),
				  &frame->ip_off);

		ret = unw_step(&c);
		if (ret < 0) {
			unw_get_reg(&c, UNW_REG_IP, &frame->ip);
			printf("FAILURE: unw_step() returned %d for ip=%lx (start ip=%lx)\n",
			       ret, (long)frame->ip, (long)start_ip);
		}

		if ((unsigned)n >= max_bt_sz) {
			/* guard against bad unwind info in old libraries... */
			printf("too deeply nested---assuming bogus unwind (start ip=%lx)\n",
			       (long)start_ip);
			break;
		}
	}
	while (ret > 0 && ++n);

	if (ret < 0)
		return ret;
	else
		return n;
}

static int is_lll_lock_wait(struct backtrace_frame *f)
{
	return (0 == strcmp(f->f_name, "__lll_lock_wait"));
}

static void print_backtrace(struct task *t,
			    struct backtrace_frame *bt, unsigned int bt_sz)
{
	unsigned int i;

	printf("Task: tgid %u, tid %u:\n", t->tgid, t->tid);

	for (i = 0; i < bt_sz; i++)
		printf("\t%016lx %s + 0x%lx\n",
		       (long)bt[i].ip, bt[i].f_name, (long)bt[i].ip_off);

	printf("\n");
}

static void do_futex_stuck_analysis(struct task *t)
{
	unw_addr_space_t as;
	struct UPT_info *ui;
	int status, ret;
	int waits = 20;
	struct backtrace_frame bt[64] = {};

	/* XXX: on sudden death we have to do detach, TODO catch signals */
	if (ptrace(PTRACE_ATTACH, t->tid, NULL, NULL) < 0) {
		perror("ptrace(PTRACE_ATTACH)");
		return;
	}

	/* Wait for ptrace stop */
	do {
		ret = wait4(t->tid, &status,
			    (t->tgid != t->tid ? __WCLONE : 0) | WNOHANG, NULL);
		if (!ret)
			usleep(10000);
	} while (ret >= 0 && !WIFSTOPPED(status) && waits--);

	if (ret < 0) {
		perror("waitpid");
		goto err_detach;
	}
	if (!WIFSTOPPED(status)) {
		printf("can't ptrace process tid %u, status %d\n",
		       t->tid, status);
		goto err_detach;
	}

	as = unw_create_addr_space(&_UPT_accessors, 0);
	if (!as) {
		printf("unw_create_addr_space() failed");
		goto err_detach;
	}

	ui = _UPT_create(t->tid);
	if (!ui) {
		printf("_UPT_create() failed");
		goto err_free_addr_space;
	}

	ret = do_backtrace(bt, ARRAY_SIZE(bt), as, ui);
	if (ret > 0 && is_lll_lock_wait(&bt[0]))
		print_backtrace(t, bt, ret);

	_UPT_destroy(ui);
err_free_addr_space:
	unw_destroy_addr_space(as);
err_detach:
	ptrace(PTRACE_DETACH, t->tid, NULL, NULL);
}

static struct list_head *swap_scan_lists(struct list_head *lists,
					 unsigned int cnt,
					 struct list_head *list)
{
	unsigned long pos;

	if (!list)
		return lists;
	pos = (unsigned long)(list - lists);
	return lists + ((pos + 1) % cnt);
}

int main(int argc, char *argv[])
{
	int ret;
	struct hash_table hash_tasks;
	struct list_head scan_lists[2];
	struct list_head stuck_list;
	struct list_head *list = NULL;

	(void)argc;
	(void)argv;

	INIT_LIST_HEAD(&scan_lists[0]);
	INIT_LIST_HEAD(&scan_lists[1]);
	INIT_LIST_HEAD(&stuck_list);
	hash_init(&hash_tasks);

	while (1) {
		struct task *t, *tmp;
		struct list_head *prev_list = list;

		list = swap_scan_lists(scan_lists, ARRAY_SIZE(scan_lists), list);

		/* Scan all the tasks and fill the hash */
		ret = do_tasks_scan(&hash_tasks, list, &stuck_list);
		if (ret) {
			printf("ERROR: do_tasks_scan failed, %d\n", ret);
			exit(1);
		}

		/* We have some tasks stuck in futex, do further analysis */
		list_for_each_entry_safe(t, tmp, &stuck_list, l_stuck) {
			do_futex_stuck_analysis(t);
			list_del(&t->l_stuck);
		}

		/* Remove all tasks which now are dead since last scan */
		if (prev_list) {
			list_for_each_entry_safe(t, tmp, prev_list, l_entry)
				hash_remove(&t->h_entry);
		}

		sleep(3);
	}

	hash_free(&hash_tasks);

	return 0;
}
