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

struct backtrace_frame {
	unw_word_t ip;
	unw_word_t ip_off;
	unw_word_t sp;
	char       f_name[32];
};

struct backtrace {
	struct backtrace_frame frames[64];
	unsigned int           cap;
	unsigned int           cnt;
};

struct loopback {
	struct list_head loop_l;
	struct list_head spur_l;
};

struct task {
	struct hash_entry h_entry;
	struct list_head  l_entry;
	struct list_head  l_stuck;

	pid_t tgid;
	pid_t tid;

	unsigned long      diff_vol_ctxt_sw;
	unsigned long      diff_nonvol_ctxt_sw;

	unsigned long long start_ms;
	unsigned long long check_ms;
	unsigned long long vol_ctxt_sw;
	unsigned long long nonvol_ctxt_sw;

	struct {
		int            nr;
		unsigned long  arg1;
		unsigned long  arg2;
		unsigned long  arg3;
	} syscall;

	struct {
		pid_t            lock_owner_pid;
		struct task     *lock_owner_task;
		struct loopback *loop;
	} pthread_info;

	struct backtrace   bt;
};

static void loopback_init(struct loopback *l)
{
	INIT_LIST_HEAD(&l->loop_l);
	INIT_LIST_HEAD(&l->spur_l);
}

static int is_chain_loopback(struct task *t)
{
	return !!(t->pthread_info.lock_owner_task);
}

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

static struct task *task_new(pid_t tgid, pid_t tid,
							 unsigned long long start_ms)
{
	struct task *t;

	t = calloc(1, sizeof(*t));
	if (!t)
		return NULL;

	t->tgid             = tgid;
	t->tid              = tid;
	t->start_ms         = start_ms;
	t->h_entry.h_key    = &t->tid;
	t->h_entry.h_key_sz = sizeof(t->tid);
	t->h_entry.h_free   = __task_free;
	t->bt.cap           = ARRAY_SIZE(t->bt.frames);

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

static void task_init_syscall(struct task *t)
{
	memset(&t->syscall, 0, sizeof(t->syscall));
}

static void task_init_pthread_info(struct task *t)
{
	memset(&t->pthread_info, 0, sizeof(t->pthread_info));
}

static int is_task_stuck(const struct task *task)
{
	return !task->diff_nonvol_ctxt_sw && !task->diff_vol_ctxt_sw;
}

static int is_task_stuck_in_futex(struct task *task)
{
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

#define hash_lookup_entry(h_tbl, key, key_sz, type, member)		  \
	({								  \
		struct hash_entry *h_e = hash_lookup(h_tbl, key, key_sz); \
		(h_e ? container_of(h_e, type, member) : NULL);		  \
	})

static int is_dot_dot_file(const char *p)
{
	return !strcmp(p, ".") || !strcmp(p, "..");
}

static int is_tgid_tid(const char *p, pid_t *tgid, pid_t *tid)
{
	return (2 == sscanf(p, "/proc/%u/task/%u", tgid, tid));
}

static int task_get_start_ms(pid_t tid, unsigned long long *start_ms)
{
	int fd;
	char buff[1024];
	size_t rd;
	int start_time_rev_field = 31;
	const char *str = buff;
	unsigned int clk_tck = sysconf(_SC_CLK_TCK);

	if (!clk_tck)
		return 0;

	snprintf(buff, sizeof(buff), "/proc/%u/stat", tid);

	fd = open(buff, O_RDONLY);
	if (fd < 0)
		return 0;

	rd = read(fd, buff, sizeof(buff) - 1);
	close(fd);
	if (rd < 2)
		return 0;

	buff[rd] = '\0';

	/* We do reverse search to avoid complicated parsing of the second
	   field, which is process name, which obviously can contains spaces */
	for (; rd; rd--) {
		if (str[rd] == ' ')
			if (!--start_time_rev_field)
				break;
	}

	if (!rd)
		return 0;

	if (1 != sscanf(str + rd, "%llu", start_ms))
		return 0;

	*start_ms = *start_ms * (1000 / clk_tck);

	return 1;
}

struct {
	struct hash_table *tasks;
	struct list_head  *list;
	struct list_head  *stuck_list;
} __nftw_ctx;

static int nftw_proc_scan(const char *fpath, const struct stat *sb,
			  int tflag, struct FTW *ftwbuf)
{
	struct task *task;
	pid_t tgid, tid;
	unsigned long long task_start_ms;

	(void)sb;

	if (tflag != FTW_D)
		return 0;
	if (ftwbuf->level != 3)
		return 0;
	if (is_dot_dot_file(fpath))
		return 0;
	if (!is_tgid_tid(fpath, &tgid, &tid))
		return 0;
	if (!task_get_start_ms(tid, &task_start_ms))
		return 0;

	task = hash_lookup_entry(__nftw_ctx.tasks, &tid, sizeof(tid),
				 struct task, h_entry);
	if (!task) {
		task = task_new(tgid, tid, task_start_ms);
		if (!task) {
			printf("memory problems\n");
			return -1;
		}
		hash_insert(__nftw_ctx.tasks, &task->h_entry);
	} else {
		/* If pid was reused - drop the task, will pick it up on next scan */
		if (task->start_ms != task_start_ms) {
			hash_remove(&task->h_entry);
			return 0;
		}
		list_del(&task->l_entry);

		/* Update tgid, it can be changed since last scan */
		task->tgid = tgid;
		/* XXX CORRECT MEMSETTING SHOULD BE GUARANTEED BY THE ALGO ITSELF ON
		*      EVERY SCAN */
		/* task_init_pthread_info(task); */
		assert(list_empty(&task->l_stuck));
		task_init_syscall(task);
	}

	list_add_tail(&task->l_entry, __nftw_ctx.list);

	task->check_ms = msecs_epoch();
	task_fill_ctxt_sw(task);

	if (is_task_stuck(task) && task_fill_syscall(task))
		if (is_task_stuck_in_futex(task))
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

static int do_backtrace(struct backtrace_frame *bt, unsigned int *bt_sz,
			unsigned int max_bt_sz, unw_addr_space_t as,
			struct UPT_info *ui)
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

	*bt_sz = n;

	return 0;
}

static int is_lll_lock_wait(struct backtrace_frame *f)
{
	return (0 == strcmp(f->f_name, "__lll_lock_wait"));
}

static int peek_pthread_info(struct task *t)
{
	pid_t tid;
	pthread_mutex_t *tracee_mutex;

	/* Black magic? No, just wrap 'int' type in complicated manner */
	typeof(tracee_mutex->__data.__lock) *tracee_lock =
		(typeof(tracee_mutex->__data.__lock) *)t->syscall.arg1;
	/* Cast tracee lock to whole pthread mutex object */
	tracee_mutex = container_of(tracee_lock, pthread_mutex_t, __data.__lock);
	/* Peek pthread onwer */
	tid = ptrace(PTRACE_PEEKDATA, t->tid, &tracee_mutex->__data.__owner, NULL);
	if (errno != 0) {
		perror("ptrace(PTRACE_PEEKDATA)");
		return -1;
	}

	t->pthread_info.lock_owner_pid = tid;

	return 0;
}

static void print_backtrace(struct task *t)
{
	unsigned int i;

	printf("  tid %u (tgid %u) waits for tid %u:\n",
	       t->tid, t->tgid, t->pthread_info.lock_owner_pid);

	for (i = 0; i < t->bt.cnt; i++)
		printf("\t%016lx %s + 0x%lx\n",
		       (long)t->bt.frames[i].ip, t->bt.frames[i].f_name,
		       (long)t->bt.frames[i].ip_off);
}

static void print_loopback(struct loopback *l, unsigned int ind)
{
	struct task *t;

	printf("----------------------------------------------\n");
	printf("%u) lock loopback:\n", ind);

	list_for_each_entry(t, &l->loop_l, l_stuck) {
		print_backtrace(t);
		printf("\n");
	}

	if (!list_empty(&l->spur_l)) {
		printf("tasks which wait for loopback:\n");

		list_for_each_entry(t, &l->spur_l, l_stuck) {
			print_backtrace(t);
			printf("\n");
		}

		printf("\n");
	}
}

static int unwind_pthread_backtrace(struct task *t)
{
	unw_addr_space_t as;
	struct UPT_info *ui;
	int status, ret;
	int waits = 20;

	/* XXX: on sudden death we have to do detach, TODO catch signals */
	if (ptrace(PTRACE_ATTACH, t->tid, NULL, NULL) < 0) {
		perror("ptrace(PTRACE_ATTACH)");
		return -1;
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
		ret = -1;
		goto err_detach;
	}

	ui = _UPT_create(t->tid);
	if (!ui) {
		printf("_UPT_create() failed");
		ret = -1;
		goto err_free_addr_space;
	}

	ret = do_backtrace(t->bt.frames, &t->bt.cnt, t->bt.cap, as, ui);
	if (!ret) {
		/* Here we are interested only in 'lll_lock_wait' */
		if (is_lll_lock_wait(&t->bt.frames[0]))
			ret = peek_pthread_info(t);
	}

	_UPT_destroy(ui);
err_free_addr_space:
	unw_destroy_addr_space(as);
err_detach:
	ptrace(PTRACE_DETACH, t->tid, NULL, NULL);

	return ret;
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
	unsigned int i;
	struct hash_table hash_tasks;
	struct list_head  scan_lists[2];
	struct list_head  stuck_list;
	struct list_head *list = NULL;
	struct loopback   loops[16];
	struct task *t_l, *tmp_l;

	(void)argc;
	(void)argv;

	INIT_LIST_HEAD(&scan_lists[0]);
	INIT_LIST_HEAD(&scan_lists[1]);
	INIT_LIST_HEAD(&stuck_list);

	hash_init(&hash_tasks);

	for (i = 0; i < ARRAY_SIZE(loops); i++)
		loopback_init(&loops[i]);

	while (1) {
		struct task *t,  *tmp;
		struct list_head *prev_list = list;
		unsigned int      loop_nr = 0;

		list = swap_scan_lists(scan_lists, ARRAY_SIZE(scan_lists), list);

		/* Everything should be correctly cleaned up */
		assert(list_empty(&stuck_list));

		/* Scan all the tasks and fill the hash */
		ret = do_tasks_scan(&hash_tasks, list, &stuck_list);
		if (ret) {
			printf("ERROR: do_tasks_scan failed, %d, repeat\n", ret);
			goto free_dead;
		}

		/* We have some tasks stuck in futex, do further analysis */
		while (!list_empty(&stuck_list)) {
			struct task *t_prev = NULL;
			struct loopback *loop;

			t = list_first_entry(&stuck_list, struct task, l_stuck);
			assert(!is_chain_loopback(t));

			if (loop_nr >= ARRAY_SIZE(loops)) {
				printf("WARNING: maximum number %d of possible loopbacks exceeded\n",
				       loop_nr);
				break;
			}

			loop = &loops[loop_nr];
			assert(list_empty(&loop->loop_l));
			assert(list_empty(&loop->spur_l));

			/* Cycle till chain is broken or loopback is found */
			do {
				pid_t tid;

				/* Move task to loop */
				list_del(&t->l_stuck);
				list_add_tail(&t->l_stuck, &loop->loop_l);
				t->pthread_info.loop = loop;

				ret = unwind_pthread_backtrace(t);
				if (ret)
					break;

				/* Every task in chain should be suspicious */
				if (list_empty(&t->l_stuck))
					break;

				/* Now we are interested only in pthread_mutex_lock */
				if (!is_lll_lock_wait(&t->bt.frames[0]))
					break;

				/* Chain it */
				if (t_prev)
					t_prev->pthread_info.lock_owner_task = t;
				t_prev = t;

				/* Do hash lookup of lock owner */
				tid = t->pthread_info.lock_owner_pid;
				assert(tid != 0);
				t = hash_lookup_entry(&hash_tasks, &tid, sizeof(tid),
						      struct task, h_entry);

			} while (t && !is_chain_loopback(t));

			/* Handle two cases: chain is broken or chain is a spur
			 * of another loop:
			 *    chain is broken:      !t || !is_chain_loopback
			 *    spur of another loop: t->loop != loop
			 *
			 * If chain is broken just forget about the tasks in this chain.
			 * If chain is a spur and belongs to another loop just splice this
			 * chain to the spur list of another loop.
			 */
			if (!t || !is_chain_loopback(t) ||
			    t->pthread_info.loop != loop) {
				int chain_broken = (!t || !is_chain_loopback(t));

				list_for_each_entry_safe(t_l, tmp_l, &loop->loop_l,
							 l_stuck) {
					list_del(&t_l->l_stuck);
					if (chain_broken) {
						INIT_LIST_HEAD(&t_l->l_stuck);
						task_init_pthread_info(t_l);
					} else {
						struct loopback *l;

						assert(t);
						l = t->pthread_info.loop;

						t_l->pthread_info.loop = l;
						list_add_tail(&t_l->l_stuck, &l->spur_l);
					}
				}
				continue;
			}

			/* Got it, loopback is found, sort out spur tasks */
			list_for_each_entry_safe(t_l, tmp_l, &loop->loop_l,
						 l_stuck) {
				/* Reach the loop entrance, quit */
				if (t_l == t)
					break;

				list_del(&t_l->l_stuck);
				list_add_tail(&t_l->l_stuck, &loop->spur_l);
			}

			loop_nr++;
		}


		/* There are no excuses to have non empty list with loops
		 * less than possible, everything should be sorted out on
		 * previous steps
		 */
		assert(list_empty(&stuck_list) || loop_nr >= ARRAY_SIZE(loops));

		/* Here we have loopbacks and its' spurs, deal with them */
		for (i = 0; i < loop_nr; i++) {
			struct loopback *loop = &loops[i];

			print_loopback(loop, i+1);

			/* Return everything back to stuck list for
			 * further cleanups
			 */
			list_splice(&loop->loop_l, &stuck_list);
			list_splice(&loop->spur_l, &stuck_list);
			loopback_init(loop);
		}

		/* Remove remains */
		list_for_each_entry_safe(t_l, tmp_l, &stuck_list,
					 l_stuck) {
			list_del_init(&t_l->l_stuck);
			task_init_pthread_info(t_l);
		}

	free_dead:
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
