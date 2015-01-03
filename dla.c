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
#include <sys/ptrace.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <libunwind-ptrace.h>

#include "list.h"
#include "proto.h"

#define MAX_HASHSIZE  1024
#define DEFAULT_DELAY 5
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

static char **arg_exe;
static int    arg_exe_cnt;

static unsigned int jhash(const void *key_, size_t len)
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

enum task_state {
	TASK_NEWBIE     = 0,
	TASK_TO_ANALYSE = 1,
	/* >1 - task stuck */
};

struct task {
	struct hash_entry h_entry;
	struct list_head  l_entry;
	struct list_head  l_stuck;

	pid_t tgid;
	pid_t tid;

	/* If true derefer analysis on next scan */
	unsigned int       need_relax;

	/*  0 - newbie, task was just created, TASK_NEWBIE
	 *  1 - task can be analysed, TASK_TO_ANALYSE
	 * >1 - has been detected as stuck */
	unsigned int       stuck_generation;

	unsigned int       diff_vol_ctxt_sw;
	unsigned int       diff_nonvol_ctxt_sw;

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

static int is_task_in_loop(struct task *t)
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

static int is_task_newbie(const struct task *task)
{
	return (task->stuck_generation == TASK_NEWBIE);
}

static int was_task_stuck(struct task *task)
{
	return (task->stuck_generation > TASK_TO_ANALYSE);
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
		struct hash_entry *e, *tmp;
		struct list_head *head = &h->h_tbl[i];
		list_for_each_entry_safe(e, tmp, head, h_list)
			e->h_free(e);
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
	   field, which is a process name, which obviously can contain spaces */
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
	struct list_head  *old_stuck_list;
	struct list_head  *new_stuck_list;
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
		assert(list_empty(&task->l_stuck));
		task_init_syscall(task);
		if (is_task_newbie(task))
			task->stuck_generation = TASK_TO_ANALYSE;
	}

	list_add_tail(&task->l_entry, __nftw_ctx.list);

	task->check_ms = msecs_epoch();
	task_fill_ctxt_sw(task);

	if (!is_task_newbie(task) && !task->need_relax) {
		if (is_task_stuck(task) &&
			task_fill_syscall(task) &&
			is_task_stuck_in_futex(task)) {
			if (was_task_stuck(task))
				list_add(&task->l_stuck, __nftw_ctx.old_stuck_list);
			else
				list_add(&task->l_stuck, __nftw_ctx.new_stuck_list);
			task->stuck_generation++;
		} else
			task->stuck_generation = TASK_TO_ANALYSE;
	}

	task->need_relax = 0;

	return 0;
}

static int do_tasks_scan(struct hash_table *hash_tasks, struct list_head *list,
			 struct list_head *old_stuck_list,
			 struct list_head *new_stuck_list)
{
	/* What we can do? Nothing, just do not use threads */
	__nftw_ctx.tasks          = hash_tasks;
	__nftw_ctx.list           = list;
	__nftw_ctx.old_stuck_list = old_stuck_list;
	__nftw_ctx.new_stuck_list = new_stuck_list;

	if (nftw("/proc", nftw_proc_scan, 32, FTW_PHYS) == -1) {
		perror("nftw");
		return -1;
	}

	return 0;
}

struct UPT_info;

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

static int output_stream_type(int fd, enum dla_stream_type t)
{
	return dla_send_stream_type(fd, t);
}

static int output_stream_field(int fd, struct dla_stream_field *f)
{
	return dla_send_stream_field(fd, f);
}

static int output_task_fields(int fd, struct task *t)
{
	int r;
	struct dla_stream_field field;
	uint32_t val32;

	r = output_stream_type(fd, TASK);
	if (r)
		return r;

	/* tgid */
	val32 = htole32((uint32_t)t->tgid);
	field.type = TASK_tgid;
	field.len  = sizeof(val32);
	memcpy(&field.data, &val32, field.len);

	r = output_stream_field(fd, &field);
	if (r)
		return r;

	/* tid */
	val32 = htole32((uint32_t)t->tid);
	field.type = TASK_tid;
	field.len  = sizeof(val32);
	memcpy(&field.data, &val32, field.len);

	r = output_stream_field(fd, &field);
	if (r)
		return r;

	/* dep tid */
	val32 = htole32((uint32_t)t->pthread_info.lock_owner_pid);
	field.type = TASK_dep_tid;
	field.len  = sizeof(val32);
	memcpy(&field.data, &val32, field.len);

	r = output_stream_field(fd, &field);
	if (r)
		return r;

	return 0;
}

static int output_frame_fields(int fd, struct backtrace_frame *f)
{
	int r;
	struct dla_stream_field field;
	uint64_t val64;
	unsigned long valvar;

	r = output_stream_type(fd, FRAME);
	if (r)
		return r;

	/* addr */
	val64 = htole64((uint64_t)f->ip);
	valvar = (unsigned long)val64;
	field.type = FRAME_addr;
	field.len  = sizeof(valvar);
	memcpy(&field.data, &valvar, field.len);

	r = output_stream_field(fd, &field);
	if (r)
		return r;

	/* off */
	val64 = htole64((uint64_t)f->ip_off);
	valvar = (unsigned long)val64;
	field.type = FRAME_off;
	field.len  = sizeof(valvar);
	memcpy(&field.data, &valvar, field.len);

	r = output_stream_field(fd, &field);
	if (r)
		return r;

	/* func */
	field.type = FRAME_func;
	field.len  = MIN(sizeof(field.data), strlen(f->f_name));
	memcpy(&field.data, f->f_name, field.len);

	r = output_stream_field(fd, &field);
	if (r)
		return r;


	return 0;
}

static int output_backtrace(int fd, struct task *t)
{
	int r;
	unsigned int i;

	r = output_task_fields(fd, t);
	if (r)
		return r;
	for (i = 0; i < t->bt.cnt; i++) {
		r = output_frame_fields(fd, &t->bt.frames[i]);
		if (r)
			return r;
	}

	return 0;
}

static int run_filter_app(pid_t *chpid)
{
	int r;
	pid_t ch;
	int pipefd[] = { [0] = -1, [1] = -1 };

	r = pipe(pipefd);
	if (r != 0) {
		perror("pipe2()");
		return -1;
	}

	ch = fork();
	if (ch < 0) {
		perror("fork()");
		goto out;
	}
	else if (!ch) {
		int fd;
		close(pipefd[1]);
		fd = dup2(pipefd[0], 0);
		if (fd < 0) {
			close(pipefd[0]);
			perror("dup2()");
			exit(1);
		}
		r = execv(arg_exe[0], arg_exe);
		perror("exec()");
		exit(1);
	}

	r = 0;
	*chpid = ch;

out:
	close(pipefd[0]);
	if (r) {
		close(pipefd[1]);
		return -1;
	}

	return pipefd[1];
}

static int output_loopback(struct loopback *l)
{
	struct task *t;
	int fd, r, status;
	pid_t chpid;

	fd = run_filter_app(&chpid);
	if (fd < 0) {
		printf("ERROR: can't execute filter app, %d\n", fd);
		return -1;
	}

	r = output_stream_type(fd, DEADLOCK);
	if (r)
		goto err;
	list_for_each_entry(t, &l->loop_l, l_stuck) {
		r = output_backtrace(fd, t);
		if (r)
			goto err;
	}

	if (!list_empty(&l->spur_l)) {
		r = output_stream_type(fd, DEPS);
		if (r)
			goto err;
		list_for_each_entry(t, &l->spur_l, l_stuck) {
			r = output_backtrace(fd, t);
			if (r)
				goto err;
		}
	}

	r = output_stream_type(fd, END);
	if (r)
		goto err;

	r = 0;

err:
	close(fd);
	waitpid(chpid, &status, 0);

	return r;
}

static int unwind_pthread_backtrace(struct task *t)
{
	unw_addr_space_t as;
	struct UPT_info *ui;
	int status, ret;
	int waits = 20;

	if (ptrace(PTRACE_ATTACH, t->tid, NULL, NULL) < 0) {
		perror("ptrace(PTRACE_ATTACH)");
		return -1;
	}

	/* Ptrace impacts on task switch counters, thus we have
	 * to skip one scan to be sure all the counters are again
	 * stable */
	t->need_relax = 1;

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

struct dla_params {
	struct hash_table hash_tasks;
	struct list_head  scan_lists[2];
	struct list_head  old_stuck_list;
	struct list_head  new_stuck_list;
	struct list_head *list;
	struct loopback   loops[16];
};

static int dla_scan(void *arg_)
{
	int ret;
	unsigned int i;
	struct dla_params *p = arg_;
	struct task *t, *t_l, *tmp_l;
	struct list_head *dead_list = p->list;
	unsigned int      loop_nr = 0;

	p->list = swap_scan_lists(p->scan_lists, ARRAY_SIZE(p->scan_lists),
				  p->list);

	/* Everything should be correctly cleaned up */
	assert(list_empty(&p->old_stuck_list));
	assert(list_empty(&p->new_stuck_list));

	/* Scan all the tasks and fill the hash */
	ret = do_tasks_scan(&p->hash_tasks, p->list, &p->old_stuck_list,
			    &p->new_stuck_list);
	if (ret) {
		printf("ERROR: do_tasks_scan failed, %d, repeat\n", ret);
		goto free_dead;
	}

	/* We have some tasks stuck in futex, do further analysis */
	while (!list_empty(&p->new_stuck_list)) {
		struct task *t_prev = NULL;
		struct loopback *loop;

		if (loop_nr >= ARRAY_SIZE(p->loops)) {
			printf("WARNING: maximum number %d of possible loopbacks exceeded\n",
			       loop_nr);
			break;
		}

		t = list_first_entry(&p->new_stuck_list, struct task, l_stuck);
		assert(!is_task_in_loop(t));

		loop = &p->loops[loop_nr];
		assert(list_empty(&loop->loop_l));
		assert(list_empty(&loop->spur_l));

		/* Cycle till chain is broken or loopback is found */
		do {
			pid_t tid;
			int is_suspicious;

			is_suspicious = !list_empty(&t->l_stuck);

			/* Loop consists of 1 element, i.e. thread was self-deadlocked.
			 * Avoid further checks and jump to chaining */
			if (t_prev == t) {
				assert(is_suspicious);
				goto chain_it;
			}

			/* Move task to loop */
			list_del(&t->l_stuck);
			list_add_tail(&t->l_stuck, &loop->loop_l);
			t->pthread_info.loop = loop;

			/* Every task in chain should be suspicious */
			if (!is_suspicious)
				break;

			/* Unwind backtrace */
			ret = unwind_pthread_backtrace(t);
			if (ret)
				break;

			/* Now we are interested only in pthread_mutex_lock */
			if (!is_lll_lock_wait(&t->bt.frames[0]))
				break;

		chain_it:
			/* Chain it */
			if (t_prev)
				t_prev->pthread_info.lock_owner_task = t;
			t_prev = t;

			/* Do hash lookup of lock owner */
			tid = t->pthread_info.lock_owner_pid;
			assert(tid != 0);
			t = hash_lookup_entry(&p->hash_tasks, &tid, sizeof(tid),
					      struct task, h_entry);

		} while (t && !is_task_in_loop(t));

		/* Handle two cases: chain is broken or chain is a spur
		 * of another loop:
		 *    chain is broken:      !t || !is_task_in_loop
		 *    spur of another loop: t->loop != loop
		 *
		 * If chain is broken just forget about the tasks in this chain.
		 * If chain is a spur and belongs to another loop just splice this
		 * chain to the spur list of another loop.
		 */
		if (!t || !is_task_in_loop(t) ||
		    t->pthread_info.loop != loop) {
			int chain_broken = (!t || !is_task_in_loop(t));

			list_for_each_entry_safe(t_l, tmp_l, &loop->loop_l,
						 l_stuck) {
				list_del(&t_l->l_stuck);
				if (chain_broken) {
					INIT_LIST_HEAD(&t_l->l_stuck);
					task_init_pthread_info(t_l);
					/* The whole chain should be analysed again */
					t_l->stuck_generation = TASK_TO_ANALYSE;
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
	assert(list_empty(&p->new_stuck_list) || loop_nr >= ARRAY_SIZE(p->loops));

	/* Here we have loopbacks and its' spurs, deal with them */
	for (i = 0; i < loop_nr; i++) {
		struct loopback *loop = &p->loops[i];

		output_loopback(loop);

		/* Return everything back to stuck list for
		 * further cleanups
		 */
		list_splice(&loop->loop_l, &p->old_stuck_list);
		list_splice(&loop->spur_l, &p->old_stuck_list);
		loopback_init(loop);
	}

	/* Move newly stuck tasks to old list */
	list_splice(&p->new_stuck_list, &p->old_stuck_list);

	/* Remove remains */
	list_for_each_entry_safe(t_l, tmp_l, &p->old_stuck_list,
				 l_stuck) {
		list_del_init(&t_l->l_stuck);
		task_init_pthread_info(t_l);
	}

free_dead:
	/* Remove all tasks which now are dead since last scan */
	if (dead_list) {
		list_for_each_entry_safe(t_l, tmp_l, dead_list, l_entry)
			hash_remove(&t_l->h_entry);
	}

	return 0;
}

static int dla_event_loop(unsigned int wakeup_sec,
			  int (*event_fn)(void *arg), void *arg)
{
	sigset_t mask, old_mask;
	int sfd;
	fd_set rfds;
	struct timeval tv;
	int ret = -1;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGQUIT);
	sigaddset(&mask, SIGPIPE);

	/* Block signals so that they aren't handled
	 * according to their default dispositions */
	if (sigprocmask(SIG_BLOCK, &mask, &old_mask) == -1) {
		perror("sigprocmask()");
		return -1;
	}

	sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (sfd == -1) {
		perror("signalfd()");
		ret = -1;
		goto out;
	}

	while (1) {
		int ret;

		FD_ZERO(&rfds);
		FD_SET(sfd, &rfds);

		/* Wakeup timeout */
		tv.tv_sec = wakeup_sec;
		tv.tv_usec = 0;

		ret = select(sfd + 1, &rfds, NULL, NULL, &tv);
		if (ret == -1) {
			perror("select()");
			goto out;
		}
		else if (ret) {
			struct signalfd_siginfo fdsi;

			ret = read(sfd, &fdsi, sizeof(struct signalfd_siginfo));
			if (ret != sizeof(fdsi)) {
				perror("read(signalfd)");
				ret = -errno;
				goto out;
			}

			switch (fdsi.ssi_signo) {
			case SIGPIPE:
				break;
			default:
				printf("Terminating\n");
				ret = -1;
				goto out;
			}
		} else {
			ret = event_fn(arg);
			if (ret)
				goto out;
		}
	}

out:
	/* Restore */
	sigprocmask(SIG_SETMASK, &old_mask, NULL);

	if (sfd != -1)
		close(sfd);

	return ret;
}

static void usage(void)
{
	printf("Deadlock analyser tool.\n\n"
	       "dla [--help] [--delay N] [-D] --exe prog [arguments]\n\n"
	       "  -e|--exe app [args]   Filter application which will be executed on every found deadlock problem.\n"
	       "                            e.g.:\n"
	       "                           --exe ./filter-deadlock\n"
	       "                        Pass arguments after the program name to the program when it is run.\n"
	       "  -d|--delay            The delay in seconds between processes scan, default is 5 seconds.\n"
	       "  -D|--daemon           Run as daemon.\n"
	       "  -h|--help             Show usage information.\n"
	);
}

struct option opts[] = {
	{ "exe",    required_argument, NULL, 'e' },
	{ "delay",  required_argument, NULL, 'd' },
	{ "daemon", no_argument,       NULL, 'D' },
	{ "help",   no_argument,       NULL, 'h' },
	{ NULL, 0, NULL, 0 }
};
const char *opts_str = "e:d:Dh";

int main(int argc, char **argv)
{
	int c, r;
	unsigned i, delay = DEFAULT_DELAY, daemonize = 0;
	struct dla_params p;

	while ((c = getopt_long(argc, argv, opts_str,
				opts, NULL)) != -1) {
		switch (c) {
		case 'e':
			arg_exe     = argv + optind - 1;
			arg_exe_cnt = argc - optind + 1;
			break;
		case 'd':
			if (1 != sscanf(optarg, "%u", &delay)) {
				usage();
				return 1;
			}
			break;
		case 'D':
			daemonize = 1;
			break;
		case 'h':
		default:
			usage();
			return 0;
		}
	}

	if (!arg_exe) {
		printf("ERROR: Filter application was not specified, see --exe option\n\n");
		usage();
		return 1;
	}
	if (access(arg_exe[0], R_OK | X_OK)) {
		perror("ERROR: access(exe, R_OK | X_OK)");
		fprintf(stderr, "\n");
		usage();
		return 1;
	}
	if (!delay) {
		printf("ERROR: Delay is wrong: %u\n\n", delay);
		usage();
		return 1;
	}

	/* Run as deamon */
	if (daemonize)
		daemon(0, 0);

	memset(&p, 0, sizeof(p));
	INIT_LIST_HEAD(&p.scan_lists[0]);
	INIT_LIST_HEAD(&p.scan_lists[1]);
	INIT_LIST_HEAD(&p.old_stuck_list);
	INIT_LIST_HEAD(&p.new_stuck_list);

	for (i = 0; i < ARRAY_SIZE(p.loops); i++)
		loopback_init(&p.loops[i]);

	hash_init(&p.hash_tasks);

	/* Call dla main loop */
	r = dla_event_loop(delay, dla_scan, &p);

	hash_free(&p.hash_tasks);

	return r;
}
