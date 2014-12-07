/*
 * test-deadlock - Tool which deadlocks, DLA should catch it
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
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/syscall.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif
#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})


struct sync_obj {
	pthread_mutex_t m;
	pthread_cond_t  c;
	const char     *l;
	const char     *n;
};

typedef struct sync_obj sync_obj_t;

#define SYNC_INIT PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER

sync_obj_t loop_1[] = { { SYNC_INIT, "loop 1", "0" },
			{ SYNC_INIT, "loop 1", "1" },
			{ SYNC_INIT, "loop 1", "2" },
			{ SYNC_INIT, "loop 1", "3" },
			{ SYNC_INIT, "loop 1", "4" },
			{ SYNC_INIT, "loop 1", "5" } };

sync_obj_t loop_2[] = { { SYNC_INIT, "loop 2", "0" } };

sync_obj_t loop_3[] = { { SYNC_INIT, "loop 3", "0" },
			{ SYNC_INIT, "loop 3", "1" },
			{ SYNC_INIT, "loop 3", "2" },
			{ SYNC_INIT, "loop 3", "3" } };

sync_obj_t loop_4[] = { { SYNC_INIT, "loop 4", "0" },
			{ SYNC_INIT, "loop 4", "1" },
			{ SYNC_INIT, "loop 4", "2" },
			{ SYNC_INIT, "loop 4", "3" } };

sync_obj_t loop_5[] = { { SYNC_INIT, "loop 5", "0" } };

struct thread_params {
	const char      *loop_name;
	unsigned         usleep;
	pthread_t        thread;
	sync_obj_t      *m_before_sleep;
	sync_obj_t      *m_after_sleep;
	sync_obj_t      *c_after_sleep;
	unsigned int     c_timeout;
	sync_obj_t      *m_after_c;
};

/*
 *           v-------\
 * 1 -> 2 -> 3 -> 4 -/
 *      ^
 *      5
 *      ^
 *      6
 *
 * one loop: 3 -> 4 -> 3
 *
 * spur: 1, 2, 5, 6
 */
struct thread_params loop_params_1[] = {

	{ .usleep         = 500000,
	  .m_before_sleep = &loop_1[3],
	  .m_after_sleep  = &loop_1[2] },

	{ .usleep         = 500000,
	  .m_before_sleep = &loop_1[2],
	  .m_after_sleep  = &loop_1[3] },

	/* sleep */	{ .usleep = 500000 },

	{ .usleep         = 0,
	  .m_before_sleep = &loop_1[1],
	  .m_after_sleep  = &loop_1[2] },

	/* sleep */	{ .usleep = 500000 },

	{ .usleep         = 0,
	  .m_before_sleep = &loop_1[0],
	  .m_after_sleep  = &loop_1[1] },

	{ .usleep         = 0,
	  .m_before_sleep = &loop_1[4],
	  .m_after_sleep  = &loop_1[1] },

	/* sleep */	{ .usleep = 500000 },

	{ .usleep         = 0,
	  .m_before_sleep = &loop_1[5],
	  .m_after_sleep  = &loop_1[4] },
};

/*
 * v--\
 * 1 -/
 *
 * one loop: 1 -> 1
 *
 * spur: none
 */
struct thread_params loop_params_2[] = {

	{ .usleep         = 0,
	  .m_before_sleep = &loop_2[0],
	  .m_after_sleep  = &loop_2[0] },
};

/*
 * 1 -> 2 -> 3 -> c
 *
 * one loop: none
 *
 * spur:     none
 */
struct thread_params loop_params_3[] = {

	{ .usleep         = 0,
	  .m_before_sleep = &loop_3[2],
	  .m_after_sleep  = &loop_3[3],
	  .c_after_sleep  = &loop_3[2] },

	/* sleep */	{ .usleep = 500000 },

	{ .usleep         = 0,
	  .m_before_sleep = &loop_3[1],
	  .m_after_sleep  = &loop_3[2] },

	/* sleep */	{ .usleep = 500000 },

	{ .usleep         = 0,
	  .m_before_sleep = &loop_3[0],
	  .m_after_sleep  = &loop_3[1] },
};

/*
 * 1 -> 2 -> c, sleep 10, -> loop 2
 *
 * one loop: loop 2
 *
 * spur:     1 -> 2
 */
struct thread_params loop_params_4[] = {

	{ .usleep         = 0,
	  .m_before_sleep = &loop_4[2],
	  .m_after_sleep  = &loop_4[3],
	  .c_after_sleep  = &loop_4[2],
	  .c_timeout      = 10,
	  .m_after_c      = &loop_2[0] },

	/* sleep */	{ .usleep = 500000 },

	{ .usleep         = 0,
	  .m_before_sleep = &loop_4[1],
	  .m_after_sleep  = &loop_4[2] },

	/* sleep */	{ .usleep = 500000 },

	{ .usleep         = 0,
	  .m_before_sleep = &loop_4[0],
	  .m_after_sleep  = &loop_4[1] },
};

/*
 * sleep, 1 -> loop 2
 *
 * one loop: loop 2
 *
 * spur:     none
 */
struct thread_params loop_params_5[] = {

	{ .usleep         = 0,
	  .m_before_sleep = &loop_5[0],
	  .m_after_sleep  = &loop_2[0] },
};

static pid_t gettid(void)
{
    return syscall(SYS_gettid);
}

static void mutex_lock(const char *loop, pthread_mutex_t *m)
{
	int r;
	sync_obj_t *s;

	s = container_of(m, sync_obj_t, m);

	printf("[%s] %5u before lock of [%s %s] mutex\n",
	       loop, gettid(), s->l, s->n);
	r = pthread_mutex_lock(m);
	printf("[%s] %5u after  lock of [%s %s] mutex\n",
	       loop, gettid(), s->l, s->n);
	assert(r == 0);
}

static void cond_wait(const char *loop,
		      pthread_cond_t *c, pthread_mutex_t *m,
		      unsigned int timeout)
{
	int r;
	sync_obj_t *s;

	s = container_of(c, sync_obj_t, c);

	printf("[%s] %5u before wait of [%s %s] cond\n",
	       loop, gettid(), s->l, s->n);
	if (timeout) {
		struct timespec wait;
		clock_gettime(CLOCK_REALTIME, &wait);
		wait.tv_sec += timeout;
		r = pthread_cond_timedwait(c, m, &wait);
		assert(r == ETIMEDOUT);
	} else {
		r = pthread_cond_wait(c, m);
		assert(r == 0);
	}
	printf("[%s] %5u after  wait of [%s %s] cond\n",
	       loop, gettid(), s->l, s->n);
}

static void *thread_start(void *arg)
{
	struct thread_params *p = arg;

	assert(p->m_before_sleep && p->m_after_sleep);

	mutex_lock(p->loop_name, &p->m_before_sleep->m);
	usleep(p->usleep);
	mutex_lock(p->loop_name, &p->m_after_sleep->m);

	if (p->c_after_sleep)
		cond_wait(p->loop_name,
			  &p->c_after_sleep->c, &p->m_after_sleep->m,
			  p->c_timeout);
	if (p->m_after_c)
		mutex_lock(p->loop_name, &p->m_after_c->m);

	assert(0);
}

static void create_mutex_lock_loop(const char *loop_name,
				   struct thread_params *params,
				   unsigned int sz)
{
	unsigned int i;

	for (i = 0; i < sz; i++) {
		struct thread_params *p = &params[i];

		p->loop_name = loop_name;

		if (!p->m_before_sleep || !p->m_after_sleep)
			usleep(p->usleep);
		else
			pthread_create(&p->thread, NULL, thread_start, p);
	}
}

static void create_mutex_lock_loop_1(void)
{
	create_mutex_lock_loop("loop 1",
			       loop_params_1,
			       ARRAY_SIZE(loop_params_1));
}

static void create_mutex_lock_loop_2(void)
{
	create_mutex_lock_loop("loop 2",
			       loop_params_2,
			       ARRAY_SIZE(loop_params_2));
}

static void create_cond_wait_loop_3(void)
{
	create_mutex_lock_loop("loop 3",
			       loop_params_3,
			       ARRAY_SIZE(loop_params_3));
}

static void create_cond_wait_loop_4(void)
{
	create_mutex_lock_loop("loop 4",
			       loop_params_4,
			       ARRAY_SIZE(loop_params_4));
}

static void *__create_mutex_lock_loop_5(void *arg)
{
	(void)arg;
	sleep(10);
	create_mutex_lock_loop("loop 5",
			       loop_params_5,
			       ARRAY_SIZE(loop_params_5));
	return NULL;
}

static void create_mutex_lock_loop_5(void)
{
	pthread_t t;
	pthread_create(&t, NULL, __create_mutex_lock_loop_5, NULL);
}

int main()
{
	create_mutex_lock_loop_1();
	create_mutex_lock_loop_2();
	create_cond_wait_loop_3();
	create_cond_wait_loop_4();
	create_mutex_lock_loop_5();

	/* We are here forever */
	while (1)
		sleep(1);
}
