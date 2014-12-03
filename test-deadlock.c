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

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

pthread_mutex_t m_loop_1[6];

pthread_mutex_t m_loop_2[1];

pthread_mutex_t m_loop_3[4];
pthread_cond_t  c_loop_3[3];

struct thread_params {
	unsigned         usleep;
	pthread_t        thread;
	pthread_mutex_t *m_before_sleep;
	pthread_mutex_t *m_after_sleep;
	pthread_cond_t  *c_after_sleep;
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
	  .m_before_sleep = &m_loop_1[3],
	  .m_after_sleep  = &m_loop_1[2] },

	{ .usleep         = 500000,
	  .m_before_sleep = &m_loop_1[2],
	  .m_after_sleep  = &m_loop_1[3] },

	/* sleep */	{ .usleep = 500000 },

	{ .usleep         = 0,
	  .m_before_sleep = &m_loop_1[1],
	  .m_after_sleep  = &m_loop_1[2] },

	/* sleep */	{ .usleep = 500000 },

	{ .usleep         = 0,
	  .m_before_sleep = &m_loop_1[0],
	  .m_after_sleep  = &m_loop_1[1] },

	{ .usleep         = 0,
	  .m_before_sleep = &m_loop_1[4],
	  .m_after_sleep  = &m_loop_1[1] },

	/* sleep */	{ .usleep = 500000 },

	{ .usleep         = 0,
	  .m_before_sleep = &m_loop_1[5],
	  .m_after_sleep  = &m_loop_1[4] },
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
	  .m_before_sleep = &m_loop_2[0],
	  .m_after_sleep  = &m_loop_2[0] },
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
	  .m_before_sleep = &m_loop_3[2],
	  .m_after_sleep  = &m_loop_3[3],
	  .c_after_sleep  = &c_loop_3[2] },

	/* sleep */	{ .usleep = 500000 },

	{ .usleep         = 0,
	  .m_before_sleep = &m_loop_3[1],
	  .m_after_sleep  = &m_loop_3[2] },

	/* sleep */	{ .usleep = 500000 },

	{ .usleep         = 0,
	  .m_before_sleep = &m_loop_3[0],
	  .m_after_sleep  = &m_loop_3[1] },
};

static void *thread_start(void *arg)
{
	struct thread_params *p = arg;

	assert(p->m_before_sleep && p->m_after_sleep);

	pthread_mutex_lock(p->m_before_sleep);
	usleep(p->usleep);
	pthread_mutex_lock(p->m_after_sleep);
	if (p->c_after_sleep)
		pthread_cond_wait(p->c_after_sleep, p->m_after_sleep);

	assert(0);
}

static void create_mutex_lock_loop(struct thread_params *params,
								   unsigned int sz)
{
	unsigned int i;

	for (i = 0; i < sz; i++) {
		pthread_mutex_init(params->m_before_sleep, NULL);
		pthread_mutex_init(params->m_after_sleep, NULL);
		if (params->c_after_sleep)
			pthread_cond_init(params->c_after_sleep, NULL);
	}

	for (i = 0; i < sz; i++) {
		struct thread_params *p = &params[i];

		if (!p->m_before_sleep || !p->m_after_sleep)
			usleep(p->usleep);
		else
			pthread_create(&p->thread, NULL, thread_start, p);
	}
}

static void create_mutex_lock_loop_1(void)
{
	create_mutex_lock_loop(loop_params_1,
						   ARRAY_SIZE(loop_params_1));
	printf("loop 1 started\n");
}

static void create_mutex_lock_loop_2(void)
{
	create_mutex_lock_loop(loop_params_2,
						   ARRAY_SIZE(loop_params_2));
	printf("loop 2 started\n");
}

static void create_cond_wait_loop_3(void)
{
	create_mutex_lock_loop(loop_params_3,
						   ARRAY_SIZE(loop_params_3));
	printf("loop 3 started\n");
}

int main()
{
	create_mutex_lock_loop_1();
	create_mutex_lock_loop_2();
	create_cond_wait_loop_3();

	/* We are here forever */
	while (1)
		sleep(1);
}
