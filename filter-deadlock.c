/*
 * filter-deadlock - Tool which parses binary stream from dla and outputs
 *                   it to stdout in human readable form.
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
#include <endian.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "proto.h"

struct task {
	pid_t     tgid;
	unsigned  tgid_valid;

	pid_t     tid;
	unsigned  tid_valid;

	pid_t     dep_tid;
	unsigned  dep_tid_valid;
};

struct frame {
	unsigned long  addr;
	unsigned       addr_valid;

	unsigned long  off;
	unsigned       off_valid;

	char           func[MAX_VALUE_SIZE + 1];
	unsigned       func_valid;
};

static int read_stream_type(enum dla_stream_type *type)
{
	ssize_t sz;
	unsigned char ch;
	sz = DO_IO(read, 0, &ch, 1);
	if (sz != 1)
		return -1;
	*type = (enum dla_stream_type)ch;
	return 0;
}

static int read_stream_field(struct dla_stream_field *field)
{
	ssize_t sz;
	unsigned char ch;
	sz = DO_IO(read, 0, &ch, 1);
	if (sz != 1)
		return -1;
	field->type = (enum dla_stream_type)ch;
	/* Not a field type */
	if (field->type <= FIELD_start || field->type == END)
		return 0;

	sz = DO_IO(read, 0, &field->len, 1);
	if (sz != 1)
		return -1;

	if (field->len > MAX_VALUE_SIZE)
		return -1;

	sz = DO_IO(read, 0, &field->data, field->len);
	if (sz != field->len)
		return -1;

	return 1;
}

static void task_add_field(struct task *task, struct dla_stream_field *field)
{
	uint32_t val;

	/* Now task has only 32 bits values */
	if (field->len != sizeof(val))
		return;

	val = le32toh(*(uint32_t *)field->data);

	switch (field->type) {
	case TASK_tgid:
		task->tgid = val;
		task->tgid_valid = 1;
		break;
	case TASK_tid:
		task->tid = val;
		task->tid_valid = 1;
		break;
	case TASK_dep_tid:
		task->dep_tid = val;
		task->dep_tid_valid = 1;
		break;
	default:
		/* silently ignore all unknown fields */
		return;
	}
}

static void frame_add_field(struct frame *frame, struct dla_stream_field *field)
{
	unsigned long addr, off;

	switch (field->type) {
	case FRAME_addr:
		if (field->len != sizeof(addr))
			return;
		frame->addr = le32toh(*(uint32_t *)field->data);
		frame->addr_valid = 1;
		break;
	case FRAME_off:
		if (field->len != sizeof(off))
			return;
		frame->off = le32toh(*(uint32_t *)field->data);
		frame->off_valid = 1;
		break;
	case FRAME_func:
		/* Frame has maximum size of the value + 1 */
		assert(field->len < sizeof(frame->func));
		memcpy(&frame->func, &field->data, field->len);
		frame->func[field->len] = '\0';
		frame->func_valid = 1;
		break;
	default:
		/* silently ignore all unknown fields */
		return;
	}
}

static void print_deadlock_header(void)
{
	printf("----------------------------------------------\n");
	printf("deadlock loop:\n");
}

static void print_deps_header(void)
{
	printf("tasks which wait for deadlock loop:\n");
}

static void print_footer(void)
{
	printf("\n");
}

static void print_task(struct task *t)
{
	char buff[128];
	int off = 0, s;
	const char *tidstr     = "???";
	const char *tgidstr    = "???";
	const char *dep_tidstr = "???";

	if (t->tgid_valid) {
		s = snprintf(buff + off, sizeof(buff) - off, "%u", t->tgid);
		tgidstr = buff + off;
		off += s + 1;
	}
	if (t->tid_valid) {
		s = snprintf(buff + off, sizeof(buff) - off, "%u", t->tid);
		tidstr = buff + off;
		off += s + 1;
	}
	if (t->dep_tid_valid) {
		s = snprintf(buff + off, sizeof(buff) - off, "%u", t->dep_tid);
		dep_tidstr = buff + off;
		off += s + 1;
	}

	printf("  tid %s (tgid %s) waits for tid %s:\n",
	       tidstr, tgidstr, dep_tidstr);
}

static void print_frame(struct frame *f)
{
	char buff[128];
	int off = 0, s;
	const char *addrstr = "???";
	const char *offstr  = "???";
	const char *funcstr = "???";

	if (f->addr_valid) {
		s = snprintf(buff + off, sizeof(buff) - off, "%016lx", f->addr);
		addrstr = buff + off;
		off += s + 1;
	}
	if (f->off_valid) {
		s = snprintf(buff + off, sizeof(buff) - off, "0x%lx", f->off);
		offstr = buff + off;
		off += s + 1;
	}
	if (f->func_valid) {
		s = snprintf(buff + off, sizeof(buff) - off, "%s", f->func);
		funcstr = buff + off;
		off += s + 1;
	}

	printf("\t%s %s+%s\n", addrstr, funcstr, offstr);
}

int main(int argc, char **argv)
{
	int ret;
	enum dla_stream_type type = UNKNOWN;
	struct dla_stream_field field;
	struct task task;
	struct frame frame;

	(void)argc; (void)argv;
	memset(&task, 0, sizeof(task));
	memset(&frame, 0, sizeof(frame));

	while (1) {
		switch (type) {
		case UNKNOWN:
		case DEADLOCK:
			if (type == DEADLOCK)
				print_deadlock_header();
			/* fall through */
		case DEPS:
			if (type == DEPS)
				print_deps_header();

			if (read_stream_type(&type))
				return -1;
			break;
		case TASK:
			ret = read_stream_field(&field);
			if (ret < 0)
				return -1;
			else if (ret > 0)
				task_add_field(&task, &field);
			else {
				print_task(&task);
				memset(&task, 0, sizeof(task));
				type = field.type;
				if (type != FRAME)
					print_footer();
			}
			break;
		case FRAME:
			ret = read_stream_field(&field);
			if (ret < 0)
				return -1;
			else if (ret > 0)
				frame_add_field(&frame, &field);
			else {
				print_frame(&frame);
				memset(&frame, 0, sizeof(frame));
				type = field.type;
				if (type != FRAME)
					print_footer();
			}
			break;
		case END:
			return 0;
		default:
			/* silently ignore all unknown fields */
			break;
		}
	}

	return 0;
}
