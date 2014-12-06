#include <unistd.h>
#include <errno.h>

#include "proto.h"

int dla_send_stream_type(int fd,  enum dla_stream_type type)
{
	ssize_t s;
	unsigned char ch;

	ch = (unsigned char)type;
	s = DO_IO(write, fd, &ch, 1);
	return (s != 1 ? -1 : 0);
}

int dla_send_stream_field(int fd, struct dla_stream_field *f)
{
	ssize_t s;
	unsigned char ch;

	ch = (unsigned char)f->type;
	s = DO_IO(write, fd, &ch, 1);
	if (s != 1)
		return -1;
	s = DO_IO(write, fd, &f->len, 1);
	if (s != 1)
		return -1;
	s = DO_IO(write, fd, f->data, f->len);
	if (s != f->len)
		return -1;

	return 0;
}
