#ifndef PROTO_H
#define PROTO_H

/* DLA binary stream protocol.
 *
 * Every stream starts with DEADLOCK byte and ends with END byte.
 * Inside DEADLOCK stream several TASK streams can be found and for each
 * task several FRAME streams can follow, but is not required. After DEADLOCK
 * stream DEPS stream can follow, but it is also not required. DEPS stream
 * describes tasks which are dependent and wait for deadlocked tasks.
 *
 * TASK and FRAME streams have fields, which decribed by 'dla_stream_field'
 * structure. Each field has type 1b, length 1b and data bytes following.
 *
 * All fields values should be passed in little-endian.convention.
 * Maximum field value size is 64 bytes.
 *
 * E.g. this binary stream can be outputed:
 *
 * DEADLOCK
 *   TASK
 *     tgid      4b 0x00000000le
 *     tid       4b 0x00000000le
 *     dep_tid   4b 0x00000000le
 *   FRAME
 *     addr      4b 0x00000000le
 *     off       4b 0x00000000le
 *     func      8b funcname
 *   TASK
 *     tgid      4b 0x00000000le
 *     tid       4b 0x00000000le
 *     dep_tid   4b 0x00000000le
 * DEPS
 *   TASK
 *     tgid      4b 0x00000000le
 *     tid       4b 0x00000000le
 *     dep_tid   4b 0x00000000le
 *
 * END
 *
 * And in binary:
 *
 * 01 10 80|04|00000000 81|04|00000000 82|04|00000000 11 90|04|00000000 ... ff
 *
 */

#define MAX_VALUE_SIZE 64

enum dla_stream_type {
	UNKNOWN      = 0x00,

	/* Major stream types */

	DEADLOCK     = 0x01, /**< tasks are deadlocked in loop */
	DEPS         = 0x02, /**< tasks are waiting for deadlock loop */

	/* Stream objects */

	TASK         = 0x10, /**< task object */
	FRAME        = 0x11, /**< frame object, follows after task */

	/* From this point Fields begin */

	FIELD_start  = 0x7f, /**< the beginning of fields */

	/* Task field names */

	TASK_tgid    = 0x80, /**< task tgid field, 4byte value */
	TASK_tid     = 0x81, /**< task tid field, 4byte value */
	TASK_dep_tid = 0x82, /**< tid of a task which is the owner of the lock,
						      4byte value */

	/* Frame field names */

	FRAME_addr   = 0x90, /**< frame address, 4 or 8 byte value */
	FRAME_off    = 0x91, /**< frame offset, 4 or 8 byte value */
	FRAME_func   = 0x92, /**< frame function name, <= MAX_VALUE_SIZE */

	/* Stream end, must be the latest */
	END          = 0xff  /**< end of the stream */
};

struct dla_stream_field {
	enum dla_stream_type  type;
	unsigned char         len;
	unsigned char         data[MAX_VALUE_SIZE];
};

int dla_send_stream_type(int fd,  enum dla_stream_type type);
int dla_send_stream_field(int fd, struct dla_stream_field *field);

/* Convenient IO helper */
#define DO_IO(func, fd, buf, nbyte)					\
	({												\
		ssize_t ret = 0, r;							\
		do {										\
			r = func(fd, buf + ret, nbyte - ret);	\
			if (r < 0 && errno != EINTR) {			\
				ret = -1;							\
				break;								\
			}										\
			else if (r > 0)							\
				ret += r;							\
		} while (r != 0 && (size_t)ret != nbyte);	\
													\
		ret;										\
	})


#endif /* PROTO_H */
