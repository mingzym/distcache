/* distcache, Distributed Session Caching technology
 * Copyright (C) 2000-2002  Geoff Thorpe, and Cryptographic Appliances, Inc.
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; using version 2.1 of the License. The copyright holders
 * may elect to allow the application of later versions of the License to this
 * software, please contact the author (geoff@distcache.org) if you wish us to
 * review any later version released by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <libnal/common.h>
#include <libnal/nal.h>
#include <libdistcache/dc_enc.h>

/* Uncomment this precompiler symbol if you want encoding and decoding of DC_MSG
 * frames to be debugged to the controlling console. */
/* #define DC_MSG_DEBUG */

int DC_MSG_set_cmd(DC_MSG *msg, DC_CMD cmd)
{
	switch(cmd) {
	case DC_CMD_ADD:
		msg->op_class = DC_CLASS_USER;
		msg->operation = DC_OP_ADD;
		return 1;
	case DC_CMD_GET:
		msg->op_class = DC_CLASS_USER;
		msg->operation = DC_OP_GET;
		return 1;
	case DC_CMD_REMOVE:
		msg->op_class = DC_CLASS_USER;
		msg->operation = DC_OP_REMOVE;
		return 1;
	case DC_CMD_HAVE:
		msg->op_class = DC_CLASS_USER;
		msg->operation = DC_OP_HAVE;
		return 1;
	default:
		break;
	}
	return 0;
}

static DC_CMD int_get_cmd(unsigned char op_class, unsigned char operation)
{
	switch(op_class) {
	case DC_CLASS_USER:
		switch(operation) {
		case DC_OP_ADD:
			return DC_CMD_ADD;
		case DC_OP_GET:
			return DC_CMD_GET;
		case DC_OP_REMOVE:
			return DC_CMD_REMOVE;
		case DC_OP_HAVE:
			return DC_CMD_HAVE;
		default:
			goto err;
		}
	default:
		break;
	}
err:
	return DC_CMD_ERROR;
}

DC_CMD DC_MSG_get_cmd(const DC_MSG *msg)
{
	return int_get_cmd(msg->op_class, msg->operation);
}

int DC_MSG_start_response(const DC_MSG *request,
				DC_MSG *response)
{
	if(request->is_response)
		return 0;
	response->is_response = 1;
	response->request_uid = request->request_uid;
	response->op_class = request->op_class;
	response->operation = request->operation;
	response->complete = 1;
	response->data_len = 0;
	return 1;
}

/********************
 * Encoding functions
 ********************
 * These have to be consistent with each other as they *all* make assumptions on
 * the 'DC_MSG' structure definition and its encoding format.
 */

unsigned int DC_MSG_encoding_size(const DC_MSG *msg)
{
	assert(msg->data_len <= DC_MSG_MAX_DATA);
	/* The fixed size fields total 10 bytes */
	return (10 + msg->data_len);
}

DC_DECODE_STATE DC_MSG_pre_decode(const unsigned char *data,
					unsigned int data_len)
{
	unsigned char op_class, complete;
	unsigned short payload_len;
	/* We *could* just check there's at least 9 bytes first, but the better
	 * approach is to catch data corruption errors immediately. So if
	 * someone accidently sends us an 8-byte "hello" for some other
	 * protocol, we'll more likely spot it. */
	if(data_len-- < 1)
		return DC_DECODE_STATE_INCOMPLETE;
	if(*(data++) > 1)
		/* invalid 'is_response' value */
		return DC_DECODE_STATE_CORRUPT;
	/* request_uid can be anything, so scan across into op_class */
	if(data_len < 5)
		return DC_DECODE_STATE_INCOMPLETE;
	data_len -= 5;
	data += 4;
	op_class = *(data++);
	if(op_class > DC_CLASS_LAST)
		/* invalid 'op_class' value */
		return DC_DECODE_STATE_CORRUPT;
	if(data_len-- < 1)
		return DC_DECODE_STATE_INCOMPLETE;
	/* Now test "operation" and that it works with "op_class" */
	if(int_get_cmd(op_class, *(data++)) == DC_CMD_ERROR)
		/* invalid 'op_class/operation' pair */
		return DC_DECODE_STATE_CORRUPT;
	/* Check "complete" */
	if(data_len-- < 1)
		return DC_DECODE_STATE_INCOMPLETE;
	complete = *(data++);
	if(complete > 1)
		/* invalid 'complete' value */
		return DC_DECODE_STATE_CORRUPT;
	/* Now check "data_len" */
	if(data_len < 2)
		return DC_DECODE_STATE_INCOMPLETE;
	payload_len = ntohs(*((const unsigned short *)data));
	if(payload_len > DC_MSG_MAX_DATA)
		/* 'data_len' out of range */
		return DC_DECODE_STATE_CORRUPT;
	if(!complete && (payload_len < 1024))
		/* to prevent "trickling", 'incomplete' messages must encode at
		 * least 1024 bytes. NB: We use 1024 rather than
		 * DC_MSG_MAX_DATA, because the latter may grow but the binary
		 * restriction (min 1024 bytes) must remain the same. */
		return DC_DECODE_STATE_CORRUPT;
	/* (data_len - 2) is what's left for the data */
	if(data_len - 2 < payload_len)
		return DC_DECODE_STATE_INCOMPLETE;
	return DC_DECODE_STATE_OK;
}

#ifdef DC_MSG_DEBUG
static const char *str_dump_class[] = { "DC_CLASS_USER", NULL };
static const char *str_dump_op[] = { "DC_OP_ADD", "DC_OP_GET",
				"DC_OP_REMOVE", "DC_OP_HAVE", NULL };
static const char *dump_int_to_str(int val, const char **strs)
{
	while(val && *strs) {
		val--;
		strs++;
	}
	if(*strs)
		return *strs;
	return "<unrecognised value>";
}
static void dump_msg(const DC_MSG *msg)
{
	NAL_fprintf(NAL_stdout(), "DC_MSG_DEBUG: dumping message...\n");
	NAL_fprintf(NAL_stdout(), "   is_response:  %u (%s)\n",
		msg->is_response, (msg->is_response ? "response" : "request"));
	NAL_fprintf(NAL_stdout(), "   request_uid:  %u\n", msg->request_uid);
	NAL_fprintf(NAL_stdout(), "   op_class:     %s\n",
		dump_int_to_str(msg->op_class, str_dump_class));
	NAL_fprintf(NAL_stdout(), "   operation:    %s\n",
		dump_int_to_str(msg->operation, str_dump_op));
	NAL_fprintf(NAL_stdout(), "   complete:     %u (%s)\n",
		msg->complete, (msg->complete ? "complete" : "incomplete"));
	NAL_fprintf(NAL_stdout(), "   data_len:     %u\n", msg->data_len);
	NAL_fprintf(NAL_stdout(), "   data:\n");
	debug_dump_bin(NAL_stdout(), "      ", msg->data, msg->data_len);
}
#endif

unsigned int DC_MSG_encode(const DC_MSG *msg, unsigned char *ptr,
				unsigned int data_len)
{
	unsigned int len = data_len;
	if(!NAL_encode_char(&ptr, &len, msg->is_response) ||
			!NAL_encode_uint32(&ptr, &len, msg->request_uid) ||
			!NAL_encode_char(&ptr, &len, msg->op_class) ||
			!NAL_encode_char(&ptr, &len, msg->operation) ||
			!NAL_encode_char(&ptr, &len, msg->complete) ||
			!NAL_encode_uint16(&ptr, &len, msg->data_len) ||
			!NAL_encode_bin(&ptr, &len, msg->data,
				msg->data_len))
		return 0;
	/* check 'len' didn't wrap down past zero! */
	assert(data_len >= len);
#ifdef DC_MSG_DEBUG
	dump_msg(msg);
#endif
	return data_len - len;
}

unsigned int DC_MSG_decode(DC_MSG *msg, const unsigned char *data,
				unsigned int data_len)
{
	unsigned char op_class, operation; /* coz msg's aren't actually chars! */
	unsigned int len = data_len;
	if(!NAL_decode_char(&data, &len, &msg->is_response) ||
			!NAL_decode_uint32(&data, &len, &msg->request_uid) ||
			!NAL_decode_char(&data, &len, &op_class) ||
			!NAL_decode_char(&data, &len, &operation) ||
			!NAL_decode_char(&data, &len, &msg->complete) ||
			!NAL_decode_uint16(&data, &len, &msg->data_len) ||
			!NAL_decode_bin(&data, &len, msg->data,
				msg->data_len))
		return 0;
	msg->op_class = op_class;
	msg->operation = operation;
	/* check 'len' didn't wrap down past zero! */
	assert(data_len >= len);
#ifdef DC_MSG_DEBUG
	dump_msg(msg);
#endif
	/* "pre_decode" should already be testing this, so abort if it slips
	 * through to here. */
	assert((msg->complete == 1) || (msg->data_len >= 1024));
	return data_len - len;
}

/*************************************************/
/* libsession's "DC_PLUG" type and funtions */
/*************************************************/

/* A "state" enum for use in the read and write sections of the plug type */
typedef enum {
	/* "idle" - nothing to read, or no writing operation in progress (and
	 * writing is therefore possible to begin) */
	PLUG_EMPTY,
	/* "I/O-incomplete" - reading is in-progress but without a complete
	 * command read yet, or writing has been committed but has not been
	 * fully encoded yet. */
	PLUG_IO,
	/* "user-incomplete" - a full command exists and the caller has started
	 * a "read" but not yet "consumed", or writing has (so far) been done
	 * ("write_more" can still be called) but not yet "commit"ted. */
	PLUG_USER,
	/* "occupied" - a full command exists to read but the caller hasn't
	 * started a "read" yet. This state should not occur with writes. */
	PLUG_FULL
} DC_PLUG_STATE;

/* A "half-a-plug" structure - the "plug" itself has one each for reading and
 * writing, and a couple of extras; connection, flags, etc. */
typedef struct st_DC_PLUG_IO {
	DC_PLUG_STATE state; /* where we're at */
	DC_MSG msg; /* a place to cache incoming frames */
	unsigned long request_uid;
	DC_CMD cmd;
	unsigned char *data;
	unsigned int data_used, data_size;
} DC_PLUG_IO;

struct st_DC_PLUG {
	NAL_CONNECTION *conn;
	unsigned int flags;
	DC_PLUG_IO read;
	DC_PLUG_IO write;
};


/* How big to make our storage in the DC_PLUG_IO structure when it is first
 * initialised. After this, expansions grow the array by 50% each time. */
#define DC_IO_START_SIZE	1024

/***************************/
/* Internal "IO" functions */

/* General "DC_PLUG_IO" functions */

static int DC_PLUG_IO_init(DC_PLUG_IO *io)
{
	io->state = PLUG_EMPTY;
	io->data = NAL_malloc(unsigned char, DC_IO_START_SIZE);
	if(!io->data)
		return 0;
	io->data_used = 0;
	io->data_size = DC_IO_START_SIZE;
	return 1;
}

static void DC_PLUG_IO_finish(DC_PLUG_IO *io)
{
	NAL_free(unsigned char, io->data);
}

static int DC_PLUG_IO_make_space(DC_PLUG_IO *io, unsigned int needed)
{
	unsigned char *newdata;
	unsigned int newsize = io->data_size;

	if(io->data_used + needed <= io->data_size)
		return 1;
	do {
		newsize = newsize * 3 /  2;
	} while(io->data_used + needed > newsize);
	newdata = NAL_malloc(unsigned char, newsize);
	if(!newdata)
		return 0;
	if(io->data_used)
		NAL_memcpy_n(unsigned char, newdata, io->data, io->data_used);
	NAL_free(unsigned char, io->data);
	io->data = newdata;
	io->data_size = newsize;
	return 1;
}

/* "DC_PLUG_IO" read-specific functions */

static int DC_PLUG_IO_read_flush(DC_PLUG_IO *io, int to_server,
				NAL_BUFFER *buffer)
{
	unsigned char *buf_ptr;
	unsigned int buf_len, tmp;
	DC_CMD cmd;

	switch(io->state) {
	case PLUG_FULL:
	case PLUG_USER:
		/* Can't do anything */
		return 1;
	case PLUG_EMPTY:
	case PLUG_IO:
		/* See if pulling data through advances our state */
		break;
	default:
		assert(NULL == "shouldn't be here");
		return 0;
	}
	buf_ptr = NAL_BUFFER_read_ptr(buffer);
	buf_len = NAL_BUFFER_used(buffer);
	/* Whichever case we are - try to decode a message, if that fails, we
	 * haven't changed anything. */
	switch(DC_MSG_pre_decode(buf_ptr, buf_len)) {
	case DC_DECODE_STATE_INCOMPLETE:
		/* We're ok, but nothing more can be done */
		return 1;
	case DC_DECODE_STATE_OK:
		/* There's data to read */
		break;
	case DC_DECODE_STATE_CORRUPT:
		/* Corruption, return an error */
		return 0;
	default:
		assert(NULL == "shouldn't be here");
		return 0;
	}
	tmp = DC_MSG_decode(&io->msg, buf_ptr, buf_len);
	NAL_BUFFER_takedata(buffer, NULL, tmp);
	cmd = DC_MSG_get_cmd(&io->msg);
	if((to_server && !io->msg.is_response) ||
			(!to_server && io->msg.is_response))
		/* Corruption */
		return 0;
	if(io->state == PLUG_EMPTY) {
		/* This is the first frame of a new command */
		io->data_used = 0;
		io->request_uid = io->msg.request_uid;
		io->cmd = cmd;
		io->state = PLUG_IO;
	} else {
		/* This is a followup frame, need to check it */
		if((io->msg.request_uid != io->request_uid) ||
				(io->cmd != cmd))
			return 0;
		if(io->msg.data_len + io->data_used > DC_MAX_TOTAL_DATA)
			return 0;
	}
	/* Append the payload data */
	if(io->msg.data_len) {
		/* Make room for the payload data */
		if(!DC_PLUG_IO_make_space(io, io->msg.data_len))
			return 0;
		NAL_memcpy_n(unsigned char, io->data + io->data_used,
				io->msg.data, io->msg.data_len);
		io->data_used += io->msg.data_len;
	}
	/* Is the message complete? */
	if(io->msg.complete)
		/* Yes */
		io->state = PLUG_FULL;
	return 1;
}

static int DC_PLUG_IO_read(DC_PLUG_IO *io, int resume,
			unsigned long *request_uid,
			DC_CMD *cmd,
			const unsigned char **payload_data,
	                unsigned int *payload_len)
{
	switch(io->state) {
	case PLUG_EMPTY:
	case PLUG_IO:
		/* Nothing to read */
		return 0;
	case PLUG_USER:
		/* Can only read if "resume"ing */
		if(!resume)
			return 0;
		break;
	case PLUG_FULL:
		/* Start reading! */
		io->state = PLUG_USER;
		break;
	default:
		assert(NULL == "shouldn't be here");
		return 0;
	}
	*request_uid = io->request_uid;
	*cmd = io->cmd;
	*payload_data = io->data;
	*payload_len = io->data_used;
	return 1;
}

static int DC_PLUG_IO_consume(DC_PLUG_IO *io, int to_server,
				NAL_BUFFER *buffer)
{
	switch(io->state) {
	case PLUG_EMPTY:
	case PLUG_IO:
		/* Nothing to consume! */
	case PLUG_FULL:
		/* Haven't even started reading! */
		return 0;
	case PLUG_USER:
		break;
	default:
		assert(NULL == "shouldn't be here");
		return 0;
	}
	/* The command is done */
	io->data_used = 0;
	io->state = PLUG_EMPTY;
	return DC_PLUG_IO_read_flush(io, to_server, buffer);
}

/* "DC_PLUG_IO" write-specific functions */

static int DC_PLUG_IO_write_flush(DC_PLUG_IO *io, int to_server,
				NAL_BUFFER *buffer)
{
	unsigned char *buf_ptr;
	unsigned int buf_len, tmp;

	switch(io->state) {
	case PLUG_EMPTY:
	case PLUG_USER:
		/* Can't do anything */
		return 1;
	case PLUG_IO:
		/* See if pulling data through advances our state */
		break;
	case PLUG_FULL:
	default:
		assert(NULL == "shouldn't be here");
		return 0;
	}
	buf_ptr = NAL_BUFFER_write_ptr(buffer);
	buf_len = NAL_BUFFER_unused(buffer);
	/* Construct the frame */
	io->msg.is_response = (to_server ? 0 : 1);
	if(!DC_MSG_set_cmd(&io->msg, io->cmd))
		return 0;
	io->msg.request_uid = io->request_uid;
	io->msg.data_len = (io->data_used > DC_MSG_MAX_DATA ?
			DC_MSG_MAX_DATA : io->data_used);
	io->msg.complete = ((io->msg.data_len == io->data_used) ? 1 : 0);
	NAL_memcpy_n(unsigned char, io->msg.data, io->data, io->msg.data_len);
	/* Check its encoding size */
	if(DC_MSG_encoding_size(&io->msg) > buf_len)
		/* Can't do anything */
		return 1;
	tmp = DC_MSG_encode(&io->msg, buf_ptr, buf_len);
	NAL_BUFFER_wrote(buffer, tmp);
	/* It's encoded, so adjust our state */
	io->data_used -= io->msg.data_len;
	if(io->data_used) {
		/* There's still more to go */
		NAL_memmove_n(unsigned char, io->data,
				io->data + io->msg.data_len,
				io->data_used);
		return 1;
	}
	/* It's completely done */
	io->state = PLUG_EMPTY;
	return 1;
}

static int DC_PLUG_IO_write(DC_PLUG_IO *io, int resume,
			unsigned long request_uid,
			DC_CMD cmd,
			const unsigned char *payload_data,
			unsigned int payload_len)
{
	switch(io->state) {
	case PLUG_IO:
		/* Occupied */
		return 0;
	case PLUG_USER:
		/* Can only write if "resume"ing */
		if(!resume)
			return 0;
	case PLUG_EMPTY:
		/* Write */
		break;
	case PLUG_FULL:
	default:
		assert(NULL == "shouldn't be here");
		return 0;
	}
	/* Check input */
	if(payload_len > DC_MAX_TOTAL_DATA)
		/* That's too much data */
		return 0;
	/* Ensure we have room */
	if(!DC_PLUG_IO_make_space(io, payload_len))
		return 0;
	/* Change state */
	io->state = PLUG_USER;
	/* Copy the values */
	io->request_uid = request_uid;
	io->cmd = cmd;
	io->data_used = payload_len;
	if(payload_len)
		NAL_memcpy_n(unsigned char, io->data, payload_data, payload_len);
	return 1;
}

static int DC_PLUG_IO_write_more(DC_PLUG_IO *io,
			const unsigned char *data,
			unsigned int data_len)
{
	switch(io->state) {
	case PLUG_USER:
		break;
	case PLUG_IO:
	case PLUG_EMPTY:
		return 0;
	case PLUG_FULL:
	default:
		assert(NULL == "shouldn't be here");
		return 0;
	}
	/* Check input */
	if((io->data_used + data_len > DC_MAX_TOTAL_DATA) ||
			!data || !data_len)
		return 0;
	if(!DC_PLUG_IO_make_space(io, data_len))
		return 0;
	NAL_memcpy_n(unsigned char, io->data + io->data_used, data, data_len);
	io->data_used += data_len;
	return 1;
}

static int DC_PLUG_IO_commit(DC_PLUG_IO *io, int to_server,
			NAL_BUFFER *buffer)
{
	switch(io->state) {
	case PLUG_USER:
		break;
	case PLUG_IO:
	case PLUG_EMPTY:
		return 0;
	case PLUG_FULL:
	default:
		assert(NULL == "shouldn't be here");
		return 0;
	}
	io->state = PLUG_IO;
	return DC_PLUG_IO_write_flush(io, to_server, buffer);
}

static int DC_PLUG_IO_rollback(DC_PLUG_IO *io)
{
	switch(io->state) {
	case PLUG_USER:
		break;
	case PLUG_IO:
	case PLUG_EMPTY:
		return 0;
	case PLUG_FULL:
	default:
		assert(NULL == "shouldn't be here");
		return 0;
	}
	io->state = PLUG_EMPTY;
	io->data_used = 0;
	return 1;
}

/************************/
/* "plug" API functions */

DC_PLUG *DC_PLUG_new(NAL_CONNECTION *conn, unsigned int flags)
{
	DC_PLUG *toret = NAL_malloc(DC_PLUG, 1);
	if(!toret)
		return NULL;
	toret->conn = conn;
	toret->flags = flags;
	if(DC_PLUG_IO_init(&toret->read) && DC_PLUG_IO_init(&toret->write))
		return toret;
	NAL_free(DC_PLUG, toret);
	return NULL;
}

int DC_PLUG_free(DC_PLUG *plug)
{
	if(!(plug->flags & DC_PLUG_FLAG_NOFREE_CONN))
		NAL_CONNECTION_free(plug->conn);
	DC_PLUG_IO_finish(&plug->read);
	DC_PLUG_IO_finish(&plug->write);
	NAL_free(DC_PLUG, plug);
	return 1;
}

int DC_PLUG_to_select(DC_PLUG *plug, NAL_SELECTOR *sel)
{
	return NAL_SELECTOR_add_conn(sel, plug->conn);
}

int DC_PLUG_io(DC_PLUG *plug, NAL_SELECTOR *sel)
{
	int to_server = plug->flags & DC_PLUG_FLAG_TO_SERVER;
	if(!NAL_CONNECTION_io(plug->conn, sel))
		return 0;
	/* Network I/O has (possibly) taken place. Ensure our "state" is
	 * adjusted appropriately. */
	if(!DC_PLUG_IO_read_flush(&plug->read, to_server,
				NAL_CONNECTION_get_read(plug->conn)) ||
			!DC_PLUG_IO_write_flush(&plug->write, to_server,
				NAL_CONNECTION_get_send(plug->conn)))
		return 0;
	return 1;
}

int DC_PLUG_read(DC_PLUG *plug, int resume,
			unsigned long *request_uid,
			DC_CMD *cmd,
			const unsigned char **payload_data,
	                unsigned int *payload_len)
{
	return DC_PLUG_IO_read(&plug->read, resume, request_uid, cmd,
			payload_data, payload_len);
}

int DC_PLUG_consume(DC_PLUG *plug)
{
	return DC_PLUG_IO_consume(&plug->read,
			plug->flags & DC_PLUG_FLAG_TO_SERVER,
			NAL_CONNECTION_get_read(plug->conn));
}

int DC_PLUG_write(DC_PLUG *plug, int resume,
			unsigned long request_uid,
			DC_CMD cmd,
			const unsigned char *payload_data,
			unsigned int payload_len)
{
	return DC_PLUG_IO_write(&plug->write, resume, request_uid, cmd,
			payload_data, payload_len);
}

int DC_PLUG_write_more(DC_PLUG *plug,
			const unsigned char *data,
			unsigned int data_len)
{
	return DC_PLUG_IO_write_more(&plug->write, data, data_len);
}

int DC_PLUG_commit(DC_PLUG *plug)
{
	return DC_PLUG_IO_commit(&plug->write,
			plug->flags & DC_PLUG_FLAG_TO_SERVER,
			NAL_CONNECTION_get_send(plug->conn));
}

int DC_PLUG_rollback(DC_PLUG *plug)
{
	return DC_PLUG_IO_rollback(&plug->write);
}
