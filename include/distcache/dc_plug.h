/* distcache, Distributed Session Caching technology
 * Copyright (C) 2000-2003  Geoff Thorpe, and Cryptographic Appliances, Inc.
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
#ifndef HEADER_DISTCACHE_DC_PLUG_H
#define HEADER_DISTCACHE_DC_PLUG_H

/* These two macros extract the "protocol version" and "patch level" from a
 * 32-bit "protocol level" value. */
#define DISTCACHE_GET_PROTO_VER(a)	((a) >> 16)
#define DISTCACHE_GET_PATCH_LEVEL(a)	((a) & 0x0000FFFF)

/* This macro creates a "protocol level" from a "protocol version" and "patch
 * level". */
#define DISTCACHE_MAKE_PROTO_LEVEL(a,b)	(((a) << 16) + (b))

/* This is the value used for "proto_level" in the currently implemented message
 * format, preceeded by its last-significant word (the "patch level") and its
 * most-significant word (the "patch level"). It is envisaged that tools with
 * matching "proto_level" will be interoperable because the more recent knows
 * how to communicate with the oldest of the two. For this reason, any genuinely
 * incompatible behavioural (or binary formatting) changes should cause an
 * corresponding bump in the most-significant word (the "protocol version") and
 * thus "officially" break interoperability with prior versions. */
#define DISTCACHE_PROTO_VER	0x11
#define DISTCACHE_PATCH_LEVEL	0x00
#define DISTCACHE_PROTO_LEVEL	DISTCACHE_MAKE_PROTO_LEVEL(\
					DISTCACHE_PROTO_VER,DISTCACHE_PATCH_LEVEL)

typedef enum {
	DC_CMD_ERROR,	/* don't "set", this is a return value only */
	DC_CMD_ADD,
	DC_CMD_GET,
	DC_CMD_REMOVE,
	DC_CMD_HAVE
} DC_CMD;

/* The maximum size of "data" in a single message (or "frame") */
#define DC_MSG_MAX_DATA		2048
/* The maximum number of messages in a command request or response */
#define DC_MAX_MSG		16
/* The maximum total payload of a defragmented command */
#define DC_MAX_TOTAL_DATA	(DC_MSG_MAX_DATA * DC_MAX_MSG)
/* The maximum length of a session ID. NB: this "enc" layer is ignorant of
 * payload interpretation, which is where we actually put session IDs and
 * session data - the limit is only mentioned here to save duplicating it in
 * other headers that are supposed to be independant of each other. */
#define DC_MAX_ID_LEN		64

/*****************************************/
/* libdistcache's "DC_PLUG" declarations */
/*****************************************/

/* Our abstract "plug" type for libsession. Abstracts the protocol (and I/O)
 * handling, allowing the caller to simply read/write payloads. */
typedef struct st_DC_PLUG DC_PLUG;

/* Flags for use in 'DC_PLUG_new' */
#define DC_PLUG_FLAG_TO_SERVER		(unsigned int)0x0001
#define DC_PLUG_FLAG_NOFREE_CONN	(unsigned int)0x0002

/* General "plug" functions */
DC_PLUG *DC_PLUG_new(NAL_CONNECTION *conn, unsigned int flags);
int DC_PLUG_free(DC_PLUG *plug);
void DC_PLUG_to_select(DC_PLUG *plug, NAL_SELECTOR *sel);
int DC_PLUG_io(DC_PLUG *plug, NAL_SELECTOR *sel);

/* Read a decoded (defragmented and parsed) message payload and message type.
 * This leaves the message blocked (future "reads" have to use a non-zero
 * "resume" to read the same message) until "consume" is called. */
int DC_PLUG_read(DC_PLUG *plug, int resume,
		/* request_uid, copied to the caller's address */
		unsigned long *request_uid,
		/* command type, copied to the caller's address */
		DC_CMD *cmd,
		/* payload, *NOT* copied, caller's pointer is set to original */
		const unsigned char **payload_data,
		/* payload length, copied to the caller's address */
		unsigned int *payload_len);
/* Discard the message currently being "read", and pull through any data behind
 * it so it will be there for the next "read" call. */
int DC_PLUG_consume(DC_PLUG *plug);
/* Start writing a message. This will cause the outgoing queue to block (and
 * future "write"s to fail unless a non-zero "resume" is used) until the data is
 * fully written. This is marked by a call to "commit" which flushes the message
 * through to make room (if possible) for the next "write" call. */
int DC_PLUG_write(DC_PLUG *plug, int resume,
		unsigned long request_uid,
		DC_CMD cmd,
		const unsigned char *payload_data,
		unsigned int payload_len);
/* Adds data to an in-progress "write". The data provided will be appended to
 * the existing payload (so the original "write" can even provide a zero-size
 * NULL payload to begin with, and this can be used to add data) */
int DC_PLUG_write_more(DC_PLUG *plug,
		const unsigned char *data, unsigned int data_len);
/* Commit an in-progress "write". */
int DC_PLUG_commit(DC_PLUG *plug);
/* Rollback an in-progress "write" (previous data added by calls to "write" and
 * perhaps "write_more" will be discarded). */
int DC_PLUG_rollback(DC_PLUG *plug);

#endif /* !defined(HEADER_DISTCACHE_DC_PLUG_H) */
