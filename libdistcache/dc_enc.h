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
#ifndef HEADER_LIBDISTCACHE_DC_ENC_H
#define HEADER_LIBDISTCACHE_DC_ENC_H

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
#define DISTCACHE_PROTO_VER	0x10
#define DISTCACHE_PATCH_LEVEL	0x00
#define DISTCACHE_PROTO_LEVEL	DISTCACHE_MAKE_PROTO_LEVEL(\
					DISTCACHE_PROTO_VER,DISTCACHE_PATCH_LEVEL)

/* This header supports the binary standard unpinning the session caching.
 *
 * --------------
 * Message format
 * --------------
 *
 * Requests and responses use the same binary "message" format with the
 * distinction between operations being made in the message's data. However,
 * "proto_level" allows for this format to evolve over time (when NECESSARY!) by
 * performing a version check on the first 4 bytes of any request/response -
 * thus allowing cleaner error handling of version incompatibilites. The
 * DISTCACHE_PROTOCOL_VER symbol is used as the "proto_level" value by the
 * sender to indicate its protocol version (most-significant word) as well as
 * its patch level (least-significant word). The patch level isn't strictly
 * needed for assuring binary format compatibility of the protocol, but it can
 * help by allowing the possibility for more recent tools to be backwards
 * compatible with older versions. When a bug-fix or enhancement can not do
 * this, an incompatible bump in the protocol version is necessary.
 * 
 * For the current protocol version, 0x0010, each message is of this basic
 * format;
 *
 * unsigned long (4-bytes)              proto_level
 * unsigned char (1-byte)               is_response
 * unsigned long (4-bytes)              request_uid
 * unsigned char (1-byte)               op_class
 * unsigned char (1-byte)               operation
 * unsigned char (1-byte)               complete
 * unsigned int (2-bytes)               data_len    (max: DC_MSG_MAX_DATA)
 * unsigned char[] ('data_len' bytes)   data
 *
 * proto_level;
 *    A 32-bit version number for the protocol used by the sender for encoding
 *    the the message. See above for explanations.
 * is_response;
 *    There are two valid values; 0 -> the message is a request
 *                                1 -> the message is a response
 * request_uid;
 *    This value only has significance to the side initiating a request. It is
 *    simply used in response messages to allow the caller to match a response
 *    to its corresponding request.
 * op_class;
 *    Indicates which set of operations 'operation' should be interpreted in.
 *    "Normal" operations always set this to the 'DC_CLASS_USER' (zero).
 * operation;
 *    Given 'op_class', this value then defines the exact operation required by
 *    the side sending the request. It is what allows the side generating a
 *    response to interpret the meaning of the 'data'/'data_len' values.
 * complete;
 *    Many messages will not actually fully encode in a single DC_MSG structure.
 *    As such, this value can be used for "framing", all frames however must
 *    have the same request_uid and only the final one should be "complete";
 *            0 -> there is more data to come
 *            1 -> this is the final message.
 *    NB: To make the protocol more sturdy, each "incomplete" message must send
 *    at least DC_MSG_MAX_DATA bytes of data. Only the final message can send
 *    less.
 * data_len;
 *    This value indicates how many bytes are in the 'data_len' field that
 *    follows it. It allows multiple requests/responses to be concatenated one
 *    after another without ambiguity. To ensure dead-locks don't occur in the
 *    framing of these messages, 'data_len' has a maximum valid value of
 *    DC_MSG_MAX_DATA.
 * data;
 *    This is the "input" to a request and the "output" for a response. The
 *    length of the field depends on 'data_len', and the interpretation of this
 *    data depends on the choice of 'op_class'/'operation'.
 *
 * ------------------------------------
 * Classes of operations and their data
 * ------------------------------------
 *
 * The current list of operation classes and operations is as follows;
 *
 *   op_class              operation
 *   --------              ---------
 *   DC_CLASS_USER         DC_OP_ADD
 *                         DC_OP_GET
 *                         DC_OP_REMOVE
 *                         DC_OP_HAVE
 *
 * All operations can return a one-byte response which is to be interpreted as
 * an "error" value (in the case of "ADD", and "REMOVE" this includes an "OK"
 * value, and in the case of "HAVE" is a boolean anyway). These values, if
 * they're less than 100, come from the DC_ERR enumerate type. Otherwise, they
 * are from the per-operation enums corresponding to the command type. The
 * meaning of the operations and their data is as follows;
 *
 * DC_OP_ADD;
 *    This operation sends an encoded SSL_SESSION (compatible with OpenSSL's
 *    d2i_SSL_SESSION() function) to a cache target for addition. The encoded
 *    data is prefixed by a 4-byte (unsigned long) value indicating the number
 *    of seconds the server should allow before automatically removing the
 *    session from its storage. The return value is 1-byte; either DC_ERR_OK, or
 *    a value chosen from DC_[ADD_]ERR_*** values.
 * DC_OP_GET;
 *    This operation looks up a cache target to see if it has the SSL_SESSION
 *    corresponding to a given session id. The payload is the session id, and
 *    the return value is either a 1-byte error value chosen from the DC_ERR
 *    type or an encoded SSL_SESSION matching the id.
 * DC_OP_REMOVE;
 *    This operation looks up a cache target to see if it has the SSL_SESSION
 *    corresponding to a given session id. The payload is the session id, and
 *    the return value is a 1-byte error value chosen from DC_ERR_TYPE.
 * DC_OP_HAVE;
 *    This operation is like DC_OP_GET, except that it doesn't return a session
 *    object even if it has the one that is asked for. The caller is simply
 *    wanting to know if the cache still has the session. The reason is for
 *    proxying code - downloading a session involves quite a bit of bandwidth -
 *    so proxies may alreay have the session cached but just want to check it
 *    hasn't been deleted from the server before they return it to an
 *    application. The format is the same as DC_OP_GET, and the return value is
 *    a 1-byte boolean value from chosen from the DC_ERR type (YES/NO is
 *    DC_ERR_OK/DC_ERR_NOTOK respectively).
 */

typedef enum {
	DC_CLASS_USER = 0,
	DC_CLASS_LAST = DC_CLASS_USER
} DC_CLASS;

typedef enum {
	DC_OP_ADD = 0,
	DC_OP_GET,
	DC_OP_REMOVE,
	DC_OP_HAVE
} DC_OP;

/* These alternative enums provide an encapsulated op_class/operation pair */
typedef enum {
	DC_CMD_ERROR,	/* don't "set", this is a return value only */
	DC_CMD_ADD,
	DC_CMD_GET,
	DC_CMD_REMOVE,
	DC_CMD_HAVE
} DC_CMD;

/* These error codes work for *all* operations. That's why per-operation errors
 * are numbered from 100 onwards. */
typedef enum {
	DC_ERR_OK = 0,
	DC_ERR_NOTOK,
	DC_ERR_DISCONNECTED
} DC_ERR;

/* Various 1-byte "per-operation-type" error codes */
typedef enum {
	DC_ADD_ERR_CORRUPT = 100,
	DC_ADD_ERR_MATCHING_SESSION,
	DC_ADD_ERR_TIMEOUT_RANGE,
	DC_ADD_ERR_ID_RANGE,
	DC_ADD_ERR_DATA_RANGE
} DC_ADD_ERR;

/* Before decoding, serialised data is scanned to see that it is valid and
 * complete using 'DC_MSG_pre_decode()'. This is the return type. */
typedef enum {
	/* Indicates serialised data is corrupt */
	DC_DECODE_STATE_CORRUPT,
	/* Indicates serialised data is incomplete (it may become "corrupt" or
	 * "OK" when more data arrives). */
	DC_DECODE_STATE_INCOMPLETE,
	/* Indicates serialised data contains a valid message. */
	DC_DECODE_STATE_OK
} DC_DECODE_STATE;

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

typedef struct st_DC_MSG {
	unsigned long	proto_level;
	unsigned char	is_response;
	unsigned long	request_uid;
	DC_CLASS	op_class;
	DC_OP		operation;
	unsigned char	complete;
	unsigned int	data_len;
	unsigned char	data[DC_MSG_MAX_DATA];
} DC_MSG;

/* Most of these have been converted to "static" functions internal to dc_enc.c
 * to ensure they're only used via "more recommended routes". I'm leaving the
 * definitions here case I want them exported again later. */
#if 0
/* Populate a DC_MSG with a command (converting to op_class/operation pairs
 * automatically). */
int DC_MSG_set_cmd(DC_MSG *msg, DC_CMD cmd);
/* Read a DC_MSG's op_class/operation pair as a command. */
DC_CMD DC_MSG_get_cmd(const DC_MSG *msg);
/* Given a request, populate a response with everything but data */
int DC_MSG_start_response(const DC_MSG *request,
				DC_MSG *response);
/* Given a message, calculate the space required for encoding */
unsigned int DC_MSG_encoding_size(const DC_MSG *msg);
/* Encode a message (returns encoding size) */
unsigned int DC_MSG_encode(const DC_MSG *msg, unsigned char *ptr,
				unsigned int data_len);
/* Given a (supposed) encoding, examine it */
DC_DECODE_STATE DC_MSG_pre_decode(const unsigned char *data,
				unsigned int data_len);
/* Decode a message (returns the number of bytes decoded) */
unsigned int DC_MSG_decode(DC_MSG *msg, const unsigned char *data,
				unsigned int data_len);
#endif

/***************************************/
/* libsession's "DC_PLUG" declarations */
/***************************************/

/* Our abstract "plug" type for libsession. Abstracts the protocol (and I/O)
 * handling, allowing the caller to simply read/write payloads. */
typedef struct st_DC_PLUG DC_PLUG;

/* Flags for use in 'DC_PLUG_new' */
#define DC_PLUG_FLAG_TO_SERVER		(unsigned int)0x0001
#define DC_PLUG_FLAG_NOFREE_CONN	(unsigned int)0x0002

/* General "plug" functions */
DC_PLUG *DC_PLUG_new(NAL_CONNECTION *conn, unsigned int flags);
int DC_PLUG_free(DC_PLUG *plug);
int DC_PLUG_to_select(DC_PLUG *plug, NAL_SELECTOR *sel);
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

#endif /* !defined(HEADER_LIBDISTCACHE_DC_ENC_H) */
