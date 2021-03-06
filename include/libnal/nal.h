/* distcache, Distributed Session Caching technology
 * Copyright (C) 2000-2003  Geoff Thorpe, and Cryptographic Appliances, Inc.
 * Copyright (C) 2004       The Distcache.org project
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
#ifndef HEADER_LIBNAL_NAL_H
#define HEADER_LIBNAL_NAL_H

/*-----------------------*/
/* "libnal" EXTERNAL API */
/* ----------------------*/

typedef struct st_NAL_ADDRESS NAL_ADDRESS;
typedef struct st_NAL_LISTENER NAL_LISTENER;
typedef struct st_NAL_CONNECTION NAL_CONNECTION;
typedef struct st_NAL_SELECTOR NAL_SELECTOR;
typedef struct st_NAL_BUFFER NAL_BUFFER;

/* Flags passed to NAL_CONNECTION_add_to_selector_ex() */
#define NAL_SELECT_FLAG_READ	(unsigned int)0x0001
#define NAL_SELECT_FLAG_SEND	(unsigned int)0x0002
#define NAL_SELECT_FLAG_RW	(NAL_SELECT_FLAG_READ | NAL_SELECT_FLAG_SEND)

/********************/
/* Global functions */
/********************/

void		NAL_config_set_nagle(int enabled);

/*********************/
/* Address functions */
/*********************/

NAL_ADDRESS *	NAL_ADDRESS_new(void);
void		NAL_ADDRESS_free(NAL_ADDRESS *addr);
void		NAL_ADDRESS_reset(NAL_ADDRESS *addr);
int		NAL_ADDRESS_create(NAL_ADDRESS *addr, const char *addr_string,
				unsigned int def_buffer_size);
unsigned int	NAL_ADDRESS_get_def_buffer_size(const NAL_ADDRESS *addr);
int		NAL_ADDRESS_set_def_buffer_size(NAL_ADDRESS *addr,
				unsigned int def_buffer_size);
int		NAL_ADDRESS_can_connect(const NAL_ADDRESS *addr);
int		NAL_ADDRESS_can_listen(const NAL_ADDRESS *addr);

/**********************/
/* Selector functions */
/**********************/

NAL_SELECTOR *	NAL_SELECTOR_new(void);
void		NAL_SELECTOR_free(NAL_SELECTOR *sel);
void		NAL_SELECTOR_reset(NAL_SELECTOR *sel);
int		NAL_SELECTOR_select(NAL_SELECTOR *sel,
				unsigned long usec_timeout,
				int use_timeout);
unsigned int	NAL_SELECTOR_num_objects(const NAL_SELECTOR *sel);
/* implementation-specific constructors */
NAL_SELECTOR *	NAL_SELECTOR_new_fdselect(void);
NAL_SELECTOR *	NAL_SELECTOR_new_fdpoll(void);

/********************************/
/* Listener functions (general) */
/********************************/

NAL_LISTENER *	NAL_LISTENER_new(void);
void		NAL_LISTENER_free(NAL_LISTENER *list);
void		NAL_LISTENER_reset(NAL_LISTENER *list);
int		NAL_LISTENER_create(NAL_LISTENER *list,
				const NAL_ADDRESS *addr);
int		NAL_LISTENER_add_to_selector(NAL_LISTENER *list,
				NAL_SELECTOR *sel);
void		NAL_LISTENER_del_from_selector(NAL_LISTENER *list);
int		NAL_LISTENER_finished(const NAL_LISTENER *list);

/************************************/
/* Listener functions (specialised) */
/************************************/

int		NAL_LISTENER_set_fs_owner(NAL_LISTENER *list,
				const char *ownername,
				const char *groupname);
int		NAL_LISTENER_set_fs_perms(NAL_LISTENER *list,
				const char *octal_string);

/**********************************/
/* Connection functions (general) */
/**********************************/

NAL_CONNECTION *NAL_CONNECTION_new(void);
void		NAL_CONNECTION_free(NAL_CONNECTION *conn);
void		NAL_CONNECTION_reset(NAL_CONNECTION *conn);
int		NAL_CONNECTION_create(NAL_CONNECTION *conn,
				const NAL_ADDRESS *addr);
int		NAL_CONNECTION_accept(NAL_CONNECTION *conn,
				NAL_LISTENER *list);
int		NAL_CONNECTION_set_size(NAL_CONNECTION *conn,
				unsigned int size);
NAL_BUFFER *	NAL_CONNECTION_get_read(NAL_CONNECTION *conn);
NAL_BUFFER *	NAL_CONNECTION_get_send(NAL_CONNECTION *conn);
const NAL_BUFFER *NAL_CONNECTION_get_read_c(const NAL_CONNECTION *conn);
const NAL_BUFFER *NAL_CONNECTION_get_send_c(const NAL_CONNECTION *conn);
int		NAL_CONNECTION_io(NAL_CONNECTION *conn);
int		NAL_CONNECTION_is_established(const NAL_CONNECTION *conn);
int		NAL_CONNECTION_add_to_selector(NAL_CONNECTION *conn,
				NAL_SELECTOR *sel);
void		NAL_CONNECTION_del_from_selector(NAL_CONNECTION *conn);

/**************************************/
/* Connection functions (specialised) */
/**************************************/

int		NAL_CONNECTION_create_pair(NAL_CONNECTION *conn1,
				NAL_CONNECTION *conn2,
				unsigned int def_buffer_size);
#if 0
int		NAL_CONNECTION_create_dummy(NAL_CONNECTION *conn,
				unsigned int def_buffer_size);
#endif

/********************/
/* Buffer functions */
/********************/

NAL_BUFFER *	NAL_BUFFER_new(void);
void		NAL_BUFFER_free(NAL_BUFFER *buf);
void		NAL_BUFFER_reset(NAL_BUFFER *buf);
int		NAL_BUFFER_set_size(NAL_BUFFER *buf,
				unsigned int size);
int		NAL_BUFFER_empty(const NAL_BUFFER *buf);
int		NAL_BUFFER_full(const NAL_BUFFER *buf);
int		NAL_BUFFER_notempty(const NAL_BUFFER *buf);
int		NAL_BUFFER_notfull(const NAL_BUFFER *buf);
unsigned int	NAL_BUFFER_used(const NAL_BUFFER *buf);
unsigned int	NAL_BUFFER_unused(const NAL_BUFFER *buf);
unsigned int	NAL_BUFFER_size(const NAL_BUFFER *buf);
const unsigned char *NAL_BUFFER_data(const NAL_BUFFER *buf);
/* Now we define the general "access" functions for the buffer type */
unsigned int 	NAL_BUFFER_write(NAL_BUFFER *buf,
				const unsigned char *ptr,
				unsigned int size);
unsigned int 	NAL_BUFFER_read(NAL_BUFFER *buf,
				unsigned char *ptr,
				unsigned int size);
unsigned int	NAL_BUFFER_transfer(NAL_BUFFER *dest, NAL_BUFFER *src,
				unsigned int max);

/***************** WARNING START ********************/
/* These functions manipulate internal data directly and are to be used with
 * caution - it's easy for data to "go missing" or "get created out of nowhere"
 * by misusing these functions. */
/******** WARNING END - you have been warned ********/

/* Returns a pointer to the tail of the buffer's data, you should never attempt
 * to write more than NAL_BUFFER_unused(buf) bytes from the return value. */
unsigned char *	NAL_BUFFER_write_ptr(NAL_BUFFER *buf);
/* If you wrote data directly to the buffer using ...write_ptr() rather than
 * NAL_BUFFER_write(), then use this call to indicate that the buffer has "size"
 * more bytes available to it at the position ...write_ptr() returned. */
void		NAL_BUFFER_wrote(NAL_BUFFER *buf,
				unsigned int size);

/*************************/
/* En/Decoding functions */
/*************************/

/* This set of functions provide architecture-independant ways of encoding
 * various primitive types. The general format of the functions is;
 *   int NAL_decode_XX(const unsigned char **bin, unsigned int *bin_len,
 *                     XX *val);
 * and
 *   int NAL_encode_XX(unsigned char **bin, unsigned int *cnt,
 *                     const XX val);
 * where 'XX' is the primitive type in question. The behaviour is that bin &
 * bin_len are altered after the encoding/decoding so that bin points to the
 * next unused byte and bin_len is reduced by the number of bytes used. As such,
 * these functions can be used in situations where (i) the input may be
 * insufficient to encode or decode the relevant structure, and (ii) where
 * multiple levels of encoding/decoding may be constructed for aggregate
 * structure types.
 *
 * The return values are zero for failure and non-zero for success.
 */
int NAL_decode_uint32(const unsigned char **bin, unsigned int *bin_len,
			unsigned long *val);
int NAL_decode_uint16(const unsigned char **bin, unsigned int *bin_len,
			unsigned int *val);
int NAL_decode_char(const unsigned char **bin, unsigned int *bin_len,
			unsigned char *val);
int NAL_decode_bin(const unsigned char **bin, unsigned int *bin_len,
			unsigned char *val, unsigned int val_len);

int NAL_encode_uint32(unsigned char **bin, unsigned int *bin_len,
			const unsigned long val);
int NAL_encode_uint16(unsigned char **bin, unsigned int *bin_len,
			const unsigned int val);
int NAL_encode_char(unsigned char **bin, unsigned int *bin_len,
			const unsigned char val);
int NAL_encode_bin(unsigned char **bin, unsigned int *bin_len,
			const unsigned char *val, const unsigned int val_len);

#endif /* !defined(HEADER_LIBNAL_NAL_H) */

