/* distcache, Distributed Session Caching technology
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
#ifndef HEADER_LIBNAL_NAL_SSL_H
#define HEADER_LIBNAL_NAL_SSL_H

#ifndef HEADER_LIBNAL_NAL_H
	#error "Must include libnal/nal.h prior to libnal/nal_ssl.h"
#endif
#ifndef HEADER_BIO_H
	#error "Must include openssl/bio.h prior to libnal/nal_ssl.h"
#endif
#ifndef HEADER_SSL_H
	#error "Must include openssl/ssl.h prior to libnal/nal_ssl.h"
#endif

/********************/
/* "libnal" SSL API */
/********************/

BIO *BIO_new_NAL_CONNECTION(NAL_CONNECTION *c);

#endif /* !defined(HEADER_LIBNAL_NAL_SSL_H) */

