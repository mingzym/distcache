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
#ifndef HEADER_PRIVATE_TIMING_H
#define HEADER_PRIVATE_TIMING_H

/* Only support "-update" if we have the goodies. C files should ignore all
 * update related stuff if SUPPORT_UPDATE isn't defined. */
#if defined(HAVE_GETTIMEOFDAY) && defined(HAVE_GETRUSAGE)
#define SUPPORT_UPDATE
#endif

typedef unsigned char UNITS;

/* The C file should use this macro, which instantiates variables, and
 * functions (util_parseunits). */
#define IMPLEMENT_UNITS() \
		static const char *UNITS_str[] = \
		{ "b", "Kb", "Mb", "Gb", "B", "KB", "MB", "GB" }; \
		static int util_parseunits(const char *s, UNITS *u) \
		{ \
			const char *foo = s; \
			*u = UNITS_bits; \
			switch(strlen(s)) { \
			case 2: \
				switch(*foo) { \
				case 'k': *u |= UNITS_kilo; break; \
				case 'm': *u |= UNITS_mega; break; \
				case 'g': *u |= UNITS_giga; break; \
				default: goto err; \
				} \
				foo++; \
			case 1: \
				switch(*foo) { \
				case 'b': *u |= UNITS_bits; break; \
				case 'B': *u |= UNITS_bytes; break; \
				default: goto err; \
				} \
				break; \
			default: \
				goto err; \
			} \
			return 1; \
		err: \
			SYS_fprintf(SYS_stderr, "Error, bad unit '%s'\n", s); \
			return 0; \
		} \
		static double util_tounits(unsigned long traffic, UNITS units) \
		{ \
			double ret = traffic; \
			if(!(units & UNITS_bytes)) ret *= 8; \
			switch(units & UNITS_mask) { \
			case UNITS_giga: ret /= 1024; \
			case UNITS_mega: ret /= 1024; \
			case UNITS_kilo: ret /= 1024; \
			case 0: break; \
			default: abort(); /* bug */ \
			} \
			return ret; \
		}

/* The bit mask for bits or bytes */
#define UNITS_bits	(UNITS)0
#define UNITS_bytes	(UNITS)4
/* The bit mask for the scale */
#define UNITS_kilo	(UNITS)1
#define UNITS_mega	(UNITS)2
#define UNITS_giga	(UNITS)3
#define UNITS_mask	(UNITS)3

/* Convert a UNITS variable to a corresponding string */
#define UNITS2STR(u)		UNITS_str[(u)]

#endif
