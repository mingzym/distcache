/* License file snipped from here. Please see the "LICENSE" file, or the top of
 * the "swamp.h" header. Both contain the current license. */


#include "swamp.h"

/*
 * returns non-zero on error, zero if otherwise it successfully initialised
 * the structure.
 */
int init_tokeniser(tokeniser_t *t, const char *string, const char *delimiters)
{
    /*
     * I think I'd prefer to see this function allocate a tokeniser_t
     * structure for itself, with the 'token' bit a part of that
     * allocation. For now, this system works, however.
     */
    if (t) {
        t->string     = string;
        t->delimiters = delimiters;
        t->position   = string;
        
        /* A token can't be longer than the length of the string itself */
        t->token = SYS_malloc(char, strlen(string) + 1);
        if (!t->token) {
            free_tokeniser(t);
            return 1;
        }
	return 0;
    }
    return 1;
}

void free_tokeniser(tokeniser_t *t)
{
    if (t) {
        t->string     = NULL;
        t->delimiters = NULL;
        t->position   = NULL;
        if (t->token)
            SYS_free(char, t->token);
        t->token = NULL;
    }
}

char *do_tokenising(tokeniser_t *t)
{
    if (t) {
        const char *p;   /* "Cursor" pointing into the string */
        int found_token = 0;
        int i = 0; /* An index into the token string */

        /*
         * If 'position' is NULL, this means we've reached the
         * end of the string
         */
        if (t->position == NULL)
            return NULL;

        p = t->position;
        while ( (strchr(t->delimiters, *p)) != NULL && *p != '\0')
            p++;

        for (; *p != '\0'; p++) {
            /*
             * Check to see if the "cursor" ('p') is over one of the
             * delimiters, and if so, move forward until a character
             * is found which *isn't* a delimiter (this also includes
             * the end of string)
             */
            while ( (strchr(t->delimiters, *p)) != NULL && *p != '\0') {
                found_token = 1;
                p++;
            }

	    /*
	     * It's important to let the 'while' loop above find all
	     * delimiters, and break out of the 'for' loop afterwards.
	     * Otherwise, the strings will be a bit scewed and
	     * empty strings will be returned.
	     */
            if (found_token)
                break;

            /*
             * A character which isn't a delimiter should be stored in
             * the token buffer.
             */
            t->token[i++] = *p;
        }

        /*
         * This seems a bit kludgy. If the last run came across a bunch of
         * tokens followed by a NULL byte, then nothing was copied into the
         * token buffer. In this case, we don't want to return an empty buffer,
         * but instead return with a "no more tokens" indicator.
         */
        if (i == 0)
            return NULL;

        t->token[i] = '\0'; /* NULL out - reasons should be obvious :-) */

        /*
         * If a token was found, update the tokeniser structure's current
         * position ready for the next run. Otherwise we reached the
         * end of the string.
         */
        if (found_token)
            t->position = p;
        else
            t->position = NULL;

        /* Return the token to the user. */
        return t->token;
    }
    return NULL;
}

#ifndef HAVE_STRTOL
static long int strtol(const char *nptr, char **endptr, int base)
{
	int negate = -1; /* not specified, assumed positive */
	long toret = 0;
	assert(base == 10);
	/* Now scan across 'nptr' processing char-by-char */
keep_scanning:
	if(isdigit(*nptr)) {
		toret += ((*nptr) - '0');
		if((LONG_MAX / 10) <= toret) {
			toret = LONG_MAX;
			goto end;
		}
		toret *= 10;
	} else if((*nptr == '-') || (*nptr == '+')) {
		if(negate != -1)
			/* We've already encountered a plus or minus */
			goto end;
		negate = ((*nptr == '-') ? 1 : 0);
	} else if(!isspace(*nptr)) {
		/* We hit something we don't like */
		goto end;
	}
	nptr++;
	if(*nptr != '\0')
		goto keep_scanning;
end:
	if(endptr)
		*endptr = nptr;
	return ((negate == 1) ? -toret : toret);
}
#endif

#ifndef HAVE_STRDUP
char *strdup(const char *s)
{
	size_t slen;
	char *toret;
	if(!s)
		return NULL;
	slen = strlen(s);
	toret = malloc(slen + 1);
	if(!toret)
		return NULL;
	if(slen)
		SYS_memcpy_n(char, toret, s, slen);
	toret[slen] = '\0';
	return toret;
}
#endif

/* Wrapper for strtol() */
int int_strtol(const char *str, long *val)
{
	char *ptr;
	long tmp = strtol(str, &ptr, 10);
	if((ptr == str) || (*ptr != '\0'))
		/* Doesn't look like a number */
		return 0;
	*val = tmp;
	return 1;
}

/* Wrapper for strtoul() */
int int_strtoul(const char *str, unsigned long *val)
{
	long tmp;
	if(!int_strtol(str, &tmp) || (tmp < 0))
		return 0;
	*val = tmp;
	return 1;
}

/* Versions of the above that allow termination other than '\0' */
int int_substrtol(const char *str, long *val, const char *valid_terms)
{
	char *ptr;
	long tmp = strtol(str, &ptr, 10);
	/* FIXME: this check that there was at least *some* numeric content
	 * parsed before a non-numeric character is bogus - it forgets possible
	 * leading whitespace. */
	if((ptr == str) || ((*str == '-') && (str + 1 == ptr)))
		/* no numeric characters at all! */
		return 0;
	*val = tmp;
	if(!valid_terms || (*ptr == '\0') || strchr(valid_terms, *ptr))
		/* Fine */
		return 1;
	/* Invalid termination */
	return 0;
}

int int_substrtoul(const char *str, unsigned long *val, const char *valid_terms)
{
	long tmp;
	if(!int_substrtol(str, &tmp, valid_terms) || (tmp < 0))
		return 0;
	*val = tmp;
	return 1;
}

/* TODO: This could probably be reviewed. Apart from being incomplete, I
 * wouldn't be surprised if there were "unexpected behaviour conditions". */
char *util_parse_escaped_string(const char *str_toconvert)
{
	char *toreturn, *dest;
	int ctrl = 0;

	/* Duplicate the input string */
	SYS_strdup(&toreturn, str_toconvert);
	if(!toreturn) return NULL;
	dest = toreturn;
	/* Iterate across the input string and output strings in a
	 * state-machine to handle control-characters. */
	while(*str_toconvert) {
		if(!ctrl) {
			/* We're not in escaped mode, what's the next char? */
			if(*str_toconvert != '\\')
				/* A "normal" character */
				*(dest++) = *str_toconvert;
			else
				/* A "\" escape character, switch mode */
				ctrl = 1;
		} else {
			/* We're in escaped mode, check what has been escaped */
			switch(*str_toconvert) {
			case 'r':
				*(dest++) = '\r'; break;
			case 'n':
				*(dest++) = '\n'; break;
			default:
				/* If the control command isn't recognised, we
				 * literally translate "\x" into "x". */
				*(dest++) = *str_toconvert;
			}
			/* We're no longer in escaped mode */
			ctrl = 0;
		}
		/* In all cases, we increment our "source" string pointer. What
		 * we do with our "destination" string pointer varies and is
		 * handled (above) case-by-case. */
		str_toconvert++;
	}
	/* NULL-terminate the output string. */
	*dest = 0;
	return toreturn;
}

int util_parse_sslmeth(const char *str_toconvert, swamp_sslmeth *val)
{
	if(!strcmp(str_toconvert, "normal"))
		*val = SWAMP_SSLMETH_NORMAL;
	else if(!strcmp(str_toconvert, "sslv2"))
		*val = SWAMP_SSLMETH_SSLv2;
	else if(!strcmp(str_toconvert, "sslv3"))
		*val = SWAMP_SSLMETH_SSLv3;
	else if(!strcmp(str_toconvert, "tlsv1"))
		*val = SWAMP_SSLMETH_TLSv1;
	else
		return 0;
	return 1;
}
