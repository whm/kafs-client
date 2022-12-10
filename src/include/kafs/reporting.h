/*
 * Error reporting context.
 *
 * Copyright (C) David Howells (dhowells@redhat.com) 2018
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _KAFS_REPORTING_H
#define _KAFS_REPORTING_H

struct kafs_report {
	void (*error)(const char *fmt, ...)
		__attribute__((format(printf, 1, 2)));
	void (*verbose)(const char *fmt, ...)
		__attribute__((format(printf, 1, 2)));
	void (*verbose2)(const char *fmt, ...)
		__attribute__((format(printf, 1, 2)));
	const char	*what;
	int		line;
	bool		bad_config;	/* T if bad config encountered */
	bool		bad_error;	/* T if fatal system error encountered */
	bool		abandon_alloc;	/* T to not clean up on error */
};

#endif /* _KAFS_REPORTING_H */
