/*
 * Kerberos-style profile file parser.
 *
 * Copyright (C) 2018 David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _KAFS_PROFILE_H
#define _KAFS_PROFILE_H

#include <stdbool.h>
#include "reporting.h"

enum kafs_profile_value_type {
	kafs_profile_value_is_list,
	kafs_profile_value_is_string,
};

struct kafs_profile {
	enum kafs_profile_value_type type : 8;
	bool			final;
	bool			dummy;
	unsigned int		nr_relations;
	unsigned int		line;
	const char		*file;
	char			*name;
	char			*value;
	struct kafs_profile	*parent;
	struct kafs_profile	**relations;
};

extern void kafs_profile_dump(const struct kafs_profile *p,
			      unsigned int depth);
extern int kafs_profile_parse_file(struct kafs_profile *prof,
				   const char *filename,
				   struct kafs_report *report);
extern int kafs_profile_parse_dir(struct kafs_profile *prof,
				  const char *dirname,
				  struct kafs_report *report);
extern const struct kafs_profile *
kafs_profile_find_first_child(const struct kafs_profile *prof,
			      enum kafs_profile_value_type type,
			      const char *name,
			      struct kafs_report *report);

typedef int (*kafs_profile_iterator)(const struct kafs_profile *child,
				     void *data,
				     struct kafs_report *report);
extern int kafs_profile_iterate(const struct kafs_profile *prof,
				enum kafs_profile_value_type type,
				const char *name,
				kafs_profile_iterator iterator,
				void *data,
				struct kafs_report *report);
extern int kafs_profile_count(const struct kafs_profile *prof,
			      enum kafs_profile_value_type type,
			      const char *name,
			      unsigned int *_nr);

/*
 * Constant matching.
 */
struct kafs_constant_table {
	const char	*name;
	int		value;
};

extern int kafs_lookup_constant2(const struct kafs_constant_table tbl[],
				 size_t tbl_size,
				 const char *name,
				 int not_found);
#define kafs_lookup_constant(t, n, nf) \
	kafs_lookup_constant2(t, sizeof(t)/sizeof(t[0]), (n), (nf))

extern int kafs_lookup_bool(const char *name, int not_found);


/*
 * Convenience relation parsers.
 */
static inline const char *kafs_profile_get_string(const struct kafs_profile *prof,
						  const char *name,
						  struct kafs_report *report)
{
	const struct kafs_profile *p;

	p = kafs_profile_find_first_child(prof, kafs_profile_value_is_string, name,
					  report);

	return p ? p->value : NULL;
}

static inline bool kafs_profile_get_bool(const struct kafs_profile *prof,
					 const char *name,
					 struct kafs_report *report)
{
	const struct kafs_profile *p;
	int tmp;

	p = kafs_profile_find_first_child(prof, kafs_profile_value_is_string, name,
					  report);
	if (!p || !p->value)
		return false;

	tmp = kafs_lookup_bool(p->value, -1);
	if (tmp == -1) {
		report->error("%s:%u: Invalid bool value", p->file, p->line);
		return false;
	}

	return tmp;
}

static inline int kafs_profile_iterate_list(const struct kafs_profile *prof,
					    const char *name,
					    kafs_profile_iterator iterator,
					    void *data,
					    struct kafs_report *report)
{
	return kafs_profile_iterate(prof, kafs_profile_value_is_list,
				    name, iterator, data, report);
}

static inline int kafs_profile_count_list(const struct kafs_profile *prof,
					  const char *name,
					  unsigned int *_nr)
{
	return kafs_profile_count(prof, kafs_profile_value_is_list,
				  name, _nr);
}

static inline int kafs_profile_iterate_strings(const struct kafs_profile *prof,
					       const char *name,
					       kafs_profile_iterator iterator,
					       void *data,
					       struct kafs_report *report)
{
	return kafs_profile_iterate(prof, kafs_profile_value_is_string,
				    name, iterator, data, report);
}

static inline int kafs_profile_count_strings(const struct kafs_profile *prof,
					     const char *name,
					     unsigned int *_nr)
{
	return kafs_profile_count(prof, kafs_profile_value_is_string,
				  name, _nr);
}

#endif /* _KAFS_PROFILE_H */
