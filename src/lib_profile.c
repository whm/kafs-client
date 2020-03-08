/*
 * Kerberos-style profile file parser.
 *
 * Copyright (C) David Howells (dhowells@redhat.com) 2018
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <kafs/profile.h>

#define report_error(r, fmt, ...)					\
	({								\
		r->error(fmt, ## __VA_ARGS__);				\
		-1;							\
	})

#define parse_error(r, fmt, ...)					\
	({								\
		r->bad_config = true;					\
		r->error("%s:%u: " fmt, r->what, r->line, ## __VA_ARGS__); \
		-1;							\
	})

/*
 * Dump a profile to stdout in tree form.
 */
void kafs_profile_dump(const struct kafs_profile *p, unsigned int depth)
{
	unsigned int i;

	if (p->type == kafs_profile_value_is_list) {
		printf("%*s [*] '%s'%s\n",
		       depth, "",
		       p->name,
		       p->final ? " [final]" : "");
		for (i = 0; i < p->nr_relations; i++)
			kafs_profile_dump(p->relations[i], depth + 2);
	} else {
		printf("%*s [=] '%s' = '%s'\n", depth, "", p->name, p->value);
	}
}

/*
 * Find/create relation in the list to which we're contributing.
 *
 * If a list relation is already closed then it is replaced unless it is final,
 * in which case the new stuff is ignored.
 */
static struct kafs_profile *kafs_profile_get_relation(struct kafs_profile *parent,
						      char *name,
						      enum kafs_profile_value_type type,
						      struct kafs_report *report)
{
	struct kafs_profile *r, **list = parent->relations;
	bool dummy = false;
	int i, n = parent->nr_relations;

	if (parent->type != kafs_profile_value_is_list) {
		report->error("%s:%u: Can't insert into a non-list",
			      report->what, report->line);
		return NULL;
	}

	if (type == kafs_profile_value_is_list) {
		for (i = 0; i < n; i++) {
			r = list[i];
			if (r->type != kafs_profile_value_is_list ||
			    strcmp(r->name, name) != 0)
				continue;

			if (r->final) {
				dummy = true;
				goto create;
			}

			r->final |= parent->final;
			return r;
		}
	}

create:
	r = malloc(sizeof(*r));
	if (!r)
		return NULL;

	memset(r, 0, sizeof(*r));
	r->type = type;
	r->name = name;
	r->parent = parent;
	r->dummy = dummy | parent->final | parent->dummy;

	if (!r->dummy) {
		list = realloc(list, sizeof(*list) * (n + 1));
		if (!list)
			return NULL;

		list[n] = r;
		parent->relations = list;
		parent->nr_relations = n + 1;
	}

	return r;
}

/*
 * Parse the contents of a kafs_profile file.
 */
static int kafs_profile_parse_content(struct kafs_profile *prof, const char *file,
				      char *p, char *end,
				      struct kafs_report *report)
{
	struct kafs_profile *section = NULL, *list = NULL, *tmp;
	unsigned int line = 0;
	char *eol, *next_line = p, *key, *value;
	bool at_left;

next_line:
	p = next_line;
	line++;
	report->line = line;
	at_left = p < end && !isblank(*p);
	while (p < end && isblank(*p)) p++;
	if (p == end)
		return 0;
	eol = strpbrk(p, "\n\r");
	if (!eol) {
		next_line = eol = end;
	} else {
		next_line = eol + 1;
		if (next_line < end && *next_line != *eol &&
		    (*next_line == '\n' || *next_line == '\r'))
			next_line++; /* handle CRLF and LFCR */
		while (eol > p && isblank(eol[-1]))
			eol--;
		*eol = 0;
	}

	if (!*p || p[0] == '#' || p[0] == ';')
		goto next_line;

	/* Deal with section markers. */
	if (list == section && p[0] == '[') {
		if (eol - p < 3 || eol[-1] != ']')
			return parse_error(report, "Bad section label");
		p++;
		eol--;
		*eol = 0;
		if (strchr(p, ']'))
			return parse_error(report, "Bad section label");

		section = kafs_profile_get_relation(prof, p, kafs_profile_value_is_list,
						    report);
		if (!section)
			return -1;
		section->file = file;
		section->line = line;
		list = section;
		goto next_line;
	}

	/* Things before the first section are either comments or inclusion
	 * directives.
	 */
	if (!section) {
		if (!at_left || strncmp(p, "include", 7) != 0)
			goto next_line;
		p += 7;

		if (isblank(*p)) {
			/* It's an include directive */
			while (*p && isblank(*p)) p++;
			if (!*p)
				return parse_error(report, "No include path");

			if (kafs_profile_parse_file(prof, p, report) < 0)
				return -1;
		}

		if (strncmp(p, "dir", 3) == 0 && (isblank(p[3]) || !p[3])) {
			/* It's an includedir directive */
			p += 3;
			while (*p && isblank(*p)) p++;
			if (!*p)
				return parse_error(report, "No includedir path");

			if (kafs_profile_parse_dir(prof, p, report) < 0)
				return -1;
		}

		goto next_line;
	}

	/* Deal with the closure of a list */
	if (p[0] == '}') {
		if (list == section)
			return parse_error(report, "Unmatched '}'");
		p++;
		if (p[0] == '*') {
			list->final = true;
			p++;
		}
		if (*p)
			return parse_error(report, "Unexpected stuff after '}'");

		tmp = list;
		list = list->parent;
		if (tmp->dummy)
			free(tmp);
		goto next_line;
	}

	/* Everything else should be a relation specifier of one of the
	 * following forms:
	 *
	 *	x = y
	 *	x = { .. }
	 */
	key = p;
	p = strchr(p, '=');
	if (!p)
		return parse_error(report, "Missing '=' in relation");
	if (p == key)
		return parse_error(report, "Anonymous key in relation");

	value = p + 1;
	while (value < eol && isblank(*value)) value++;
	p--;
	while (p > key && isblank(p[-1]))
		p--;
	*p = 0;

	/* Handle the opening of a new list-type relation */
	if (value[0] == '{') {
		if (value[1])
			return parse_error(report, "Unexpected stuff after '{'");

		list = kafs_profile_get_relation(list, key, kafs_profile_value_is_list,
						 report);
		if (!list)
			return -1;
		list->file = file;
		list->line = line;
		goto next_line;
	}

	/* Handle a relation with a quoted-string value */
	if (value[0] == '"') {
		char *q;

		value++;
		if (eol <= value || eol[-1] != '"')
			return parse_error(report, "Unterminated string");
		eol--;
		eol[0] = 0;

		/* Substitute for all the escape chars in place */
		for (p = q = value; p < eol;) {
			char ch = *p++;
			if (ch == '\\') {
				if (p >= eol)
					return parse_error(report, "Uncompleted '\\' escape");

				ch = *p++;
				switch (ch) {
				case 'n': ch = '\n'; break;
				case 't': ch = '\t'; break;
				case 'b': ch = '\b'; break;
				}
			}
			*q++ = ch;
		}

		*q = 0;
	}

	tmp = kafs_profile_get_relation(list, key, kafs_profile_value_is_string, report);
	if (!tmp)
		return -1;
	tmp->file = file;
	tmp->line = line;
	tmp->value = value;
	goto next_line;
}

/*
 * Parse a kafs_profile file.
 */
int kafs_profile_parse_file(struct kafs_profile *prof, const char *file,
			    struct kafs_report *report)
{
	const char *old_file = report->what;
	struct stat st;
	ssize_t n;
	char *buffer;
	int fd, ret;

	report->what = file;
	fd = open(file, O_RDONLY);
	if (fd == -1)
		return -1;

	if (fstat(fd, &st) == -1) {
		close(fd);
		return -1;
	}

	buffer = malloc(st.st_size + 1);
	if (!buffer) {
		close(fd);
		return -1;
	}

	n = read(fd, buffer, st.st_size);
	close(fd);
	if (n == -1) {
		free(buffer);
		return -1;
	}
	buffer[n] = 0;

	ret = kafs_profile_parse_content(prof, file, buffer, buffer + n, report);
	if (ret == 0)
		report->what = old_file;
	return ret;
}

/*
 * Parse a kafs_profile directory.
 */
int kafs_profile_parse_dir(struct kafs_profile *prof,
			   const char *dirname,
			   struct kafs_report *report)
{
	const char *old_file = report->what;
	struct dirent *de;
	char *filename;
	DIR *dir;
	int ret, n;

	report->what = dirname;
	report->line = 0;
	dir = opendir(dirname);
	if (!dir)
		return report_error(report, "%s: %m", dirname);

	while (errno = 0,
	       (de = readdir(dir))) {
		if (de->d_name[0] == '.')
			continue;
		n = strlen(de->d_name);
		if (n < 1 || de->d_name[n - 1] == '~')
			continue;

		if (asprintf(&filename, "%s/%s", dirname, de->d_name) == -1) {
			closedir(dir);
			return report_error(report, "%m");
		}

		ret = kafs_profile_parse_file(prof, filename, report);
		if (ret < 0) {
			closedir(dir);
			return -1;
		}
	}

	report->what = dirname;
	closedir(dir);
	if (errno != 0)
		return -1;
	report->what = old_file;
	return 0;
}

/*
 * Find the first child object of a type and name in the list attached to the
 * given object.
 */
const struct kafs_profile *kafs_profile_find_first_child(const struct kafs_profile *prof,
							 enum kafs_profile_value_type type,
							 const char *name,
							 struct kafs_report *report)
{
	unsigned int i;

	if (prof->type != kafs_profile_value_is_list) {
		report_error(report, "Trying to find '%s' in relation '%s'",
			     name, prof->name);
		return NULL;
	}

	for (i = 0; i < prof->nr_relations; i++) {
		const struct kafs_profile *r = prof->relations[i];

		if (r->type == type &&
		    strcmp(r->name, name) == 0)
			return r;
	}

	return NULL;
}

/*
 * Iterate over all the child objects of the given type and name in the list
 * attached to the given object until the iterator function returns non-zero.
 */
int kafs_profile_iterate(const struct kafs_profile *prof,
			 enum kafs_profile_value_type type,
			 const char *name,
			 kafs_profile_iterator iterator,
			 void *data,
			 struct kafs_report *report)
{
	unsigned int i;
	int ret;

	if (prof->type != kafs_profile_value_is_list) {
		report_error(report, "Trying to iterate over relation '%s'",
			     prof->name);
		return -1;
	}

	for (i = 0; i < prof->nr_relations; i++) {
		const struct kafs_profile *r = prof->relations[i];

		if (r->type != type)
			continue;
		if (name && strcmp(r->name, name) != 0)
			continue;
		ret = iterator(r, data, report);
		if (ret)
			return ret;
	}

	return 0;
}

static int kafs_count_objects(const struct kafs_profile *child,
			      void *data,
			      struct kafs_report *report)
{
	unsigned int *_nr = data;

	*_nr += 1;
	return 0;
}

/*
 * Count the number of matching children of an object.
 */
int kafs_profile_count(const struct kafs_profile *prof,
		       enum kafs_profile_value_type type,
		       const char *name,
		       unsigned int *_nr)
{
	return kafs_profile_iterate(prof, type, NULL, kafs_count_objects, _nr, NULL);
}

static int cmp_constant(const void *name, const void *entry)
{
	const struct kafs_constant_table *e = entry;
	return strcasecmp(name, e->name);
}

/*
 * Turn a string into a constant.
 */
int kafs_lookup_constant2(const struct kafs_constant_table *tbl, size_t tbl_size,
			  const char *name, int not_found)
{
	const struct kafs_constant_table *e;

	e = bsearch(name, tbl, tbl_size, sizeof(tbl[0]), cmp_constant);
	if (!e)
		return not_found;
	return e->value;
}

static const struct kafs_constant_table bool_names[] = {
	{ "0",		false },
	{ "1",		true },
	{ "f",		false },
	{ "false",	false },
	{ "n",		false },
	{ "no",		false },
	{ "off",	false },
	{ "on",		true },
	{ "t",		true },
	{ "true",	true },
	{ "y",		true },
	{ "yes",	true },
};

/*
 * Parse a string as a bool constant.
 */
int kafs_lookup_bool(const char *name, int not_found)
{
	return kafs_lookup_constant(bool_names, name, not_found);
}
