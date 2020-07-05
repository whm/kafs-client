/*
 * Object creation/destruction.
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
#include <string.h>
#include <limits.h>
#include <arpa/inet.h>
#include <kafs/cellserv.h>
#include <kafs/profile.h>

/*
 * Initialise state in a lookup context.
 */
int kafs_init_lookup_context(struct kafs_lookup_context *ctx)
{
	memset(&ctx->res, 0, sizeof(ctx->res));
	if (res_ninit(&ctx->res) < 0) {
		ctx->report.bad_error = true;
		ctx->report.error("%m");
		return -1;
	}
	return 0;
}

/*
 * Clear state in a lookup context.
 */
void kafs_clear_lookup_context(struct kafs_lookup_context *ctx)
{
	res_nclose(&ctx->res);
}

/*
 * Allocate a blank server list.
 */
struct kafs_server_list *kafs_alloc_server_list(struct kafs_report *report)
{
	struct kafs_server_list *sl;

	sl = calloc(1, sizeof(*sl));
	if (!sl) {
		report->bad_error = true;
		report->error("%m");
		return NULL;
	}

	sl->ttl = UINT_MAX;
	return sl;
}

/*
 * Free a server list.
 */
void kafs_free_server_list(struct kafs_server_list *sl)
{
	unsigned int i;

	if (sl->servers) {
		for (i = 0; i < sl->nr_servers; i++) {
			struct kafs_server *s = &sl->servers[i];
			if (!s->borrowed_name)
				free(s->name);
			if (!s->borrowed_addrs)
				free(s->addrs);
		}
		free(sl->servers);
	}

	free(sl);
}

/*
 * Free a cell.
 */
void kafs_free_cell(struct kafs_cell *cell)
{
	if (!cell->borrowed_name)	free(cell->name);
	if (!cell->borrowed_desc)	free(cell->desc);
	if (!cell->borrowed_realm)	free(cell->realm);

	if (cell->vlservers)
		kafs_free_server_list(cell->vlservers);

	free(cell);
}

/*
 * Transfer the addresses from one server to another.
 */
void kafs_transfer_addresses(struct kafs_server *to,
			     const struct kafs_server *from)
{
	to->max_addrs = 0;
	to->nr_addrs = from->nr_addrs;
	to->addrs = from->addrs;
	to->borrowed_addrs = true;
}

/*
 * Transfer the list of servers from one server list to another.
 */
int kafs_transfer_server_list(struct kafs_server_list *to,
			      const struct kafs_server_list *from)
{
	unsigned int i, nr = from->nr_servers;

	to->source = from->source;
	to->status = from->status;
	to->nr_servers = nr;
	to->max_servers = from->max_servers;
	to->ttl = from->ttl;

	if (nr == 0) {
		to->servers = NULL;
		return 0;
	}

	to->servers = malloc(nr * sizeof(struct kafs_server));
	if (!to->servers)
		return -1;

	memcpy(to->servers, from->servers, nr * sizeof(struct kafs_server));
	for (i = 0; i < nr; i++) {
		struct kafs_server *s = &to->servers[i];

		s->borrowed_name = true;
		s->max_addrs = 0;
		s->nr_addrs = 0;
		s->addrs = NULL;
	}

	return 0;
}

/*
 * Transfer information from one cell record to another.
 */
void kafs_transfer_cell(struct kafs_cell *to, const struct kafs_cell *from)
{
	if (!to->name) {
		to->name = from->name;
		to->borrowed_name = true;
	}

	if (from->desc) {
		to->desc = from->desc;
		to->borrowed_desc = true;
	}

	if (from->realm) {
		to->realm = from->realm;
		to->borrowed_realm = true;
	}

	to->use_dns = from->use_dns;
	to->show_cell = from->show_cell;
}
