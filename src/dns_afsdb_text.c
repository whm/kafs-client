/*
 * Generate a set of addresses as a text string.
 *
 * Copyright (C) David Howells (dhowells@redhat.com) 2018
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <kafs/cellserv.h>
#include <arpa/inet.h>
#include "dns_afsdb.h"

static void store_char(char **_b, char n)
{
	*(*_b)++ = n;
}

static void store_string(char **_b, const char *p)
{
	unsigned int len = strlen(p);

	memcpy(*_b, p, len);
	*_b += len;
}

/*
 * Generate the payload to pass to the kernel as v1 server bundle.
 */
static void emit_text_str(char **_b,
			  struct kafs_server_list *vls,
			  unsigned short default_port)
{
	struct kafs_server_addr *addr;
	struct kafs_server *server;
	const char *p;
	unsigned int i, j;
	char buf[100];
	bool need_sep = false;

	for (i = 0; i < vls->nr_servers; i++) {
		server = &vls->servers[i];

		for (j = 0; j < server->nr_addrs; j++) {
			addr = &server->addrs[j];

			if (need_sep)
				store_char(_b, ',');
			need_sep = true;

			switch (addr->sin.sin_family) {
			case AF_INET:
				p = inet_ntop(AF_INET, &addr->sin.sin_addr,
					      buf, sizeof(buf));
				if (p) {
					store_char(_b, '[');
					store_string(_b, buf);
					store_char(_b, ']');
				}
				break;
			case AF_INET6:
				p = inet_ntop(AF_INET6, &addr->sin6.sin6_addr,
					      buf, sizeof(buf));
				if (p) {
					store_char(_b, '[');
					store_string(_b, buf);
					store_char(_b, ']');
				}
				break;
			default:
				continue;
			}

			if (server->port && server->port != default_port) {
				sprintf(buf, "%u", server->port);
				store_char(_b, '+');
				store_string(_b, buf);
			}
		}
	}

	store_char(_b, 0);
}

void *kafs_generate_text_payload(void *result,
				 const char *cell_name,
				 unsigned int *_ttl,
				 struct kafs_lookup_context *ctx)
{
	struct kafs_cell *cell;
	char *b = result;

	ctx->report.what = cell_name;
	cell = kafs_lookup_cell(cell_name, ctx);
	if (!cell)
		return NULL;

	if (cell->vlservers)
		emit_text_str(&b, cell->vlservers, 7003);
	return b;
}
