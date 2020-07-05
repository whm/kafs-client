/*
 * Generate a v1 servers and addresses list.
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
#include "dns_afsdb.h"
#include "dns_resolver.h"

static void store_u8(unsigned char **_b, unsigned char n)
{
	*(*_b)++ = n;
}

static void store_u16(unsigned char **_b, unsigned short n)
{
	*(*_b)++ = (n >>  0) & 0xff;
	*(*_b)++ = (n >>  8) & 0xff;
}

static void store_octets(unsigned char **_b, const void *p, size_t n)
{
	memcpy(*_b, p, n);
	*_b += n;
}

/*
 * Generate the payload to pass to the kernel as v1 server bundle.
 */
static void emit_v1(unsigned char **_b, struct kafs_server_list *vls)
{
	struct kafs_server_addr *addr;
	struct kafs_server *server;
	unsigned int i, j, n;

	store_u8 (_b, 0); /* It's not a string */
	store_u8 (_b, DNS_PAYLOAD_IS_SERVER_LIST);
	store_u8 (_b, 1); /* Encoding version */
	store_u8 (_b, vls->source);
	store_u8 (_b, vls->status);
	store_u8 (_b, vls->nr_servers);

	for (i = 0; i < vls->nr_servers; i++) {
		server = &vls->servers[i];

		n = strlen(server->name);
		store_u16(_b, n);
		store_u16(_b, server->pref);
		store_u16(_b, server->weight);
		store_u16(_b, server->port);
		store_u8 (_b, server->source);
		store_u8 (_b, server->status);
		store_u8 (_b, server->protocol);
		store_u8 (_b, server->nr_addrs);
		store_octets(_b, server->name, n);

		for (j = 0; j < server->nr_addrs; j++) {
			addr = &server->addrs[j];

			switch (addr->sin.sin_family) {
			case AF_INET:
				store_u8(_b, DNS_ADDRESS_IS_IPV4);
				store_octets(_b, &addr->sin.sin_addr, 4);
				break;
			case AF_INET6:
				store_u8(_b, DNS_ADDRESS_IS_IPV6);
				store_octets(_b, &addr->sin6.sin6_addr, 16);
				break;
			default:
				store_u8(_b, 0);
				continue;
			}
		}
	}
}

void *kafs_generate_v1_payload(void *result,
			       const char *cell_name,
			       unsigned int *_ttl,
			       struct kafs_lookup_context *ctx)
{
	struct kafs_cell *cell;
	unsigned char *b = result;

	ctx->report.what = cell_name;
	cell = kafs_lookup_cell(cell_name, ctx);
	if (!cell)
		return NULL;

	if (_ttl)
		*_ttl = cell->vlservers->ttl;
	if (cell->vlservers)
		emit_v1(&b, cell->vlservers);
	return b;
}
