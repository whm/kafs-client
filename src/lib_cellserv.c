/*
 * Parse the profile tree into a cell server database
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
#include <arpa/inet.h>
#include <kafs/cellserv.h>
#include <kafs/profile.h>
#include "dns_resolver.h"

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

#define verbose(r, fmt, ...)						\
	do {								\
		if (r->verbose)						\
			r->verbose(fmt, ## __VA_ARGS__);		\
	} while(0)

#define verbose2(r, fmt, ...)						\
	do {								\
		if (r->verbose2)					\
			r->verbose2(fmt, ## __VA_ARGS__);		\
	} while(0)

/*
 * Parse an address.
 */
static int cellserv_parse_address(const struct kafs_profile *child,
				  void *data,
				  struct kafs_report *report)
{
	struct kafs_server *server = data;
	struct kafs_server_addr *addr = &server->addrs[server->nr_addrs];
	const char *v = child->value;

	if (server->nr_addrs >= server->max_addrs) {
		report_error(report, "%s: Address list overrun", server->name);
		return 0;
	}

	if (inet_pton(AF_INET, v, &addr->sin.sin_addr) == 1) {
		addr->sin.sin_family = AF_INET;
		addr->sin.sin_port = htons(server->port);
		server->nr_addrs++;
		return 0;
	}

	if (v[0] == '[') {
		char *p;

		v++;
		p = strchr(v, ']');
		if (!p || p[1])
			goto invalid;
		p[0] = 0;
	}

	if (inet_pton(AF_INET6, v, &addr->sin6.sin6_addr) == 1) {
		addr->sin6.sin6_family = AF_INET6;
		addr->sin6.sin6_port = htons(server->port);
		server->nr_addrs++;
		return 0;
	}

invalid:
	parse_error(report, "%s:%u: Invalid address '%s'",
		    child->file, child->line, child->value);
	return 0;
}

/*
 * Parse a server definition.
 */
static int cellserv_parse_server(const struct kafs_profile *child,
				 void *data,
				 struct kafs_report *report)
{
	struct kafs_server_list *vsl = data;
	struct kafs_server *server = &vsl->servers[vsl->nr_servers];
	unsigned long tmp;
	unsigned int max_addrs = 0;
	const char *p;
	char *q;

	if (vsl->nr_servers >= vsl->max_servers) {
		report_error(report, "%s: Server list overrun", server->name);
		return 0;
	}

	memset(server, 0, sizeof(*server));
	server->source = kafs_record_from_config;

	/* Strip off any protocol indicator */
	server->name = child->name;
	if (strncmp(server->name, "udp/", 4) == 0) {
		server->protocol = DNS_SERVER_PROTOCOL_UDP;
		server->name += 4;
	} else if (strncmp(server->name, "tcp/", 4) == 0) {
		server->protocol = DNS_SERVER_PROTOCOL_TCP;
		server->name += 4;
	}

	if (!server->name[0])
		return 0;

	/* Strip any port number and square brackets */
	if (server->name[0] == '[') {
		server->name++;
		p = strchr(server->name, ']');
		if (!*p)
			return 0;
		*(char *)p = 0;
		p++;
		if (*p) {
			if (*p != ':')
				return 0;
			p++;
			goto extract_port;
		}
	}

	/* Look for foo.com:port or 1.2.3.4:port, but dodge 1:2:3:4 */
	p = strchr(server->name, ':');
	if (!p)
		goto no_port;
	*(char *)p = 0;
	p++;
	if (strchr(p, ':'))
		goto no_port;

extract_port:
	tmp = strtoul(p, &q, 0);
	if (*q)
		goto unparseable;
	if (tmp > 65536)
		goto unparseable;
	server->port = tmp;
no_port:

	p = kafs_profile_get_string(child, "port", report);
	if (p) {
		tmp = strtoul(p, &q, 0);
		if (*q)
			goto unparseable;
		if (tmp > 65536)
			goto unparseable;
		server->port = tmp;
	}

	/* Generate a list of addresses */
	if (kafs_profile_count_strings(child, "address", &max_addrs) < 0)
		return -1;

	server->addrs = calloc(max_addrs, sizeof(struct kafs_server));
	if (!server->addrs)
		return -1;
	server->max_addrs = max_addrs;

	if (kafs_profile_iterate_strings(child, "address",
					 cellserv_parse_address, server,
					 report) < 0)
		return -1;

	p = kafs_profile_get_string(child, "type", report);
	if (p) {
		if (strcmp(p, "vlserver") == 0)
			server->type = kafs_server_is_afs_vlserver;
		else if (strcmp(p, "ptserver") == 0)
			server->type = kafs_server_is_afs_ptserver;
		else
			fprintf(stderr, "Unknown type '%s'\n", p);
	}

	vsl->nr_servers++;
	return 0;

unparseable:
	parse_error(report, "%s:%u: Invalid address\n", child->file, child->line);
	return 0;
}

/*
 * Find any Volume Location servers listed for a cell.
 */
static int kafs_cellserv_parse_vl(const struct kafs_profile *child,
				  struct kafs_cell *cell,
				  struct kafs_report *report)
{
	const struct kafs_profile *servers;
	struct kafs_server_list *vsl;
	unsigned int max_servers = 0;

	/* Find any Volume Location servers listed for that cell */
	servers = kafs_profile_find_first_child(child, kafs_profile_value_is_list,
						"servers", report);
	if (!servers) {
		verbose(report, "%s: No servers list", child->name);
		return 0;
	}

	if (kafs_profile_count_list(servers, NULL, &max_servers) < 0)
		return -1;

	vsl = calloc(1, sizeof(*vsl));
	if (!vsl)
		return -1;
	vsl->source = kafs_record_from_config;

	cell->vlservers = vsl;
	vsl->servers = calloc(max_servers, sizeof(struct kafs_server));
	if (!vsl->servers)
		return -1;

	vsl->max_servers = max_servers;
	return kafs_profile_iterate_list(servers, NULL, cellserv_parse_server,
					 vsl, report);
}

/*
 * Parse a cell definition.
 */
static int kafs_cellserv_parse_cell(const struct kafs_profile *child,
				    void *data,
				    struct kafs_report *report)
{
	struct kafs_cell_db *db = data;
	struct kafs_cell *cell;

	cell = calloc(1, sizeof(*cell));
	if (!cell)
		return -1;
	cell->name = child->name;
	cell->show_cell	= kafs_profile_get_bool(child, "show_cell", report);
	cell->use_dns	= kafs_profile_get_bool(child, "use_dns", report);
	cell->desc	= (char *)kafs_profile_get_string(child, "description", report);
	cell->realm	= (char *)kafs_profile_get_string(child, "kerberos_realm", report);
	cell->borrowed_name = true;
	cell->borrowed_desc = true;
	cell->borrowed_realm = true;

	verbose2(report, "CELL: %s: %s", cell->name, cell->desc);
	db->cells[db->nr_cells] = cell;
	db->nr_cells++;

	return kafs_cellserv_parse_vl(child, cell, report);
}

/*
 * Extract cell information from a kafs_profile parse tree.
 */
struct kafs_cell_db *kafs_cellserv_parse_conf(const struct kafs_profile *prof,
					      struct kafs_report *report)
{
	const struct kafs_profile *cells;
	struct kafs_cell_db *db;
	unsigned int nr_cells = 0;

	cells = kafs_profile_find_first_child(prof, kafs_profile_value_is_list, "cells", report);
	if (!cells) {
		report_error(report, "Cannot find [cells] section");
		return NULL;
	}

	if (kafs_profile_count_list(cells, NULL, &nr_cells) < 0)
		return NULL;

	db = calloc(1, sizeof(*db) + nr_cells * sizeof(struct kafs_cell *));
	if (!db)
		return NULL;
	if (!nr_cells)
		return db;

	if (kafs_profile_iterate_list(cells, NULL,
				      kafs_cellserv_parse_cell, db,
				      report) == -1)
		return NULL;

	return db;
}

static const char *const kafs_record_sources[nr__kafs_record_source] = {
	[kafs_record_unavailable]	= "unavailable",
	[kafs_record_from_config]	= "config",
	[kafs_record_from_dns_a]	= "A",
	[kafs_record_from_dns_afsdb]	= "AFSDB",
	[kafs_record_from_dns_srv]	= "SRV",
	[kafs_record_from_nss]		= "nss",
};

static const char *const kafs_lookup_statuses[nr__kafs_lookup_status] = {
	[kafs_lookup_not_done]		= "no-lookup",
	[kafs_lookup_good]		= "good",
	[kafs_lookup_good_with_bad]	= "good/bad",
	[kafs_lookup_bad]		= "bad",
	[kafs_lookup_got_not_found]	= "not-found",
	[kafs_lookup_got_local_failure]	= "local-failure",
	[kafs_lookup_got_temp_failure]	= "temp-failure",
	[kafs_lookup_got_ns_failure]	= "ns-failure",
};

const char *kafs_record_source(enum kafs_record_source source)
{
	if (source >= nr__kafs_record_source)
		return "unknown";
	return kafs_record_sources[source] ?: "unknown";
}

const char *kafs_lookup_status(enum kafs_lookup_status status)
{
	if (status >= nr__kafs_lookup_status)
		return "unknown";
	return kafs_lookup_statuses[status] ?: "unknown";
}

/*
 * Dump a server set.
 */
void kafs_dump_server_list(const struct kafs_server_list *sl,
			   const char *server_type)
{
	unsigned int j, k;
	const char *p;
	char buf[100];

	for (j = 0; j < sl->nr_servers; j++) {
		const struct kafs_server *srv = &sl->servers[j];

		printf("  - %s %s [%s; %s]\n",
		       server_type, srv->name,
		       kafs_lookup_status(srv->status),
		       kafs_record_source(srv->source));

		if (srv->type)
			printf("    - %s\n",
			       srv->type == kafs_server_is_afs_vlserver ?
			       "VLServer" : "PTServer");
		if (srv->protocol)
			printf("    - %s\n",
			       srv->protocol == DNS_SERVER_PROTOCOL_UDP ? "udp" : "tcp");
		if (srv->port || srv->pref || srv->weight)
			printf("    - port %u, pref %u, weight %u\n",
			       srv->port, srv->pref, srv->weight);

		for (k = 0; k < srv->nr_addrs; k++) {
			const struct kafs_server_addr *addr = &srv->addrs[k];

			switch (addr->sin.sin_family) {
			case AF_INET:
				p = inet_ntop(AF_INET, &addr->sin.sin_addr,
					      buf, sizeof(buf));
				break;
			case AF_INET6:
				p = inet_ntop(AF_INET6, &addr->sin6.sin6_addr,
					      buf, sizeof(buf));
				break;
			default:
				p = NULL;
				break;
			}

			if (p)
				printf("    - address %s\n", p);
		}
	}
}

/*
 * Dump a cell.
 */
void kafs_dump_cell(const struct kafs_cell *cell)
{
	const struct kafs_server_list *vsl = cell->vlservers;

	if (!cell->use_dns)
		printf("  - use-dns=no\n");
	if (!cell->show_cell)
		printf("  - show-cell=no\n");

	if (vsl) {
		printf("  - status: %s, from %s\n",
		       kafs_lookup_status(vsl->status),
		       kafs_record_source(vsl->source));
		kafs_dump_server_list(vsl, "VLSERVER");
	}
}

/*
 * Dump the parsed afs database.
 */
void kafs_cellserv_dump(const struct kafs_cell_db *db)
{
	unsigned int i;

	for (i = 0; i < db->nr_cells; i++) {
		const struct kafs_cell *cell = db->cells[i];

		printf("CELL %s\n", cell->name);
		kafs_dump_cell(cell);
	}
}
