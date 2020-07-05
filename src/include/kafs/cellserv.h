/*
 * kAFS config and cell database parser.
 *
 * Copyright (C) David Howells (dhowells@redhat.com) 2018
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef _KAFS_CELLSERV_H
#define _KAFS_CELLSERV_H

#include <stdbool.h>
#include <resolv.h>
#include <netinet/in.h>
#include "reporting.h"

struct kafs_profile;
struct kafs_profile_parse;

enum kafs_server_type {
	kafs_server_is_untyped,
	kafs_server_is_afs_vlserver,
	kafs_server_is_afs_ptserver,
};

enum kafs_record_source {
	kafs_record_unavailable,
	kafs_record_from_config,
	kafs_record_from_dns_a,
	kafs_record_from_dns_afsdb,
	kafs_record_from_dns_srv,
	kafs_record_from_nss,
	nr__kafs_record_source
};

enum kafs_lookup_status {
	kafs_lookup_not_done,
	kafs_lookup_good,
	kafs_lookup_good_with_bad,
	kafs_lookup_bad,
	kafs_lookup_got_not_found,
	kafs_lookup_got_local_failure,
	kafs_lookup_got_temp_failure,
	kafs_lookup_got_ns_failure,
	nr__kafs_lookup_status
};

struct kafs_server_addr {
	union {
		struct sockaddr_in	sin;
		struct sockaddr_in6	sin6;
	};
};

struct kafs_server {
	char			*name;
	struct kafs_server_addr	*addrs;
	unsigned int		max_addrs;
	unsigned int		nr_addrs;
	unsigned short		port;
	unsigned short		pref;
	unsigned short		weight;
	unsigned char		protocol;
	bool			borrowed_name;
	bool			borrowed_addrs;
	enum kafs_record_source	source : 8;
	enum kafs_lookup_status	status : 8;
	enum kafs_server_type	type : 8;
};

struct kafs_server_list {
	unsigned int		nr_servers;
	unsigned int		max_servers;
	unsigned int		ttl;
	enum kafs_record_source	source : 8;
	enum kafs_lookup_status	status : 8;
	struct kafs_server	*servers;
};

struct kafs_cell {
	char			*name;
	char			*desc;
	char			*realm;
	bool			use_dns;
	bool			show_cell;
	bool			borrowed_name;
	bool			borrowed_desc;
	bool			borrowed_realm;
	struct kafs_server_list	*vlservers;
};

struct kafs_cell_db {
	unsigned int		nr_cells;
	struct kafs_cell	*cells[];
};

struct kafs_lookup_context {
	struct kafs_report	report;
	struct __res_state	res;
	bool			want_ipv4_addrs;
	bool			want_ipv6_addrs;
	bool			no_vls_afsdb;
	bool			no_vls_srv;
	bool			no_vl_host;
};

/*
 * object.c
 */
extern int kafs_init_lookup_context(struct kafs_lookup_context *ctx);
extern void kafs_clear_lookup_context(struct kafs_lookup_context *ctx);
extern struct kafs_server_list *kafs_alloc_server_list(struct kafs_report *report);
extern void kafs_free_server_list(struct kafs_server_list *sl);
extern void kafs_free_cell(struct kafs_cell *cell);
extern void kafs_transfer_addresses(struct kafs_server *to,
				    const struct kafs_server *from);
extern int kafs_transfer_server_list(struct kafs_server_list *to,
				     const struct kafs_server_list *from);
extern void kafs_transfer_cell(struct kafs_cell *to,
			       const struct kafs_cell *from);

/*
 * cellserv.c
 */
extern struct kafs_cell_db *kafs_cellserv_parse_conf(const struct kafs_profile *prof,
						     struct kafs_report *report);
extern void kafs_cellserv_dump(const struct kafs_cell_db *db);
extern const char *kafs_record_source(enum kafs_record_source source);
extern const char *kafs_lookup_status(enum kafs_lookup_status status);
extern void kafs_dump_cell(const struct kafs_cell *cell);

/*
 * dns_lookup.c
 */
extern int kafs_dns_lookup_addresses(struct kafs_server_list *sl,
				     struct kafs_lookup_context *ctx);
extern int kafs_dns_lookup_vlservers(struct kafs_server_list *vsl,
				     const char *cell_name,
				     struct kafs_lookup_context *ctx);

/*
 * cell_lookup.c
 */
extern struct kafs_profile kafs_config_profile;
extern struct kafs_cell_db *kafs_cellserv_db;
extern const char *kafs_this_cell;
extern const char *kafs_sysname;
extern int kafs_read_config(const char *const *files,
			    struct kafs_report *report);
extern struct kafs_cell *kafs_lookup_cell(const char *cell_name,
					  struct kafs_lookup_context *ctx);

#endif /* _KAFS_CELLSERV_H */
