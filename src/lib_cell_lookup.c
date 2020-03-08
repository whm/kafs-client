/*
 * Cell database access.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <resolv.h>
#include <netdb.h>
#include <errno.h>
#include <kafs/cellserv.h>
#include <kafs/profile.h>

static const char *const kafs_std_config[] = {
	ETCDIR "/kafs/client.conf",
	NULL
};

struct kafs_profile kafs_config_profile = { .name = "<kafsconfig>" };
struct kafs_cell_db *kafs_cellserv_db;
const char *kafs_this_cell;
const char *kafs_sysname;

#define verbose(r, fmt, ...)						\
	do {								\
		if ((r)->verbose)					\
			(r)->verbose(fmt, ## __VA_ARGS__);		\
	} while(0)

/*
 * Allocate a cell record.
 */
struct kafs_cell *kafs_alloc_cell(const char *cell_name,
				  struct kafs_lookup_context *ctx)
{
	struct kafs_cell *cell;

	cell = calloc(1, sizeof(*cell));
	if (!cell)
		goto error;

	cell->name = strdup(cell_name);
	if (!cell->name)
		goto error;

	return cell;

error:
	ctx->report.error("%m");
	return NULL;
}

/*
 * Read the [defaults] section.
 */
static void kafs_read_defaults(struct kafs_profile *prof, struct kafs_report *report)
{
	const struct kafs_profile *def;
	const char *p;

	def = kafs_profile_find_first_child(prof, kafs_profile_value_is_list, "defaults", report);
	if (!def) {
		verbose(report, "Cannot find [defaults] section");
		return;
	}

	/* Find the current cell name (thiscell = <cellname>) */
	p = kafs_profile_get_string(def, "thiscell", report);
	if (p)
		kafs_this_cell = p;

	/* Find the @sys substitutions (sysname = <sub> <sub> ...) */
	p = kafs_profile_get_string(def, "sysname", report);
	if (p)
		kafs_sysname = p;
}

/*
 * Read the configuration and initialise the cell database.
 */
int kafs_read_config(const char *const *files, struct kafs_report *report)
{

	if (!files)
		files = kafs_std_config;

	for (; *files; files++)
		if (kafs_profile_parse_file(&kafs_config_profile, *files, report) == -1)
			return -1;

	kafs_cellserv_db = kafs_cellserv_parse_conf(&kafs_config_profile, report);
	if (!kafs_cellserv_db)
		return -1;

	kafs_read_defaults(&kafs_config_profile, report);
	return 0;
}

/*
 * Deal with an unconfigured cell.
 */
static int kafs_unconfigured_cell(struct kafs_cell *cell,
				  struct kafs_lookup_context *ctx)
{
	struct kafs_server_list *vsl;

	verbose(&ctx->report, "%s: Cell not found in config", cell->name);

	vsl = kafs_alloc_server_list(&ctx->report);
	if (!vsl)
		return -1;
	cell->vlservers = vsl;

	if (kafs_dns_lookup_vlservers(vsl, cell->name, ctx) < 0 ||
	    kafs_dns_lookup_addresses(vsl, ctx) < 0)
		return -1;

	verbose(&ctx->report, "DNS query AFSDB RR results:%u ttl:%u",
		vsl->nr_servers, vsl->ttl);
	return 0;
}

/*
 * Look up a cell in configuration and DNS.
 *
 * The rules are:
 *
 *  (*) Look up the cell in the configuration first.
 *
 *  (*) If there's no cell in the config, we have to try and build it entirely
 *	from the DNS.
 *
 *  (*) Else:
 *
 *      (*) We look at the configured no_dns setting:
 *
 *	    (*) If true, we use the list of servers listed in the config
 *
 *	    (*) If false, we try to replace that with one derived from the DNS.
 *
 *      (*) For each server:
 *
 *	    (*) we try to look up a list of addresses in NSS/DNS.
 *
 *	    (*) If that fails, we use the list of addresses from the config.
 */
struct kafs_cell *kafs_lookup_cell(const char *cell_name,
				   struct kafs_lookup_context *ctx)
{
	const struct kafs_server_list *cvsl;
	struct kafs_server_list *vsl;
	const struct kafs_cell *conf_cell;
	struct kafs_cell *cell;
	unsigned int i, j;

	if (!kafs_cellserv_db && kafs_read_config(NULL, &ctx->report) < 0)
		return NULL;

	cell = kafs_alloc_cell(cell_name, ctx);
	if (!cell)
		return NULL;

	for (i = 0; i < kafs_cellserv_db->nr_cells; i++) {
		conf_cell = kafs_cellserv_db->cells[i];

		if (strcmp(cell_name, conf_cell->name) == 0)
			goto cell_is_configured;
	}

	if (kafs_unconfigured_cell(cell, ctx) < 0)
		goto error;
	return cell;

	/* Deal with the case where we have a configuration. */
cell_is_configured:
	verbose(&ctx->report, "%s: Found cell in config", cell_name);

	kafs_transfer_cell(cell, conf_cell);

	vsl = kafs_alloc_server_list(&ctx->report);
	if (!vsl)
		goto error;
	cell->vlservers = vsl;

	/* The DNS overrides the configuration if indicated. */
	if (conf_cell->use_dns) {
		verbose(&ctx->report, "Query DNS for server list");
		if (kafs_dns_lookup_vlservers(vsl, cell_name, ctx) < 0)
			goto error;

		verbose(&ctx->report, "Looked up %u VL servers [%s, %s]",
			vsl->nr_servers,
			kafs_lookup_status(vsl->status),
			kafs_record_source(vsl->source));
	}

	/* If we didn't get any servers, copy the server list from the
	 * configuration.
	 */
	if (vsl->nr_servers == 0) {
		verbose(&ctx->report, "Use configured server list");
		if (kafs_transfer_server_list(vsl, conf_cell->vlservers) < 0)
			goto error;
	}

	/* Try and look up addresses for all the servers in the list. */
	if (kafs_dns_lookup_addresses(vsl, ctx) < 0)
		goto error;

	/* Borrow addresses from the config for any server that didn't find any
	 * in the DNS.
	 */
	cvsl = conf_cell->vlservers;
	if (cvsl) {
		for (i = 0; i < vsl->nr_servers; i++) {
			struct kafs_server *srv = &vsl->servers[i];

			if (srv->nr_addrs)
				continue;

			verbose(&ctx->report, "Borrow addresses for '%s'", srv->name);
			for (j = 0; j < cvsl->nr_servers; j++) {
				const struct kafs_server *csrv = &cvsl->servers[j];

				if (strcmp(srv->name, csrv->name) == 0) {
					verbose(&ctx->report, "From '%s' %u",
						csrv->name, csrv->nr_addrs);
					kafs_transfer_addresses(srv, csrv);
					break;
				}
			}
		}
	}

	return cell;

error:
	if (!ctx->report.abandon_alloc)
		kafs_free_cell(cell);
	return NULL;
}
