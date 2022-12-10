/*
 * Build a cell VL address set based on DNS records.
 *
 * Copyright (C) Wang Lei (wang840925@gmail.com) 2010
 * Authors: Wang Lei (wang840925@gmail.com)
 *
 * Copyright (C) David Howells (dhowells@redhat.com) 2018
 *
 * This is a userspace tool for querying AFSDB RR records in the DNS on behalf
 * of the kernel, and converting the VL server addresses to IPv4 format so that
 * they can be used by the kAFS filesystem.
 *
 * As some function like res_init() should use the static liberary, which is a
 * bug of libresolv, that is the reason for cifs.upcall to reimplement.
 *
 * To use this program, you must tell /sbin/request-key how to invoke it.  You
 * need to have the keyutils package installed and something like the following
 * lines added to your /etc/request-key.conf file:
 *
 * 	#OP    TYPE         DESCRIPTION CALLOUT INFO PROGRAM ARG1 ARG2 ARG3 ...
 * 	====== ============ =========== ============ ==========================
 * 	create dns_resolver afsdb:*     *            /sbin/key.dns_resolver %k
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <resolv.h>
#include <netdb.h>
#include <errno.h>
#include <sys/socket.h>
#include <kafs/cellserv.h>
#include "dns_resolver.h"

#define AFS_VL_PORT		7003	/* volume location service port */

#define verbose(fmt, ...)							\
	do {								\
		if (ctx->report.verbose)				\
			ctx->report.verbose(fmt, ## __VA_ARGS__);	\
	} while(0)

/*
 * Perform address resolution on a hostname and add the resulting address as a
 * string to the list of payload segments.
 */
static int kafs_resolve_addrs(struct kafs_server *server,
			      int socktype,
			      struct kafs_lookup_context *ctx)
{
	struct kafs_server_addr *addr;
	struct addrinfo hints, *addrs, *ai;
	int ret, count = 0;

	verbose("Resolve '%s'", server->name);

	server->source = kafs_record_from_nss;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = socktype;
	if (ctx->want_ipv4_addrs && !ctx->want_ipv6_addrs)
		hints.ai_family = AF_INET;
	else if (ctx->want_ipv6_addrs && !ctx->want_ipv4_addrs)
		hints.ai_family = AF_INET6;

	/* resolve name to ip */
	ret = getaddrinfo(server->name, NULL, &hints, &addrs);
	if (ret) {
		verbose("%s: getaddrinfo() = %d", server->name, ret);
		switch (ret) {
		case EAI_MEMORY:
		case EAI_SYSTEM:
			ctx->report.error("%s: getaddrinfo(): %m", server->name);
			goto system_error;
		case EAI_FAMILY:
		case EAI_SOCKTYPE:
			ctx->report.bad_error = true;
			server->status = kafs_lookup_got_local_failure;
			goto fail;
		default:
			server->status = kafs_lookup_got_local_failure;
			/* Fall through. */
		fail:
			ctx->report.error("%s: %s", server->name, gai_strerror(ret));
			return 0;
		case EAI_FAIL:
#ifdef EAI_NODATA
		case EAI_NODATA:
#endif
		case EAI_NONAME:
		case EAI_SERVICE:
			server->status = kafs_lookup_got_not_found;
			goto fail;
		case EAI_AGAIN:
			server->status = kafs_lookup_got_temp_failure;
			goto fail;
		}
	}

	for (ai = addrs; ai; ai = ai->ai_next)
		count++;

	server->addrs = calloc(count, sizeof(*addr));
	if (!server->addrs) {
		ctx->report.error("%m");
		goto system_error;
	}

	server->max_addrs = count;
	server->source = kafs_record_from_nss;
	server->status = kafs_lookup_good;

	for (ai = addrs; ai; ai = ai->ai_next) {
		addr = &server->addrs[server->nr_addrs];

		verbose("RR: %x,%x,%x,%x,%x,%s",
			ai->ai_flags, ai->ai_family,
			ai->ai_socktype, ai->ai_protocol,
			ai->ai_addrlen, ai->ai_canonname);

		/* convert address to string */
		switch (ai->ai_family) {
		case AF_INET:
			if (!ctx->want_ipv4_addrs)
				continue;
			memcpy(&addr->sin, (struct sockaddr_in *)ai->ai_addr,
			       sizeof(addr->sin));
			server->nr_addrs++;
			break;
		case AF_INET6:
			if (!ctx->want_ipv6_addrs)
				continue;
			memcpy(&addr->sin6, (struct sockaddr_in *)ai->ai_addr,
			       sizeof(addr->sin6));
			server->nr_addrs++;
			break;
		default:
			verbose("Address of unknown family %u", ai->ai_family);
			continue;
		}
	}

	freeaddrinfo(addrs);
	return 0;

system_error:
	ctx->report.bad_error = true;
	return -1;
}

/*
 * Go through all the servers records and look up addresses for them.
 */
int kafs_dns_lookup_addresses(struct kafs_server_list *ss,
			      struct kafs_lookup_context *ctx)
{
	struct kafs_server *server;
	unsigned int i;
	int ret;

	if (ss) {
		verbose("NR_SERVERS %u", ss->nr_servers);

		if (ctx->no_vl_host) {
			verbose("Use of DNS for FS server lookup is disabled.");
			return 0;
		}

		for (i = 0; i < ss->nr_servers; i++) {
			server = &ss->servers[i];

			/* Turn the hostname into IP addresses */
			ret = kafs_resolve_addrs(server, SOCK_DGRAM, ctx);
			if (ret)
				verbose("AFSDB RR can't resolve. subtype:1, server name:%s",
					server->name);
			else
				verbose("NR_ADDRS %u", server->nr_addrs);
		}
	}

	return 0;
}

/*
 * Convert the outcome of an AFSDB record lookup into a set of server records.
 */
static int kafs_parse_afsdb(struct kafs_server_list *vsl,
			    const char *cell_name,
			    unsigned short subtype,
			    ns_msg handle,
			    ns_sect section,
			    struct kafs_lookup_context *ctx)
{
	struct kafs_server *server;
	unsigned int rr_ttl, max_servers = 0, i;
	ns_rr rr;
	char buf[MAXDNAME];
	int rrnum, rr_subtype;

	verbose("AFSDB RR count is %d", ns_msg_count(handle, section));

	/* Count the number of afsdb records */
	for (rrnum = 0; rrnum < ns_msg_count(handle, section); rrnum++) {
		if (ns_parserr(&handle, section, rrnum, &rr)) {
			ctx->report.error("%s: afsdb parse failed", cell_name);
			continue;
		}

		if (ns_rr_type(rr) != ns_t_afsdb)
			continue;
		rr_subtype = ns_get16(ns_rr_rdata(rr));
		if (rr_subtype != subtype)
			continue;
		max_servers++;
	}

	verbose("NR_SERVER %u", max_servers);

	vsl->max_servers = max_servers;
	vsl->servers = calloc(max_servers, sizeof(struct kafs_server));
	if (!vsl->servers)
		goto system_error;

	/* Look at all the resource records in this section. */
	for (rrnum = 0; rrnum < ns_msg_count(handle, section); rrnum++) {
		server = &vsl->servers[vsl->nr_servers];

		/* Expand the resource record number rrnum into rr. */
		if (ns_parserr(&handle, section, rrnum, &rr)) {
			ctx->report.error("%s: afsdb parse failed", cell_name);
			vsl->status = kafs_lookup_bad;
			continue;
		}

		/* We're only interested in AFSDB records */
		if (ns_rr_type(rr) != ns_t_afsdb)
			continue;
		rr_subtype = ns_get16(ns_rr_rdata(rr));
		if (rr_subtype != subtype)
			continue;

		/* Expand the name server's domain name */
		if (ns_name_uncompress(ns_msg_base(handle),
				       ns_msg_end(handle),
				       ns_rr_rdata(rr) + 2,
				       buf,
				       MAXDNAME) < 0) {
			ctx->report.error("%s: afsdb uncompress failed", cell_name);
			vsl->status = kafs_lookup_bad;
			continue;
		}

		rr_ttl = ns_rr_ttl(rr);
		if (vsl->ttl > rr_ttl)
			vsl->ttl = rr_ttl;

		/* Check the domain name we've just unpacked and add it to
		 * the list of VL servers if it is not a duplicate.
		 * If it is a duplicate, just ignore it.
		 */
		for (i = 0; i < vsl->nr_servers; i++)
			if (strcasecmp(buf, vsl->servers[i].name) == 0)
				continue;

		server->name = strdup(buf);
		if (!server->name)
			goto system_error;
		server->port = AFS_VL_PORT;
		server->protocol = DNS_SERVER_PROTOCOL_UDP;

		verbose("SERVER[%u] %s", vsl->nr_servers, server->name);
		vsl->nr_servers++;
	}

	if (vsl->nr_servers > 0 && vsl->status == kafs_lookup_bad)
		vsl->status = kafs_lookup_good_with_bad;
	if (vsl->nr_servers == 0 && vsl->status == kafs_lookup_good_with_bad)
		vsl->status = kafs_lookup_got_not_found;

	return 0;

system_error:
	ctx->report.bad_error = true;
	ctx->report.error("%m");
	return -1;
}

/*
 * Look up an AFSDB record to get the VL server addresses.
 */
static int dns_query_AFSDB(struct kafs_server_list *vsl,
			   const char *cell_name,
			   unsigned short subtype,
			   struct kafs_lookup_context *ctx)
{
	int	response_len;		/* buffer length */
	ns_msg	handle;			/* handle for response message */
	union {
		HEADER hdr;
		u_char buf[NS_PACKETSZ];
	} response;		/* response buffers */

	verbose("Get AFSDB RR for cell name:'%s'", cell_name);

	/* query the dns for an AFSDB resource record */
	response_len = res_nquery(&ctx->res,
				  cell_name,
				  ns_c_in,
				  ns_t_afsdb,
				  response.buf,
				  sizeof(response));

	if (response_len < 0) {
		ctx->report.error("%s: %s", cell_name, hstrerror(h_errno));
		switch (h_errno) {
		case HOST_NOT_FOUND:
		case NO_DATA:
		default:
			vsl->status = kafs_lookup_got_not_found;
			break;
		case NO_RECOVERY:
			vsl->status = kafs_lookup_got_ns_failure;
			break;
		case TRY_AGAIN:
			vsl->status = kafs_lookup_got_temp_failure;
			break;
		}
		return 0;
	}

	vsl->source = kafs_record_from_dns_afsdb;

	if (ns_initparse(response.buf, response_len, &handle) < 0) {
		ctx->report.error("%s: ns_initparse: %s",
				  cell_name, hstrerror(h_errno));
		vsl->status = kafs_lookup_bad;
		return 0;
	}

	/* look up the hostnames we've obtained to get the actual addresses */
	vsl->status = kafs_lookup_good;
	return kafs_parse_afsdb(vsl, cell_name, subtype, handle, ns_s_an, ctx);
}

/*
 * Convert the outcome of an SRV record lookup into a set of server records.
 */
static int kafs_parse_srv(struct kafs_server_list *vsl,
			  const char *domain_name,
			  ns_msg handle,
			  ns_sect section,
			  enum dns_payload_protocol_type protocol,
			  struct kafs_lookup_context *ctx)
{
	struct kafs_server *server;
	unsigned int max_servers = 0, rr_ttl, i;
	ns_rr rr;
	char buf[MAXDNAME];
	int rrnum;

	verbose("SRV RR count is %d", ns_msg_count(handle, section));

	/* Count the number of srv records */
	for (rrnum = 0; rrnum < ns_msg_count(handle, section); rrnum++) {
		if (ns_parserr(&handle, section, rrnum, &rr)) {
			ctx->report.error("%s: ns_parserr", domain_name);
			continue;
		}

		if (ns_rr_type(rr) != ns_t_srv)
			continue;
		max_servers++;
	}

	verbose("NR_SERVER %u", max_servers);

	vsl->max_servers = max_servers;
	vsl->servers = calloc(max_servers, sizeof(struct kafs_server));
	if (!vsl->servers)
		goto system_error;

	for (rrnum = 0; rrnum < ns_msg_count(handle, section); rrnum++) {
		server = &vsl->servers[vsl->nr_servers];

		/* Expand the resource record number rrnum into rr. */
		if (ns_parserr(&handle, section, rrnum, &rr)) {
			ctx->report.error("%s: ns_parserr", domain_name);
			vsl->status = kafs_lookup_bad;
			continue;
		}

		if (ns_rr_type(rr) != ns_t_srv)
			continue;

		ns_get16(ns_rr_rdata(rr)); /* subtype */

		/* Expand the name server's domain name */
		if (ns_name_uncompress(ns_msg_base(handle),
				       ns_msg_end(handle),
				       ns_rr_rdata(rr) + 6,
				       buf,
				       MAXDNAME) < 0) {
			ctx->report.error("%s: ns_name_uncompress", domain_name);
			vsl->status = kafs_lookup_bad;
			continue;
		}

		rr_ttl = ns_rr_ttl(rr);
		if (vsl->ttl > rr_ttl)
			vsl->ttl = rr_ttl;

		server->pref   = ns_get16(ns_rr_rdata(rr));
		server->weight = ns_get16(ns_rr_rdata(rr) + 2);
		server->port   = ns_get16(ns_rr_rdata(rr) + 4);
		verbose("rdata %u %u %u", server->pref, server->weight, server->port);

		/* Check the domain name we've just unpacked and add it to
		 * the list of VL servers if it is not a duplicate.
		 * If it is a duplicate, just ignore it.
		 */
		for (i = 0; i < vsl->nr_servers; i++)
			if (strcasecmp(buf, vsl->servers[i].name) == 0)
				continue;

		server->name = strdup(buf);
		if (!server->name)
			goto system_error;
		server->port = AFS_VL_PORT;
		server->protocol = protocol;

		verbose("SERVER[%u] %s", vsl->nr_servers, server->name);
		vsl->nr_servers++;
	}

	if (vsl->nr_servers > 0 && vsl->status == kafs_lookup_bad)
		vsl->status = kafs_lookup_good_with_bad;
	if (vsl->nr_servers == 0 && vsl->status == kafs_lookup_good_with_bad)
		vsl->status = kafs_lookup_got_not_found;

	return 0;

system_error:
	ctx->report.bad_error = true;
	ctx->report.error("%m");
	return -1;
}

/*
 * Look up an SRV record to get the VL server addresses [RFC 5864].
 */
static int dns_query_SRV(struct kafs_server_list *vsl,
			 const char *domain_name,
			 const char *service_name,
			 const char *proto_name,
			 struct kafs_lookup_context *ctx)
{
	int	response_len;		/* buffer length */
	ns_msg	handle;			/* handle for response message */
	union {
		HEADER hdr;
		u_char buf[NS_PACKETSZ];
	} response;
	enum dns_payload_protocol_type protocol;
	char name[1024];

	snprintf(name, sizeof(name), "_%s._%s.%s",
		 service_name, proto_name, domain_name);

	verbose("Get SRV RR for name:'%s'", name);

	response_len = res_nquery(&ctx->res,
				  name,
				  ns_c_in,
				  ns_t_srv,
				  response.buf,
				  sizeof(response));

	if (response_len < 0) {
		ctx->report.error("%s: dns: %s",
				  domain_name, hstrerror(h_errno));
		switch (h_errno) {
		case HOST_NOT_FOUND:
		case NO_DATA:
			vsl->status = kafs_lookup_got_not_found;
			break;
		case NO_RECOVERY:
			vsl->status = kafs_lookup_got_ns_failure;
			break;
		case TRY_AGAIN:
			vsl->status = kafs_lookup_got_temp_failure;
			break;
		}
		return 0;
	}

	vsl->source = kafs_record_from_dns_srv;

	if (ns_initparse(response.buf, response_len, &handle) < 0) {
		ctx->report.error("%s: ns_initparse: %s",
				  domain_name, hstrerror(h_errno));
		vsl->status = kafs_lookup_bad;
		return 0;
	}

	if (strcmp(proto_name, "udp") == 0)
		protocol = DNS_SERVER_PROTOCOL_UDP;
	else if (strcmp(proto_name, "tcp") == 0)
		protocol = DNS_SERVER_PROTOCOL_TCP;
	else
		protocol = DNS_SERVER_PROTOCOL_UNSPECIFIED;

	vsl->status = kafs_lookup_good;
	return kafs_parse_srv(vsl, domain_name, handle, ns_s_an, protocol, ctx);
}

/*
 * Look up a cell by name in the DNS.
 */
int kafs_dns_lookup_vlservers(struct kafs_server_list *vsl,
			      const char *cell_name,
			      struct kafs_lookup_context *ctx)
{
	int ret;

	vsl->status = kafs_lookup_not_done;

	if (!ctx->no_vls_srv) {
		ret = dns_query_SRV(vsl, cell_name, "afs3-vlserver", "udp", ctx);
		if (ret == 0 && vsl->nr_servers > 0)
			return 0;
	} else {
		verbose("Use of DNS/SRV for VL server lookup is disabled.");
	}

	if (!ctx->no_vls_afsdb) {
		ret = dns_query_AFSDB(vsl, cell_name, 1, ctx);
		if (ret == 0 && vsl->nr_servers > 0)
			return 0;
	} else {
		verbose("Use of DNS/AFSDB for VL server lookup is disabled.");
	}

	return 0;
}
