/*
 * DNS Resolver Module User-space Helper for AFSDB records
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
#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <keyutils.h>
#include <sys/mman.h>
#include <kafs/cellserv.h>
#include "dns_afsdb.h"

static const char *DNS_PARSE_VERSION = "2.0";
static const char prog[] = "dns_afsdb";
static const char key_type[] = "dns_resolver";
static const char afsdb_query_type[] = "afsdb:";
static key_serial_t key;
static int debug_mode;
static bool one_addr_only = true;
static unsigned int output_version = 0;

/*
 * Print an error to stderr or the syslog, negate the key being created and
 * exit
 */
void error(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	if (isatty(2)) {
		fputs("E: ", stderr);
		vfprintf(stderr, fmt, va);
		fputc('\n', stderr);
	} else {
		vsyslog(LOG_ERR, fmt, va);
	}
	va_end(va);

	/*
	 * on error, negatively instantiate the key ourselves so that we can
	 * make sure the kernel doesn't hang it off of a searchable keyring
	 * and interfere with the next attempt to instantiate the key.
	 */
	if (!debug_mode)
		keyctl_negate(key, 1, KEY_REQKEY_DEFL_DEFAULT);

	exit(1);
}

#define error(FMT, ...) error("Error: " FMT, ##__VA_ARGS__)

/*
 * Just print an error to stderr or the syslog
 */
static void print_error(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	if (isatty(2)) {
		fputs("E: ", stderr);
		vfprintf(stderr, fmt, va);
		fputc('\n', stderr);
	} else {
		vsyslog(LOG_ERR, fmt, va);
	}
	va_end(va);
}

/*
 * Print status information
 */
static void verbose(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	if (isatty(1)) {
		fputs("I: ", stdout);
		vfprintf(stdout, fmt, va);
		fputc('\n', stdout);
	} else {
		vsyslog(LOG_INFO, fmt, va);
	}
	va_end(va);
}

/*
 * Print usage details,
 */
static __attribute__((noreturn))
void usage(void)
{
	if (isatty(2)) {
		fprintf(stderr,	"Usage: %s [OPTION]... <key_serial>\n",
			prog);
		fprintf(stderr,	"       %s -D [OPTION]... <desc> <calloutinfo>\n",
			prog);
		fprintf(stderr,	"       %s -V\n",
			prog);

		fprintf(stderr,	"\n");
		fprintf(stderr,	"Where [OPTION].. is a combination of one or more of:\n");
		fprintf(stderr,	"\t-c <conffile>\n");
		fprintf(stderr,	"\t-N dns\n");
		fprintf(stderr,	"\t-N vls-afsdb\n");
		fprintf(stderr,	"\t-N vls-srv\n");
		fprintf(stderr,	"\t-N vls-all\n");
		fprintf(stderr,	"\t-N vl-host\n");
		fprintf(stderr,	"\t-o <dumpfile>\n");
		fprintf(stderr,	"\t-v\n");
	} else {
		verbose("Usage: %s [-vv] <key_serial>", prog);
	}
	exit(2);
}

/*
 * Parse the callout info string.
 */
static void parse_callout(char *options, struct kafs_lookup_context *ctx)
{
	char *k, *val;

	ctx->want_ipv4_addrs = true;
	ctx->want_ipv6_addrs = true;

	if (!*options) {
		/* legacy mode */
		ctx->want_ipv6_addrs = false;
		return;
	}

	do {
		k = options;
		options = strchr(options, ' ');
		if (!options)
			options = k + strlen(k);
		else
			*options++ = '\0';
		if (!*k)
			continue;
		if (strchr(k, ','))
			error("Option name '%s' contains a comma", k);

		val = strchr(k, '=');
		if (val)
			*val++ = '\0';

		if (ctx->report.verbose)
			ctx->report.verbose("Opt %s", k);

		if (strcmp(k, "ipv4") == 0) {
			ctx->want_ipv4_addrs = true;
			ctx->want_ipv6_addrs = false;
		} else if (strcmp(k, "ipv6") == 0) {
			ctx->want_ipv4_addrs = false;
			ctx->want_ipv6_addrs = true;
		} else if (strcmp(k, "list") == 0) {
			one_addr_only = false;
		} else if (strcmp(k, "srv") == 0) {
			output_version = atoi(val);
		}
	} while (*options);
}

const struct option long_options[] = {
	{ "conf",	0, NULL, 'c' },
	{ "debug",	0, NULL, 'D' },
	{ "no",		0, NULL, 'N' },
	{ "output",	0, NULL, 'o' },
	{ "verbose",	0, NULL, 'v' },
	{ "version",	0, NULL, 'V' },
	{ NULL,		0, NULL, 0 }
};

/*
 *
 */
int main(int argc, char *argv[])
{
	struct kafs_lookup_context ctx = { .report.error = print_error, };
	const char *dump_file = NULL;
	const char *filev[10], **filep = NULL;
	char *keyend, *p;
	char *callout_info = NULL;
	char *buf = NULL, *name, *result, *r_end;
	unsigned int ttl;
	size_t ktlen;
	int ret, filec = 0;

	if (argc > 1 && strcmp(argv[1], "--help") == 0)
		usage();

	openlog(prog, 0, LOG_DAEMON);

	while ((ret = getopt_long(argc, argv, "Dvc:N:o:V:", long_options, NULL)) != -1) {
		switch (ret) {
		case 'c':
			if (filec >= 9) {
				fprintf(stderr, "Max 9 files\n");
				exit(2);
			}
			filev[filec++] = optarg;
			break;
		case 'D':
			debug_mode = 1;
			break;
		case 'V':
			printf("version: %s from %s (%s)\n",
			       DNS_PARSE_VERSION,
			       keyutils_version_string,
			       keyutils_build_string);
			exit(0);
		case 'v':
			if (!ctx.report.verbose)
				ctx.report.verbose = verbose;
			else
				ctx.report.verbose2 = verbose;
			break;
		case 'N':
			if (strcmp(optarg, "vls-srv") == 0) {
				ctx.no_vls_srv = true;
			} else if (strcmp(optarg, "vls-afsdb") == 0) {
				ctx.no_vls_afsdb = true;
			} else if (strcmp(optarg, "vls-all") == 0) {
				ctx.no_vls_srv = true;
				ctx.no_vls_afsdb = true;
			} else if (strcmp(optarg, "vl-host") == 0) {
				ctx.no_vl_host = true;
			} else if (strcmp(optarg, "dns") == 0) {
				ctx.no_vls_srv = true;
				ctx.no_vls_afsdb = true;
				ctx.no_vl_host = true;
			} else {
				fprintf(stderr, "Unknown restriction '-N %s'\n", optarg);
				usage();
			}
			break;
		case 'o':
			dump_file = optarg;
			break;
		default:
			if (!isatty(2))
				syslog(LOG_ERR, "unknown option: %c", ret);
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (!debug_mode) {
		if (argc != 1)
			usage();

		/* get the key ID */
		if (!**argv)
			error("Invalid blank key ID");
		key = strtol(*argv, &p, 10);
		if (*p)
			error("Invalid key ID format");

		/* get the key description (of the form "x;x;x;x;<query_type>:<name>") */
		ret = keyctl_describe_alloc(key, &buf);
		if (ret == -1)
			error("keyctl_describe_alloc failed: %m");

		/* get the callout_info (which can supply options) */
		ret = keyctl_read_alloc(KEY_SPEC_REQKEY_AUTH_KEY, (void **)&callout_info);
		if (ret == -1)
			error("Invalid key callout_info read: %m");
	} else {
		if (argc != 2)
			usage();

		ret = asprintf(&buf, "%s;-1;-1;0;%s", key_type, argv[0]);
		if (ret < 0)
			error("Error %m");
		callout_info = argv[1];
	}

	ret = 1;
	verbose("Key description: '%s'", buf);
	verbose("Callout info: '%s'", callout_info);

	p = strchr(buf, ';');
	if (!p)
		error("Badly formatted key description '%s'", buf);
	ktlen = p - buf;

	/* make sure it's the type we are expecting */
	if (ktlen != sizeof(key_type) - 1 ||
	    memcmp(buf, key_type, ktlen) != 0)
		error("Key type is not supported: '%*.*s'", ktlen, ktlen, buf);

	keyend = buf + ktlen + 1;

	/* the actual key description follows the last semicolon */
	keyend = rindex(keyend, ';');
	if (!keyend)
		error("Invalid key description: %s", buf);
	keyend++;

	if (memcmp(keyend, afsdb_query_type, sizeof(afsdb_query_type) - 1) != 0)
		error("Only 'afsdb' supported: %s", buf);
	name = keyend + sizeof(afsdb_query_type) - 1;

	verbose("Do AFS VL server query for:'%s' mask:'%s'", name, callout_info);

	parse_callout(callout_info, &ctx);

	/* Anything we create must fit into 1MiB buffer */
	result = mmap(NULL, 1024 * 1024, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANON, -1, 0);
	if (result == MAP_FAILED)
		error("mmap: %m");

	if (filec > 0) {
		filev[filec] = NULL;
		filep = filev;
	}

	if (kafs_init_lookup_context(&ctx) < 0)
		exit(1);

	if (kafs_read_config(filep, &ctx.report) < 0)
		exit(ctx.report.bad_config ? 3 : 1);

	/* Generate the payload */
	switch (output_version) {
	case 0:
		r_end = kafs_generate_text_payload(result, name, &ttl, &ctx);
		break;

	case 1:
	default:
		r_end = kafs_generate_v1_payload(result, name, &ttl, &ctx);
		break;
	}

	if (!r_end)
		error("failed");

	verbose("version %u %zu", output_version, r_end - result);

	if (dump_file) {
		int fd = open(dump_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd == -1) {
			perror(dump_file);
			exit(1);
		}

		if (write(fd, result, r_end - result) != r_end - result)  {
			perror(dump_file);
			exit(1);
		}
		close(fd);
	}

	/* Set the key's expiry time from the minimum TTL encountered and then
	 * pass the data to the key.
	 */
	if (!debug_mode) {
		if (ttl != UINT_MAX) {
			ret = keyctl_set_timeout(key, ttl);
			if (ret == -1)
				error("keyctl_set_timeout: %m");
		}

		ret = keyctl_instantiate(key, result, r_end - result, 0);
		if (ret == -1)
			error("keyctl_instantiate: %m");
	}

	verbose("Success (%zu bytes)", r_end - result);
	return 0;
}
