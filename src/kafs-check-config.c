/*
 * kAFS filesystem configuration checker.
 *
 * Copyright (C) David Howells (dhowells@redhat.com) 2018
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <kafs/cellserv.h>
#include <kafs/profile.h>

static void error_report(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	vfprintf(stderr, fmt, va);
	fputc('\n', stderr);
	va_end(va);
}

static void verbose(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	printf("[V] ");
	vprintf(fmt, va);
	putchar('\n');
	va_end(va);
}

static __attribute__((noreturn))
void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-46PDvv] [-c <conffile>]* [-N <restriction>] [<cellname>]*\n",
		prog);
	fprintf(stderr,	"\n");
	fprintf(stderr,	"Where restrictions are one or more of:\n");
	fprintf(stderr,	"\t-N dns\n");
	fprintf(stderr,	"\t-N vls-afsdb\n");
	fprintf(stderr,	"\t-N vls-srv\n");
	fprintf(stderr,	"\t-N vls-all\n");
	fprintf(stderr,	"\t-N vl-host\n");
	exit(2);
}

int main(int argc, char *argv[])
{
	struct kafs_lookup_context ctx = {
		.report.error		= error_report,
		.want_ipv4_addrs	= true,
		.want_ipv6_addrs	= true,
	};
	const char *filev[10], **filep = NULL;
	bool dump_profile = false, dump_db = false;
	int opt, filec = 0;

	if (argc > 1 && strcmp(argv[1], "--help") == 0)
		usage(argv[0]);

	while (opt = getopt(argc, argv, "46PDc:vN:"),
	       opt != -1) {
		switch (opt) {
		case 'c':
			if (filec >= 9) {
				fprintf(stderr, "Max 9 files\n");
				exit(2);
			}
			filev[filec++] = optarg;
			break;
		case 'v':
			if (!ctx.report.verbose)
				ctx.report.verbose = verbose;
			else
				ctx.report.verbose2 = verbose;
			break;
		case 'P':
			dump_profile = true;
			break;
		case 'D':
			dump_db = true;
			break;
		case '4':
			ctx.want_ipv4_addrs = true;
			ctx.want_ipv6_addrs = false;
			break;
		case '6':
			ctx.want_ipv4_addrs = false;
			ctx.want_ipv6_addrs = true;
			break;
		case 'N':
			if (strcmp(optarg, "vl-srv") == 0) {
				ctx.no_vls_srv = true;
			} else if (strcmp(optarg, "vl-afsdb") == 0) {
				ctx.no_vls_afsdb = true;
			} else if (strcmp(optarg, "vl-all") == 0) {
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
				usage(argv[0]);
			}
			break;
		default:
			usage(argv[0]);
		}
	}

	argc -= optind;
	argv += optind;

	if (filec > 0) {
		filev[filec] = NULL;
		filep = filev;
	}

	if (kafs_init_lookup_context(&ctx) < 0)
		exit(1);

	if (kafs_read_config(filep, &ctx.report) < 0)
		exit(ctx.report.bad_config ? 3 : 1);

	if (dump_profile)
		kafs_profile_dump(&kafs_config_profile, 0);
	if (dump_db)
		kafs_cellserv_dump(kafs_cellserv_db);

	for (; *argv; argv++) {
		struct kafs_cell *cell;

		cell = kafs_lookup_cell(*argv, &ctx);
		if (cell) {
			printf("\n");
			printf("=== Found cell %s ===\n", cell->name);
			kafs_dump_cell(cell);
		}
	}

	kafs_clear_lookup_context(&ctx);
	return 0;
}
