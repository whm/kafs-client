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
#include <fcntl.h>
#include <getopt.h>
#include <kafs/cellserv.h>
#include <kafs/profile.h>

// default cell file path
static const char rootcell[] = "/proc/net/afs/rootcell";

// Debug setting
int opt_debug = 0;

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

/*
 * Print a message and bail out if the default cell is not available
 */
void error_get_default_cell(void)
{
	fprintf(stderr, "ERROR: The default cell is NOT set\n");
	fprintf(stderr, "\n");
	fprintf(stderr,
		"INFO: Ensure that thiscell is set in the [defaults]\n");
	fprintf(stderr,
		"      section of the /etc/kafs/client.conf file.\n");
	exit(1);
}

/*
 * Read the name of default cell.
 */
static char *get_default_cell(void)
{
	ssize_t n;
	char buf[260];
	char *cell;
	char *nl;
	int fd;

	if (access(rootcell, F_OK) != 0) {
		if (opt_debug) {
			fprintf(stdout, "INFO: file not found %s\n", rootcell);
		}
		error_get_default_cell();
	}

	fd = open(rootcell, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "ERROR: problem opening %s\n", rootcell);
		error_get_default_cell();
	}
	n = read(fd, buf, sizeof(buf) - 2);
	if (n == -1) {
		fprintf(stderr, "ERROR: problem reading %s\n", rootcell);
		error_get_default_cell();
	}
	close(n);
	if (n == 0) {
		error_get_default_cell();
	}

	buf[n] = 0;
	nl = memchr(buf, '\n', n);
	if (nl == buf) {
		error_get_default_cell();
	}
	*nl = 0;

	cell = strdup(buf);
	if (cell == 0) {
		fprintf(stderr,
			"ERROR: zero length default cell in %s\n", rootcell);
		error_get_default_cell();
	}
	return cell;
}

int main(int argc, char *argv[])
{
	struct kafs_cell *cell;
	struct kafs_lookup_context ctx = {
		.report.error		= error_report,
		.want_ipv4_addrs	= true,
		.want_ipv6_addrs	= true,
	};
	const char *filev[10], **filep = NULL;
	bool dump_profile = false, dump_db = false;
	int opt, filec = 0;
	int cell_cnt = 0;

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
			++opt_debug;
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
		++cell_cnt;
		cell = kafs_lookup_cell(*argv, &ctx);
		if (cell) {
			printf("\n");
			printf("=== Found cell %s ===\n", cell->name);
			kafs_dump_cell(cell);
		}
	}
	if (cell_cnt == 0) {
		char *thiscell;
		thiscell = get_default_cell();
		if (opt_debug) {
			printf("Default cell from %s: %s\n",
				rootcell,
				thiscell);
		}
		cell = kafs_lookup_cell(thiscell, &ctx);
		if (cell) {
			printf("\n");
			printf("=== Found cell %s ===\n", cell->name);
			kafs_dump_cell(cell);
		} else {
			printf("\n");
			printf("INFO: Default cell not found %s", thiscell);
		}
	}
	kafs_clear_lookup_context(&ctx);

	return 0;
}
