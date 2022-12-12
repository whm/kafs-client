/* aklog.c: description
 * vim: noet:ts=2:sw=2:tw=80:nowrap
 *
 * Copyright (C) 2017 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * Based on code:
 * Copyright (C) 2007 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 * Copyright (C) 2008 Chaskiel Grundman. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 * Kerberos-5 strong enctype support for rxkad:
 *	https://tools.ietf.org/html/draft-kaduk-afs3-rxkad-k5-kdf-00
 *
 * Invoke as: aklog-k5 [-dhv] <cell> [<realm>]
 */

#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <keyutils.h>
#include <byteswap.h>
#include <sys/socket.h>
#include <krb5/krb5.h>
#include <linux/if_alg.h>

// command line switches
int opt_debug = 0;

// default cell file path
static const char rootcell[] = "/proc/net/afs/rootcell";

struct rxrpc_key_sec2_v1 {
	uint32_t        kver;                   /* key payload interface version */
	uint16_t        security_index;         /* RxRPC header security index */
	uint16_t        ticket_length;          /* length of ticket[] */
	uint32_t        expiry;                 /* time at which expires */
	uint32_t        kvno;                   /* key version number */
	uint8_t         session_key[8];         /* DES session key */
	uint8_t         ticket[0];              /* the encrypted ticket */
};

#define MD5_DIGEST_SIZE		16

#define RXKAD_TKT_TYPE_KERBEROS_V5              256
#define OSERROR(X, Y) do { if ((long)(X) == -1) { perror(Y); exit(1); } } while(0)
#define OSZERROR(X, Y) do { if ((long)(X) == 0) { perror(Y); exit(1); } } while(0)
#define KRBERROR(X, Y) do { if ((X) != 0) { const char *msg = krb5_get_error_message(k5_ctx, (X)); fprintf(stderr, "%s: %s\n", (Y), msg); krb5_free_error_message(k5_ctx, msg); exit(1); } } while(0)

static const uint64_t des_weak_keys[16] = {
	0x0101010101010101ULL,
	0xFEFEFEFEFEFEFEFEULL,
	0xE0E0E0E0F1F1F1F1ULL,
	0x1F1F1F1F0E0E0E0EULL,
	0x011F011F010E010EULL,
	0x1F011F010E010E01ULL,
	0x01E001E001F101F1ULL,
	0xE001E001F101F101ULL,
	0x01FE01FE01FE01FEULL,
	0xFE01FE01FE01FE01ULL,
	0x1FE01FE00EF10EF1ULL,
	0xE01FE01FF10EF10EULL,
	0x1FFE1FFE0EFE0EFEULL,
	0xFE1FFE1FFE0EFE0EULL,
	0xE0FEE0FEF1FEF1FEULL,
	0xFEE0FEE0FEF1FEF1ULL
};

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static bool des_is_weak_key(uint64_t des)
{
	size_t i;

#if __BYTE_ORDER == __LITTLE_ENDIAN
	des = bswap_64(des);
#endif

	for (i = 0; i < ARRAY_SIZE(des_weak_keys); i++)
		if (des_weak_keys[i] == des)
			return true;
	return false;
}

static void des_set_odd_parity(uint64_t *p)
{
	uint64_t x = *p, y, z;

	y = x | 0x0101010101010101ULL;
	y ^= y >> 4;
	y ^= y >> 2;
	y ^= y >> 1;
	z = x | (y & 0x0101010101010101ULL);
	*p = z;
}

/*
 * Strip Triple-DES parity bits from a block.
 *
 * Discard the parity bits and converts an 8-octet block to a 7-octet block.
 *
 * See [afs3-rxkad-k5-kdf-00 §4.2] and [RFC3961 §6.3.1].
 *
 * [These docs number the bits weirdly.  Bit '8' appears to be the LSB of the
 * first octet, and 1 the MSB].
 */
static void des3_strip_parity_bits(void *random, const void *key)
{
	const unsigned char *k = key;
	unsigned char *r = random, lsbs;
	int i;

	lsbs = k[7] >> 1;
	for (i = 0; i < 7; i++) {
		r[i] = (k[i] & 0xfe) | (lsbs & 0x1);
		lsbs >>= 1;
	}
}

/*
 * Reverse the Triple-DES random-to-key operation, converting three 64-bit DES
 * keys to 56-bit random strings and concatenate to give a 168-bit random
 * string that can then be fed to the KDF.
 */
static unsigned int des3_key_to_random(void *random, const void *key, unsigned int len)
{
	unsigned int new_len = 0;

	while (len > 8) {
		des3_strip_parity_bits(random, key);
		key += 8;
		random += 7;
		len -= 8;
		new_len += 7;
	}

	return new_len;
}

/*
 * Do HMAC(MD5).
 */
static size_t HMAC_MD5(const void *key, size_t key_len,
		       const void *data, size_t data_len,
		       unsigned char *md, size_t md_len)
{
	static struct sockaddr_alg sa = {
		.salg_family	= AF_ALG,
		.salg_type	= "hash",
		.salg_name	= "hmac(md5)",
	};
	int alg, sock, ret;

	alg = socket(AF_ALG, SOCK_SEQPACKET, 0);
	OSERROR(alg, "AF_ALG");
	OSERROR(bind(alg, (struct sockaddr *)&sa, sizeof(sa)), "bind/AF_ALG");
	OSERROR(setsockopt(alg, SOL_ALG, ALG_SET_KEY, key, key_len), "setsockopt/AF_ALG");
	sock = accept(alg, NULL, 0);
	OSERROR(sock, "AF_ALG");
	OSERROR(write(sock, data, data_len), "write/AF_ALG");
	ret = read(sock, md, md_len);
	OSERROR(ret, "read/AF_ALG");
	close(sock);
	close(alg);
	return ret;
}

/*
 * The data to pass into the key derivation function.
 */
struct kdf_data {
	unsigned char i_2;
	unsigned char Label[6];
	unsigned char L_2[4];
} __attribute__((packed));

static const struct kdf_data rxkad_kdf_data = {
	.Label	= "rxkad",		/* Including NUL separator */
	.L_2	= { 0, 0, 0, 64 },	/* BE integer */
};

/*
 * Derive a 64-bit key we can pass to rxkad from the ticket data.  The ticket
 * data is used as the key for the HMAC-MD5 algorithm, which is used as the
 * PRF.  We then iterate over a series of constructed source strings, passing
 * each one through the PRF until we get an MD5 output that we can cut down and
 * use as a substitute for the DES session key that isn't too weak.
 *
 * [afs3-rxkad-k5-kdf-00 §4.3]
 */
static void key_derivation_function(krb5_creds *creds, uint8_t *session_key)
{
	struct kdf_data kdf_data = rxkad_kdf_data;
	unsigned int i, len;
	union {
		unsigned char md5[MD5_DIGEST_SIZE];
		uint64_t n_des;
	} buf;

	for (i = 1; i <= 255; i++) {
		/* K(i) = PRF(Ks, [i]_2 || Label || 0x00 || [L]_2) */
		kdf_data.i_2 = i;
		len = HMAC_MD5(creds->keyblock.contents, creds->keyblock.length,
			       (unsigned char *)&kdf_data, sizeof(kdf_data),
			       buf.md5, sizeof(buf.md5));

		if (len < sizeof(buf.n_des)) {
			fprintf(stderr, "aklog: HMAC returned short result\n");
			exit(1);
		}

		/* Overlay the DES parity. */
		buf.n_des &= 0xfefefefefefefefeULL;
		des_set_odd_parity(&buf.n_des);
		if (!des_is_weak_key(buf.n_des))
			goto success;
	}

	fprintf(stderr, "aklog: Unable to derive strong DES key\n");
	exit(1);

success:
	memcpy(session_key, &buf.n_des, sizeof(buf.n_des));
}

/*
 * Extract or derive the session key.
 */
static void derive_key(krb5_creds *creds, uint8_t *session_key)
{
	unsigned int length = creds->keyblock.length;

	switch (creds->keyblock.enctype) {
	case ENCTYPE_NULL:		goto not_supported;
	case ENCTYPE_DES_CBC_CRC:	goto just_copy;
	case ENCTYPE_DES_CBC_MD4:	goto just_copy;
	case ENCTYPE_DES_CBC_MD5:	goto just_copy;
	case ENCTYPE_DES_CBC_RAW:	goto deprecated;
	case ENCTYPE_DES3_CBC_SHA:	goto des3_discard_parity; /* des3-cbc-md5 */
	case ENCTYPE_DES3_CBC_RAW:	goto deprecated;
	case 7:				goto des3_discard_parity; /* des3-cbc-sha1 */
	case ENCTYPE_DES_HMAC_SHA1:	goto deprecated;
	case ENCTYPE_DSA_SHA1_CMS:	goto not_supported;
	case ENCTYPE_MD5_RSA_CMS:	goto not_supported;
	case ENCTYPE_SHA1_RSA_CMS:	goto not_supported;
	case ENCTYPE_RC2_CBC_ENV:	goto not_supported;
	case ENCTYPE_RSA_ENV:		goto not_supported;
	case ENCTYPE_RSA_ES_OAEP_ENV:	goto not_supported;
	case ENCTYPE_DES3_CBC_ENV:	goto not_supported;
	case ENCTYPE_DES3_CBC_SHA1:	goto des3_discard_parity; /* des3-cbc-sha1-kd */
	default:
		if (length < 7)
			goto key_too_short;
		if (creds->keyblock.enctype < 0)
			goto not_supported;
		goto derive_key;
	}

	/* Strip the parity bits for 3DES then do KDF [afs3-rxkad-k5-kdf-00 §4.2]. */
des3_discard_parity:
	if (length & 7) {
		fprintf(stderr, "aklog: 3DES session key not multiple of 8 octets.\n");
		exit(1);
	}
	creds->keyblock.length = des3_key_to_random(creds->keyblock.contents,
						    creds->keyblock.contents,
						    length);
	goto derive_key;

	/* Do KDF [afs3-rxkad-k5-kdf-00 §4.3]. */
derive_key:
	key_derivation_function(creds, session_key);
	return;

	/* Use as-is for single-DES [afs3-rxkad-k5-kdf-00 §4.1]. */
just_copy:
	if (length != 8) {
		fprintf(stderr, "aklog: DES session key not 8 octets.\n");
		exit(1);
	}

	memcpy(session_key, creds->keyblock.contents, length);
	return;

deprecated:
	fprintf(stderr, "aklog: Ticket contains deprecated enc type (%d)\n",
		creds->keyblock.enctype);
	exit(1);

not_supported:
	fprintf(stderr, "aklog: Ticket contains unsupported enc type (%d)\n",
		creds->keyblock.enctype);
	exit(1);
key_too_short:
	fprintf(stderr, "aklog: Ticket contains short key block (%u)\n", length);
	exit(1);
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

/*
 * Display a short usage message and exit
 */
void display_usage (int exit_status)
{
	fprintf(stderr,
		"Usage: \n"
		" aklog-kafs [OPTIONS] [<cell> [<realm>]]\n"
		"\n"
		"Options:\n"
		" -h    display this help and exit\n"
		" -d    increase verbosity with each instance of this argument\n"
		" -k    manually specify keyring to add AFS key into:\n"
		"         session\n"
		"         uid-session\n"
		"       Otherwise, a session keyring will be used first if found before \n"
		"       automatically switching to the uid-session keyring.\n"
		" -V    Show version and exit\n"
	);
	exit(exit_status);
}

/*
 *
 */
int main(int argc, char **argv)
{
	int opt;

	char *cell_scratch;
	char *cell, *realm, *princ, *desc, *p;
	int ret;
	size_t plen;
	struct rxrpc_key_sec2_v1 *payload;
	key_serial_t dest_keyring, sessring, usessring;
	krb5_error_code kresult;
	krb5_context k5_ctx;
	krb5_ccache cc;
	krb5_creds search_cred, *creds;

	dest_keyring = 0;

	while ((opt = getopt(argc, argv, "hdVk:")) != -1) {
		switch (opt) {
		case 'h':
			display_usage(EXIT_SUCCESS);
			break;
		case 'k':
			if (strcmp(optarg, "session") == 0)
				dest_keyring = KEY_SPEC_SESSION_KEYRING;
			else if (strcmp(optarg, "uid-session") == 0)
				dest_keyring = KEY_SPEC_USER_SESSION_KEYRING;
			else
				display_usage(EXIT_FAILURE);
			break;
		case 'd':
			++opt_debug;
			break;
		case 'V':
			printf("kAFS client: %s\n", VERSION);
			exit(0);
		default:
			display_usage(EXIT_SUCCESS);
		}
	}

	if (argc - optind > 2) {
		fprintf(stderr, "ERROR: too many arguments\n");
		display_usage(EXIT_FAILURE);
	}

	if ((argc - optind) <= 0) {
		cell = cell_scratch = get_default_cell();
		if (opt_debug) {
			printf("Default cell from %s: %s\n", rootcell, cell);
		}
	} else {
		cell_scratch = NULL;
		cell = argv[optind];
	}

	if ((argc - optind) > 1) {
		realm = strdup(argv[optind + 1]);
		OSZERROR(realm, "strdup");
	} else {
		realm = strdup(cell);
		OSZERROR(realm, "strdup");
		for (p = realm; *p; p++) {
			*p = toupper(*p);
		}
	}
	if (opt_debug) {
		printf("Realm: %s\n", realm);
	}

	for (p = cell; *p; p++)
		*p = tolower(*p);

	ret = asprintf(&princ, "afs/%s@%s", cell, realm);
	OSERROR(ret, "asprintf");
	ret = asprintf(&desc, "afs@%s", cell);
	OSERROR(ret, "asprintf");

	if (opt_debug) {
		printf("CELL %s\n", cell);
		printf("PRINC %s\n", princ);
	}

	kresult = krb5_init_context(&k5_ctx);
	if (kresult) {
		fprintf(stderr, "krb5_init_context failed\n");
		exit(1);
	}

	kresult = krb5_cc_default(k5_ctx, &cc);
	KRBERROR(kresult, "Getting credential cache");

	memset(&search_cred, 0, sizeof(krb5_creds));

	kresult = krb5_cc_get_principal(k5_ctx, cc, &search_cred.client);
	KRBERROR(kresult, "Getting client principal");

	kresult = krb5_parse_name(k5_ctx, princ, &search_cred.server);
	KRBERROR(kresult, "Parsing server principal name");

	//search_cred.keyblock.enctype = ENCTYPE_DES_CBC_CRC;

	kresult = krb5_get_credentials(k5_ctx, 0, cc, &search_cred, &creds);
	KRBERROR(kresult, "Getting tickets");

	plen = sizeof(*payload) + creds->ticket.length;
	payload = calloc(1, plen + 4);
	if (!payload) {
		perror("calloc");
		exit(1);
	}

	if (opt_debug >= 2) {
		printf("plen=%zu tklen=%u rk=%zu\n",
			plen, creds->ticket.length, sizeof(*payload));
	}

	/* use version 1 of the key data interface */
	payload->kver           = 1;
	payload->security_index = 2;
	payload->ticket_length  = creds->ticket.length;
	payload->expiry         = creds->times.endtime;
	payload->kvno           = RXKAD_TKT_TYPE_KERBEROS_V5;

	derive_key(creds, payload->session_key);
	memcpy(payload->ticket, creds->ticket.data, creds->ticket.length);

	/* if the session keyring is not set (i.e. using the uid
	 * session keyring), then the kernel will instantiate a new
	 * session keyring if any keys are added to
	 * KEY_SPEC_SESSION_KEYRING! Since we exit immediately, that
	 * keyring will be orphaned. So, add the key to
	 * KEY_SPEC_USER_SESSION_KEYRING in that case.
	 */
	sessring  = keyctl_get_keyring_ID(KEY_SPEC_SESSION_KEYRING, 0);
	usessring = keyctl_get_keyring_ID(KEY_SPEC_USER_SESSION_KEYRING, 0);
	if (opt_debug >= 2) {
		printf("session keyring found: %d\n", sessring);
		printf("uid-session keyring found: %d\n", usessring);
	}

	if (dest_keyring == 0) {
		/* attempt to automatically select the correct keyring. */
		if (sessring == -1 || sessring == usessring)
			dest_keyring = KEY_SPEC_USER_SESSION_KEYRING;
		else
			dest_keyring = KEY_SPEC_SESSION_KEYRING;
	} else {
		if (keyctl_get_keyring_ID(dest_keyring, 0) == -1 ||
		    (dest_keyring == KEY_SPEC_SESSION_KEYRING &&
		     sessring == usessring)) {
			fprintf(stderr, "Could not find requested keyring\n");
			exit(EXIT_FAILURE);
		}
	}

	if (dest_keyring != KEY_SPEC_SESSION_KEYRING &&
	    dest_keyring != KEY_SPEC_USER_SESSION_KEYRING) {
		fprintf(stderr, "using unknown keyring (%d)\n", dest_keyring);
		exit(EXIT_FAILURE);
	} else if (opt_debug >= 2) {
		if (dest_keyring == KEY_SPEC_SESSION_KEYRING)
			printf("using session keyring (%d)\n", dest_keyring);
		else if (dest_keyring == KEY_SPEC_USER_SESSION_KEYRING)
			printf("using uid-session keyring (%d)\n", dest_keyring);
	}

	ret = add_key("rxrpc", desc, payload, plen, dest_keyring);
	OSERROR(ret, "add_key");
	if (opt_debug) {
		if (dest_keyring == KEY_SPEC_SESSION_KEYRING)
			printf("successfully added key: %d to session keyring\n", ret);
		else if (dest_keyring == KEY_SPEC_USER_SESSION_KEYRING)
			printf("successfully added key: %d to uid-session keyring\n", ret);
		else
			printf("successfully added key: %d to an unknown keyring\n", ret);
	}

	if (cell_scratch) {
		free(cell_scratch);
	}
	free(realm);
	free(princ);
	free(desc);
	free(payload);
	krb5_free_creds(k5_ctx, creds);
	krb5_free_cred_contents(k5_ctx, &search_cred);
	krb5_cc_close(k5_ctx, cc);
	krb5_free_context(k5_ctx);
	exit(0);
}
