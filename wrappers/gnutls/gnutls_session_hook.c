/*
 * Interop hook: export session after first handshake (save) or import before
 * handshake (resume). Used with gnutls-cli via GNUTLS_INTEROP_SESSION_{OUT,IN}.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <gnutls/gnutls.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int (*real_get_data2)(gnutls_session_t, gnutls_datum_t *);
static int (*real_handshake)(gnutls_session_t);

static int load_session_file(gnutls_session_t session)
{
	const char *path = getenv("GNUTLS_INTEROP_SESSION_IN");
	static int applied;
	unsigned char *buf;
	size_t n;
	FILE *f;
	int (*set_data)(gnutls_session_t, const void *, size_t);

	if (!path || !*path || applied)
		return 0;
	applied = 1;
	f = fopen(path, "rb");
	if (!f)
		return -1;
	if (fseek(f, 0, SEEK_END) != 0) {
		fclose(f);
		return -1;
	}
	n = (size_t) ftell(f);
	if (n == 0) {
		fclose(f);
		return -1;
	}
	rewind(f);
	buf = malloc(n);
	if (!buf) {
		fclose(f);
		return -1;
	}
	if (fread(buf, 1, n, f) != n) {
		free(buf);
		fclose(f);
		return -1;
	}
	fclose(f);
	set_data = dlsym(RTLD_NEXT, "gnutls_session_set_data");
	if (!set_data) {
		free(buf);
		return -1;
	}
	if (set_data(session, buf, n) < 0) {
		free(buf);
		return -1;
	}
	free(buf);
	return 0;
}

int gnutls_session_get_data2(gnutls_session_t session, gnutls_datum_t *data)
{
	const char *out_path;
	FILE *f;

	if (!real_get_data2)
		real_get_data2 = dlsym(RTLD_NEXT, "gnutls_session_get_data2");
	if (!real_get_data2)
		return GNUTLS_E_INTERNAL_ERROR;

	if (real_get_data2(session, data) < 0)
		return -1;

	out_path = getenv("GNUTLS_INTEROP_SESSION_OUT");
	if (!out_path || !*out_path || !data->data || data->size == 0)
		return 0;

	f = fopen(out_path, "wb");
	if (!f)
		return -1;
	if (fwrite(data->data, 1, data->size, f) != data->size) {
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

int gnutls_handshake(gnutls_session_t session)
{
	if (!real_handshake)
		real_handshake = dlsym(RTLD_NEXT, "gnutls_handshake");
	if (!real_handshake)
		return GNUTLS_E_INTERNAL_ERROR;

	if (getenv("GNUTLS_INTEROP_SESSION_IN"))
		load_session_file(session);

	return real_handshake(session);
}
