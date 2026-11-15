#include "vauth_attest.h"

#include <string.h>

static int valid_field(const char *s, size_t max_len, int allow_space) {
    size_t n;
    if (!s) return 0;
    for (n = 0; s[n]; n++) {
        unsigned char c = (unsigned char)s[n];
        if (n >= max_len) return 0;
        if (allow_space) {
            if (c <= 0x20 || c >= 0x7f) return 0;
        } else if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                     c == '.' || c == '_' || c == '-')) {
            return 0;
        }
    }
    return n > 0;
}

int vauth_attest_message(const char *kind, const vauth_attest_input *in, char *out,
                         size_t out_size, size_t *out_len) {
    const char *fields[6];
    char text_hex[VAUTH_HASH_HEX_SIZE];
    size_t len = 0, i;
    if (!in || !out || !in->text_hash || !valid_field(kind, 32, 0) ||
        !valid_field(in->challenge_hex, 128, 0) || !valid_field(in->subject, 128, 0) ||
        !valid_field(in->veteris_version, VAUTH_MAX_VERSION, 1) ||
        !valid_field(in->helper_version, VAUTH_MAX_VERSION, 1))
        return VAUTH_E_ARG;
    vauth_hex_encode(in->text_hash, VAUTH_HASH_SIZE, text_hex);
    fields[0] = kind;
    fields[1] = in->challenge_hex;
    fields[2] = in->subject;
    fields[3] = in->veteris_version;
    fields[4] = in->helper_version;
    fields[5] = text_hex;
    if (out_size < sizeof("VETERIS-ATTEST-1")) return VAUTH_E_SIZE;
    memcpy(out, "VETERIS-ATTEST-1", sizeof("VETERIS-ATTEST-1") - 1);
    len = sizeof("VETERIS-ATTEST-1") - 1;
    for (i = 0; i < 6; i++) {
        size_t n = strlen(fields[i]);
        if (len + 1 + n + 1 > out_size) return VAUTH_E_SIZE;
        out[len++] = '\n';
        memcpy(out + len, fields[i], n);
        len += n;
    }
    out[len] = 0;
    if (out_len) *out_len = len;
    return VAUTH_OK;
}
