#include "vauth.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "mbedtls/bignum.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/ecp.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"

static const char HEX_LOWER[] = "0123456789abcdef";
static const char HEX_UPPER[] = "0123456789ABCDEF";

int vauth_random_urandom(void *ctx, unsigned char *out, size_t len) {
    int fd;
    (void)ctx;
    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    while (len > 0) {
        ssize_t n = read(fd, out, len);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        out += n;
        len -= (size_t)n;
    }
    close(fd);
    return 0;
}

void vauth_hex_encode(const uint8_t *in, size_t len, char *out) {
    size_t i;
    for (i = 0; i < len; i++) {
        out[2 * i] = HEX_LOWER[in[i] >> 4];
        out[2 * i + 1] = HEX_LOWER[in[i] & 15];
    }
    out[2 * len] = 0;
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int vauth_hex_decode(const char *hex, uint8_t *out, size_t out_len) {
    size_t i;
    if (!hex || !out) return VAUTH_E_ARG;
    for (i = 0; i < out_len; i++) {
        int hi = hex_value(hex[2 * i]);
        int lo = hi < 0 ? -1 : hex_value(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return VAUTH_E_ARG;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return hex[2 * out_len] == 0 ? VAUTH_OK : VAUTH_E_ARG;
}

int vauth_ct_equal(const void *a, const void *b, size_t len) {
    const volatile uint8_t *x = (const volatile uint8_t *)a;
    const volatile uint8_t *y = (const volatile uint8_t *)b;
    uint8_t diff = 0;
    size_t i;
    for (i = 0; i < len; i++) diff |= (uint8_t)(x[i] ^ y[i]);
    return diff == 0;
}

void vauth_wipe(void *p, size_t len) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (len--) *v++ = 0;
}

void vauth_sha256(const void *data, size_t len, uint8_t out[VAUTH_HASH_SIZE]) {
    mbedtls_sha256_ret((const unsigned char *)data, len, out, 0);
}

void vauth_hmac_sha256(const uint8_t *key, size_t key_len, const void *data, size_t len,
                       uint8_t out[VAUTH_HASH_SIZE]) {
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, key_len,
                    (const unsigned char *)data, len, out);
}

int vauth_split_url(const char *url, vauth_url_parts *parts) {
    const char *p, *authority, *authority_end, *host, *host_end, *at, *colon;
    if (!url || !parts) return VAUTH_E_ARG;
    memset(parts, 0, sizeof(*parts));
    p = strstr(url, "://");
    if (!p) return VAUTH_E_ARG;
    authority = p + 3;
    authority_end = authority;
    while (*authority_end && *authority_end != '/' && *authority_end != '?' && *authority_end != '#')
        authority_end++;
    host = authority;
    for (at = authority; at < authority_end; at++) {
        if (*at == '@') host = at + 1;
    }
    host_end = authority_end;
    for (colon = host; colon < authority_end; colon++) {
        if (*colon == ':') {
            host_end = colon;
            break;
        }
    }
    if (host_end == host) return VAUTH_E_ARG;
    parts->host = host;
    parts->host_len = (size_t)(host_end - host);

    p = authority_end;
    if (*p == '/') {
        const char *path_end = p;
        while (*path_end && *path_end != '?' && *path_end != '#') path_end++;
        parts->path = p;
        parts->path_len = (size_t)(path_end - p);
        p = path_end;
    } else {
        parts->path = "/";
        parts->path_len = 1;
    }
    if (*p == '?') {
        const char *query_end = ++p;
        while (*query_end && *query_end != '#') query_end++;
        parts->query = p;
        parts->query_len = (size_t)(query_end - p);
    } else {
        parts->query = "";
        parts->query_len = 0;
    }
    return VAUTH_OK;
}

int vauth_is_signed_host(const char *host, size_t host_len) {
    static const char expected[] = VAUTH_HOST;
    size_t i;
    if (!host || host_len != sizeof(expected) - 1) return 0;
    for (i = 0; i < host_len; i++) {
        char c = host[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        if (c != expected[i]) return 0;
    }
    return 1;
}

static int is_plain_path_char(unsigned char c) {
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) return 1;
    return c != 0 && strchr("-._~!$&'()*+,;=:@", c) != NULL;
}

static size_t remove_dot_segments(char *s, size_t n) {
    size_t r = 0, w = 0;
    int trailing = 0;
    while (r < n) {
        size_t start, len;
        int last;
        while (r < n && s[r] == '/') r++;
        if (r >= n) {
            trailing = 1;
            break;
        }
        start = r;
        while (r < n && s[r] != '/') r++;
        len = r - start;
        last = r >= n;
        trailing = 0;
        if (len == 1 && s[start] == '.') {
            trailing = last;
            continue;
        }
        if (len == 2 && s[start] == '.' && s[start + 1] == '.') {
            while (w > 0 && s[w - 1] != '/') w--;
            if (w > 0) w--;
            trailing = last;
            continue;
        }
        s[w++] = '/';
        memmove(s + w, s + start, len);
        w += len;
    }
    if (w == 0 || trailing) s[w++] = '/';
    return w;
}

int vauth_canonical_path(const char *path, size_t path_len, char *out, size_t out_size,
                         size_t *out_len) {
    size_t i, w = 0;
    if (!path || !out || out_size == 0) return VAUTH_E_ARG;
    if (path_len == 0) {
        path = "/";
        path_len = 1;
    }
    if (path[0] != '/') return VAUTH_E_ARG;
    for (i = 0; i < path_len; i++) {
        unsigned char c = (unsigned char)path[i];
        if (c == '%') {
            int hi, lo;
            if (i + 2 >= path_len) return VAUTH_E_PATH;
            hi = hex_value(path[i + 1]);
            lo = hi < 0 ? -1 : hex_value(path[i + 2]);
            if (hi < 0 || lo < 0) return VAUTH_E_PATH;
            c = (unsigned char)((hi << 4) | lo);
            i += 2;
            if (c == '/') return VAUTH_E_PATH;
            if (is_plain_path_char(c)) {
                if (w + 1 >= out_size) return VAUTH_E_SIZE;
                out[w++] = (char)c;
                continue;
            }
        } else if (c == '/' || is_plain_path_char(c)) {
            if (w + 1 >= out_size) return VAUTH_E_SIZE;
            out[w++] = (char)c;
            continue;
        } else if (c == 0 || c == '\n' || c == '\r') {
            return VAUTH_E_PATH;
        }
        if (w + 3 >= out_size) return VAUTH_E_SIZE;
        out[w++] = '%';
        out[w++] = HEX_UPPER[c >> 4];
        out[w++] = HEX_UPPER[c & 15];
    }
    w = remove_dot_segments(out, w);
    if (w >= out_size) return VAUTH_E_SIZE;
    out[w] = 0;
    if (out_len) *out_len = w;
    return VAUTH_OK;
}

static int valid_token(const char *s, size_t min_len, size_t max_len) {
    size_t n = 0;
    if (!s) return min_len == 0;
    for (; s[n]; n++) {
        unsigned char c = (unsigned char)s[n];
        if (n >= max_len) return 0;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '.' || c == '_' || c == '-'))
            return 0;
    }
    return n >= min_len;
}

int vauth_valid_key_id(const char *key_id) {
    return key_id && valid_token(key_id, 1, VAUTH_MAX_KEY_ID);
}

int vauth_valid_session(const char *session) {
    return valid_token(session, 0, VAUTH_MAX_SESSION);
}

static int valid_version(const char *s) {
    size_t n;
    if (!s) return 0;
    for (n = 0; s[n]; n++) {
        if (n >= VAUTH_MAX_VERSION || (unsigned char)s[n] <= 0x20 || (unsigned char)s[n] >= 0x7f)
            return 0;
    }
    return n > 0;
}

static int valid_method(const char *s) {
    size_t n;
    if (!s) return 0;
    for (n = 0; s[n]; n++) {
        if (n >= 16 || s[n] < 'A' || s[n] > 'Z') return 0;
    }
    return n > 0;
}

static int valid_nonce(const char *s) {
    size_t n;
    if (!s) return 0;
    for (n = 0; s[n]; n++) {
        if (n >= 32 || !((s[n] >= '0' && s[n] <= '9') || (s[n] >= 'a' && s[n] <= 'f'))) return 0;
    }
    return n == 32;
}

typedef struct {
    char *out;
    size_t size;
    size_t len;
    int failed;
} builder;

static void put(builder *b, const char *s, size_t n) {
    if (b->failed) return;
    if (b->len + n + 1 > b->size) {
        b->failed = 1;
        return;
    }
    memcpy(b->out + b->len, s, n);
    b->len += n;
    b->out[b->len] = 0;
}

static void put_str(builder *b, const char *s) {
    put(b, s, strlen(s));
}

static void put_line(builder *b, const char *s) {
    put_str(b, s);
    put(b, "\n", 1);
}

static void put_int64(builder *b, int64_t value) {
    char digits[24];
    size_t n = 0;
    uint64_t v;
    int negative = value < 0;
    v = negative ? (uint64_t)(-(value + 1)) + 1 : (uint64_t)value;
    do {
        digits[n++] = (char)('0' + (v % 10));
        v /= 10;
    } while (v);
    if (negative) put(b, "-", 1);
    while (n) put(b, &digits[--n], 1);
}

int vauth_canonical_request(const vauth_request *req, char *out, size_t out_size,
                            size_t *out_len) {
    builder b;
    char body_hex[VAUTH_HASH_HEX_SIZE];
    uint8_t body_hash[VAUTH_HASH_SIZE];
    size_t path_len, i;
    int ret;
    const char *session;
    if (!req || !out || out_size == 0) return VAUTH_E_ARG;
    session = req->session ? req->session : "";
    if (!valid_method(req->method) || !req->path || !valid_nonce(req->nonce_hex) ||
        !vauth_valid_key_id(req->key_id) || !vauth_valid_session(session) ||
        !valid_version(req->veteris_version) || !valid_version(req->helper_version))
        return VAUTH_E_ARG;
    if (req->body_len && !req->body) return VAUTH_E_ARG;
    for (i = 0; i < req->query_len; i++) {
        if (req->query[i] == '\n' || req->query[i] == '\r' || req->query[i] == 0) return VAUTH_E_ARG;
    }

    b.out = out;
    b.size = out_size;
    b.len = 0;
    b.failed = 0;
    out[0] = 0;
    put_line(&b, "VETERIS-AUTH-" VAUTH_PROTOCOL_VERSION);
    put_line(&b, req->method);
    put_line(&b, VAUTH_HOST);
    if (b.failed) return VAUTH_E_SIZE;
    ret = vauth_canonical_path(req->path, req->path_len, out + b.len, out_size - b.len, &path_len);
    if (ret != VAUTH_OK) return ret;
    b.len += path_len;
    put(&b, "\n", 1);
    if (req->query_len) put(&b, req->query, req->query_len);
    put(&b, "\n", 1);
    put_int64(&b, req->timestamp);
    put(&b, "\n", 1);
    put_line(&b, req->nonce_hex);
    vauth_sha256(req->body_len ? req->body : (const uint8_t *)"", req->body_len, body_hash);
    vauth_hex_encode(body_hash, sizeof(body_hash), body_hex);
    put_line(&b, body_hex);
    put_line(&b, req->key_id);
    put_line(&b, session);
    put_line(&b, req->veteris_version);
    put_str(&b, req->helper_version);
    if (b.failed) return VAUTH_E_SIZE;
    if (out_len) *out_len = b.len;
    return VAUTH_OK;
}

int vauth_sign_request(const uint8_t install_key[VAUTH_KEY_SIZE], const vauth_request *req,
                       char signature_hex[VAUTH_HASH_HEX_SIZE]) {
    char canonical[4096];
    uint8_t mac[VAUTH_HASH_SIZE];
    size_t len;
    int ret;
    if (!install_key || !signature_hex) return VAUTH_E_ARG;
    ret = vauth_canonical_request(req, canonical, sizeof(canonical), &len);
    if (ret != VAUTH_OK) return ret;
    vauth_hmac_sha256(install_key, VAUTH_KEY_SIZE, canonical, len, mac);
    vauth_hex_encode(mac, sizeof(mac), signature_hex);
    vauth_wipe(mac, sizeof(mac));
    return VAUTH_OK;
}

int vauth_new_nonce(vauth_random_fn rng, void *rng_ctx, char nonce_hex[VAUTH_NONCE_HEX_SIZE]) {
    uint8_t nonce[VAUTH_NONCE_SIZE];
    if (!rng || !nonce_hex) return VAUTH_E_ARG;
    if (rng(rng_ctx, nonce, sizeof(nonce)) != 0) return VAUTH_E_CRYPTO;
    vauth_hex_encode(nonce, sizeof(nonce), nonce_hex);
    return VAUTH_OK;
}

static int x25519(const uint8_t scalar[32], const uint8_t *point, uint8_t out[32]) {
    uint8_t k[32];
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point P, R;
    int ret;
    memcpy(k, scalar, 32);
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&P);
    mbedtls_ecp_point_init(&R);
    ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (ret == 0) ret = mbedtls_mpi_read_binary_le(&d, k, 32);
    if (ret == 0) {
        if (point) {
            uint8_t u[32];
            memcpy(u, point, 32);
            u[31] &= 127;
            ret = mbedtls_mpi_read_binary_le(&P.X, u, 32);
            if (ret == 0) ret = mbedtls_mpi_lset(&P.Z, 1);
            if (ret == 0) ret = mbedtls_ecp_mul(&grp, &R, &d, &P, NULL, NULL);
        } else {
            ret = mbedtls_ecp_mul(&grp, &R, &d, &grp.G, NULL, NULL);
        }
    }
    if (ret == 0) ret = mbedtls_mpi_write_binary_le(&R.X, out, 32);
    vauth_wipe(k, sizeof(k));
    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&P);
    mbedtls_ecp_point_free(&R);
    mbedtls_ecp_group_free(&grp);
    return ret == 0 ? VAUTH_OK : VAUTH_E_CRYPTO;
}

int vauth_x25519_keypair(vauth_random_fn rng, void *rng_ctx, uint8_t secret[VAUTH_KEY_SIZE],
                         uint8_t public_key[VAUTH_KEY_SIZE]) {
    int ret;
    if (!rng || !secret || !public_key) return VAUTH_E_ARG;
    if (rng(rng_ctx, secret, VAUTH_KEY_SIZE) != 0) return VAUTH_E_CRYPTO;
    secret[0] &= 248;
    secret[31] &= 127;
    secret[31] |= 64;
    ret = x25519(secret, NULL, public_key);
    if (ret != VAUTH_OK) vauth_wipe(secret, VAUTH_KEY_SIZE);
    return ret;
}

int vauth_x25519(const uint8_t secret[VAUTH_KEY_SIZE], const uint8_t peer_public[VAUTH_KEY_SIZE],
                 uint8_t shared[VAUTH_KEY_SIZE]) {
    if (!secret || !peer_public || !shared) return VAUTH_E_ARG;
    return x25519(secret, peer_public, shared);
}

void vauth_key_fingerprint(const uint8_t public_key[VAUTH_KEY_SIZE],
                           char out[VAUTH_FINGERPRINT_HEX_SIZE]) {
    uint8_t digest[VAUTH_HASH_SIZE];
    vauth_sha256(public_key, VAUTH_KEY_SIZE, digest);
    vauth_hex_encode(digest, 8, out);
}

static const char WRAP_INFO[] = "veteris-auth-1 install-key\n";

static int wrap_key(const uint8_t shared[32], const uint8_t client_public[32],
                    const uint8_t server_public[32], const char *key_id, uint8_t out[32]) {
    uint8_t salt[64];
    unsigned char info[sizeof(WRAP_INFO) - 1 + VAUTH_MAX_KEY_ID];
    size_t key_id_len = strlen(key_id);
    static const uint8_t zero[32] = {0};
    int ret;
    if (vauth_ct_equal(shared, zero, 32)) return VAUTH_E_CRYPTO;
    memcpy(salt, client_public, 32);
    memcpy(salt + 32, server_public, 32);
    memcpy(info, WRAP_INFO, sizeof(WRAP_INFO) - 1);
    memcpy(info + sizeof(WRAP_INFO) - 1, key_id, key_id_len);
    ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt, sizeof(salt), shared, 32,
                       info, sizeof(WRAP_INFO) - 1 + key_id_len, out, 32);
    return ret == 0 ? VAUTH_OK : VAUTH_E_CRYPTO;
}

int vauth_unwrap_install_key(const uint8_t client_secret[VAUTH_KEY_SIZE],
                             const uint8_t server_public[VAUTH_KEY_SIZE], const char *key_id,
                             const uint8_t wrapped[VAUTH_WRAPPED_KEY_SIZE],
                             uint8_t install_key[VAUTH_KEY_SIZE]) {
    uint8_t client_public[32], shared[32], key[32];
    mbedtls_chachapoly_context ctx;
    int ret;
    if (!client_secret || !server_public || !wrapped || !install_key || !vauth_valid_key_id(key_id))
        return VAUTH_E_ARG;
    ret = x25519(client_secret, NULL, client_public);
    if (ret == VAUTH_OK) ret = x25519(client_secret, server_public, shared);
    if (ret == VAUTH_OK) ret = wrap_key(shared, client_public, server_public, key_id, key);
    if (ret == VAUTH_OK) {
        mbedtls_chachapoly_init(&ctx);
        if (mbedtls_chachapoly_setkey(&ctx, key) != 0) {
            ret = VAUTH_E_CRYPTO;
        } else {
            int r = mbedtls_chachapoly_auth_decrypt(
                &ctx, VAUTH_KEY_SIZE, wrapped, (const unsigned char *)key_id, strlen(key_id),
                wrapped + VAUTH_WRAP_NONCE_SIZE + VAUTH_KEY_SIZE, wrapped + VAUTH_WRAP_NONCE_SIZE,
                install_key);
            if (r == MBEDTLS_ERR_CHACHAPOLY_AUTH_FAILED) ret = VAUTH_E_AUTH;
            else if (r != 0) ret = VAUTH_E_CRYPTO;
        }
        mbedtls_chachapoly_free(&ctx);
    }
    if (ret != VAUTH_OK) vauth_wipe(install_key, VAUTH_KEY_SIZE);
    vauth_wipe(shared, sizeof(shared));
    vauth_wipe(key, sizeof(key));
    return ret;
}

int vauth_wrap_install_key(const uint8_t server_secret[VAUTH_KEY_SIZE],
                           const uint8_t client_public[VAUTH_KEY_SIZE], const char *key_id,
                           const uint8_t install_key[VAUTH_KEY_SIZE],
                           const uint8_t nonce[VAUTH_WRAP_NONCE_SIZE],
                           uint8_t wrapped[VAUTH_WRAPPED_KEY_SIZE]) {
    uint8_t server_public[32], shared[32], key[32];
    mbedtls_chachapoly_context ctx;
    int ret;
    if (!server_secret || !client_public || !install_key || !nonce || !wrapped ||
        !vauth_valid_key_id(key_id))
        return VAUTH_E_ARG;
    ret = x25519(server_secret, NULL, server_public);
    if (ret == VAUTH_OK) ret = x25519(server_secret, client_public, shared);
    if (ret == VAUTH_OK) ret = wrap_key(shared, client_public, server_public, key_id, key);
    if (ret == VAUTH_OK) {
        memcpy(wrapped, nonce, VAUTH_WRAP_NONCE_SIZE);
        mbedtls_chachapoly_init(&ctx);
        if (mbedtls_chachapoly_setkey(&ctx, key) != 0 ||
            mbedtls_chachapoly_encrypt_and_tag(&ctx, VAUTH_KEY_SIZE, nonce,
                                               (const unsigned char *)key_id, strlen(key_id),
                                               install_key, wrapped + VAUTH_WRAP_NONCE_SIZE,
                                               wrapped + VAUTH_WRAP_NONCE_SIZE + VAUTH_KEY_SIZE) != 0)
            ret = VAUTH_E_CRYPTO;
        mbedtls_chachapoly_free(&ctx);
    }
    vauth_wipe(shared, sizeof(shared));
    vauth_wipe(key, sizeof(key));
    return ret;
}

#define VAUTH_MH_MAGIC     0xfeedfaceu
#define VAUTH_MH_MAGIC_64  0xfeedfacfu
#define VAUTH_LC_SEGMENT    0x1u
#define VAUTH_LC_SEGMENT_64 0x19u

static uint32_t read32(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

static uint64_t read64(const uint8_t *p) {
    uint64_t v;
    memcpy(&v, p, 8);
    return v;
}

int vauth_macho_text_hash(const void *mach_header, intptr_t slide, uint8_t out[VAUTH_HASH_SIZE]) {
    const uint8_t *header = (const uint8_t *)mach_header;
    const uint8_t *command;
    const uint8_t *text = NULL, *cstring = NULL;
    uint64_t text_size = 0, cstring_size = 0;
    uint32_t magic, ncmds, index, section_index;
    int is64;
    mbedtls_sha256_context sha;
    if (!header || !out) return VAUTH_E_ARG;
    magic = read32(header);
    if (magic != VAUTH_MH_MAGIC && magic != VAUTH_MH_MAGIC_64) return VAUTH_E_FORMAT;
    is64 = magic == VAUTH_MH_MAGIC_64;
    ncmds = read32(header + 16);
    if (ncmds > 4096) return VAUTH_E_FORMAT;
    command = header + (is64 ? 32 : 28);
    for (index = 0; index < ncmds; index++) {
        uint32_t cmd = read32(command), cmdsize = read32(command + 4);
        if (cmdsize < 8) return VAUTH_E_FORMAT;
        if ((!is64 && cmd == VAUTH_LC_SEGMENT) || (is64 && cmd == VAUTH_LC_SEGMENT_64)) {
            const uint8_t *section = command + (is64 ? 72 : 56);
            uint32_t nsects = read32(command + (is64 ? 64 : 48));
            if (strncmp((const char *)command + 8, "__TEXT", 16) == 0) {
                for (section_index = 0; section_index < nsects; section_index++) {
                    uint64_t addr = is64 ? read64(section + 32) : read32(section + 32);
                    uint64_t size = is64 ? read64(section + 40) : read32(section + 36);
                    if (strncmp((const char *)section, "__text", 16) == 0) {
                        text = (const uint8_t *)(uintptr_t)(addr + (uint64_t)slide);
                        text_size = size;
                    } else if (strncmp((const char *)section, "__cstring", 16) == 0) {
                        cstring = (const uint8_t *)(uintptr_t)(addr + (uint64_t)slide);
                        cstring_size = size;
                    }
                    section += is64 ? 80 : 68;
                }
            }
        }
        command += cmdsize;
    }
    if (!text || text_size == 0) return VAUTH_E_FORMAT;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts_ret(&sha, 0);
    mbedtls_sha256_update_ret(&sha, text, (size_t)text_size);
    if (cstring && cstring_size) mbedtls_sha256_update_ret(&sha, cstring, (size_t)cstring_size);
    mbedtls_sha256_finish_ret(&sha, out);
    mbedtls_sha256_free(&sha);
    return VAUTH_OK;
}
