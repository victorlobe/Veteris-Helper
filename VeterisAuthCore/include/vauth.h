#ifndef VAUTH_H
#define VAUTH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VAUTH_PROTOCOL_VERSION "1"

#define VAUTH_HOST "api.victorlobe.me"

#define VAUTH_HEADER_VERSION   "X-Veteris-Auth-Version"
#define VAUTH_HEADER_KEY_ID    "X-Veteris-Auth-KeyId"
#define VAUTH_HEADER_TIMESTAMP "X-Veteris-Auth-Timestamp"
#define VAUTH_HEADER_NONCE     "X-Veteris-Auth-Nonce"
#define VAUTH_HEADER_SESSION   "X-Veteris-Auth-Session"
#define VAUTH_HEADER_SIGNATURE "X-Veteris-Auth-Signature"
#define VAUTH_HEADER_HELPER    "X-Veteris-Helper-Version"
#define VAUTH_HEADER_SERVER_TIME "X-Veteris-Server-Time"
#define VAUTH_HEADER_AUTH_STATE  "X-Veteris-Auth"

#define VAUTH_KEY_SIZE        32
#define VAUTH_HASH_SIZE       32
#define VAUTH_HASH_HEX_SIZE   65
#define VAUTH_NONCE_SIZE      16
#define VAUTH_NONCE_HEX_SIZE  33
#define VAUTH_WRAP_NONCE_SIZE 12
#define VAUTH_WRAP_TAG_SIZE   16
#define VAUTH_WRAPPED_KEY_SIZE (VAUTH_WRAP_NONCE_SIZE + VAUTH_KEY_SIZE + VAUTH_WRAP_TAG_SIZE)
#define VAUTH_FINGERPRINT_HEX_SIZE 17
#define VAUTH_MAX_KEY_ID   64
#define VAUTH_MAX_SESSION  256
#define VAUTH_MAX_VERSION  32

#define VAUTH_OK            0
#define VAUTH_E_ARG        -1
#define VAUTH_E_SIZE       -2
#define VAUTH_E_PATH       -3
#define VAUTH_E_CRYPTO     -4
#define VAUTH_E_AUTH       -5
#define VAUTH_E_FORMAT     -6

typedef int (*vauth_random_fn)(void *ctx, unsigned char *out, size_t len);
int vauth_random_urandom(void *ctx, unsigned char *out, size_t len);

void vauth_hex_encode(const uint8_t *in, size_t len, char *out);
int vauth_hex_decode(const char *hex, uint8_t *out, size_t out_len);
int vauth_ct_equal(const void *a, const void *b, size_t len);
void vauth_wipe(void *p, size_t len);

void vauth_sha256(const void *data, size_t len, uint8_t out[VAUTH_HASH_SIZE]);
void vauth_hmac_sha256(const uint8_t *key, size_t key_len, const void *data, size_t len,
                       uint8_t out[VAUTH_HASH_SIZE]);

typedef struct {
    const char *host;  size_t host_len;
    const char *path;  size_t path_len;
    const char *query; size_t query_len;
} vauth_url_parts;
int vauth_split_url(const char *url, vauth_url_parts *parts);

int vauth_is_signed_host(const char *host, size_t host_len);

int vauth_canonical_path(const char *path, size_t path_len, char *out, size_t out_size,
                         size_t *out_len);

typedef struct {
    const char *method;
    const char *path;
    size_t path_len;
    const char *query;
    size_t query_len;
    const uint8_t *body;
    size_t body_len;
    int64_t timestamp;
    const char *nonce_hex;
    const char *key_id;
    const char *session;
    const char *veteris_version;
    const char *helper_version;
} vauth_request;

int vauth_canonical_request(const vauth_request *req, char *out, size_t out_size,
                            size_t *out_len);

int vauth_sign_request(const uint8_t install_key[VAUTH_KEY_SIZE], const vauth_request *req,
                       char signature_hex[VAUTH_HASH_HEX_SIZE]);

int vauth_new_nonce(vauth_random_fn rng, void *rng_ctx, char nonce_hex[VAUTH_NONCE_HEX_SIZE]);

int vauth_x25519_keypair(vauth_random_fn rng, void *rng_ctx, uint8_t secret[VAUTH_KEY_SIZE],
                         uint8_t public_key[VAUTH_KEY_SIZE]);
int vauth_x25519(const uint8_t secret[VAUTH_KEY_SIZE], const uint8_t peer_public[VAUTH_KEY_SIZE],
                 uint8_t shared[VAUTH_KEY_SIZE]);

void vauth_key_fingerprint(const uint8_t public_key[VAUTH_KEY_SIZE],
                           char out[VAUTH_FINGERPRINT_HEX_SIZE]);

int vauth_unwrap_install_key(const uint8_t client_secret[VAUTH_KEY_SIZE],
                             const uint8_t server_public[VAUTH_KEY_SIZE], const char *key_id,
                             const uint8_t wrapped[VAUTH_WRAPPED_KEY_SIZE],
                             uint8_t install_key[VAUTH_KEY_SIZE]);
int vauth_wrap_install_key(const uint8_t server_secret[VAUTH_KEY_SIZE],
                           const uint8_t client_public[VAUTH_KEY_SIZE], const char *key_id,
                           const uint8_t install_key[VAUTH_KEY_SIZE],
                           const uint8_t nonce[VAUTH_WRAP_NONCE_SIZE],
                           uint8_t wrapped[VAUTH_WRAPPED_KEY_SIZE]);

int vauth_valid_key_id(const char *key_id);
int vauth_valid_session(const char *session);

int vauth_macho_text_hash(const void *mach_header, intptr_t slide, uint8_t out[VAUTH_HASH_SIZE]);

#ifdef __cplusplus
}
#endif

#endif
