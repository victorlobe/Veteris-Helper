#ifndef VAUTH_ATTEST_H
#define VAUTH_ATTEST_H

#include "vauth.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *challenge_hex;
    const char *subject;
    const char *veteris_version;
    const char *helper_version;
    const uint8_t *text_hash;
} vauth_attest_input;

int vauth_attest_message(const char *kind, const vauth_attest_input *in, char *out,
                         size_t out_size, size_t *out_len);

const char *vauth_attest_kind(void);
int vauth_attest(const vauth_attest_input *in, char proof_hex[VAUTH_HASH_HEX_SIZE]);

#ifdef __cplusplus
}
#endif

#endif
