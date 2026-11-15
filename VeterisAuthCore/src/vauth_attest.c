#include "vauth_attest.h"
#include "vauth_build_key.h"

const char *vauth_attest_kind(void) { return VAUTH_BUILD_KIND; }

int vauth_attest(const vauth_attest_input *in, char proof_hex[VAUTH_HASH_HEX_SIZE]) {
    char message[512];
    uint8_t key[32] = {0}, effective[32] = {0}, mac[32] = {0};
    size_t len = 0;
    int result;
    if (!in || !in->text_hash || !proof_hex) return VAUTH_E_ARG;
    proof_hex[0] = 0;
    result = vauth_attest_message(vauth_attest_kind(), in, message, sizeof(message), &len);
    if (result == VAUTH_OK) {
        vauth_load_build_key(key);
        vauth_hmac_sha256(key, sizeof(key), in->text_hash, 32, effective);
        vauth_wipe(key, sizeof(key));
        vauth_hmac_sha256(effective, sizeof(effective), message, len, mac);
        vauth_hex_encode(mac, sizeof(mac), proof_hex);
    }
    vauth_wipe(key, sizeof(key));
    vauth_wipe(effective, sizeof(effective));
    vauth_wipe(mac, sizeof(mac));
    vauth_wipe(message, sizeof(message));
    return result;
}
