#!/usr/bin/env python3
"""Generate the auth build headers."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import secrets

HERE = Path(__file__).resolve().parent
BUILD_KEY = HERE / 'build_key'
STRINGS = {
    'SERVICE': 'com.victorlobe.veteris.auth',
    'ENDPOINT': 'http://api.victorlobe.me/veteris/1.1/auth/',
    'VERSION': 'X-Veteris-Auth-Version', 'KEY_ID': 'X-Veteris-Auth-KeyId',
    'TIMESTAMP': 'X-Veteris-Auth-Timestamp', 'NONCE': 'X-Veteris-Auth-Nonce',
    'SESSION': 'X-Veteris-Auth-Session', 'SIGNATURE': 'X-Veteris-Auth-Signature',
    'HELPER': 'X-Veteris-Helper-Version', 'SERVER_TIME': 'X-Veteris-Server-Time',
    'AUTH_STATE': 'X-Veteris-Auth',
}


def write_private(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(text)
    os.replace(str(temporary), str(path))


def read_key(path):
    key = bytes.fromhex(path.read_text().strip())
    if len(key) != 32:
        raise ValueError('build key must contain exactly 32 bytes as hex')
    return key


def load_build_key(kind, secrets_dir, build_key, require_operator_key):
    operator = secrets_dir / ('build_key_' + kind)
    if operator.exists():
        key = read_key(operator)
        if build_key.exists() and key == read_key(build_key):
            raise ValueError('operator build key equals ' + build_key.name)
        return key
    if require_operator_key:
        raise FileNotFoundError('missing operator build key: %s' % operator)
    return read_key(build_key)


def build_key_header(kind, key):
    shares = [secrets.token_bytes(32) for _ in range(3)]
    shares.append(bytes(key[i] ^ shares[0][i] ^ shares[1][i] ^ shares[2][i] for i in range(32)))
    # volatile keeps the compiler from folding the shares back together
    declarations, loads = [], [[] for _ in range(32)]
    for share in shares:
        name = 'v_' + secrets.token_hex(8)
        positions = secrets.SystemRandom().sample(range(256), 32)
        data = bytearray(secrets.token_bytes(256))
        for i, position in enumerate(positions):
            data[position] = share[i]
            loads[i].append('%s[%d]' % (name, position))
        declarations.append('static volatile const unsigned char %s[256] = {%s};\n' %
                            (name, ','.join(str(v) for v in data)))
    secrets.SystemRandom().shuffle(declarations)
    header = '#include <stdint.h>\n#define VAUTH_BUILD_KIND "' + kind + '"\n' + ''.join(declarations)
    header += 'static __attribute__((noinline)) void vauth_load_build_key(uint8_t out[32]) {\n'
    header += ''.join('out[%d] = %s;\n' % (i, ' ^ '.join(parts)) for i, parts in enumerate(loads))
    header += '}\n'
    return header


def prepare(kind, secrets_dir, public_keys, output, version, build_key=BUILD_KEY, require_operator_key=False):
    if kind not in ('dev', 'release'):
        raise ValueError('kind must be dev or release')
    if not re.fullmatch(r'[0-9]+(?:\.[0-9]+)*', version):
        raise ValueError('invalid helper version')
    keys = []
    for public, fingerprint in re.findall(r'public=([0-9a-f]{64}) fingerprint=([0-9a-f]{16})', public_keys.read_text()):
        if hashlib.sha256(bytes.fromhex(public)).hexdigest()[:16] != fingerprint:
            raise ValueError('server public key fingerprint mismatch')
        keys.append(public)
    if not 1 <= len(keys) <= 2:
        raise ValueError('provide the current and optionally prepared server public key')
    secret = load_build_key(kind, secrets_dir, build_key, require_operator_key)
    config = '#ifndef VAUTH_BUILD_CONFIG_H\n#define VAUTH_BUILD_CONFIG_H\n'
    config += '#define VAUTH_HELPER_VERSION "' + version + '"\n'
    config += 'static const char * const vauth_server_keys[] = {'
    config += ','.join('"' + key + '"' for key in keys) + '};\n'
    config += '#include <stddef.h>\n'
    for index, (name, text) in enumerate(STRINGS.items()):
        mask = secrets.randbelow(255) + 1
        data = [b ^ mask for b in text.encode()]
        config += '#define VAS_%s %d\n' % (name, index)
        config += 'static volatile const unsigned char vas_%d[] = {%s};\n' % (index, ','.join(map(str, data)))
        config += 'static volatile const unsigned char vam_%d = %d;\n' % (index, mask)
    config += 'static void vauth_build_string(unsigned n, char out[128]) {\nsize_t i; out[0] = 0; switch(n) {\n'
    for index, text in enumerate(STRINGS.values()):
        config += 'case %d: for(i=0;i<%d;i++) out[i]=vas_%d[i]^vam_%d; out[i]=0; break;\n' % (index, len(text), index, index)
    config += '} }\n#endif\n'
    write_private(output / 'vauth_build_config.h', config)
    write_private(output / 'vauth_build_key.h', build_key_header(kind, secret))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kind', choices=('dev', 'release'), required=True)
    parser.add_argument('--secrets-dir', type=Path, default=Path.home() / '.veteris-secrets/auth')
    parser.add_argument('--build-key', type=Path, default=BUILD_KEY)
    parser.add_argument('--require-operator-key', action='store_true')
    parser.add_argument('--public-keys', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    try:
        prepare(args.kind, args.secrets_dir, args.public_keys, args.output, args.version,
                args.build_key, args.require_operator_key)
    except (ValueError, OSError) as error:
        parser.exit(1, 'Auth build configuration failed: %s\n' % error)
