/*
 * Copyright (C) 2025 Indraj Gandham <support@indraj.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */


typedef unsigned long size_t;   // POSIX only

typedef struct crypto_secretstream_xchacha20poly1305_state {
        unsigned char k[32];
        unsigned char nonce[24];
        unsigned char _pad[8];
} crypto_secretstream_xchacha20poly1305_state;

int sodium_init(void);
void sodium_memzero(void *const pnt, const size_t len);
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);
int crypto_kx_keypair(unsigned char *pk, unsigned char *sk);
void randombytes_buf(void *const buf, const size_t size);

int crypto_sign_detached(unsigned char *sig,
                         unsigned long long *siglen_p,
                         const unsigned char *m,
                         unsigned long long mlen,
                         const unsigned char *sk);

int crypto_sign_verify_detached(const unsigned char *sig,
                                const unsigned char *m,
                                unsigned long long mlen,
                                const unsigned char *pk);

int crypto_kx_client_session_keys(unsigned char *rx,
                                  unsigned char *tx,
                                  const unsigned char *client_pk,
                                  const unsigned char *client_sk,
                                  const unsigned char *server_pk);

int crypto_kx_server_session_keys(unsigned char *rx,
                                  unsigned char *tx,
                                  const unsigned char *server_pk,
                                  const unsigned char *server_sk,
                                  const unsigned char *client_pk);

int crypto_generichash(unsigned char *out,
                       size_t outlen,
                       const unsigned char *in,
                       unsigned long long inlen,
                       const unsigned char *key,
                       size_t keylen);

int crypto_secretstream_xchacha20poly1305_init_push(
        crypto_secretstream_xchacha20poly1305_state *state,
        unsigned char *header,
        const unsigned char *k);

int crypto_secretstream_xchacha20poly1305_push(
        crypto_secretstream_xchacha20poly1305_state *state,
        unsigned char *c,
        unsigned long long *clen_p,
        const unsigned char *m,
        unsigned long long mlen,
        const unsigned char *ad,
        unsigned long long adlen,
        unsigned char tag);

int crypto_secretstream_xchacha20poly1305_init_pull(
        crypto_secretstream_xchacha20poly1305_state *state,
        const unsigned char *header,
        const unsigned char *k);

int crypto_secretstream_xchacha20poly1305_pull(
        crypto_secretstream_xchacha20poly1305_state *state,
        unsigned char *m,
        unsigned long long *mlen_p,
        unsigned char *tag_p,
        const unsigned char *c,
        unsigned long long clen,
        const unsigned char *ad,
        unsigned long long adlen);
