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
typedef unsigned char uint8_t;
typedef enum {
        OQS_ERROR = -1,
        OQS_SUCCESS = 0,
        OQS_EXTERNAL_LIB_ERROR_OPENSSL = 50,
} OQS_STATUS;

OQS_STATUS OQS_SIG_ml_dsa_65_keypair(uint8_t *public_key,
                                     uint8_t *secret_key);

OQS_STATUS OQS_KEM_ml_kem_768_keypair(uint8_t *public_key, uint8_t *secret_key);

OQS_STATUS OQS_SIG_ml_dsa_65_sign(uint8_t *signature,
                                  size_t *signature_len,
                                  const uint8_t *message,
                                  size_t message_len,
                                  const uint8_t *secret_key);

OQS_STATUS OQS_SIG_ml_dsa_65_verify(const uint8_t *message,
                                    size_t message_len,
                                    const uint8_t *signature,
                                    size_t signature_len,
                                    const uint8_t *public_key);

OQS_STATUS OQS_KEM_ml_kem_768_encaps(uint8_t *ciphertext,
                                     uint8_t *shared_secret,
                                     const uint8_t *public_key);

OQS_STATUS OQS_KEM_ml_kem_768_decaps(uint8_t *shared_secret,
                                     const uint8_t *ciphertext,
                                     const uint8_t *secret_key);
