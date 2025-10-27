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


module libreshield;

import std.stdio;
import std.exception;
import std.json;
import std.base64;
import std.bitmanip;

import sodium;
import oqs;

enum versionMajor = 1;  // breaking changes
enum versionMinor = 0;  // non-breaking changes

// signing
enum publicKeyBytes = 32;
enum privateKeyBytes = 64;
enum signatureBytes = 64;
enum PQCPublicKeyBytes = 1952;
enum PQCPrivateKeyBytes = 4032;
enum PQCSignatureBytes = 3309;

// key exchange
enum ECDHPublicKeyBytes = 32;
enum ECDHPrivateKeyBytes = 32;
enum ECDHSessionKeyBytes = 32;
enum KEMPublicKeyBytes = 1184;
enum KEMPrivateKeyBytes = 2400;
enum KEMSessionKeyBytes = 32;
enum KEMCipherTextBytes = 1088;
enum nonceBytes = 24;
enum clientHelloBytes = nonceBytes +
                        ECDHPublicKeyBytes +
                        KEMPublicKeyBytes +
                        signatureBytes +
                        PQCSignatureBytes;
enum serverHelloBytes = nonceBytes +
                        ECDHPublicKeyBytes +
                        KEMCipherTextBytes +
                        signatureBytes +
                        PQCSignatureBytes;

// session
enum sessionKeyBytes = 32;
enum hashInputBytes = (nonceBytes * 2) +
                       ECDHSessionKeyBytes +
                       KEMSessionKeyBytes;
enum chunkBytes = 8192;
enum headerBytes = 24;
enum cipherTextBytes = 17;

class SecurityException : Exception
{
        this(string msg, string file = __FILE__, size_t line = __LINE__)
        {
                super(msg, file, line);
        }
}

struct Session {

        // signing
        ubyte[publicKeyBytes]           identityPublicKey;
        ubyte[PQCPublicKeyBytes]        PQCIdentityPublicKey;
        ubyte[privateKeyBytes]          identityPrivateKey;
        ubyte[PQCPrivateKeyBytes]       PQCIdentityPrivateKey;
        ubyte[publicKeyBytes]           certIdentityPublicKey;
        ubyte[PQCPublicKeyBytes]        certPQCIdentityPublicKey;

        // key exchange
        ubyte[ECDHPublicKeyBytes]       clientECDHPublicKey;
        ubyte[ECDHPrivateKeyBytes]      ECDHPrivateKey;
        ubyte[ECDHPublicKeyBytes]       serverECDHPublicKey;
        ubyte[ECDHSessionKeyBytes]      ECDHSessionKey;
        ubyte[KEMPublicKeyBytes]        clientKEMPublicKey;
        ubyte[KEMPrivateKeyBytes]       KEMPrivateKey;
        ubyte[KEMSessionKeyBytes]       KEMSessionKey;
        ubyte[KEMCipherTextBytes]       KEMCipherText;
        ubyte[nonceBytes]               clientNonce;
        ubyte[nonceBytes]               serverNonce;

        // session
        ubyte[sessionKeyBytes]          sessionKey;
        uint                            messageCounter;

        this(JSONValue identity, JSONValue cert)
        {
                enforce(sodium_init() >= 0, "failed to initialise libsodium");

                this.identityPrivateKey = Base64.decode(
                        identity["private"]["ed25519"].str);
                this.PQCIdentityPrivateKey = Base64.decode(
                        identity["private"]["ml_dsa_65"].str);
                this.identityPublicKey = Base64.decode(
                        identity["public"]["ed25519"].str);
                this.PQCIdentityPublicKey = Base64.decode(
                        identity["public"]["ml_dsa_65"].str);

                this.certIdentityPublicKey = Base64.decode(
                        cert["public"]["ed25519"].str);
                this.certPQCIdentityPublicKey = Base64.decode(
                        cert["public"]["ml_dsa_65"].str);

                this.messageCounter = 0;
                randombytes_buf(this.sessionKey.ptr, this.sessionKey.length);
        }

        ~this()
        {
                sodium_memzero(this.identityPrivateKey.ptr,
                               this.identityPrivateKey.length);
                sodium_memzero(this.PQCIdentityPrivateKey.ptr,
                               this.PQCIdentityPrivateKey.length);
                sodium_memzero(this.ECDHPrivateKey.ptr,
                               this.ECDHPrivateKey.length);
                sodium_memzero(this.ECDHSessionKey.ptr,
                               this.ECDHSessionKey.length);
                sodium_memzero(this.KEMPrivateKey.ptr,
                               this.KEMPrivateKey.length);
                sodium_memzero(this.KEMSessionKey.ptr,
                               this.KEMSessionKey.length);
                sodium_memzero(this.sessionKey.ptr,
                               this.sessionKey.length);
        }
}

ubyte[] clientHandshake(ref Session session)
{
        ubyte[] toServer;
        toServer.reserve(clientHelloBytes);

        randombytes_buf(session.clientNonce.ptr, session.clientNonce.length);
        toServer ~= session.clientNonce;

        crypto_kx_keypair(session.clientECDHPublicKey.ptr,
                          session.ECDHPrivateKey.ptr);
        toServer ~= session.clientECDHPublicKey;
        OQS_STATUS rc = OQS_KEM_ml_kem_768_keypair(
                                        session.clientKEMPublicKey.ptr,
                                        session.KEMPrivateKey.ptr);
        enforce(rc == OQS_SUCCESS, "failed to create KEM keys");
        toServer ~= session.clientKEMPublicKey;

        ubyte[signatureBytes] signature;
        ubyte[PQCSignatureBytes] PQCSignature;

        crypto_sign_detached(signature.ptr,
                             null,
                             toServer.ptr,
                             toServer.length,
                             session.identityPrivateKey.ptr);
        ulong sigLength;
        rc = OQS_SIG_ml_dsa_65_sign(PQCSignature.ptr,
                                    &sigLength,
                                    toServer.ptr,
                                    toServer.length,
                                    session.PQCIdentityPrivateKey.ptr);
        enforce(rc == OQS_SUCCESS, "failed to sign hello");

        toServer ~= signature;
        toServer ~= PQCSignature;

        return toServer;
}

ubyte[] serverHandshake(ref Session session, ubyte[] hello)
{
        if (hello.length != clientHelloBytes) {
                throw new SecurityException("invalid client hello");
        }

        ulong end = 0;
        end += nonceBytes;
        session.clientNonce = hello[0 .. end];
        end += ECDHPublicKeyBytes;
        session.clientECDHPublicKey =
                        hello[(end - ECDHPublicKeyBytes) .. end];
        end += KEMPublicKeyBytes;
        session.clientKEMPublicKey =
                        hello[(end - KEMPublicKeyBytes) .. end];

        ubyte[] message = hello[0 .. end];
        ubyte[signatureBytes] clientSignature;
        ubyte[PQCSignatureBytes] clientPQCSignature;

        end += signatureBytes;
        clientSignature = hello[(end - signatureBytes) .. end];
        end += PQCSignatureBytes;
        clientPQCSignature = hello[(end - PQCSignatureBytes) .. end];

        if (crypto_sign_verify_detached(clientSignature.ptr,
                                        message.ptr,
                                        message.length,
                                        session.certIdentityPublicKey.ptr)
                                        != 0) {
                throw new SecurityException("invalid signature");
        }

        if (OQS_SIG_ml_dsa_65_verify(message.ptr,
                                     message.length,
                                     clientPQCSignature.ptr,
                                     PQCSignatureBytes,
                                     session.certPQCIdentityPublicKey.ptr)
                                     != OQS_SUCCESS) {
                throw new SecurityException("invalid PQC signature");
        }
        
        ubyte[] toClient;
        toClient.reserve(serverHelloBytes);

        randombytes_buf(session.serverNonce.ptr, session.serverNonce.length);
        toClient ~= session.serverNonce;

        crypto_kx_keypair(session.serverECDHPublicKey.ptr,
                          session.ECDHPrivateKey.ptr);
        toClient ~= session.serverECDHPublicKey;

        OQS_STATUS rc = OQS_KEM_ml_kem_768_encaps(
                                        session.KEMCipherText.ptr,
                                        session.KEMSessionKey.ptr,
                                        session.clientKEMPublicKey.ptr);
        enforce(rc == OQS_SUCCESS, "failed to encapsulate secret");
        toClient ~= session.KEMCipherText;

        ubyte[signatureBytes] signature;
        ubyte[PQCSignatureBytes] PQCSignature;

        crypto_sign_detached(signature.ptr,
                             null,
                             toClient.ptr,
                             toClient.length,
                             session.identityPrivateKey.ptr);
        ulong sigLength;
        rc = OQS_SIG_ml_dsa_65_sign(PQCSignature.ptr,
                                    &sigLength,
                                    toClient.ptr,
                                    toClient.length,
                                    session.PQCIdentityPrivateKey.ptr);
        enforce(rc == OQS_SUCCESS, "failed to sign hello");

        toClient ~= signature;
        toClient ~= PQCSignature;

        return toClient;
}

void clientStart(ref Session session, ubyte[] hello)
{
        if (hello.length != serverHelloBytes) {
                throw new SecurityException("invalid server hello");
        }

        ulong end = 0;
        end += nonceBytes;
        session.serverNonce = hello[0 .. end];
        end += ECDHPublicKeyBytes;
        session.serverECDHPublicKey =
                        hello[(end - ECDHPublicKeyBytes) .. end];
        end += KEMCipherTextBytes;
        session.KEMCipherText =
                        hello[(end - KEMCipherTextBytes) .. end];

        ubyte[] message = hello[0 .. end];
        ubyte[signatureBytes] serverSignature;
        ubyte[PQCSignatureBytes] serverPQCSignature;

        end += signatureBytes;
        serverSignature = hello[(end - signatureBytes) .. end];
        end += PQCSignatureBytes;
        serverPQCSignature = hello[(end - PQCSignatureBytes) .. end];

        if (crypto_sign_verify_detached(serverSignature.ptr,
                                        message.ptr,
                                        message.length,
                                        session.certIdentityPublicKey.ptr)
                                        != 0) {
                throw new SecurityException("invalid signature");
        }

        if (OQS_SIG_ml_dsa_65_verify(message.ptr,
                                     message.length,
                                     serverPQCSignature.ptr,
                                     PQCSignatureBytes,
                                     session.certPQCIdentityPublicKey.ptr)
                                     != OQS_SUCCESS) {
                throw new SecurityException("invalid PQC signature");
        }

        OQS_STATUS rc = OQS_KEM_ml_kem_768_decaps(session.KEMSessionKey.ptr,
                                                  session.KEMCipherText.ptr,
                                                  session.KEMPrivateKey.ptr);
        if (rc != OQS_SUCCESS) {
                throw new SecurityException("invalid ciphertext");
        }

        if (crypto_kx_client_session_keys(session.ECDHSessionKey.ptr,
                                          null,
                                          session.clientECDHPublicKey.ptr,
                                          session.ECDHPrivateKey.ptr,
                                          session.serverECDHPublicKey.ptr)
                                          != 0) {
                throw new SecurityException("invalid public key");
        }

        ubyte[] hashInput;
        hashInput.reserve(hashInputBytes);
        scope(exit) sodium_memzero(hashInput.ptr, hashInput.length);

        hashInput ~= session.clientNonce;
        hashInput ~= session.serverNonce;
        hashInput ~= session.ECDHSessionKey;
        hashInput ~= session.KEMSessionKey;

        crypto_generichash(session.sessionKey.ptr,
                           sessionKeyBytes,
                           hashInput.ptr,
                           hashInputBytes,
                           null,
                           0);
}

void serverStart(ref Session session)
{
        if (crypto_kx_server_session_keys(session.ECDHSessionKey.ptr,
                                          null,
                                          session.serverECDHPublicKey.ptr,
                                          session.ECDHPrivateKey.ptr,
                                          session.clientECDHPublicKey.ptr)
                                          != 0) {
                throw new SecurityException("invalid public key");
        }

        ubyte[] hashInput;
        hashInput.reserve(hashInputBytes);
        scope(exit) sodium_memzero(hashInput.ptr, hashInput.length);

        hashInput ~= session.clientNonce;
        hashInput ~= session.serverNonce;
        hashInput ~= session.ECDHSessionKey;
        hashInput ~= session.KEMSessionKey;

        crypto_generichash(session.sessionKey.ptr,
                           sessionKeyBytes,
                           hashInput.ptr,
                           hashInputBytes,
                           null,
                           0);
}

ubyte[] seal(ref Session session, ubyte[] plainText)
{
        crypto_secretstream_xchacha20poly1305_state state;
        ubyte[headerBytes] header;
        ubyte[chunkBytes + cipherTextBytes] cipherChunk;
        ubyte[] cipherText;
        auto sessionCounterByteArray = nativeToLittleEndian(
                                                session.messageCounter);

        ulong start = 0;
        ulong end = 0;

        crypto_secretstream_xchacha20poly1305_init_push(
                &state,
                header.ptr,
                session.sessionKey.ptr);
        cipherText ~= header;

        while (true) {
                end += chunkBytes;
                if (end >= plainText.length) {
                        end = plainText.length;
                        break;
                }
                crypto_secretstream_xchacha20poly1305_push(
                        &state,
                        cipherChunk.ptr,
                        null,
                        plainText[start .. end].ptr,
                        chunkBytes,
                        sessionCounterByteArray.ptr,
                        sessionCounterByteArray.length,
                        0);
                cipherText ~= cipherChunk;
                start += chunkBytes;
        }

        ulong bytesWritten;
        crypto_secretstream_xchacha20poly1305_push(
                &state,
                cipherChunk.ptr,
                &bytesWritten,
                plainText[start .. end].ptr,
                (end - start),
                sessionCounterByteArray.ptr,
                sessionCounterByteArray.length,
                3);
        cipherText ~= cipherChunk[0 .. bytesWritten];

        if (session.messageCounter == uint.max) {
                ubyte[sessionKeyBytes] oldKey = session.sessionKey;
                crypto_generichash(session.sessionKey.ptr,
                                   sessionKeyBytes,
                                   oldKey.ptr,
                                   sessionKeyBytes,
                                   null,
                                   0);
                session.messageCounter = 0;
        } else {
                session.messageCounter++;
        }

        return cipherText;
}

ubyte[] unseal(ref Session session, ubyte[] cipherText)
{
        crypto_secretstream_xchacha20poly1305_state state;
        ubyte[chunkBytes] chunk;
        ubyte tag;
        ubyte[] plainText;
        auto sessionCounterByteArray = nativeToLittleEndian(
                                                session.messageCounter);

        ulong start = headerBytes;
        ulong end = headerBytes;

        scope(exit) sodium_memzero(chunk.ptr, chunk.length);

        if (crypto_secretstream_xchacha20poly1305_init_pull(
                &state,
                cipherText.ptr,
                session.sessionKey.ptr)
                != 0) {

                throw new SecurityException("invalid header");
        }

        while (true) {
                end += (chunkBytes + cipherTextBytes);
                if (end >= cipherText.length) {
                        end = cipherText.length;
                        break;
                }
                if (crypto_secretstream_xchacha20poly1305_pull(
                        &state,
                        chunk.ptr,
                        null,
                        &tag,
                        cipherText[start .. end].ptr,
                        (chunkBytes + cipherTextBytes),
                        sessionCounterByteArray.ptr,
                        sessionCounterByteArray.length)
                        != 0) {
                        
                        throw new SecurityException("invalid stream");
                }
                if (tag != 0) throw new SecurityException("invalid tag");

                plainText ~= chunk;
                start += (chunkBytes + cipherTextBytes);
        }

        ulong bytesWritten;
        if (crypto_secretstream_xchacha20poly1305_pull(
                &state,
                chunk.ptr,
                &bytesWritten,
                &tag,
                cipherText[start .. end].ptr,
                (end - start),
                sessionCounterByteArray.ptr,
                sessionCounterByteArray.length)
                != 0) {
                
                throw new SecurityException("invalid stream");
        }
        if (tag != 3) throw new SecurityException("invalid tag");

        plainText ~= chunk[0 .. bytesWritten];

        if (session.messageCounter == uint.max) {
                ubyte[sessionKeyBytes] oldKey = session.sessionKey;
                crypto_generichash(session.sessionKey.ptr,
                                   sessionKeyBytes,
                                   oldKey.ptr,
                                   sessionKeyBytes,
                                   null,
                                   0);
                session.messageCounter = 0;
        } else {
                session.messageCounter++;
        }

        return plainText;
}

void generateIdentity(ref JSONValue identity, ref JSONValue cert)
{
        ubyte[publicKeyBytes]           identityPublicKey;
        ubyte[PQCPublicKeyBytes]        PQCIdentityPublicKey;
        ubyte[privateKeyBytes]          identityPrivateKey;
        ubyte[PQCPrivateKeyBytes]       PQCIdentityPrivateKey;

        scope(exit) sodium_memzero(identityPrivateKey.ptr,
                                   identityPrivateKey.length);
        scope(exit) sodium_memzero(PQCIdentityPrivateKey.ptr,
                                   PQCIdentityPrivateKey.length);
        
        enforce(sodium_init() >= 0, "failed to initialise libsodium");
        crypto_sign_keypair(identityPublicKey.ptr, identityPrivateKey.ptr);
        OQS_STATUS rc = OQS_SIG_ml_dsa_65_keypair(
                                PQCIdentityPublicKey.ptr,
                                PQCIdentityPrivateKey.ptr);
        enforce(rc == OQS_SUCCESS, "failed to create PQC signing keys");

        identity = [
                        "public": [
                                "ed25519":
                                        Base64.encode(identityPublicKey),
                                "ml_dsa_65":
                                        Base64.encode(PQCIdentityPublicKey),
                        ],
                        "private": [
                                "ed25519":
                                        Base64.encode(identityPrivateKey),
                                "ml_dsa_65":
                                        Base64.encode(PQCIdentityPrivateKey),
                        ],
        ];

        cert = [
                        "public": [
                                "ed25519":
                                        Base64.encode(identityPublicKey),
                                "ml_dsa_65":
                                        Base64.encode(PQCIdentityPublicKey),
                        ],
        ];
}
