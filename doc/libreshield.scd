LIBRESHIELD(3)["version 1.0"]

; Copyright (C) 2025 Indraj Gandham <support@indraj.net>

; This program is free software: you can redistribute it and/or modify
; it under the terms of the GNU Affero General Public License as published by
; the Free Software Foundation, either version 3 of the License, or
; (at your option) any later version.

; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU Affero General Public License for more details.

; You should have received a copy of the GNU Affero General Public License
; along with this program.  If not, see <https://www.gnu.org/licenses/>.


# ABOUT

LibreShield is a modern, easy-to-use alternative to mTLS for secure
communication across untrusted networks.
It features post-quantum cryptography (PQC), perfect forward secrecy and
anti-replay protection.

LibreShield can be used with any transport layer protocol, provided that
streams are reliable and in-order.
Adoption of LibreShield may help your organisation align with the
PQC migration timelines set out by the UK NCSC.

# PRACTICAL ADVICE

If you are defining a new protocol, you should consider compressing your
plaintexts (e.g. with zstd) prior to encryption.
You should also consider the use of a messaging library (e.g. ZeroMQ).

# INTERFACE

## class SecurityException : Exception;

Some functions throw SecurityException when they detect corruption or tampering
in a data stream.
When this exception is raised, you should catch it and reset the session.

## void generateIdentity(ref JSONValue identity, ref JSONValue cert);

Generates a new identity and a corresponding certificate.
The identity must be kept secret and the certificate must be securely
pre-shared.
Both are stored in JSON format, and the keys themselves are Base64 encoded
strings.
They can be written to files, databases or any other medium, as long as they
can be converted back into JSONValue types for the Session constructor.

_Example_

```
JSONValue cert;
JSONValue identity;
libreshield.generateIdentity(identity, cert);
```

## struct Session(JSONValue identity, JSONValue cert);

This is the main type defined by LibreShield.
The constructor accepts the identity of this host and the certificate of the
remote host.

IMPORTANT: you must call destroy() on Session when it is no longer needed;
this ensures that memory locations containing sensitive data are overwritten.

The functions which accept Session are designed to be called using UFCS
(Universal Functional Call Syntax), which simulates object-oriented
programming.
However, this is optional.

_Example_

```
auto client = libreshield.Session(clientIdentity, serverCert);
auto server = libreshield.Session(serverIdentity, clientCert);
destroy(client);
destroy(server);
```

## ubyte[] clientHandshake(ref Session session);

This function prepares the client hello message, which will be sent to the
server and used in the handshake.

The message contains two ephemeral public keys (X25519 and ML-KEM-768) and a
random 192-bit nonce.
It also contains two signatures (ed25519 and ML-DSA-65)
which the server will validate during the handshake.

_Example_

```
ubyte[] clientHello = client.clientHandshake();
```

## ubyte[] serverHandshake(ref Session session, ubyte[] hello);

This function accepts the client hello message, validates the signatures,
then generates the server hello message.
This will be sent back to the client and used to complete the handshake.

The message contains an ephemeral public key (X25519), an encapsulated secret
(ML-KEM-768) and a random 192-bit nonce.
It also contains two signatures (ed25519 and ML-DSA-65)
which the client will validate before completing the handshake.

This function can throw SecurityException.

_Example_

```
try {
        auto serverHello = server.serverHandshake(clientHello);
}
catch (SecurityException) {
        // reset the session!
}

```

## void clientStart(ref Session session, ubyte[] hello);

This function accepts the server hello message and completes the handshake.

The server's signatures are validated, then the PQC secret is de-encapsulated.
ECDH is performed to derive the classical secret.
Both secrets and both client and server nonces are concatenated and hashed
using BLAKE2b to derive the session key.

This function can throw SecurityException.

_Example_

```
try {
        client.clientStart(serverHello);
}
catch (SecurityException) {
        // reset the session!
}
```

## void serverStart(ref Session session);

This function completes the handshake.

ECDH is performed to derive the classical secret.
(The PQC secret was generated during serverHandshake().)
Both secrets and both client and server nonces are concatenated and hashed
using BLAKE2b to derive the session key.

This function can throw SecurityException.

_Example_

```
try {
        server.serverStart();
}
catch (SecurityException) {
        // reset the session!
}
```

## ubyte[] seal(ref Session session, ubyte[] plainText);

This function encrypts a message to a remote host.

Encryption is performed using the XChaCha20-Poly1305 AEAD construction.
A counter is used as part of the MAC calculation so that the remote host can
verify that the message has not been replayed.

When this counter reaches (2^32 - 1), the session key is rotated using
BLAKE2b and the counter is reset.

_Example_

```
ubyte[] plainText = cast(ubyte[]) "Hello from client!";
ubyte[] cipherText = client.seal(plainText);
```

## ubyte[] unseal(ref Session session, ubyte[] cipherText);

This function decrypts a message from a remote host.

Decryption is performed using the XChaCha20-Poly1305 AEAD construction.
A counter is used as part of the MAC calculation so that the decryption process
will fail if the message has been replayed.

When this counter reaches (2^32 - 1), the session key is rotated using
BLAKE2b and the counter is reset.

This function can throw SecurityException.

_Example_

```
try {
        plainText = server.unseal(cipherText);
}
catch (SecurityException) {
        // reset the session!
}
```
