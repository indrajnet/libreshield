<!--
Copyright (C) 2025 Indraj Gandham <support@indraj.net>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
-->


LibreShield is a modern, easy-to-use alternative to mTLS for secure
communication across untrusted networks.
It features post-quantum cryptography (PQC), perfect forward secrecy and
anti-replay protection.

LibreShield can be used with any transport layer protocol, provided that
streams are reliable and in-order.
Adoption of LibreShield may help your organisation align with the
[PQC migration timelines](https://www.ncsc.gov.uk/guidance/pqc-migration-timelines)
set out by the UK NCSC.

## Examples

Generating an identity:

```d
JSONValue cert;
JSONValue identity;
libreshield.generateIdentity(identity, cert);
```

Creating a session:

```d
auto client = libreshield.Session(clientIdentity, serverCert);
auto server = libreshield.Session(serverIdentity, clientCert);
ubyte[] clientHello = client.clientHandshake();
ubyte[] serverHello = server.serverHandshake(clientHello);
client.clientStart(serverHello);
server.serverStart();
```

Exchanging messages:

```d
ubyte[] clientMessage = cast(ubyte[]) "Hello from client!";
ubyte[] serverMessage = cast(ubyte[]) "Hello from server!";
assert(server.unseal(client.seal(clientMessage)) == clientMessage);
assert(client.unseal(server.seal(serverMessage)) == serverMessage);
```

The full documentation can be found under `/doc` as an scdoc manpage.

## Cryptography

Identities use a hybrid combination of ed25519 and ML-DSA-65.
Key exchange uses a hybrid combination of ECDH (X25519) and KEM
(ML-KEM-768).
Messages are encrypted using XChaCha20-Poly1305.

## API stability

Interface stability is guaranteed for releases within a
single major series.

## Compatibility

The target platform is GNU/Linux, but the code is mostly portable.

## Dependencies

To use the LibreShield module, the following dependencies are required:

- the GNU D compiler (gdc)
- libsodium
- liboqs

To build the test suite, you will need:

- GNU make

To build the documentation, you will need:

- scdoc

## Report a bug

Report bugs directly to [support@indraj.net](mailto:support@indraj.net).

For security vulnerabilities, please allow up to 48 hours for a reply,
and up to 90 days for the issue(s) to be confirmed and fixed before
disclosing them publicly.

## License

LibreShield is licensed under the GNU Affero General Public License.
