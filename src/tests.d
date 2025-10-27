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


import std.stdio;
import std.exception;
import std.json;
import std.random;

import libreshield;

unittest {
        writefln("Test suite for LibreShield %d.%d\n"
                ~"Copyright (C) 2025 Indraj Gandham\n"
                ~"This program comes with ABSOLUTELY NO WARRANTY. "
                ~"See COPYING.",
                libreshield.versionMajor,
                libreshield.versionMinor);

        writeln("Generating identities...");

        JSONValue clientIdentity;
        JSONValue clientCert;
        JSONValue serverIdentity;
        JSONValue serverCert;

        libreshield.generateIdentity(clientIdentity, clientCert);
        libreshield.generateIdentity(serverIdentity, serverCert);

        writeln("Initialising session...");

        auto client = libreshield.Session(clientIdentity, serverCert);
        auto server = libreshield.Session(serverIdentity, clientCert);

        assert(client.sessionKey != server.sessionKey);

        writeln("Performing handshake...");

        ubyte[] clientHello = client.clientHandshake();
        ubyte[] serverHello = server.serverHandshake(clientHello);
        client.clientStart(serverHello);
        server.serverStart();

        assert(client.sessionKey == server.sessionKey);

        writeln("Exchanging messages...");

        ubyte[] clientMessage = cast(ubyte[]) "Hello from client!";
        ubyte[] serverMessage = cast(ubyte[]) "Hello from server!";
        ubyte[8193] clientMessageLong = 0;
        ubyte[8193] serverMessageLong = 0;

        assert(server.unseal(client.seal(clientMessage)) == clientMessage);
        assert(client.unseal(server.seal(serverMessage)) == serverMessage);

        auto c1 = client.seal(clientMessage);
        auto c2 = client.seal(clientMessage);
        assert(server.unseal(c1) == clientMessage);
        assert(server.unseal(c2) == clientMessage);

        assert(server.unseal(client.seal(clientMessageLong))
                == clientMessageLong);
        assert(client.unseal(server.seal(serverMessageLong))
                == serverMessageLong);

        writeln("Reordered messages test...");

        c1 = client.seal(clientMessage);
        c2 = client.seal(clientMessage);

        try {
                server.unseal(c2);
                assert(false);
        }
        catch (SecurityException) { }

        writeln("Replayed message test...");

        c1 = client.seal(clientMessage);

        try {
                server.unseal(c1);
                server.unseal(c1);
                assert(false);
        }
        catch (SecurityException) { }

        writeln("Corrupted messages test...");

        c1 = client.seal(clientMessage);
        c1[uniform(0, c1.length)] ^= 1;
        try {
                server.unseal(c1);
                assert(false);
        }
        catch (SecurityException) { }

        server.messageCounter++;

        c1 = client.seal(clientMessageLong);
        c1[uniform(0, (chunkBytes + cipherTextBytes) - 1)] ^= 1;
        try {
                server.unseal(c1);
                assert(false);
        }
        catch (SecurityException) { }

        writeln("Client handshake corruption test...");

        destroy(client);
        destroy(server);

        client = libreshield.Session(clientIdentity, serverCert);
        server = libreshield.Session(serverIdentity, clientCert);

        clientHello = client.clientHandshake();
        clientHello[uniform(0, clientHello.length)] ^= 1;
        try {
                server.serverHandshake(clientHello);
                assert(false);
        }
        catch (SecurityException) { }

        writeln("Server handshake corruption test...");

        destroy(client);
        destroy(server);

        client = libreshield.Session(clientIdentity, serverCert);
        server = libreshield.Session(serverIdentity, clientCert);

        clientHello = client.clientHandshake();
        serverHello = server.serverHandshake(clientHello);
        serverHello[uniform(0, serverHello.length)] ^= 1;
        try {
                client.clientStart(serverHello);
                assert(false);
        }
        catch (SecurityException) { }

        writeln("Client handshake replay test...");

        destroy(client);
        destroy(server);

        client = libreshield.Session(clientIdentity, serverCert);
        server = libreshield.Session(serverIdentity, clientCert);

        clientHello = client.clientHandshake();
        serverHello = server.serverHandshake(clientHello);
        client.clientStart(serverHello);
        server.serverStart();

        c1 = client.seal(clientMessage);

        destroy(client);
        destroy(server);

        server = libreshield.Session(serverIdentity, clientCert);
        server.serverHandshake(clientHello);
        server.serverStart();
        try {
                server.unseal(c1);
                assert(false);
        }
        catch (SecurityException) { }

        writeln("Server handshake replay test...");

        destroy(client);
        destroy(server);

        client = libreshield.Session(clientIdentity, serverCert);
        server = libreshield.Session(serverIdentity, clientCert);

        clientHello = client.clientHandshake();
        serverHello = server.serverHandshake(clientHello);
        client.clientStart(serverHello);
        server.serverStart();

        c1 = server.seal(serverMessage);

        destroy(client);
        destroy(server);

        client = libreshield.Session(clientIdentity, serverCert);
        client.clientHandshake();
        client.clientStart(serverHello);
        try {
                client.unseal(c1);
                assert(false);
        }
        catch (SecurityException) { }

        writeln("Counter reset and key rotation test...");

        destroy(client);
        destroy(server);

        client = libreshield.Session(clientIdentity, serverCert);
        server = libreshield.Session(serverIdentity, clientCert);

        clientHello = client.clientHandshake();
        serverHello = server.serverHandshake(clientHello);
        client.clientStart(serverHello);
        server.serverStart();

        auto oldKey = client.sessionKey;

        client.messageCounter = uint.max;
        server.messageCounter = uint.max;
        server.unseal(client.seal(clientMessage));

        assert(client.sessionKey != oldKey);
        assert(server.sessionKey != oldKey);
        assert(client.messageCounter == 0);
        assert(server.messageCounter == 0);
}

void main() { }
