#!/usr/bin/env python3
"""Reset the live-test server to a clean state between runs.

The live tests connect as a fresh client each time, and a TeamSpeak server keeps
a database row for every client identity it has ever seen. Those rows are part of
`serversnapshotcreate`'s reply, so a fixture used for a few dozen runs grows a
snapshot from ~5 KB to ~45 KB — large enough that the reply is split across many
UDP fragments, and one lost fragment makes `serversnapshotcreate` time out. That
looks like a broken declaration and is not one.

This connects over ServerQuery (plain TCP, port 10011), deletes the client rows
and channels the tests made, and reports what is left. Run it before a test run
on a server that has been used a few times:

    LITESPEAK_QUERY_PASSWORD=... tools/live-server-clean.py

Environment:
    LITESPEAK_QUERY_HOST      default 127.0.0.1
    LITESPEAK_QUERY_PORT      default 10011
    LITESPEAK_QUERY_USER      default serveradmin
    LITESPEAK_QUERY_PASSWORD  required
    LITESPEAK_QUERY_SID       default 1

Nothing outside the name prefixes below is touched, so a server that is also used
for something else keeps its own objects.
"""

import os
import re
import socket
import sys

# Names the live tests create. Keep in step with `live_parallel.rs`,
# `live_delete.rs` and `live_commands.rs`.
NAME_PREFIXES = ("tsb-", "del-", "probe", "diag-")

# Client database rows carry the nickname the test connected with.
CLIENT_PREFIXES = ("tsb-", "del-", "probe", "diag-")


class ServerQuery:
    """Just enough of the ServerQuery protocol to run commands and read rows."""

    def __init__(self, host, port, timeout=10.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        # One read can carry several lines, and the remainder has to be kept:
        # dropping it loses the rest of the reply and the next read blocks.
        self.buffer = ""
        self._read_line()  # "TS3"
        self._read_line()  # welcome text

    def _read_line(self):
        while "\n" not in self.buffer:
            data = self.sock.recv(4096)
            if not data:
                line, self.buffer = self.buffer, ""
                return line
            self.buffer += data.decode("utf-8", "replace")
        # TeamSpeak puts a \r at the *start* of each line after the first.
        line, _, self.buffer = self.buffer.partition("\n")
        return line.strip("\r")

    def cmd(self, command):
        """Send one command; return (payload, error_line)."""
        self.sock.sendall((command + "\n").encode())
        first = ""
        while first == "":
            first = self._read_line()
        if first.startswith("error"):
            return "", first
        return first, self._read_line()

    def ok(self, command):
        payload, error = self.cmd(command)
        if "id=0" not in error:
            raise RuntimeError(f"{command!r} failed: {error}")
        return payload

    def close(self):
        try:
            self.cmd("quit")
        finally:
            self.sock.close()


def rows(payload):
    """Split a reply into dicts, one per `|`-separated row."""
    return [
        dict(p.split("=", 1) for p in row.split(" ") if "=" in p)
        for row in payload.split("|")
        if row
    ]


def unescape(text):
    return (
        text.replace("\\s", " ")
        .replace("\\/", "/")
        .replace("\\p", "|")
        .replace("\\\\", "\\")
    )


def delete_clients(q):
    """Delete every client database row whose nickname is a test name."""
    deleted = 0
    for _ in range(8):
        found = []
        start = 0
        while start < 2000:
            command = f"clientdblist start={start} duration=25" if start else "clientdblist"
            payload, error = q.cmd(command)
            if "id=0" not in error:
                break
            page = rows(payload)
            if not page:
                break
            for row in page:
                name = unescape(row.get("client_nickname", ""))
                if name.startswith(CLIENT_PREFIXES):
                    found.append(row["cldbid"])
            start += 25
        if not found:
            break
        for cldbid in found:
            _, error = q.cmd(f"clientdbdelete cldbid={cldbid}")
            if "id=0" in error:
                deleted += 1
    return deleted


def delete_objects(q):
    """Delete channels, server groups and channel groups named like test objects."""
    deleted = 0
    while True:
        targets = []
        for command, id_key, name_key in (
            ("channelgrouplist", "cgid", "name"),
            ("servergrouplist", "sgid", "name"),
            ("channellist", "cid", "channel_name"),
        ):
            payload, error = q.cmd(command)
            if "id=0" not in error:
                continue
            for row in rows(payload):
                if unescape(row.get(name_key, "")).startswith(NAME_PREFIXES):
                    targets.append((command, row[id_key]))
        if not targets:
            return deleted
        before = len(targets)
        for command, ident in targets:
            if command == "channelgrouplist":
                q.cmd(f"channelgroupdel cgid={ident} force=1")
            elif command == "servergrouplist":
                q.cmd(f"servergroupdel sgid={ident} force=1")
            else:
                q.cmd(f"channeldelete cid={ident} force=1")
            deleted += 1
        # A pass that removes nothing would loop forever.
        if before == 0:
            return deleted


def main():
    host = os.environ.get("LITESPEAK_QUERY_HOST", "127.0.0.1")
    port = int(os.environ.get("LITESPEAK_QUERY_PORT", "10011"))
    user = os.environ.get("LITESPEAK_QUERY_USER", "serveradmin")
    password = os.environ.get("LITESPEAK_QUERY_PASSWORD")
    sid = os.environ.get("LITESPEAK_QUERY_SID", "1")

    if not password:
        print("LITESPEAK_QUERY_PASSWORD is required", file=sys.stderr)
        return 2

    q = ServerQuery(host, port)
    try:
        q.ok(f"login {user} {password}")
        q.ok(f"use sid={sid}")

        channels = delete_objects(q)
        clients = delete_clients(q)

        payload, _ = q.cmd("clientdblist -count")
        match = re.search(r"count=(\d+)", payload)
        left = match.group(1) if match else "?"
        print(f"removed {channels} objects and {clients} client rows; {left} client rows left")
    finally:
        q.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
