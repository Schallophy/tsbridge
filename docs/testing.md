# Testing

How this crate is checked, and the traps that have already produced passing tests
that verified nothing. Read this before adding a test that asserts something is
*absent*.

## The layers

| Layer | What it can prove | Runs |
|---|---|---|
| unit tests in `src/` | the bytes a command writes, the fields a message fills | always |
| contract tests in `tests/` (`events`, `protocol_coverage`, `snapshot_coverage`, `account_*`) | the declarations, the docs and the code agree | always |
| `live_*.rs` | a real server understands what this crate sends | `--ignored`, needs a server |

Everything offline asserts what *this side* produces. Only a live server can say
whether the other side accepted it. When the two disagree, the offline test is
usually the one that is wrong about the protocol, not the server.

## The empty assertion

The most expensive mistake in this repository has been a test that passes because
the signal it checks can never arrive. It looks like a safety check and is not
one.

The concrete case: `a_snapshot_round_trips` ran `serversnapshotdeploy` and
asserted that no `command_error` came back.

```rust
let refused = deployed.iter().filter(|e| e.kind == "command_error");
assert!(refused.is_empty(), "the server refused the snapshot body");
```

The command was refused every time. The refusal was invisible, because a
fire-and-forget command answers `-> void`: the error packet carries no
`return_code`, tsclientlib turns it into a message event, and `handle_message`
had no arm for it, so it was dropped. `refused` was therefore always empty, the
assertion always true, and the test name — *round trips* — described something
that never happened.

When that arm was added, four tests that had been green turned red at once. None
was a regression: each had been reporting success on a channel that carried
nothing.

### The shapes it takes

| Shape | Why it cannot fail |
|---|---|
| asserts nothing bad happened | when the bad news has no path to the test, the collection is always empty |
| restates the implementation | a hardcoded expected value that was copied from the code drifts with it |
| skips unconditionally | any outcome ends in `println!("skipped")` and a return |
| asserts only that parsing succeeded | a parse that succeeds into an empty struct is indistinguishable from a correct one |

The last one is a real case too: `ServerInfo` was declared with `attributes=[]`,
so its reply parsed cleanly into a struct with nothing in it. A parse that
succeeds and yields nothing is worse than one that fails.

## How to tell a real assertion from an empty one

Break the thing under test and confirm the test goes red. If it does not, the
assertion is empty regardless of how specific it looks.

This is cheap and has already caught one: `handshake_contract.rs` asserts that
every attribute `InitServer` declares required appears in a captured reply. Making
`virtualserver_filebase` required again fails it by name:

```
3.11.0 does not send these attributes declared required: ["virtualserver_filebase"]
```

That test was written by first making it fail, then fixing the declaration.

## When a lot of tests go red after one change

Read the failure messages before assuming the change broke something. If they say
"the server refused", "insufficient permission", or "not understood" — things that
were previously invisible — the tests were green on a channel that carried
nothing, and the change just connected the channel.

A change that fixes an observation path and produces **no** new failures is the
suspicious one: it means nothing was checking that path.

## Live tests

`live_commands`, `live_parallel`, `live_delete` and `live_server` are `#[ignore]`d
and need `TSBRIDGE_TEST_SERVER`. Write ones are additionally gated on
`TSBRIDGE_TEST_DESTRUCTIVE=1`, because they create channels, groups, tokens and
bans.

Rules that came out of using them:

* **One connection per command.** A shared connection interleaves its event
  stream, and there is no way to say which answer belongs to which command.
  Successes now carry `command_ok`, so a command returns as soon as its own
  acknowledgement arrives instead of waiting out a window — 39 write commands
  went from 190 s to 28 s.
* **Ask the server, do not trust the book.** A delete is told to the book
  directly, so the connection that performed it agrees with itself. Verify with a
  connection that never deleted anything.
* **Clean by name, not by a remembered id.** A list of ids recorded per worker
  came out with twelve entries for four workers, two repeated and one worker's
  three missing; every omission was an object left behind. Read the server's own
  list and delete what carries the run's prefix.
* **Keep the fixture small.** A server keeps a database row per client identity,
  and those rows are part of `serversnapshotcreate`'s reply. A fixture reused for
  a few dozen runs grows one from ~5 KB to ~45 KB, which is split across many UDP
  fragments, and one lost fragment makes the command time out — which reads as a
  broken declaration and is not one. `tools/live-server-clean.py` resets it.

## What is verified, and what is not

Being explicit about the gaps is part of the method, not an admission. The current
ones:

* `talk_power_request` — the wire form is pinned offline (two field names and
  nothing else), but whether a server accepts it is unknown. `client_talk_request=1`
  is refused as `invalid parameter` on 3.13.9, and the permission that would make
  the request meaningful, `i_channel_needed_talk_power`, does not exist there:
  `permidgetbyname` rejects the name itself.
* Commands that are destructive and unrecoverable — `server_process_stop`,
  `server_delete`, `perm_reset` — are checked only offline, byte for byte. They
  are probed against a live server with an id that cannot exist, which proves the
  transport accepts the command without performing the operation.

## Transport boundaries

Upstream's client declaration table was written partly from the ServerQuery
documentation, so a few entries are query commands in the client section. A
client connection is answered `invalid client type` for those. This has produced
two wrappers that could never work:

* `serversnapshotdeploy` — removed. The same body deploys fine over ServerQuery,
  so the encoding was right and the transport was not.
* `servernotifyregister` (`notify_register`) — removed. The client protocol has no
  `clientnotifyregister`; probing it gets no answer at all.

The other `# TODO` entries in that section were probed on 3.13.9 and *are* client
commands: `permreset`, `servercreate`, `serverdelete`, `serverstart`, `serverstop`
and `serverprocessstop` each answer a permission refusal rather than a transport
one. So the mark is upstream's uncertainty about the field sets, not about the
transport.

## Fixture rules that are not obvious

* A permission can be set by name over ServerQuery but not over the client
  protocol: `channeladdperm permsid=…` works from a query connection and the same
  command from a client is refused with `invalid permission ID`.
* `perm_list` reports `permid=0`, so a client cannot learn numeric ids from it;
  `permidgetbyname` needs instance permissions a virtual-server admin does not
  have.
* A large snapshot reply is the one place where the client protocol is
  unreliable; see the fixture note above.
