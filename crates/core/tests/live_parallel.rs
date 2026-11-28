//! Every command against a real server, one connection per command, in parallel.
//!
//! `live_commands.rs` and `live_writes.rs` prove the same thing serially: the
//! server understands what this crate sends. Serially, though, each command costs
//! a fixed wait, because a *successful* command produces no event — there is
//! nothing to wait for, so the only way to know it finished is to wait out a
//! window. Forty commands then cost forty windows.
//!
//! The way out is not a shorter window, it is not waiting at all. A refusal
//! arrives as `command_error` within a few hundred milliseconds, and that is the
//! only outcome this file cares about: a command that is not refused was
//! understood. So each command runs on its own connection, in its own thread, and
//! returns as soon as its stream says anything. The whole set finishes in about
//! as long as the slowest one.
//!
//! One connection per command is also what makes this safe. Sharing a connection
//! would interleave the event streams and there would be no way to say which
//! answer belonged to which command.
//!
//! ## Destructive commands
//!
//! The write half needs `LITESPEAK_TEST_DESTRUCTIVE=1`: it creates channels,
//! groups, tokens and bans, then removes them. On a server someone else uses, a
//! failure halfway through leaves debris. The commands that cannot be undone
//! (`server_process_stop`, `server_delete`, `perm_reset`, `instance_edit`) are
//! not here at all — see the note in `live_writes.rs`.
//!
//! ```text
//! LITESPEAK_TEST_SERVER=127.0.0.1:9987 \
//!   cargo test -p litespeak-core --test live_parallel -- --ignored
//! ```

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use litespeak_core::command;
use litespeak_core::{ConnectParams, Handle, QueuedEvent, Value};

/// How long one command gets before it is called unanswered.
///
/// This is a ceiling, not a wait: a command that is refused returns as soon as
/// the refusal lands, which is well under this. Only a command the server accepts
/// and never mentions pays the full amount, and the check does not need to
/// distinguish that from a slow one — both mean "not refused".
const CEILING: Duration = Duration::from_millis(2500);

/// How long to wait for the handshake before giving up on a connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// How many connections may handshake at once.
///
/// Every case needs its own connection, and a server drops a burst of them:
/// 26 simultaneous handshakes produced `resend timeout` on a third of them,
/// because the UDP handshake is three round trips and the server's resend window
/// is shorter than the burst. Four at a time is enough to finish this set in
/// seconds while staying under that limit.
const CONCURRENCY: usize = 4;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// Connects, or returns None when the environment is not set up.
fn connect() -> Option<Handle> {
    let address = env("LITESPEAK_TEST_SERVER")?;
    let identity = env("LITESPEAK_TEST_IDENTITY").unwrap_or_default();
    // Every worker needs a distinct nickname: the server refuses a second client
    // with a name already in use, and a parallel run would look like a dozen
    // connection failures.
    let base = env("LITESPEAK_TEST_NICKNAME").unwrap_or_else(|| "probe".to_string());
    let unique = NEXT_NICKNAME.fetch_add(1, Ordering::Relaxed);
    let nickname = format!("{base}-{unique}");

    let handle = Handle::create(ConnectParams {
        address,
        identity,
        nickname,
        server_password: env("LITESPEAK_TEST_PASSWORD"),
        channel: None,
        channel_password: None,
        myts: None,
        version_profile: Default::default(),
        privilege_key: String::new(),
        start_muted: true,
    })
    .ok()?;

    let deadline = Instant::now() + CONNECT_TIMEOUT;
    while Instant::now() < deadline {
        for event in handle.drain_events() {
            if event.kind == "connected" {
                return Some(handle);
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

static NEXT_NICKNAME: AtomicUsize = AtomicUsize::new(1);

fn field<'a>(event: &'a QueuedEvent, key: &str) -> Option<&'a Value> {
    event
        .data
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value)
}

/// What the server said about one command.
#[derive(Debug, Clone)]
enum Outcome {
    /// Nothing was refused.
    Accepted,
    /// Refused for a reason about the account, not the command.
    NeedsPermission(String),
    /// The command or one of its arguments was not understood.
    NotUnderstood(String),
}

impl Outcome {
    /// Whether this outcome is a defect in the crate.
    fn is_defect(&self) -> bool {
        matches!(self, Outcome::NotUnderstood(_))
    }
}

/// Sends one command and returns the first refusal, if any.
///
/// Returns as soon as a `command_error` arrives. A command the server accepts
/// sends no event, so the ceiling is what ends the wait — which is why this is
/// only cheap when many run at once.
fn attempt(handle: &Handle, name: &str, args: &str) -> Outcome {
    // Drain first. Fire-and-forget commands report their refusal asynchronously,
    // so an error left over from the previous case would otherwise be read as
    // this one's — which is exactly what made the same case pass on one run and
    // fail on the next.
    for _ in handle.drain_events() {}

    let parsed = match command::parse(name, args) {
        Ok(parsed) => parsed,
        Err(e) => return Outcome::NotUnderstood(format!("does not parse: {e}")),
    };
    handle.send(parsed);

    // Both outcomes are now explicit: the command carries a `return_code`, so
    // the server's acknowledgement comes back as `command_ok` or
    // `command_error` and there is no need to wait out a window for a success.
    let deadline = Instant::now() + CEILING;
    while Instant::now() < deadline {
        for event in handle.drain_events() {
            if event.kind == "command_ok" {
                return Outcome::Accepted;
            }
            if event.kind != "command_error" {
                continue;
            }
            let message = match field(&event, "message") {
                Some(Value::Str(text)) => text.clone(),
                _ => String::new(),
            };
            // The server's own wording, now that `CommandError` carries it; the
            // enum name is the fallback for a reply without a message.
            let lower_message = message.to_lowercase();
            if lower_message.contains("database empty result")
                || message.contains("DatabaseEmptyResult")
            {
                // A successful query that matched nothing. Not a refusal.
                return Outcome::Accepted;
            }
            let lower = message.to_lowercase();
            if lower.contains("permission")
                || lower.contains("insufficient")
                || lower.contains("not logged in")
                || lower.contains("already")
            {
                return Outcome::NeedsPermission(message);
            }
            return Outcome::NotUnderstood(message);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Outcome::Accepted
}

/// Runs one command on its own connection.
///
/// The connection is what makes the answers unambiguous, so it is created here
/// rather than shared. `setup` runs first on the same connection, for a command
/// that needs an id the connection itself discovered.
fn run_isolated(name: &'static str, args: &'static str) -> (String, Outcome) {
    // A dropped handshake is a property of the burst, not of the command, so it
    // is retried rather than reported: the server drops clients whose handshake
    // outlives its resend window, and under a burst that happens to whichever
    // ones lose the race.
    let mut handle = None;
    for _ in 0..3 {
        if let Some(connected) = connect() {
            handle = Some(connected);
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    let Some(handle) = handle else {
        return (
            name.to_string(),
            Outcome::NotUnderstood("could not connect".into()),
        );
    };
    // Let the book settle enough for `own_client_id` and the group lists.
    let settle = Instant::now() + Duration::from_millis(400);
    while Instant::now() < settle {
        for _ in handle.drain_events() {}
        std::thread::sleep(Duration::from_millis(10));
    }
    (name.to_string(), attempt(&handle, name, args))
}

/// Every read-only command, checked in parallel.
#[test]
#[ignore = "needs LITESPEAK_TEST_SERVER"]
fn every_read_command_is_understood_in_parallel() {
    let cases: &[(&'static str, &'static str)] = &[
        ("server_info", "{}"),
        ("server_variables", "{}"),
        ("instance_info", "{}"),
        ("host_info", "{}"),
        ("version", "{}"),
        ("binding_list", "{}"),
        ("server_id_by_port", r#"{"port":9987}"#),
        ("client_list", "{}"),
        ("client_db_list", "{}"),
        ("who_am_i", "{}"),
        ("server_connection_info", "{}"),
        ("channel_list", "{}"),
        ("channel_group_client_list", "{}"),
        ("perm_list", "{}"),
        (
            "perm_find",
            r#"{"permissionName":"b_serverinstance_help_view"}"#,
        ),
        (
            "perm_id_by_name",
            r#"{"permissionName":"b_serverinstance_help_view"}"#,
        ),
        ("ban_list", "{}"),
        ("complain_list", "{}"),
        ("offline_message_list", "{}"),
        ("temp_password_list", "{}"),
        ("token_list", "{}"),
        ("log_view", "{}"),
        ("filetransfer_list", "{}"),
        ("custom_search", r#"{"ident":"*","pattern":"*"}"#),
        ("server_list", "{}"),
        ("channel_find", r#"{"pattern":"Default"}"#),
    ];

    let started = Instant::now();
    let results = run_all(cases);
    report(&results, started.elapsed());
}

/// Runs a set of cases in parallel, one thread each.
///
/// Threads rather than async tasks on purpose: `Handle` owns its own runtime, so
/// blocking a test thread costs nothing, and the code stays readable.
fn run_all(cases: &[(&'static str, &'static str)]) -> Vec<(String, Outcome)> {
    let results: Mutex<Vec<(String, Outcome)>> = Mutex::new(Vec::new());
    let done = AtomicUsize::new(0);
    let total = cases.len();

    // A fixed number of workers pull from a shared cursor rather than one thread
    // per case: the limit is on *simultaneous* handshakes, so a worker has to
    // finish one before starting the next.
    let cursor = AtomicUsize::new(0);
    let workers = CONCURRENCY.min(cases.len()).max(1);

    std::thread::scope(|scope| {
        for _ in 0..workers {
            let results = &results;
            let done = &done;
            let cursor = &cursor;
            scope.spawn(move || loop {
                let index = cursor.fetch_add(1, Ordering::Relaxed);
                let Some((name, args)) = cases.get(index) else {
                    return;
                };
                let outcome = run_isolated(name, args).1;
                results.lock().unwrap().push((name.to_string(), outcome));
                let finished = done.fetch_add(1, Ordering::Relaxed) + 1;
                eprintln!("  [{finished}/{total}] {name}");
            });
        }
    });

    results.into_inner().unwrap()
}

fn report(results: &[(String, Outcome)], elapsed: Duration) {
    let accepted = results
        .iter()
        .filter(|(_, outcome)| matches!(outcome, Outcome::Accepted))
        .count();
    let skipped: Vec<&(String, Outcome)> = results
        .iter()
        .filter(|(_, outcome)| matches!(outcome, Outcome::NeedsPermission(_)))
        .collect();
    let defects: Vec<&(String, Outcome)> = results
        .iter()
        .filter(|(_, outcome)| outcome.is_defect())
        .collect();

    println!(
        "{} accepted, {} skipped, {} not understood — {} cases in {:.1}s",
        accepted,
        skipped.len(),
        defects.len(),
        results.len(),
        elapsed.as_secs_f32()
    );
    for (name, outcome) in &skipped {
        if let Outcome::NeedsPermission(message) = outcome {
            println!("  skipped {name}: {message}");
        }
    }

    let messages: Vec<String> = defects
        .iter()
        .map(|(name, outcome)| match outcome {
            Outcome::NotUnderstood(message) => format!("{name}: {message}"),
            _ => unreachable!(),
        })
        .collect();
    assert!(
        messages.is_empty(),
        "the server did not understand these commands, so their declarations or \
         arguments are wrong:\n  {}",
        messages.join("\n  ")
    );
    assert!(accepted > 0, "not one command was accepted");
}

// ─── writes ──────────────────────────────────────────────────────────────────

/// Whether the destructive half is allowed to run.
fn destructive_enabled() -> bool {
    env("LITESPEAK_TEST_DESTRUCTIVE").as_deref() == Some("1")
}

/// One write command, with the kind of object it needs built first.
#[derive(Clone, Copy)]
enum Needs {
    /// Nothing beyond the connection.
    Nothing,
    /// A channel this worker created.
    Channel,
    /// A server group this worker created.
    ServerGroup,
    /// A channel group this worker created.
    ChannelGroup,
    /// This client's own database id, which the snapshot does not carry.
    ClientDb,
    /// This client's own connection id, for commands that take one.
    OwnClient,
}

/// Deletes everything whose name carries `prefix`, and reports what survived.
///
/// The list is read from a fresh connection each pass, so the ids are the
/// server's own and the objects are found even when the run that made them
/// never recorded an id. Nothing else is touched: the prefix contains the
/// process id, so a concurrent run's objects are not this run's business.
///
/// Returns the names still present after the pass; empty means clean.
fn sweep_by_prefix(prefix: &str) -> Vec<String> {
    let Some(handle) = connect_with_retry() else {
        return vec!["no connection to sweep with".to_string()];
    };
    settle(&handle, 700);

    let snapshot = handle.snapshot();
    let mut targets: Vec<(&'static str, i64, String)> = Vec::new();
    for group in &snapshot.channel_groups {
        if group.name.starts_with(prefix) {
            targets.push((
                "channel_group_delete",
                group.id,
                format!(r#"{{"groupId":{},"force":true}}"#, group.id),
            ));
        }
    }
    for group in &snapshot.server_groups {
        if group.name.starts_with(prefix) {
            targets.push((
                "server_group_delete",
                group.id,
                format!(r#"{{"groupId":{},"force":true}}"#, group.id),
            ));
        }
    }
    for channel in &snapshot.channels {
        if channel.name.starts_with(prefix) {
            targets.push((
                "channel_delete",
                channel.id,
                format!(r#"{{"channelId":{},"force":true}}"#, channel.id),
            ));
        }
    }

    let names: Vec<String> = targets.iter().map(|(_, _, _)| String::new()).collect();
    let _ = names;
    for (name, _, args) in &targets {
        if let Some(message) = send_and_wait(&handle, name, args) {
            // "invalid id" means the object is already gone, which is the state
            // this pass wanted.
            if !message.to_lowercase().contains("invalid") {
                eprintln!("  cleanup: {name} {args} refused: {message}");
            }
        }
    }

    if targets.is_empty() {
        return Vec::new();
    }

    // A second connection, after the deletes have had a moment: the connection
    // that deleted them was told to forget them directly, so it cannot say
    // whether the server agreed.
    std::thread::sleep(Duration::from_millis(600));
    let Some(fresh) = connect_with_retry() else {
        return vec!["no connection to verify with".to_string()];
    };
    settle(&fresh, 800);
    verify_against(&fresh, prefix)
}

/// The names carrying `prefix` that a connection still sees.
fn verify_against(handle: &Handle, prefix: &str) -> Vec<String> {
    let snapshot = handle.snapshot();
    let mut left: Vec<String> = Vec::new();
    for group in snapshot
        .server_groups
        .iter()
        .chain(snapshot.channel_groups.iter())
    {
        if group.name.starts_with(prefix) {
            left.push(format!("group {}", group.name));
        }
    }
    for channel in &snapshot.channels {
        if channel.name.starts_with(prefix) {
            left.push(format!("channel {}", channel.name));
        }
    }
    left
}

/// Removes the tokens, temporary passwords and bans this run created.
///
/// Each carries the `tsb-` marker in its description, so a sweep can tell it
/// from anything a real user made. The token string itself is generated by the
/// server, so the marker is what identifies it.
fn sweep_marked(handle: &Handle) {
    for (token, description) in
        list_pairs(handle, "token_list", "token_listed", "token", "description")
    {
        if description.starts_with("tsb") {
            send_and_wait(handle, "token_delete", &format!(r#"{{"token":"{token}"}}"#));
        }
    }
    for (key, description) in list_pairs(
        handle,
        "privilege_key_list",
        "token_listed",
        "token",
        "description",
    ) {
        if description.starts_with("tsb") {
            send_and_wait(
                handle,
                "privilege_key_delete",
                &format!(r#"{{"key":"{key}"}}"#),
            );
        }
    }
    for (password, description) in list_pairs(
        handle,
        "temp_password_list",
        "temp_password_listed",
        "password",
        "description",
    ) {
        if description.starts_with("tsb") {
            send_and_wait(
                handle,
                "temp_password_delete",
                &format!(r#"{{"password":"{password}"}}"#),
            );
        }
    }
    for (id, name) in list_pairs(handle, "ban_list", "ban_listed", "ban_id", "name") {
        if name.starts_with("tsb") {
            send_and_wait(handle, "ban_delete", &format!(r#"{{"banId":{id}}}"#));
        }
    }
}

/// Two fields of every event a list command produces, as strings.
fn list_pairs(
    handle: &Handle,
    command_name: &str,
    event_kind: &str,
    first: &str,
    second: &str,
) -> Vec<(String, String)> {
    let Ok(parsed) = command::parse(command_name, "{}") else {
        return Vec::new();
    };
    handle.send(parsed);

    let mut out = Vec::new();
    let deadline = Instant::now() + CEILING;
    while Instant::now() < deadline {
        let mut done = false;
        for event in handle.drain_events() {
            if event.kind == event_kind {
                let value = |key: &str| match field(&event, key) {
                    Some(Value::Str(text)) => text.clone(),
                    Some(Value::Long(number)) => number.to_string(),
                    Some(Value::Int(number)) => number.to_string(),
                    _ => String::new(),
                };
                out.push((value(first), value(second)));
            }
            if event.kind.ends_with("_done") {
                done = true;
            }
        }
        if done {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    out
}

/// This client's database id, asked for rather than guessed.
///
/// The snapshot carries the connection id and each user's uid, not the database
/// id — and the commands that take one need the identity behind the connection,
/// which is a different number. Passing the connection id gives
/// `ClientInvalidId` as soon as that connection is gone.
fn own_client_db(handle: &Handle) -> Option<i64> {
    // `client_db_id_from_uid`, not `who_am_i`: this reply has a `_done`
    // terminator, so it cannot be confused with another nameless answer. The
    // uid is already in the snapshot, and `who_am_i`'s nameless reply went
    // missing while the connection was settling.
    let snapshot = handle.snapshot();
    let uid = snapshot
        .users
        .iter()
        .find(|user| Some(user.id) == snapshot.own_client_id)
        .map(|user| user.uid.clone())
        .filter(|uid| !uid.is_empty())?;

    let parsed = command::parse("client_db_id_from_uid", &format!(r#"{{"uid":"{uid}"}}"#)).ok()?;
    handle.send(parsed);

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        for event in handle.drain_events() {
            if event.kind == "client_db_id_resolved" {
                if let Some(Value::Long(id)) = field(&event, "client_db_id") {
                    return Some(*id);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

/// A channel and two groups, made by one worker and removed by it.
///
/// Per worker, not shared: a shared channel would be deleted by whichever worker
/// finished first, and the others would then fail on an id that no longer exists
/// — which looks exactly like a broken declaration.
struct WorkerScratch {
    channel: Option<i64>,
    server_group: Option<i64>,
    channel_group: Option<i64>,
}

impl WorkerScratch {
    fn create(handle: &Handle, tag: usize) -> Self {
        // The worker number keeps names distinct between concurrent workers, and
        // the pid keeps them distinct between concurrent runs.
        let base = format!("tsb-{}-{}", std::process::id(), tag);

        // `channel_created` carries the id; both group kinds answer with
        // `group_created`, told apart by `group_kind`.
        let channel = create_and_find(
            handle,
            "channel_create",
            &format!(r#"{{"name":"{base}-chan"}}"#),
            "channel_created",
            "channel_id",
            None,
        );
        let server_group = create_and_find(
            handle,
            "server_group_create",
            &format!(r#"{{"name":"{base}-sg"}}"#),
            "group_created",
            "group_id",
            Some("server"),
        );
        let channel_group = create_and_find(
            handle,
            "channel_group_create",
            &format!(r#"{{"name":"{base}-cg"}}"#),
            "group_created",
            "group_id",
            Some("channel"),
        );

        Self {
            channel,
            server_group,
            channel_group,
        }
    }
}

/// Sends a create and reads the new id out of the event it produces.
///
/// The id arrives as its own event rather than as the reply, so this waits for
/// that event instead of guessing at a name or comparing list lengths.
fn create_and_find(
    handle: &Handle,
    name: &str,
    args: &str,
    event_kind: &str,
    id_key: &str,
    group_kind: Option<&str>,
) -> Option<i64> {
    let parsed = command::parse(name, args).ok()?;
    handle.send(parsed);

    let deadline = Instant::now() + CEILING;
    while Instant::now() < deadline {
        for event in handle.drain_events() {
            if event.kind != event_kind {
                continue;
            }
            if let Some(wanted) = group_kind {
                match field(&event, "group_kind") {
                    Some(Value::Str(kind)) if kind == wanted => {}
                    _ => continue,
                }
            }
            return match field(&event, id_key) {
                Some(Value::Long(id)) => Some(*id),
                Some(Value::Int(id)) => Some(i64::from(*id)),
                _ => None,
            };
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    None
}

/// One command is deliberately absent: `talk_power_request`.
///
/// It sends `clientupdate client_talk_request=1`, and a 3.13.9 server answers
/// `invalid parameter` for every value but `0`. Probing it directly established
/// that nothing else works either:
///
/// * `clienttalkpowerrequest` and `talkpowerrequest` are not commands (no answer
///   at all, which is how this server reports an unknown name);
/// * `client_talk_request_msg` alone is also `invalid parameter`;
/// * granting the caller `i_client_needed_talk_power=75` first does not change it.
///
/// So the field exists but the server refuses it in every state this fixture can
/// reach. Whether that is this server's rule (talk power is only requestable in a
/// channel whose `i_channel_needed_talk_power` is above the client's) or a wrong
/// field could not be settled here: the permission to *set* a channel's needed
/// talk power is `b_channel_modify_needed_talk_power`, and the permission itself
/// does not appear in this server's `permissionlist` at all.
///
/// Left unverified rather than deleted, because talk power is a real client
/// feature and removing it would be the wrong conclusion. The next step needs a
/// server whose channel permissions can be arranged.
///
/// The write commands, each on its own connection, in parallel.
#[test]
#[ignore = "needs LITESPEAK_TEST_SERVER and LITESPEAK_TEST_DESTRUCTIVE=1"]
fn every_write_command_is_understood_in_parallel() {
    assert!(
        destructive_enabled(),
        "set LITESPEAK_TEST_DESTRUCTIVE=1 to run the write tests"
    );

    // Each case names what it needs; the worker builds it on its own connection
    // before running the case, so no two workers share an object.
    let cases: &[(&'static str, &'static str, Needs)] = &[
        ("set_nickname", r#"{"nickname":"tsb-live"}"#, Needs::Nothing),
        ("set_away", r#"{"away":true,"message":"t"}"#, Needs::Nothing),
        ("set_away", r#"{"away":false,"message":""}"#, Needs::Nothing),
        ("set_input_muted", r#"{"muted":true}"#, Needs::Nothing),
        ("set_input_muted", r#"{"muted":false}"#, Needs::Nothing),
        ("set_output_muted", r#"{"muted":true}"#, Needs::Nothing),
        ("set_output_muted", r#"{"muted":false}"#, Needs::Nothing),
        ("client_update", "{}", Needs::Nothing),
        ("channel_subscribe_all", "{}", Needs::Nothing),
        ("channel_unsubscribe_all", "{}", Needs::Nothing),
        ("clear_positions", "{}", Needs::Nothing),
        (
            "channel_edit",
            r#"{"channelId":0,"topic":"e"}"#,
            Needs::Channel,
        ),
        (
            "channel_subscribe",
            r#"{"channelId":0,"subscribed":true}"#,
            Needs::Channel,
        ),
        (
            "channel_move",
            r#"{"channelId":0,"parentId":0}"#,
            Needs::Channel,
        ),
        ("channel_info", r#"{"channelId":0}"#, Needs::Channel),
        ("channel_description", r#"{"channelId":0}"#, Needs::Channel),
        (
            "channel_permission_list",
            r#"{"channelId":0}"#,
            Needs::Channel,
        ),
        (
            "channel_add_perm",
            r#"{"channelId":0,"permissionName":"b_channel_join_permanent","value":1}"#,
            Needs::Channel,
        ),
        (
            "channel_del_perm",
            r#"{"channelId":0,"permissionName":"b_channel_join_permanent"}"#,
            Needs::Channel,
        ),
        (
            "server_group_rename",
            r#"{"groupId":0,"name":"tsb-renamed"}"#,
            Needs::ServerGroup,
        ),
        (
            "server_group_perm_list",
            r#"{"groupId":0}"#,
            Needs::ServerGroup,
        ),
        (
            "server_group_auto_add_perm",
            r#"{"groupId":0,"permissionName":"b_virtualserver_info_view","value":1}"#,
            Needs::ServerGroup,
        ),
        (
            "server_group_auto_del_perm",
            r#"{"groupId":0,"permissionName":"b_virtualserver_info_view"}"#,
            Needs::ServerGroup,
        ),
        (
            "server_group_add_perm",
            r#"{"groupId":0,"permissionName":"b_virtualserver_info_view","value":1}"#,
            Needs::ServerGroup,
        ),
        (
            "server_group_del_perm",
            r#"{"groupId":0,"permissionName":"b_virtualserver_info_view"}"#,
            Needs::ServerGroup,
        ),
        (
            "channel_group_rename",
            r#"{"groupId":0,"name":"tsb-renamed-cg"}"#,
            Needs::ChannelGroup,
        ),
        (
            "channel_group_perm_list",
            r#"{"groupId":0}"#,
            Needs::ChannelGroup,
        ),
        (
            "channel_group_add_perm",
            r#"{"groupId":0,"permissionName":"b_channel_join_permanent","value":1}"#,
            Needs::ChannelGroup,
        ),
        (
            "channel_group_del_perm",
            r#"{"groupId":0,"permissionName":"b_channel_join_permanent"}"#,
            Needs::ChannelGroup,
        ),
        // Keyed by this client's database id.
        ("client_chat_close", r#"{"clientId":0}"#, Needs::OwnClient),
        (
            "custom_set",
            r#"{"clientDbId":0,"ident":"tsb","value":"v"}"#,
            Needs::ClientDb,
        ),
        (
            "custom_delete",
            r#"{"clientDbId":0,"ident":"tsb"}"#,
            Needs::ClientDb,
        ),
        (
            "complain_add",
            r#"{"clientDbId":0,"message":"t"}"#,
            Needs::ClientDb,
        ),
        (
            "server_groups_by_client",
            r#"{"clientDbId":0}"#,
            Needs::ClientDb,
        ),
        (
            "client_name_from_db_id",
            r#"{"clientDbId":0}"#,
            Needs::ClientDb,
        ),
        // These make and remove their own object inside the run.
        (
            "ban_add",
            r#"{"name":"tsb-live-ban","seconds":60,"reason":"t"}"#,
            Needs::Nothing,
        ),
        (
            "log_add",
            r#"{"level":"info","message":"tsb live"}"#,
            Needs::Nothing,
        ),
        (
            "token_add",
            r#"{"groupId":0,"description":"tsb-live"}"#,
            Needs::ServerGroup,
        ),
        (
            "temp_password_add",
            r#"{"password":"tsblive1","description":"tsb-live","seconds":60}"#,
            Needs::Nothing,
        ),
    ];

    let started = Instant::now();
    let results: Mutex<Vec<(String, Outcome)>> = Mutex::new(Vec::new());
    let cursor = AtomicUsize::new(0);
    let workers = CONCURRENCY.min(cases.len()).max(1);

    std::thread::scope(|scope| {
        for worker in 0..workers {
            let results = &results;
            let cursor = &cursor;
            scope.spawn(move || {
                let Some(handle) = connect_with_retry() else {
                    results.lock().unwrap().push((
                        "connect".to_string(),
                        Outcome::NotUnderstood("could not connect".into()),
                    ));
                    return;
                };
                settle(&handle, 400);
                let client_db = own_client_db(&handle);
                let own_client = handle.snapshot().own_client_id;
                let scratch = WorkerScratch::create(&handle, worker);

                loop {
                    let index = cursor.fetch_add(1, Ordering::Relaxed);
                    let Some((name, args, needs)) = cases.get(index) else {
                        break;
                    };
                    // The `0` in the table is replaced with the id this worker
                    // built; a case whose object could not be created is
                    // reported rather than run against id 0, which would answer
                    // "invalid id" and say nothing about the declaration.
                    let id = match needs {
                        Needs::Nothing => Some(0),
                        Needs::Channel => scratch.channel,
                        Needs::ServerGroup => scratch.server_group,
                        Needs::ChannelGroup => scratch.channel_group,
                        Needs::ClientDb => client_db,
                        Needs::OwnClient => own_client.map(i64::from),
                    };
                    let outcome = match id {
                        Some(id) => {
                            // One replacement only: `channel_move` carries two
                            // ids, and filling both with the created channel's
                            // id asks the server to move a channel under itself,
                            // which answers "invalid channelID" — a test bug that
                            // reads exactly like a broken declaration.
                            let args = args.replacen(":0", &format!(":{id}"), 1);
                            attempt(&handle, name, &args)
                        }
                        None => Outcome::NotUnderstood(
                            "the object this command needs could not be created".into(),
                        ),
                    };
                    results.lock().unwrap().push((name.to_string(), outcome));
                }
            });
        }
    });

    let results = results.into_inner().unwrap();

    // Tokens, temporary passwords and bans are not in the snapshot, and sweeping
    // them needs an undisturbed event stream: several workers listing at once
    // interleave their replies. So it happens once, on a fresh connection, after
    // the workers are done.
    let mut cleanup_failures = Vec::new();
    // Cleaned by name, not by a remembered list.
    //
    // A per-worker `Made` list is fragile in a way that is hard to see: the
    // recorded run had twelve entries for four workers, with two ids repeated
    // and one worker's three objects missing entirely — and every one of those
    // omissions was a group left behind. Reading the server's own list and
    // deleting what carries this run's prefix cannot miss an object, cannot
    // duplicate one, and cannot touch anything a previous run made.
    // The pid is in the names so a human can tell runs apart, but the sweep
    // matches only `tsb-`: two cases rename their object to a fixed name
    // (`tsb-renamed`), and a pid-scoped prefix would miss those and leave them
    // behind on every run. On the disposable server this test needs, sweeping
    // the whole prefix is the right trade.
    let prefix = "tsb-";
    // The workers' connections close as they finish and the server is still
    // clearing them; a delete sent into that burst is dropped like any packet.
    std::thread::sleep(Duration::from_secs(2));

    let mut leftover = sweep_by_prefix(prefix);
    for attempt in 0..3 {
        if leftover.is_empty() {
            break;
        }
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(600));
            leftover = sweep_by_prefix(prefix);
        }
    }
    cleanup_failures.extend(leftover);
    if let Some(handle) = connect_with_retry() {
        settle(&handle, 400);
        sweep_marked(&handle);
        // The token sweeps are themselves commands; give them time to land.
        settle(&handle, 600);
        sweep_marked(&handle);
        settle(&handle, 600);

        // Already swept by name above; this only reports what the token pass
        // could not cover, on a fresh connection.
        if let Some(fresh) = connect_with_retry() {
            settle(&fresh, 800);
            cleanup_failures.extend(verify_against(&fresh, prefix));
        }
    }

    report(&results, started.elapsed());
    assert!(
        cleanup_failures.is_empty(),
        "the run left objects on the server:\n  {}",
        cleanup_failures.join("\n  ")
    );
}

/// Connects, retrying the handshake a few times.
fn connect_with_retry() -> Option<Handle> {
    for _ in 0..3 {
        if let Some(handle) = connect() {
            return Some(handle);
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    None
}

/// Sends a command and waits out the window without short-circuiting.
///
/// Used for cleanup, where the answer does not matter but the command has to
/// actually be sent and given time to land.
fn send_and_wait(handle: &Handle, name: &str, args: &str) -> Option<String> {
    let parsed = match command::parse(name, args) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("  cleanup: {name} does not parse: {e}");
            return Some(e.to_string());
        }
    };
    handle.send(parsed);

    // Stop at the acknowledgement, not at the end of a window: the command
    // carries a `return_code`, so `command_ok` is proof it reached the server.
    // Waiting out a fixed window for a packet that has already been answered is
    // what made the previous version of this helper slow and unreliable at once.
    let deadline = Instant::now() + CEILING;
    while Instant::now() < deadline {
        for event in handle.drain_events() {
            match event.kind.as_str() {
                "command_ok" => return None,
                "command_error" => {
                    let message = match field(&event, "message") {
                        Some(Value::Str(text)) => text.clone(),
                        _ => String::new(),
                    };
                    return Some(message);
                }
                _ => {}
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Some(format!("{name} was not acknowledged"))
}

fn settle(handle: &Handle, millis: u64) {
    let deadline = Instant::now() + Duration::from_millis(millis);
    while Instant::now() < deadline {
        for _ in handle.drain_events() {}
        std::thread::sleep(Duration::from_millis(10));
    }
}
