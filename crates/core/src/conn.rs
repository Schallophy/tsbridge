//! The connection thread: the only place a tsclientlib `Connection` exists.
//!
//! It is created here, driven by one loop over "network events", "commands from
//! the UI" and a 20 ms audio clock, and dropped here. Everything else talks to it
//! through the command channel and reads results from the snapshot.
//!
//! Borrowing note: `Connection::events()` borrows the connection mutably, so a
//! command cannot be applied while an event stream is alive. The stream is
//! therefore rebuilt per iteration — safe because `EventStream` is a thin wrapper
//! around `poll_next` with no state of its own.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::prelude::*;
use futures::StreamExt;
use tokio::sync::mpsc::UnboundedReceiver;
use tsclientlib::messages::c2s;
use tsclientlib::PacketStat;
use tsclientlib::{
    ChannelGroupId, ChannelId, ClientDbId, ClientId, ClientType, Connection, DisconnectOptions,
    GroupType, Identity, InMessage, LogLevel, MessageTarget, OutCommandExt, Permission,
    PermissionType, PluginTargetMode, Reason, ServerGroupId, StreamItem, TokenType, UidBuf,
};
use tsproto_packets::packets::{Direction, Flags, OutCommand, PacketType};

use crate::audio::{AudioEngine, WhisperTargets};
use crate::events::QueuedEvent;
use crate::handle::{Command, ConnectParams, Inner, TextTarget};
use crate::state::{compute_file_permission_hints, FileEntry, GroupEntry, NetworkEntry};

/// How long the speaking indicator stays lit after the last transmitted frame.
const OWN_TALK_HOLD: Duration = Duration::from_millis(300);

/// A transfer that was requested but whose TCP stream has not arrived yet.
struct Pending {
    name: String,
    local: PathBuf,
}

struct Session {
    audio: AudioEngine,
    downloads: HashMap<u16, Pending>,
    uploads: HashMap<u16, Pending>,
    /// File-transfer handles that belong to an icon fetch, by `icon_id`.
    ///
    /// The server answers with the same `FileDownload` item whatever the file
    /// is, so the handle is what tells an icon apart from a document the user
    /// asked for.
    icon_fetches: HashMap<u16, i64>,
    /// Which channel the outstanding `filelist` request belongs to. Needed
    /// because an empty directory produces a response with no entries at all.
    listing_channel: Option<i64>,
    /// Whether `channelsubscribeall` was sent on this connection.
    ///
    /// The server only reports clients for subscribed channels, so without
    /// this the tree would show just the own channel and a move into any other
    /// channel would be invisible. A reconnect builds a fresh connection whose
    /// subscription starts empty, so the flag resets there too.
    subscribed: bool,
    /// When voice was last sent. The speaking flag holds for a short tail so
    /// word gaps do not flicker the indicator.
    last_voice: Option<Instant>,
}

enum Step {
    Item(Option<Result<StreamItem, tsclientlib::Error>>),
    Command(Command),
    CommandsClosed,
    Tick,
}

pub async fn run(
    inner: Arc<Inner>,
    mut commands: UnboundedReceiver<Command>,
    params: ConnectParams,
) {
    let ConnectParams {
        address,
        identity: identity_input,
        nickname,
        server_password,
        channel,
        channel_password,
        myts,
        version_profile,
        privilege_key,
        start_muted,
    } = params;
    let identity = if identity_input.trim().is_empty() {
        log::info!("No identity supplied; generating a new one for this session");
        Identity::create()
    } else {
        match Identity::new_from_ts_str(&identity_input) {
            Ok(identity) => identity,
            Err(e) => {
                log::error!("Rejected identity input: {e}");
                inner.push_event(
                    QueuedEvent::new("error")
                        .str("message", format!("invalid identity: {e}"))
                        .str("kind", "identity")
                        .bool("terminal", true),
                );
                return;
            }
        }
    };
    // Hand the caller something they can persist. Without this the server sees a
    // fresh UID on every launch, because the key is generated per session.
    inner.set_identity(crate::identity_to_ts_str(&identity));
    // The key is not part of the snapshot (logs); this flag is how a shell
    // learns that the one-time `identity` read will now return it.
    inner.with_state(|snapshot| snapshot.set_identity_ready());

    // Never log the password itself — only whether one arrived. This line is what
    // proves the Kotlin field actually reached the native side, which is the
    // first thing to check when a locked server keeps refusing.
    log::info!(
        "Connecting to {address}: server password {}, target channel {}",
        if server_password.is_some() {
            "provided"
        } else {
            "NOT provided"
        },
        channel.as_deref().unwrap_or("<default>"),
    );

    // A taken nickname is a normal server answer, not a dead end: retry with a
    // numeric suffix like the desktop client. The rules live here so every
    // shell gets the same result instead of each inventing its own.
    const MAX_NAME_ATTEMPTS: u32 = 20;
    let mut connection = None;
    for attempt in 0..MAX_NAME_ATTEMPTS {
        let candidate = if attempt == 0 {
            nickname.clone()
        } else {
            format!("{nickname}{attempt}")
        };
        let mut options = Connection::build(address.clone())
            .identity(identity.clone())
            .name(candidate.clone())
            .version(client_version(&version_profile))
            // Declared here rather than corrected afterwards: the server records
            // the client's mute state from `clientinit`, and a later
            // `clientupdate` carrying only that flag does not reliably come back
            // in our own client state — the member list kept showing an open
            // microphone while the audio path was already muted.
            .input_muted(start_muted)
            .output_muted(false);
        // The six myTeamSpeak parameters go into `clientinit` itself, which is
        // what the official client does (verified: its ID is accepted by a local
        // 3.13.9 server). Sending them later on `updatemytsid` signs a challenge
        // whose generation counter has already advanced.
        //
        // The provider comes from the caller — a session that is already signed
        // in — not from this connection: the login that produces the proof
        // happens on the account side, and `clientinit` is the first packet.
        if let Some(provider) = myts.clone() {
            options = options.myts(provider);
        }
        // The server password is not the channel password: one unlocks the
        // server, the other a channel inside it, and a server can require
        // either, both or neither.
        if let Some(password) = &server_password {
            options = options.password(password.clone());
        }
        if let Some(channel) = &channel {
            options = options.channel(channel.clone());
        }
        if let Some(password) = &channel_password {
            options = options.channel_password(password.clone());
        }
        if !privilege_key.is_empty() {
            // Single-use on the server: keep it out of the log line below and
            // report only that one was supplied. Cloned per attempt because a
            // retried connect (nickname taken) must send the same key.
            log::info!("Redeeming a privilege key on clientinit");
            options = options.default_token(privilege_key.clone());
        }

        match options.connect() {
            Ok(open) => {
                if attempt > 0 {
                    log::warn!("Nickname was taken; connected as `{candidate}`");
                }
                connection = Some(open);
                break;
            }
            Err(tsclientlib::Error::ConnectTs(
                tsproto_types::errors::Error::ClientNicknameInuse,
            )) if attempt + 1 < MAX_NAME_ATTEMPTS => {
                log::warn!("Nickname `{candidate}` is in use; retrying");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            Err(e) => {
                log::error!("Connect to {address} failed: {e}");
                inner.push_event(
                    QueuedEvent::new("error")
                        .str("message", format!("connect failed: {e}"))
                        .str("kind", "connect")
                        .bool("terminal", true),
                );
                return;
            }
        }
    }
    let mut connection = match connection {
        Some(connection) => connection,
        None => {
            inner.push_event(
                QueuedEvent::new("error")
                    .str(
                        "message",
                        format!("nickname `{nickname}` is still in use after {MAX_NAME_ATTEMPTS} attempts"),
                    )
                    .str("kind", "nickname")
                    .bool("terminal", true),
            );
            return;
        }
    };
    log::info!("Connected to {address}; waiting for the first book events");

    let mut session = Session {
        audio: AudioEngine::new(),
        downloads: HashMap::new(),
        uploads: HashMap::new(),
        icon_fetches: HashMap::new(),
        listing_channel: None,
        subscribed: false,
        last_voice: None,
    };

    // 20 ms is one Opus frame: the same clock drives capture and playback, so
    // there is exactly one place where audio timing is decided.
    let mut ticker = tokio::time::interval(Duration::from_millis(20));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Set once the goodbye is queued. `disconnect()` only enqueues the packet,
    // and dropping the connection right after would cancel the write — the
    // server would never see `clientdisconnect` and keep the client listed
    // until its timeout. So the loop keeps running until the server closes
    // the socket, with this as the ceiling.
    let mut goodbye_deadline: Option<tokio::time::Instant> = None;

    loop {
        if let Some(deadline) = goodbye_deadline {
            if tokio::time::Instant::now() >= deadline {
                log::info!("Disconnect wait timed out; closing anyway");
                break;
            }
        }

        let step = {
            let mut stream = connection.events();
            tokio::select! {
                item = stream.next() => Step::Item(item),
                command = commands.recv() => match command {
                    Some(command) => Step::Command(command),
                    None => Step::CommandsClosed,
                },
                _ = ticker.tick() => Step::Tick,
            }
        };

        match step {
            Step::CommandsClosed => {
                log::info!("Handle dropped; closing the connection");
                break;
            }
            Step::Command(Command::Disconnect) => match connection
                .disconnect(DisconnectOptions::new())
            {
                Ok(()) => {
                    log::info!("Goodbye sent; waiting for the server to close");
                    goodbye_deadline = Some(tokio::time::Instant::now() + Duration::from_secs(1));
                }
                Err(e) => {
                    log::warn!("Disconnect failed: {e}");
                    break;
                }
            },
            Step::Command(command) => {
                if !handle_command(&inner, &mut connection, &mut session, command) {
                    break;
                }
            }
            Step::Tick => {
                let spoke = match inner.take_capture_frame() {
                    Some(frame) => session.audio.transmit(&mut connection, &frame),
                    None => false,
                };
                let now = Instant::now();
                if spoke {
                    session.last_voice = Some(now);
                }
                let talking = session
                    .last_voice
                    .map(|last| now.duration_since(last) < OWN_TALK_HOLD)
                    .unwrap_or(false);
                inner.with_state(|snapshot| snapshot.set_own_talking(talking));
                session.audio.tick(&inner);
                // The recorder's elapsed time moves with the tick, so the
                // snapshot carries it rather than a shell keeping its own clock.
                let recording = crate::state::RecordingEntry {
                    active: session.audio.is_recording(),
                    path: session.audio.recording_path(),
                    seconds: session.audio.recording_seconds(),
                };
                inner.with_state(|snapshot| snapshot.set_recording(recording));
                // The counters move whether or not the server says anything, so
                // the ping is sampled from the tick rather than from a book
                // event. `get_network_stats` is cheap: it borrows the resender's
                // own struct.
                //
                // Only the public fields are read. Packet loss is kept in a
                // private array behind no accessor, so it is reported as
                // "unmeasured" rather than guessed from the byte totals — a
                // wrong loss figure is worse than an absent one.
                if let Ok(stats) = connection.get_network_stats() {
                    let measured = !stats.rtt.is_zero();
                    let mut sent = 0u64;
                    let mut received = 0u64;
                    for (index, bytes) in stats.total_bytes.iter().enumerate() {
                        match index {
                            i if i == PacketStat::OutControl as usize
                                || i == PacketStat::OutKeepalive as usize
                                || i == PacketStat::OutSpeech as usize =>
                            {
                                sent += bytes
                            }
                            i if i == PacketStat::InControl as usize
                                || i == PacketStat::InKeepalive as usize
                                || i == PacketStat::InSpeech as usize =>
                            {
                                received += bytes
                            }
                            _ => {}
                        }
                    }
                    inner.with_state(|snapshot| {
                        snapshot.set_network(NetworkEntry {
                            rtt_ms: stats.rtt.as_millis().min(i32::MAX as u128) as i32,
                            rtt_dev_ms: stats.rtt_dev.as_millis().min(i32::MAX as u128) as i32,
                            bytes_sent: sent,
                            bytes_received: received,
                            packet_loss: 0.0,
                            measured,
                        });
                    });
                }
            }
            Step::Item(None) => {
                log::info!("Event stream ended");
                break;
            }
            Step::Item(Some(Err(e))) => {
                log::error!("Event stream failed: {e}");
                let (message, kind) = describe_stream_error(&e);
                inner.push_event(
                    QueuedEvent::new("error")
                        .str("message", message)
                        .str("kind", kind)
                        // The loop breaks next, so no further command will be
                        // handled; the `disconnected` that follows is the same
                        // fact in the other vocabulary.
                        .bool("terminal", true),
                );
                break;
            }
            Step::Item(Some(Ok(item))) => {
                if !handle_stream_item(&inner, &mut connection, &mut session, item) {
                    break;
                }
            }
        }
    }

    inner.set_connected(false);
    inner.set_talking(Vec::new());
    inner.clear_audio();
    inner.push_event(QueuedEvent::new("disconnected"));
    log::info!("Connection thread stopped");
}

/// Returns false when the session is over.
fn handle_stream_item(
    inner: &Arc<Inner>,
    connection: &mut Connection,
    session: &mut Session,
    item: StreamItem,
) -> bool {
    match item {
        StreamItem::BookEvents(_) => {
            // The book has already been updated when these arrive, so the
            // snapshot diff sees the new state even if the event batch is split.
            let talking = inner.talking();
            let outcome = match connection.get_state() {
                Ok(book) => Some(inner.with_state(|snapshot| {
                    // `servergrouplist` is a command whose reply the bookkeeping
                    // consumes into the book, so it never arrives as a
                    // `MessageEvent`. Read the book's maps instead: that is what
                    // turns `self.serverGroups` ids into names and fills the
                    // "which groups am I in" list.
                    let groups = book
                        .server_groups
                        .values()
                        .map(|group| GroupEntry {
                            id: group.id.0 as i64,
                            name: group.name.clone(),
                            icon_id: group.icon.0 as i64,
                            sort_id: group.sort_id,
                            is_permanent: group.is_permanent,
                        })
                        .collect();
                    snapshot.set_server_groups(groups);
                    let channel_groups = book
                        .channel_groups
                        .values()
                        .map(|group| GroupEntry {
                            id: group.id.0 as i64,
                            name: group.name.clone(),
                            icon_id: group.icon.0 as i64,
                            sort_id: group.sort_id,
                            is_permanent: group.is_permanent,
                        })
                        .collect();
                    snapshot.set_channel_groups(channel_groups);
                    let events = snapshot.sync_from(book, &talking);
                    (events, snapshot.connected)
                })),
                Err(e) => {
                    log::warn!("No book state while handling events: {e}");
                    None
                }
            };
            if let Some((events, connected)) = outcome {
                // Connected-ness is owned by the snapshot (it knows whether the
                // server entries arrived); mirror it for the JNI query.
                inner.set_connected(connected);
                for event in events {
                    inner.push_event(event);
                }
                // Every client event carries a channel id, but the server only
                // sends those for channels this client is subscribed to. Stay
                // subscribed to all of them, like the desktop client, so the
                // tree can show who is in the other channels and follow moves.
                // The myTeamSpeak ID is *not* sent here: it rides on
                // `clientinit`, which the connection library builds with the
                // handshake IV already in scope. Sending it later would sign a
                // challenge whose generation counter has moved on.
                if connected && !session.subscribed && subscribe_all(connection) {
                    session.subscribed = true;
                    log::info!("Subscribed to all channels");
                    // Group names back the whisper and member panels; asking on
                    // every connection keeps them from outliving a server change.
                    request_group_lists(connection);
                }
            }
            true
        }

        StreamItem::MessageEvent(message) => {
            handle_message(inner, session, message, ClientId(own_id(connection)));
            true
        }

        StreamItem::Audio(packet) => {
            session.audio.receive(inner, packet);
            true
        }

        StreamItem::DisconnectedTemporarily(reason) => {
            log::warn!("Temporarily disconnected: {reason:?}; tsclientlib will reconnect");
            // The reestablished connection starts with no subscriptions.
            session.subscribed = false;
            inner.set_connected(false);
            inner.push_event(QueuedEvent::new("reconnecting"));
            true
        }

        StreamItem::MessageResult(handle, result) => {
            if let Err(e) = result {
                log::warn!("Command {} failed: {e}", handle.0);
                inner.push_event(
                    QueuedEvent::new("command_error")
                        .str("message", e.to_string())
                        .str(
                            "missing_permission",
                            e.missing_permission
                                .map(|p| format!("{p:?}"))
                                .unwrap_or_default(),
                        )
                        .int("command_id", handle.0 as i32),
                );
            }
            true
        }

        StreamItem::FileDownload(handle, result) => {
            if let Some(icon_id) = session.icon_fetches.remove(&handle.0) {
                let inner = inner.clone();
                tokio::spawn(crate::icons::receive(
                    inner,
                    icon_id,
                    result.size,
                    result.stream,
                ));
            } else if let Some(pending) = session.downloads.remove(&handle.0) {
                let inner = inner.clone();
                tokio::spawn(crate::files::download(
                    inner,
                    pending.name,
                    result.size,
                    result.stream,
                    pending.local,
                ));
            }
            true
        }

        StreamItem::FileUpload(handle, result) => {
            if let Some(pending) = session.uploads.remove(&handle.0) {
                let inner = inner.clone();
                tokio::spawn(crate::files::upload(
                    inner,
                    pending.name,
                    result.seek_position,
                    result.stream,
                    pending.local,
                ));
            }
            true
        }

        StreamItem::FiletransferFailed(handle, error) => {
            transfer_failed(inner, session, handle.0, &error.to_string());
            true
        }

        _ => true,
    }
}

fn transfer_failed(inner: &Arc<Inner>, session: &mut Session, handle: u16, error: &str) {
    let name = session
        .downloads
        .remove(&handle)
        .or_else(|| session.uploads.remove(&handle))
        .map(|pending| pending.name)
        .unwrap_or_else(|| format!("transfer {handle}"));
    log::warn!("{name} failed: {error}");
    inner.push_event(
        QueuedEvent::new("transfer_error")
            .str("name", &name)
            .str("message", error),
    );
}

fn handle_message(
    inner: &Arc<Inner>,
    session: &mut Session,
    message: InMessage,
    own_client: ClientId,
) {
    match message {
        InMessage::PermOverview(overview) => {
            let channel_id = overview.iter().next().map(|part| part.channel_id.0 as i64);
            let Some(channel_id) = channel_id else {
                return;
            };
            let mut perms = HashMap::new();
            for part in overview.iter() {
                // -1 (unlimited) wins; otherwise keep the highest value.
                let value = part.permission_value;
                let entry = perms.entry(part.permission_id.0).or_insert(0);
                if *entry != -1 && (value == -1 || value > *entry) {
                    *entry = value;
                }
            }
            let hints = compute_file_permission_hints(&perms);
            inner.with_state(|snapshot| snapshot.set_channel_permission_hints(channel_id, hints));
        }

        InMessage::TextMessage(text) => {
            for part in text.iter() {
                let target = match part.target {
                    tsclientlib::TextMessageTargetMode::Server => "server",
                    tsclientlib::TextMessageTargetMode::Channel => "channel",
                    _ => "client",
                };
                let seconds = part.timestamp.map(|t| t.unix_timestamp()).unwrap_or(0);
                let millis = part
                    .timestamp
                    .map(|t| seconds * 1000 + i64::from(t.millisecond()))
                    .unwrap_or(0);
                inner.push_event(
                    QueuedEvent::new("text_message")
                        .str("target", target)
                        .int("from_id", part.invoker_id.0 as i32)
                        .str("from_name", &part.invoker_name)
                        .str(
                            "from_uid",
                            part.invoker_uid
                                .as_ref()
                                .map(|u| u.to_string())
                                .unwrap_or_default(),
                        )
                        .str("message", &part.message)
                        .int(
                            "to_id",
                            part.target_client_id.map(|id| id.0 as i32).unwrap_or(0),
                        )
                        // The shell compares ids anyway; the flag saves every
                        // shell from having to know its own id at event time.
                        .bool("from_self", part.invoker_id == own_client)
                        .long("timestamp", seconds)
                        .long("timestamp_ms", millis),
                );
            }
        }

        InMessage::ClientPoke(poke) => {
            for part in poke.iter() {
                inner.push_event(
                    QueuedEvent::new("poked")
                        .int("from_id", part.invoker_id.0 as i32)
                        .str("from_name", &part.invoker_name)
                        .str("message", &part.message),
                );
            }
        }

        InMessage::ServerGroupList(list) => {
            let groups = list
                .iter()
                .map(|part| GroupEntry {
                    id: part.server_group_id.0 as i64,
                    name: part.name.clone(),
                    icon_id: part.icon.0 as i64,
                    sort_id: part.sort_id,
                    is_permanent: part.is_permanent,
                })
                .collect();
            inner.with_state(|snapshot| snapshot.set_server_groups(groups));
        }

        InMessage::ChannelGroupList(list) => {
            let groups = list
                .iter()
                .map(|part| GroupEntry {
                    id: part.channel_group.0 as i64,
                    name: part.name.clone(),
                    icon_id: part.icon.0 as i64,
                    sort_id: part.sort_id,
                    is_permanent: part.is_permanent,
                })
                .collect();
            inner.with_state(|snapshot| snapshot.set_channel_groups(groups));
        }

        InMessage::BanList(list) => {
            for part in list.iter() {
                inner.push_event(
                    QueuedEvent::new("ban_listed")
                        .long("ban_id", part.ban_id as i64)
                        .str("ip", part.ip.to_string())
                        .str("name", &part.name)
                        .str("uid", part.uid.to_string())
                        .str("last_nickname", &part.last_nickname)
                        .long("created", part.created.unix_timestamp())
                        .long("duration", part.duration.whole_seconds())
                        .str("invoker_name", &part.invoker_name)
                        .str("reason", &part.reason),
                );
            }
            inner.push_event(QueuedEvent::new("ban_list_done"));
        }

        InMessage::ComplainList(list) => {
            for part in list.iter() {
                inner.push_event(
                    QueuedEvent::new("complaint_listed")
                        .long("target_db_id", part.target_client_db_id.0 as i64)
                        .str("target_name", &part.target_name)
                        .long("from_db_id", part.from_client_db_id.0 as i64)
                        .str("from_name", &part.from_name)
                        .str("message", &part.message)
                        .long("timestamp", part.timestamp.unix_timestamp()),
                );
            }
            inner.push_event(QueuedEvent::new("complaint_list_done"));
        }

        InMessage::OfflineMessageList(list) => {
            for part in list.iter() {
                inner.push_event(
                    QueuedEvent::new("offline_message_listed")
                        .long("message_id", part.message_id as i64)
                        .str("uid", part.client_uid.to_string())
                        .str("subject", &part.subject)
                        .long("timestamp", part.timestamp.unix_timestamp())
                        .bool("read", part.is_read),
                );
            }
            inner.push_event(QueuedEvent::new("offline_message_list_done"));
        }

        InMessage::OfflineMessage(message) => {
            for part in message.iter() {
                inner.push_event(
                    QueuedEvent::new("offline_message")
                        .long("message_id", part.message_id as i64)
                        .str("uid", part.client_uid.to_string())
                        .str("subject", &part.subject)
                        .str("message", &part.message)
                        .long("timestamp", part.timestamp.unix_timestamp()),
                );
            }
        }

        InMessage::ClientPermList(list) => {
            for part in list.iter() {
                inner.push_event(
                    QueuedEvent::new("client_permission")
                        .long("client_db_id", part.client_db_id.0 as i64)
                        .str(
                            "name",
                            part.permission_name_id.clone().unwrap_or_else(|| {
                                part.permission_id
                                    .map(|id| id.0.to_string())
                                    .unwrap_or_default()
                            }),
                        )
                        .int("value", part.permission_value)
                        .bool("negated", part.permission_negated)
                        .bool("skip", part.permission_skip),
                );
            }
            inner.push_event(QueuedEvent::new("client_permission_list_done"));
        }

        InMessage::ChannelPermList(list) => {
            for part in list.iter() {
                inner.push_event(
                    QueuedEvent::new("channel_permission")
                        .long("channel_id", part.channel_id.0 as i64)
                        .str("name", part.permission_id.0.to_string())
                        .int("value", part.permission_value)
                        .bool("negated", part.permission_negated)
                        .bool("skip", part.permission_skip),
                );
            }
            inner.push_event(QueuedEvent::new("channel_permission_list_done"));
        }

        InMessage::ServerTempPasswordList(list) => {
            for part in list.iter() {
                inner.push_event(
                    QueuedEvent::new("temp_password_listed")
                        .str("nickname", &part.nickname)
                        .str("uid", part.uid.to_string())
                        .str("description", &part.description)
                        .str("password", &part.password_clear)
                        .long("start", part.start.unix_timestamp())
                        .long("end", part.end.unix_timestamp())
                        .long("channel_id", part.target_channel_id.0 as i64),
                );
            }
            inner.push_event(QueuedEvent::new("temp_password_list_done"));
        }

        InMessage::ClientDbList(list) => {
            for part in list.iter() {
                inner.push_event(
                    QueuedEvent::new("client_db_entry")
                        .long("client_db_id", part.client_db_id.0 as i64)
                        .str("uid", part.uid.to_string())
                        .str("nickname", &part.name)
                        .long("created", part.created.unix_timestamp())
                        .long("last_connected", part.last_connected.unix_timestamp())
                        .long("connections", i64::from(part.connections_total))
                        .str("description", &part.description),
                );
            }
            inner.push_event(QueuedEvent::new("client_db_list_done"));
        }

        InMessage::ClientDbInfo(info) => {
            for part in info.iter() {
                inner.push_event(
                    QueuedEvent::new("client_db_info")
                        .long("client_db_id", part.database_id.0 as i64)
                        .str("uid", part.uid.to_string())
                        .str("nickname", &part.name)
                        .int("client_id", part.client_id.0 as i32)
                        .long("channel_id", part.channel_id.0 as i64)
                        .str("description", &part.description)
                        .str("avatar_hash", &part.avatar_hash)
                        .long("icon_id", part.icon.0 as i64)
                        .long("created", part.created.unix_timestamp()),
                );
            }
        }

        InMessage::ClientDbFind(list) => {
            for part in list.iter() {
                inner.push_event(
                    QueuedEvent::new("client_db_found")
                        .long("client_db_id", part.client_db_id.0 as i64)
                        .str("uid", part.uid.to_string())
                        .str("nickname", &part.name)
                        .long("last_connected", part.last_connected.unix_timestamp())
                        .long("connections", i64::from(part.connections_total)),
                );
            }
            inner.push_event(QueuedEvent::new("client_db_find_done"));
        }

        InMessage::ChannelEditedLow(edited) => {
            // The low form is what the server answers `channelgetdescription`
            // with: no invoker, just the description. The full `ChannelEdited`
            // is a different variant and carries other fields.
            for part in edited.iter() {
                inner.push_event(
                    QueuedEvent::new("channel_edited")
                        .long("channel_id", part.channel_id.0 as i64)
                        .str("description", part.description.clone().unwrap_or_default()),
                );
            }
        }

        InMessage::ClientDbIdFromUid(found) => {
            for part in found.iter() {
                inner.push_event(
                    QueuedEvent::new("client_db_id_resolved")
                        .str("uid", part.client_uid.to_string())
                        .long("client_db_id", part.client_db_id.0 as i64),
                );
            }
            inner.push_event(QueuedEvent::new("client_db_id_resolved_done"));
        }

        InMessage::CustomInfoResponse(info) => {
            for part in info.iter() {
                inner.push_event(
                    QueuedEvent::new("custom_entry")
                        .long("client_db_id", part.client_db_id.0 as i64)
                        .str("ident", &part.external_identity)
                        .str("value", &part.value),
                );
            }
            inner.push_event(QueuedEvent::new("custom_info_done"));
        }

        InMessage::CustomSearchResponse(found) => {
            for part in found.iter() {
                inner.push_event(
                    QueuedEvent::new("custom_entry")
                        .long("client_db_id", part.client_db_id.0 as i64)
                        .str("ident", &part.external_identity)
                        .str("value", &part.value),
                );
            }
            inner.push_event(QueuedEvent::new("custom_search_done"));
        }

        InMessage::ClientFind(found) => {
            for part in found.iter() {
                inner.push_event(
                    QueuedEvent::new("client_found")
                        .int("client_id", part.client_id.0 as i32)
                        .str("nickname", &part.name),
                );
            }
            inner.push_event(QueuedEvent::new("client_find_done"));
        }

        InMessage::PermGet(perm) => {
            for part in perm.iter() {
                inner.push_event(
                    QueuedEvent::new("perm_value")
                        .long("permission_id", part.permission_id.0 as i64)
                        .str("name", part.permission_name_id.clone().unwrap_or_default())
                        .int("value", part.permission_value),
                );
            }
        }

        InMessage::ServerInfoResponse(info) => {
            for part in info.iter() {
                inner.push_event(
                    QueuedEvent::new("server_info")
                        .str(
                            "uid",
                            part.virtual_server_uid
                                .as_ref()
                                .map(|u| u.to_string())
                                .unwrap_or_default(),
                        )
                        .str("name", &part.name)
                        .str("welcome_message", &part.welcome_message)
                        .str("platform", &part.platform)
                        .str("version", &part.version)
                        .int("max_clients", i32::from(part.max_clients))
                        .int("clients_online", i32::from(part.client_count))
                        .long("channels_online", part.channel_count as i64)
                        .long("created", part.created.unix_timestamp())
                        .long("uptime", part.uptime.whole_seconds())
                        .int("port", i32::from(part.port))
                        .bool("has_password", part.has_password)
                        .bool("autostart", part.autostart)
                        .bool("weblist_enabled", part.weblist_enabled)
                        .bool("ask_for_privilegekey", part.ask_for_privilegekey)
                        .str("hostmessage", &part.hostmessage)
                        .int("hostmessage_mode", part.hostmessage_mode as i32)
                        .str("hostbanner_url", &part.hostbanner_url)
                        .str("hostbanner_gfx_url", &part.hostbanner_gfx_url)
                        .str("hostbutton_tooltip", &part.hostbutton_tooltip)
                        .str("hostbutton_url", &part.hostbutton_url)
                        .str("hostbutton_gfx_url", &part.hostbutton_gfx_url)
                        .str("machine_id", &part.machine_id)
                        .str("nickname", &part.nickname)
                        .str("phonetic_name", &part.phonetic_name)
                        .long("icon_id", part.icon.0 as i64)
                        .int("reserved_slots", i32::from(part.reserved_slots))
                        .long("download_quota", part.download_quota as i64)
                        .long("upload_quota", part.upload_quota as i64)
                        .long("bytes_downloaded_month", part.bytes_downloaded_month as i64)
                        .long("bytes_uploaded_month", part.bytes_uploaded_month as i64)
                        .long("bytes_downloaded_total", part.bytes_downloaded_total as i64)
                        .long("bytes_uploaded_total", part.bytes_uploaded_total as i64)
                        .int("packet_loss", percent_of(Some(part.total_packetloss)))
                        .long("ping", part.total_ping.whole_milliseconds() as i64)
                        .long("query_clients_online", i64::from(part.query_count))
                        .long("connection_count_total", part.connection_count_total as i64)
                        .long("query_count_total", part.query_count_total as i64)
                        .int(
                            "needed_identity_security_level",
                            i32::from(part.needed_identity_security_level),
                        )
                        .int(
                            "priority_speaker_dimm_modificator",
                            part.priority_speaker_dimm_modificator as i32,
                        )
                        .str("status", &part.virtual_server_status)
                        .long("default_server_group", part.default_server_group.0 as i64)
                        .long("default_channel_group", part.default_channel_group.0 as i64)
                        .long(
                            "default_channel_admin_group",
                            part.default_channel_admin_group.0 as i64,
                        )
                        .long(
                            "max_download_bandwidth_total",
                            part.max_download_bandwidth_total as i64,
                        )
                        .long(
                            "max_upload_bandwidth_total",
                            part.max_upload_bandwidth_total as i64,
                        )
                        .long(
                            "temp_channel_default_delete_delay",
                            part.temp_channel_default_delete_delay.whole_seconds(),
                        )
                        .bool("log_client", part.log_client)
                        .bool("log_query", part.log_query)
                        .bool("log_channel", part.log_channel)
                        .bool("log_permissions", part.log_permissions)
                        .bool("log_server", part.log_server)
                        .bool("log_filetransfer", part.log_filetransfer),
                );
            }
        }

        InMessage::ServerSnapshotCreateResponse(created) => {
            for part in created.iter() {
                inner.push_event(
                    QueuedEvent::new("server_snapshot")
                        .str("snapshot", &part.snapshot)
                        .long("size", part.snapshot.len() as i64),
                );
            }
        }

        InMessage::ClientInfo(info) => {
            for part in info.iter() {
                inner.push_event(
                    QueuedEvent::new("client_info")
                        // The reply carries no client id: the protocol answers
                        // `clientinfo` without echoing `clid`, so a shell
                        // matches the answer to the request it made.
                        .long("client_db_id", part.database_id.0 as i64)
                        .str("uid", part.uid.to_string())
                        .str("nickname", &part.name)
                        .long("channel_id", part.channel_id.0 as i64)
                        .str("platform", &part.platform)
                        .str("version", &part.version)
                        .str("version_sign", &part.version_sign)
                        .str("login_name", &part.login_name)
                        .str("ip", &part.ip)
                        .str("country", &part.country_code)
                        .str("description", &part.description)
                        .str("avatar_hash", &part.avatar_hash)
                        .long("icon_id", part.icon.0 as i64)
                        .str("badges", &part.badges)
                        .long("idle_time", part.client_idle_time.whole_seconds())
                        .long("connected_time", part.connected_time.whole_seconds())
                        .long("packets_sent", part.packets_sent_total as i64)
                        .long("packets_received", part.packets_received_total as i64)
                        .long("bytes_sent", part.bytes_sent_total as i64)
                        .long("bytes_received", part.bytes_received_total as i64)
                        .long(
                            "filetransfer_bytes_sent",
                            part.filetransfer_bandwidth_sent as i64,
                        )
                        .long(
                            "filetransfer_bytes_received",
                            part.filetransfer_bandwidth_received as i64,
                        )
                        .int("client_type", client_type_code(part.client_type))
                        .bool("recording", part.is_recording)
                        .bool("away", part.is_away)
                        .str("away_message", &part.away_message)
                        .int("talk_power", part.talk_power)
                        .long("channel_group_id", part.channel_group.0 as i64),
                );
            }
        }

        InMessage::ChannelInfoResponse(info) => {
            for part in info.iter() {
                inner.push_event(
                    QueuedEvent::new("channel_info")
                        .long("parent_id", part.parent_channel_id.0 as i64)
                        .str("name", &part.name)
                        .str("topic", &part.topic)
                        .str("description", &part.description)
                        .bool("has_password", part.has_password)
                        .str("codec", crate::state::codec_name(&part.codec))
                        .int("codec_quality", i32::from(part.codec_quality))
                        .int("max_clients", part.max_clients)
                        .int("max_family_clients", part.max_family_clients)
                        .long("order", part.order.0 as i64)
                        .bool("is_permanent", part.is_permanent)
                        .bool("is_default", part.is_default)
                        .int("needed_talk_power", part.needed_talk_power)
                        .bool("forced_silence", part.forced_silence)
                        .long("icon_id", part.icon.0 as i64)
                        .long("delete_delay", part.delete_delay.whole_seconds()),
                );
            }
        }

        InMessage::ChannelFind(found) => {
            for part in found.iter() {
                inner.push_event(
                    QueuedEvent::new("channel_found")
                        .long("channel_id", part.channel_id.0 as i64)
                        .str("name", &part.name),
                );
            }
            inner.push_event(QueuedEvent::new("channel_find_done"));
        }

        InMessage::ClientList(list) => {
            for part in list.iter() {
                inner.push_event(
                    QueuedEvent::new("client_listed")
                        .int("client_id", part.client_id.0 as i32)
                        .long("channel_id", part.channel_id.0 as i64)
                        .long("client_db_id", part.database_id.0 as i64)
                        .str("nickname", &part.name)
                        .str(
                            "uid",
                            part.uid.as_ref().map(|u| u.to_string()).unwrap_or_default(),
                        )
                        .int("client_type", client_type_code(part.client_type))
                        .bool("away", part.is_away.unwrap_or(false))
                        .str(
                            "away_message",
                            part.away_message.clone().unwrap_or_default(),
                        )
                        .bool("talking", part.is_talking.unwrap_or(false))
                        .bool("input_muted", part.input_muted.unwrap_or(false))
                        .bool("output_muted", part.output_muted.unwrap_or(false))
                        .bool("recording", part.is_recording.unwrap_or(false))
                        .int("talk_power", part.talk_power.unwrap_or(0))
                        .long(
                            "channel_group_id",
                            part.channel_group.map_or(0, |id| id.0 as i64),
                        )
                        .str("platform", part.platform.clone().unwrap_or_default())
                        .str("version", part.version.clone().unwrap_or_default())
                        .str("country", part.country_code.clone().unwrap_or_default()),
                );
            }
            inner.push_event(QueuedEvent::new("client_list_done"));
        }

        InMessage::ServerListResponse(servers) => {
            for part in servers.iter() {
                inner.push_event(
                    QueuedEvent::new("virtual_server_listed")
                        .long("server_id", part.virtual_server_id as i64)
                        .int("port", i32::from(part.port))
                        .str("status", &part.virtual_server_status)
                        .int("clients_online", i32::from(part.client_count.unwrap_or(0)))
                        .int("query_clients_online", part.query_count.unwrap_or(0) as i32)
                        .int("max_clients", i32::from(part.max_clients.unwrap_or(0)))
                        .long("uptime", part.uptime.map_or(0, |d| d.whole_seconds()))
                        .bool("autostart", part.autostart.unwrap_or(false))
                        .str("machine_id", part.machine_id.clone().unwrap_or_default())
                        .str("name", part.name.clone().unwrap_or_default())
                        .str(
                            "uid",
                            part.virtual_server_uid
                                .as_ref()
                                .map(|u| u.to_string())
                                .unwrap_or_default(),
                        ),
                );
            }
            inner.push_event(QueuedEvent::new("virtual_server_list_done"));
        }

        InMessage::WhoAmI(me) => {
            for part in me.iter() {
                inner.push_event(
                    QueuedEvent::new("who_am_i")
                        .int("client_id", part.client_id.0 as i32)
                        .long("channel_id", part.channel_id.0 as i64)
                        .str("nickname", &part.name)
                        .long("client_db_id", part.database_id.0 as i64)
                        .str("login_name", &part.login_name)
                        .str("uid", part.uid.to_string())
                        .long("server_id", part.virtual_server_id as i64)
                        .long("origin_server_id", part.origin_server_id as i64)
                        .str("server_uid", part.virtual_server_uid.to_string())
                        .int("port", i32::from(part.port))
                        .str("server_status", &part.virtual_server_status),
                );
            }
        }

        InMessage::ServerGroupClientList(list) => {
            for part in list.iter() {
                inner.push_event(
                    QueuedEvent::new("server_group_client")
                        .long("group_id", part.server_group_id.0 as i64)
                        .long("client_db_id", part.client_db_id.0 as i64)
                        .str("nickname", part.name.clone().unwrap_or_default())
                        .str(
                            "uid",
                            part.uid.as_ref().map(|u| u.to_string()).unwrap_or_default(),
                        ),
                );
            }
            inner.push_event(QueuedEvent::new("server_group_client_list_done"));
        }

        InMessage::ServerGroupPermList(list) => {
            for part in list.iter() {
                inner.push_event(
                    QueuedEvent::new("group_permission")
                        .str("group_kind", "server")
                        .long("group_id", part.server_group_id.0 as i64)
                        .str(
                            "name",
                            permission_name(part.permission_id, &part.permission_name_id),
                        )
                        .int("value", part.permission_value)
                        .bool("negated", part.permission_negated)
                        .bool("skip", part.permission_skip),
                );
            }
            inner.push_event(
                QueuedEvent::new("group_permission_list_done").str("group_kind", "server"),
            );
        }

        InMessage::ChannelGroupPermList(list) => {
            for part in list.iter() {
                inner.push_event(
                    QueuedEvent::new("group_permission")
                        .str("group_kind", "channel")
                        .long("group_id", part.channel_group.0 as i64)
                        .str(
                            "name",
                            permission_name(part.permission_id, &part.permission_name_id),
                        )
                        .int("value", part.permission_value)
                        .bool("negated", part.permission_negated)
                        .bool("skip", part.permission_skip),
                );
            }
            inner.push_event(
                QueuedEvent::new("group_permission_list_done").str("group_kind", "channel"),
            );
        }

        InMessage::ChannelGroupClientList(list) => {
            for part in list.iter() {
                inner.push_event(
                    QueuedEvent::new("channel_group_client")
                        .long("channel_id", part.channel_id.0 as i64)
                        .long("client_db_id", part.client_db_id.0 as i64)
                        .long("group_id", part.channel_group.0 as i64),
                );
            }
            inner.push_event(QueuedEvent::new("channel_group_client_list_done"));
        }

        InMessage::ChannelClientPermList(list) => {
            for part in list.iter() {
                inner.push_event(
                    QueuedEvent::new("channel_client_permission")
                        .long("channel_id", part.channel_id.0 as i64)
                        .long("client_db_id", part.client_db_id.0 as i64)
                        .str(
                            "name",
                            permission_name(part.permission_id, &part.permission_name_id),
                        )
                        .int("value", part.permission_value)
                        .bool("negated", part.permission_negated)
                        .bool("skip", part.permission_skip),
                );
            }
            inner.push_event(QueuedEvent::new("channel_client_permission_list_done"));
        }

        InMessage::ServerGroupsByClientId(list) => {
            for part in list.iter() {
                inner.push_event(
                    QueuedEvent::new("client_server_group")
                        .long("client_db_id", part.client_db_id.0 as i64)
                        .long("group_id", part.server_group_id.0 as i64)
                        .str("name", &part.name),
                );
            }
            inner.push_event(QueuedEvent::new("client_server_group_list_done"));
        }

        InMessage::ClientIds(list) => {
            for part in list.iter() {
                inner.push_event(
                    QueuedEvent::new("client_id_resolved")
                        .str("uid", part.client_uid.to_string())
                        .int("client_id", part.client_id.0 as i32)
                        .str("nickname", &part.name),
                );
            }
            inner.push_event(QueuedEvent::new("client_id_resolved_done"));
        }

        InMessage::ClientNameFromDbId(list) => {
            for part in list.iter() {
                inner.push_event(
                    QueuedEvent::new("client_name_resolved")
                        .str("uid", part.client_uid.to_string())
                        .long("client_db_id", part.client_db_id.0 as i64)
                        .str("nickname", &part.name),
                );
            }
            inner.push_event(QueuedEvent::new("client_name_resolved_done"));
        }

        InMessage::ClientNameFromUid(list) => {
            for part in list.iter() {
                inner.push_event(
                    QueuedEvent::new("client_name_resolved")
                        .str("uid", part.client_uid.to_string())
                        .long("client_db_id", part.client_db_id.0 as i64)
                        .str("nickname", &part.name),
                );
            }
            inner.push_event(QueuedEvent::new("client_name_resolved_done"));
        }

        InMessage::ClientUidFromClid(list) => {
            for part in list.iter() {
                inner.push_event(
                    QueuedEvent::new("client_uid_resolved")
                        .str("uid", part.client_uid.to_string())
                        .int("client_id", part.client_id.0 as i32)
                        .str("nickname", &part.nickname),
                );
            }
            inner.push_event(QueuedEvent::new("client_uid_resolved_done"));
        }

        InMessage::ClientConnectionInfo(info) => {
            for part in info.iter() {
                inner.push_event(
                    QueuedEvent::new("client_connection_info")
                        .int("client_id", part.client_id.0 as i32)
                        .long("ping", signed_millis_of(part.ping))
                        .long("ping_deviation", signed_millis_of(part.ping_deviation))
                        .long(
                            "connected_time",
                            part.connected_time.map_or(0, |d| d.whole_seconds()),
                        )
                        .str("ip", part.ip.clone().unwrap_or_default())
                        .int("port", part.port.map_or(0, i32::from))
                        .long(
                            "packets_sent",
                            part.packets_sent_speech.unwrap_or(0) as i64
                                + part.packets_sent_keepalive.unwrap_or(0) as i64
                                + part.packets_sent_control.unwrap_or(0) as i64,
                        )
                        .long(
                            "bytes_sent",
                            part.bytes_sent_speech.unwrap_or(0) as i64
                                + part.bytes_sent_keepalive.unwrap_or(0) as i64
                                + part.bytes_sent_control.unwrap_or(0) as i64,
                        )
                        .long(
                            "packets_received",
                            part.packets_received_speech.unwrap_or(0) as i64
                                + part.packets_received_keepalive.unwrap_or(0) as i64
                                + part.packets_received_control.unwrap_or(0) as i64,
                        )
                        .long(
                            "bytes_received",
                            part.bytes_received_speech.unwrap_or(0) as i64
                                + part.bytes_received_keepalive.unwrap_or(0) as i64
                                + part.bytes_received_control.unwrap_or(0) as i64,
                        )
                        // The server-side loss is the one a caller can act on:
                        // it measures what the server failed to send us.
                        .int(
                            "packet_loss",
                            percent_of(part.server_to_client_packetloss_total),
                        ),
                );
            }
        }

        InMessage::ServerConnectionInfo(info) => {
            for part in info.iter() {
                inner.push_event(
                    QueuedEvent::new("server_connection_info")
                        .long("packets_sent", part.packets_sent_total as i64)
                        .long("bytes_sent", part.bytes_sent_total as i64)
                        .long("packets_received", part.packets_received_total as i64)
                        .long("bytes_received", part.bytes_received_total as i64)
                        .long(
                            "filetransfer_bytes_sent",
                            part.filetransfer_bytes_sent_total as i64,
                        )
                        .long(
                            "filetransfer_bytes_received",
                            part.filetransfer_bytes_received_total as i64,
                        )
                        .long("connected_time", part.connected_time_total.whole_seconds())
                        .long("ping", part.ping.whole_milliseconds() as i64)
                        // Hundredths of a percent, so the value stays an integer:
                        // the wire sends a float and every shell would round it.
                        .int("packet_loss", percent_of(Some(part.packetloss_total))),
                );
            }
        }

        InMessage::FileInfo(info) => {
            for part in info.iter() {
                inner.push_event(
                    QueuedEvent::new("file_info")
                        .long("channel_id", part.channel_id.0 as i64)
                        .str("path", &part.path)
                        .str("name", &part.name)
                        .long("size", part.size as i64)
                        .long("date_time", part.date_time.unix_timestamp()),
                );
            }
        }

        InMessage::PermFind(found) => {
            for part in found.iter() {
                inner.push_event(
                    QueuedEvent::new("perm_found")
                        .str("scope", permission_type_name(part.permission_type))
                        .long("id1", part.id1 as i64)
                        .long("id2", part.id2 as i64)
                        .long("permission_id", part.permission_id.0 as i64),
                );
            }
            inner.push_event(QueuedEvent::new("perm_find_done"));
        }

        InMessage::PermList(list) => {
            for part in list.iter() {
                inner.push_event(
                    QueuedEvent::new("perm_listed")
                        .long("group_id_end", part.group_id_end.0 as i64)
                        .long(
                            "permission_id",
                            part.permission_id.map_or(0, |id| id.0 as i64),
                        )
                        .str("name", part.permission_name.clone().unwrap_or_default())
                        .str(
                            "description",
                            part.permission_description.clone().unwrap_or_default(),
                        ),
                );
            }
            inner.push_event(QueuedEvent::new("perm_list_done"));
        }

        InMessage::ServerLog(log) => {
            for part in log.iter() {
                inner.push_event(
                    QueuedEvent::new("log_line")
                        .long("offset", part.last_offset as i64)
                        .long("file_size", part.file_size as i64)
                        .str("line", &part.log),
                );
            }
        }

        InMessage::TokenAdd(added) => {
            for part in added.iter() {
                inner.push_event(QueuedEvent::new("token_created").str("token", &part.token));
            }
        }

        InMessage::TokenList(list) => {
            for part in list.iter() {
                inner.push_event(
                    QueuedEvent::new("token_listed")
                        .str("token", &part.token)
                        .str("token_kind", token_type_name(part.token_type))
                        .long("group_id", part.token_id1 as i64)
                        .long("channel_id", part.token_id2.0 as i64)
                        .long("created", part.token_create_time.unix_timestamp())
                        .str("description", &part.token_description),
                );
            }
            inner.push_event(QueuedEvent::new("token_list_done"));
        }

        InMessage::TokenUsed(used) => {
            for part in used.iter() {
                inner.push_event(
                    QueuedEvent::new("token_used")
                        .str("token", &part.token)
                        .str("custom_set", &part.token_custom_set)
                        .str("group_id", &part.token1)
                        .str("channel_id", &part.token2)
                        .int("client_id", part.client_id.0 as i32)
                        .long("client_db_id", part.client_db_id.0 as i64)
                        .str("uid", part.client_uid.to_string()),
                );
            }
        }

        InMessage::ClientChatClosed(closed) => {
            for part in closed.iter() {
                inner.push_event(
                    QueuedEvent::new("chat_closed")
                        .int("client_id", part.client_id.0 as i32)
                        .str("uid", part.client_uid.to_string()),
                );
            }
        }

        InMessage::Filetransfer(transfers) => {
            for part in transfers.iter() {
                inner.push_event(
                    QueuedEvent::new("filetransfer")
                        .int("client_id", part.client_id.0 as i32)
                        .str("path", &part.path)
                        .str("name", &part.name)
                        .long("size", part.size as i64)
                        .long("size_done", part.size_done)
                        .int("server_id", i32::from(part.server_filetransfer_id))
                        .int("client_id_transfer", i32::from(part.client_filetransfer_id))
                        .str("sender", part.sender.to_string())
                        .int("status", part.status)
                        .int("speed", part.current_speed as i32)
                        .long("runtime", part.runtime.whole_seconds()),
                );
            }
            inner.push_event(QueuedEvent::new("filetransfer_list_done"));
        }

        InMessage::FileList(list) => {
            let mut entries = Vec::new();
            let mut channel_id = session.listing_channel.unwrap_or(0);
            for part in list.iter() {
                channel_id = part.channel_id.0 as i64;
                entries.push(FileEntry {
                    channel_id,
                    path: part.path.clone(),
                    name: part.name.clone(),
                    size: part.size,
                    is_file: part.is_file,
                    date_time: part.date_time.unix_timestamp(),
                });
            }
            let event = inner.with_state(|snapshot| snapshot.set_files(channel_id, entries));
            inner.push_event(event);
        }

        _ => {}
    }
}

/// Returns false when the session is over.
fn handle_command(
    inner: &Arc<Inner>,
    connection: &mut Connection,
    session: &mut Session,
    command: Command,
) -> bool {
    match command {
        Command::Disconnect => return false,

        Command::SendText { target, message } => {
            let target = match target {
                TextTarget::Server => MessageTarget::Server,
                TextTarget::Channel => MessageTarget::Channel,
                TextTarget::Client(id) => MessageTarget::Client(ClientId(id as u16)),
            };
            let command = match connection.get_state() {
                Ok(book) => book.send_message(target, &message),
                Err(e) => {
                    push_command_error(inner, &e.to_string());
                    return true;
                }
            };
            if let Err(e) = command.send(connection) {
                push_command_error(inner, &e.to_string());
            }
        }

        Command::Poke { client_id, message } => {
            let command = match connection.get_state() {
                Ok(book) => {
                    book.send_message(MessageTarget::Poke(ClientId(client_id as u16)), &message)
                }
                Err(e) => {
                    push_command_error(inner, &e.to_string());
                    return true;
                }
            };
            if let Err(e) = command.send(connection) {
                push_command_error(inner, &e.to_string());
            }
        }

        Command::JoinChannel {
            channel_id,
            password,
        } => {
            let command =
                c2s::OutClientMoveMessage::new(&mut std::iter::once(c2s::OutClientMovePart {
                    client_id: ClientId(own_id(connection)),
                    channel_id: ChannelId(channel_id as u64),
                    channel_password: password.map(Into::into),
                }));
            if let Err(e) = command.send(connection) {
                push_command_error(inner, &e.to_string());
            }
        }

        Command::SetInputMuted(muted) => {
            send_update(inner, connection, |part| part.input_muted = Some(muted));
            // Dropping whatever was captured before the mute keeps a stale
            // syllable from being transmitted after the fact.
            if muted {
                inner.clear_capture();
                session.last_voice = None;
                inner.with_state(|snapshot| snapshot.set_own_talking(false));
            }
            session.audio.set_enabled(!muted);
        }

        Command::SetOutputMuted(muted) => {
            send_update(inner, connection, |part| part.output_muted = Some(muted));
        }

        Command::SetAway { away, message } => {
            send_update(inner, connection, |part| {
                part.is_away = Some(away);
                part.away_message = Some(message.unwrap_or_default().into());
            });
        }

        Command::SetNickname(name) => {
            send_update(inner, connection, |part| part.name = Some(name.into()));
        }

        Command::ListFiles {
            channel_id,
            path,
            password,
        } => {
            session.listing_channel = Some(channel_id);
            let command = c2s::OutFileListRequestMessage::new(&mut std::iter::once(
                c2s::OutFileListRequestPart {
                    channel_id: ChannelId(channel_id as u64),
                    channel_password: password.unwrap_or_default().into(),
                    path: path.into(),
                },
            ));
            if let Err(e) = command.send(connection) {
                push_command_error(inner, &e.to_string());
            }
            // The answer decides which write buttons should exist, and it is
            // per client, so it is requested next to the listing rather than
            // for every channel at connect time.
            request_file_permissions(connection, channel_id);
        }

        Command::Download {
            channel_id,
            path,
            local,
            password,
        } => {
            match connection.download_file(
                ChannelId(channel_id as u64),
                &path,
                password.as_deref(),
                None,
            ) {
                Ok(handle) => {
                    session.downloads.insert(
                        handle.0,
                        Pending {
                            name: file_name(&path),
                            local: PathBuf::from(local),
                        },
                    );
                }
                Err(e) => push_command_error(inner, &e.to_string()),
            }
        }

        Command::Upload {
            channel_id,
            path,
            local,
            password,
            overwrite,
        } => {
            let local_path = PathBuf::from(&local);
            let size = match std::fs::metadata(&local_path) {
                Ok(meta) => meta.len(),
                Err(e) => {
                    push_command_error(inner, &format!("cannot read {local}: {e}"));
                    return true;
                }
            };
            match connection.upload_file(
                ChannelId(channel_id as u64),
                &path,
                password.as_deref(),
                size,
                overwrite,
                false,
            ) {
                Ok(handle) => {
                    session.uploads.insert(
                        handle.0,
                        Pending {
                            name: file_name(&path),
                            local: local_path,
                        },
                    );
                }
                Err(e) => push_command_error(inner, &e.to_string()),
            }
        }

        Command::SetAudioEnabled(enabled) => session.audio.set_enabled(enabled),

        Command::SetMicGain(gain) => session.audio.set_gain(gain),

        Command::SetUserVolume { client_id, volume } => {
            session
                .audio
                .set_user_volume(ClientId(client_id as u16), volume);
        }

        Command::SetWhisperTargets {
            clients,
            channels,
            groups,
        } => {
            session.audio.set_whisper_targets(WhisperTargets {
                clients: clients.clone(),
                channels: channels.clone(),
                groups,
            });
            // The snapshot carries the same list so a shell can light the
            // whisper mark without keeping its own copy of what it asked for.
            let client_ids: Vec<i32> = clients.iter().map(|id| *id as i32).collect();
            let channel_ids: Vec<i64> = channels.iter().map(|id| *id as i64).collect();
            inner.with_state(|snapshot| snapshot.set_whisper_targets(client_ids, channel_ids));
        }

        Command::KickClient {
            client_id,
            reason,
            message,
        } => {
            let reason = match reason {
                4 => Reason::KickChannel,
                _ => Reason::KickServer,
            };
            let part = c2s::OutClientKickPart {
                client_id: ClientId(client_id as u16),
                reason,
                reason_message: message.map(std::borrow::Cow::Owned),
            };
            send_message(inner, connection, part, "clientkick");
        }

        Command::MoveClient {
            client_id,
            channel_id,
            password,
        } => {
            let part = c2s::OutClientMovePart {
                client_id: ClientId(client_id as u16),
                channel_id: ChannelId(channel_id as u64),
                channel_password: password.map(std::borrow::Cow::Owned),
            };
            send_message(inner, connection, part, "clientmove");
        }

        Command::BanAdd {
            uid,
            ip,
            name,
            seconds,
            reason,
        } => {
            if uid.is_none() && ip.is_none() && name.is_none() {
                push_command_error(inner, "ban needs a uid, an ip or a name");
                return true;
            }
            let ip = match ip.as_deref().map(str::parse) {
                Some(Ok(ip)) => Some(ip),
                Some(Err(_)) => {
                    push_command_error(inner, "ban ip is not an address");
                    return true;
                }
                None => None,
            };
            let uid = match uid {
                None => None,
                Some(text) => match BASE64_STANDARD.decode(text.as_bytes()) {
                    Ok(bytes) => Some(std::borrow::Cow::Owned(UidBuf(bytes))),
                    Err(_) => {
                        push_command_error(inner, "ban uid is not base64");
                        return true;
                    }
                },
            };
            let part = c2s::OutBanAddPart {
                ip,
                name: name.map(std::borrow::Cow::Owned),
                uid,
                time: (seconds > 0)
                    .then(|| time::Duration::seconds(seconds.min(i64::MAX as u64) as i64)),
                ban_reason: reason.map(std::borrow::Cow::Owned),
            };
            send_message(inner, connection, part, "banadd");
        }

        Command::BanDelete { ban_id } => {
            if ban_id <= 0 {
                let message = c2s::OutBanDelAllMessage::new();
                send_packet(inner, connection, message, "bandelall");
            } else {
                let part = c2s::OutBanDelPart {
                    ban_id: ban_id as u32,
                };
                send_message(inner, connection, part, "bandel");
            }
        }

        Command::BanList => {
            let message = c2s::OutBanListRequestMessage::new();
            send_packet(inner, connection, message, "banlist");
        }

        Command::ChannelCreate {
            parent_id,
            name,
            topic,
            description,
            password,
            max_clients,
            order,
        } => {
            let part = c2s::OutChannelCreatePart {
                parent_id: parent_id.map(|id| ChannelId(id as u64)),
                name: std::borrow::Cow::Owned(name),
                topic: topic.map(std::borrow::Cow::Owned),
                description: description.map(std::borrow::Cow::Owned),
                password: password.map(std::borrow::Cow::Owned),
                codec: None,
                codec_quality: None,
                max_clients,
                max_family_clients: None,
                order: order.map(|id| ChannelId(id as u64)),
                has_password: None,
                is_unencrypted: None,
                delete_delay: None,
                is_max_clients_unlimited: None,
                is_max_family_clients_unlimited: None,
                inherits_max_family_clients: None,
                phonetic_name: None,
                is_permanent: None,
                is_semi_permanent: None,
                is_default: None,
            };
            send_message(inner, connection, part, "channelcreate");
        }

        Command::ChannelEdit {
            channel_id,
            name,
            topic,
            description,
            max_clients,
        } => {
            let part = c2s::OutChannelEditPart {
                channel_id: ChannelId(channel_id as u64),
                order: None,
                name: name.map(std::borrow::Cow::Owned),
                topic: topic.map(std::borrow::Cow::Owned),
                is_default: None,
                has_password: None,
                password: None,
                is_permanent: None,
                is_semi_permanent: None,
                codec: None,
                codec_quality: None,
                needed_talk_power: None,
                max_clients,
                max_family_clients: None,
                codec_latency_factor: None,
                is_unencrypted: None,
                delete_delay: None,
                is_max_clients_unlimited: None,
                is_max_family_clients_unlimited: None,
                inherits_max_family_clients: None,
                phonetic_name: None,
                description: description.map(std::borrow::Cow::Owned),
            };
            send_message(inner, connection, part, "channeledit");
        }

        Command::ChannelDelete { channel_id, force } => {
            let part = c2s::OutChannelDeletePart {
                channel_id: ChannelId(channel_id as u64),
                force,
            };
            send_message(inner, connection, part, "channeldelete");
        }

        Command::ChannelSubscribe {
            channel_id,
            subscribed,
        } => {
            if subscribed {
                let part = c2s::OutChannelSubscribePart {
                    channel_id: ChannelId(channel_id as u64),
                };
                send_message(inner, connection, part, "channelsubscribe");
            } else {
                let part = c2s::OutChannelUnsubscribePart {
                    channel_id: ChannelId(channel_id as u64),
                };
                send_message(inner, connection, part, "channelunsubscribe");
            }
        }

        Command::ComplainAdd {
            client_db_id,
            message,
        } => {
            let part = c2s::OutComplainAddPart {
                target_client_db_id: ClientDbId(client_db_id as u64),
                message: std::borrow::Cow::Owned(message),
            };
            send_message(inner, connection, part, "complainadd");
        }

        Command::ComplainDelete {
            client_db_id,
            message,
        } => {
            if client_db_id <= 0 {
                let mut parts = std::iter::empty::<c2s::OutComplainDelAllPart>();
                let message = c2s::OutComplainDelAllMessage::new(&mut parts);
                send_packet(inner, connection, message, "complaindelall");
            } else {
                // The protocol drops one complaint by (target, author); this
                // shell has no author to name, so it removes the caller's own.
                let _ = message;
                let part = c2s::OutComplainDelPart {
                    target_client_db_id: ClientDbId(client_db_id as u64),
                    from_client_db_id: ClientDbId(0),
                };
                send_message(inner, connection, part, "complaindel");
            }
        }

        Command::PrivilegeKeyCreate {
            group_id,
            channel_id,
            description,
        } => {
            let part = c2s::OutPrivilegeKeyAddRequestPart {
                token_type: if channel_id > 0 {
                    TokenType::ChannelGroup
                } else {
                    TokenType::ServerGroup
                },
                token_id1: group_id as u64,
                token_id2: ChannelId(channel_id.max(0) as u64),
                token_description: description.map(std::borrow::Cow::Owned),
                token_custom_set: None,
            };
            send_message(inner, connection, part, "privilegekeyadd");
        }

        Command::PrivilegeKeyUse { key } => {
            let part = c2s::OutPrivilegeKeyUsePart {
                token: std::borrow::Cow::Owned(key),
            };
            send_message(inner, connection, part, "privilegekeyuse");
        }

        Command::PrivilegeKeyList => {
            let message = c2s::OutPrivilegeKeyListRequestMessage::new();
            send_packet(inner, connection, message, "privilegekeylist");
        }

        Command::SetClientChannelGroup {
            client_db_id,
            channel_id,
            group_id,
        } => {
            let part = c2s::OutSetClientChannelGroupPart {
                channel_group: ChannelGroupId(group_id as u64),
                channel_id: ChannelId(channel_id as u64),
                client_db_id: ClientDbId(client_db_id as u64),
            };
            send_message(inner, connection, part, "setclientchannelgroup");
        }

        Command::OfflineMessageList => {
            let message = c2s::OutOfflineMessageListRequestMessage::new();
            send_packet(inner, connection, message, "messagelist");
        }

        Command::OfflineMessageGet { message_id } => {
            let part = c2s::OutOfflineMessageGetPart {
                message_id: message_id as u32,
            };
            send_message(inner, connection, part, "messageget");
        }

        Command::OfflineMessageDelete { message_id } => {
            let part = c2s::OutOfflineMessageDelPart {
                message_id: message_id as u32,
            };
            send_message(inner, connection, part, "messagedel");
        }

        Command::OfflineMessageSend {
            uid,
            subject,
            message,
        } => {
            let uid = match BASE64_STANDARD.decode(uid.as_bytes()) {
                Ok(bytes) => UidBuf(bytes),
                Err(_) => {
                    push_command_error(inner, "offline message uid is not base64");
                    return true;
                }
            };
            let part = c2s::OutOfflineMessageAddPart {
                client_uid: std::borrow::Cow::Owned(uid),
                subject: std::borrow::Cow::Owned(subject),
                message: std::borrow::Cow::Owned(message),
            };
            send_message(inner, connection, part, "messageadd");
        }

        Command::ServerVariables => {
            let message = c2s::OutServerVariablesRequestMessage::new();
            send_packet(inner, connection, message, "servervariable");
        }

        Command::ClientVariables { client_id } => {
            let part = c2s::OutClientVariablesRequestPart {
                client_id: ClientId(client_id as u16),
            };
            send_message(inner, connection, part, "clientvariable");
        }

        Command::TempPasswordAdd {
            password,
            description,
            seconds,
            channel_id,
            channel_password,
        } => {
            let part = c2s::OutServerTempPasswordAddPart {
                password: std::borrow::Cow::Owned(password),
                description: std::borrow::Cow::Owned(description),
                duration: time::Duration::seconds(seconds.min(i64::MAX as u64) as i64),
                target_channel_id: ChannelId(channel_id.max(0) as u64),
                target_channel_password: std::borrow::Cow::Owned(channel_password),
            };
            send_message(inner, connection, part, "servertemppasswordadd");
        }

        Command::TempPasswordDelete { password } => {
            let part = c2s::OutServerTempPasswordDelPart {
                password: std::borrow::Cow::Owned(password),
            };
            send_message(inner, connection, part, "servertemppassworddel");
        }

        Command::TempPasswordList => {
            let message = c2s::OutServerTempPasswordListRequestMessage::new();
            send_packet(inner, connection, message, "servertemppasswordlist");
        }

        Command::ClientPermissionList { client_db_id } => {
            let part = c2s::OutClientPermListRequestPart {
                client_db_id: ClientDbId(client_db_id as u64),
            };
            send_message(inner, connection, part, "clientpermlist");
        }

        Command::ChannelPermissionList { channel_id } => {
            let part = c2s::OutChannelPermListRequestPart {
                channel_id: ChannelId(channel_id as u64),
            };
            send_message(inner, connection, part, "channelpermlist");
        }

        Command::ClientEdit {
            client_id,
            description,
            talk_power_granted,
        } => {
            let part = c2s::OutClientEditPart {
                client_id: ClientId(client_id as u16),
                description: description.map(std::borrow::Cow::Owned),
                talk_power_granted,
            };
            send_message(inner, connection, part, "clientedit");
        }

        Command::ClientUpdate {
            channel_commander,
            recording,
            phonetic_name,
            input_hardware_enabled,
            output_hardware_enabled,
            avatar_hash,
        } => {
            let part = c2s::OutClientUpdatePart {
                name: None,
                input_muted: None,
                output_muted: None,
                is_away: None,
                away_message: None,
                input_hardware_enabled,
                output_hardware_enabled,
                is_channel_commander: channel_commander,
                avatar_hash: avatar_hash.map(std::borrow::Cow::Owned),
                phonetic_name: phonetic_name.map(std::borrow::Cow::Owned),
                talk_power_request: None,
                talk_power_request_message: None,
                is_recording: recording,
                badges: None,
            };
            send_message(inner, connection, part, "clientupdate");
        }

        Command::TalkPowerRequest { message } => {
            let part = c2s::OutClientUpdatePart {
                name: None,
                input_muted: None,
                output_muted: None,
                is_away: None,
                away_message: None,
                input_hardware_enabled: None,
                output_hardware_enabled: None,
                is_channel_commander: None,
                avatar_hash: None,
                phonetic_name: None,
                talk_power_request: Some(true),
                talk_power_request_message: message.map(std::borrow::Cow::Owned),
                is_recording: None,
                badges: None,
            };
            send_message(inner, connection, part, "clientupdate");
        }

        Command::ServerEdit {
            name,
            welcome_message,
            max_clients,
        } => {
            // Forty-four optional fields, all `None` except the three this
            // command can set. Written out because the type has no `Default`:
            // a `..` here would hide which fields the protocol has.
            let part = c2s::OutServerEditPart {
                server_id: None,
                name: name.map(std::borrow::Cow::Owned),
                welcome_message: welcome_message.map(std::borrow::Cow::Owned),
                max_clients: max_clients.map(|v| v.clamp(0, u16::MAX as i32) as u16),
                password: None,
                hostmessage: None,
                hostmessage_mode: None,
                hostbanner_url: None,
                hostbanner_gfx_url: None,
                hostbanner_gfx_interval: None,
                hostbutton_tooltip: None,
                hostbutton_url: None,
                hostbutton_gfx_url: None,
                icon: None,
                reserved_slots: None,
                hostbanner_mode: None,
                nickname: None,
                max_download_bandwidth_total: None,
                max_upload_bandwidth_total: None,
                download_quota: None,
                upload_quota: None,
                antiflood_points_tick_reduce: None,
                antiflood_points_to_command_block: None,
                antiflood_points_to_ip_block: None,
                codec_encryption_mode: None,
                needed_identity_security_level: None,
                default_server_group: None,
                default_channel_group: None,
                default_channel_admin_group: None,
                complain_autoban_count: None,
                complain_autoban_time: None,
                complain_remove_time: None,
                min_clients_in_channel_before_forced_silence: None,
                priority_speaker_dimm_modificator: None,
                phonetic_name: None,
                temp_channel_default_delete_delay: None,
                weblist_enabled: None,
                log_client: None,
                log_query: None,
                log_channel: None,
                log_permissions: None,
                log_server: None,
                log_filetransfer: None,
            };
            send_message(inner, connection, part, "serveredit");
        }

        Command::NotifyRegister {
            channel_id,
            subscribed,
        } => {
            if subscribed {
                // `server` with no id is the whole-server event set; naming a
                // channel narrows it to that channel's events.
                let part = c2s::OutServerNotifyRegisterPart {
                    event_type: std::borrow::Cow::Borrowed("server"),
                    id: (channel_id > 0).then_some(ChannelId(channel_id as u64)),
                };
                send_message(inner, connection, part, "servernotifyregister");
            } else {
                let message = c2s::OutServerNotifyUnregisterMessage::new();
                send_packet(inner, connection, message, "servernotifyunregister");
            }
        }

        Command::DeleteFile {
            channel_id,
            path,
            password,
        } => {
            let part = c2s::OutDeleteFilePart {
                channel_id: ChannelId(channel_id as u64),
                channel_password: std::borrow::Cow::Borrowed(password.as_deref().unwrap_or("")),
                name: std::borrow::Cow::Owned(path),
            };
            send_message(inner, connection, part, "ftdeletefile");
        }

        Command::RenameFile {
            channel_id,
            path,
            new_name,
            target_channel_id,
            target_password,
            password,
        } => {
            let part = c2s::OutRenameFilePart {
                channel_id: ChannelId(channel_id as u64),
                channel_password: std::borrow::Cow::Borrowed(password.as_deref().unwrap_or("")),
                target_channel_id: target_channel_id.map(|id| ChannelId(id as u64)),
                target_channel_password: target_password.map(std::borrow::Cow::Owned),
                old_name: std::borrow::Cow::Owned(path),
                new_name: std::borrow::Cow::Owned(new_name),
            };
            send_message(inner, connection, part, "ftrenamefile");
        }

        Command::CreateDirectory {
            channel_id,
            path,
            password,
        } => {
            let part = c2s::OutCreateDirectoryPart {
                channel_id: ChannelId(channel_id as u64),
                channel_password: std::borrow::Cow::Borrowed(password.as_deref().unwrap_or("")),
                directory_name: std::borrow::Cow::Owned(path),
            };
            send_message(inner, connection, part, "ftcreatedir");
        }

        Command::ServerGroupCreate { name, group_type } => {
            let part = c2s::OutServerGroupAddPart {
                name: std::borrow::Cow::Owned(name),
                group_type: group_type.map(group_type_of),
            };
            send_message(inner, connection, part, "servergroupadd");
        }

        Command::ServerGroupDelete { group_id, force } => {
            let part = c2s::OutServerGroupDelPart {
                server_group_id: ServerGroupId(group_id.max(0) as u64),
                force,
            };
            send_message(inner, connection, part, "servergroupdel");
        }

        Command::ServerGroupRename { group_id, name } => {
            let part = c2s::OutServerGroupRenamePart {
                server_group_id: ServerGroupId(group_id.max(0) as u64),
                name: std::borrow::Cow::Owned(name),
            };
            send_message(inner, connection, part, "servergrouprename");
        }

        Command::ServerGroupAddClient {
            group_id,
            client_db_id,
        } => {
            let part = c2s::OutServerGroupAddClientPart {
                server_group_id: ServerGroupId(group_id.max(0) as u64),
                client_db_id: ClientDbId(client_db_id.max(0) as u64),
            };
            send_message(inner, connection, part, "servergroupaddclient");
        }

        Command::ServerGroupDelClient {
            group_id,
            client_db_id,
        } => {
            let part = c2s::OutServerGroupDelClientPart {
                server_group_id: ServerGroupId(group_id.max(0) as u64),
                client_db_id: ClientDbId(client_db_id.max(0) as u64),
            };
            send_message(inner, connection, part, "servergroupdelclient");
        }

        Command::ChannelGroupCreate { name, group_type } => {
            let part = c2s::OutChannelGroupAddPart {
                name: std::borrow::Cow::Owned(name),
                group_type: group_type.map(group_type_of),
            };
            send_message(inner, connection, part, "channelgroupadd");
        }

        Command::ChannelGroupDelete { group_id, force } => {
            let part = c2s::OutChannelGroupDelPart {
                channel_group: ChannelGroupId(group_id.max(0) as u64),
                force,
            };
            send_message(inner, connection, part, "channelgroupdel");
        }

        Command::ChannelGroupRename { group_id, name } => {
            let part = c2s::OutChannelGroupRenamePart {
                channel_group: ChannelGroupId(group_id.max(0) as u64),
                name: std::borrow::Cow::Owned(name),
            };
            send_message(inner, connection, part, "channelgrouprename");
        }

        Command::ChannelClientAddPerm {
            channel_id,
            client_db_id,
            permission_id,
            permission_name,
            value,
        } => {
            if permission_id.is_none() && permission_name.is_none() {
                push_command_error(inner, "a permission needs an id or a name");
                return true;
            }
            let part = c2s::OutChannelClientAddPermPart {
                channel_id: ChannelId(channel_id as u64),
                client_db_id: ClientDbId(client_db_id.max(0) as u64),
                permission_id: permission_id.map(|id| Permission(id as u32)),
                permission_name_id: permission_name.map(std::borrow::Cow::Owned),
                permission_value: value,
            };
            send_message(inner, connection, part, "channelclientaddperm");
        }

        Command::ChannelClientDelPerm {
            channel_id,
            client_db_id,
            permission_id,
            permission_name,
        } => {
            if permission_id.is_none() && permission_name.is_none() {
                push_command_error(inner, "a permission needs an id or a name");
                return true;
            }
            let part = c2s::OutChannelClientDelPermPart {
                channel_id: ChannelId(channel_id as u64),
                client_db_id: ClientDbId(client_db_id.max(0) as u64),
                permission_id: permission_id.map(|id| Permission(id as u32)),
                permission_name_id: permission_name.map(std::borrow::Cow::Owned),
            };
            send_message(inner, connection, part, "channelclientdelperm");
        }

        Command::ClientDbList { offset, limit } => {
            let part = c2s::OutClientDbListRequestPart {
                offset: offset.map(|v| v.max(0) as u32),
                limit: limit.map(|v| v.max(0) as u32),
            };
            send_message(inner, connection, part, "clientdblist");
        }

        Command::ClientDbFind { pattern } => {
            let part = c2s::OutClientDbFindRequestPart {
                pattern: std::borrow::Cow::Owned(pattern),
            };
            send_message(inner, connection, part, "clientdbfind");
        }

        Command::ClientDbInfo { client_db_id } => {
            let part = c2s::OutClientDbInfoRequestPart {
                client_db_id: ClientDbId(client_db_id.max(0) as u64),
            };
            // `clientdbinfo` is answered as a bare argument list with no command
            // name, so the reply has to be declared by type rather than matched
            // by name. See `Connection::send_expecting`.
            send_expecting(inner, connection, part, "ClientDbInfo", "clientdbinfo");
        }

        Command::OfflineMessageFlag { message_id, read } => {
            let part = c2s::OutOfflineMessageUpdateFlagPart {
                message_id: message_id.max(0) as u32,
                is_read: read,
            };
            send_message(inner, connection, part, "messageupdateflag");
        }

        Command::ServerGroupAddPerm {
            group_id,
            permission_id,
            permission_name,
            value,
            negated,
            skip,
        } => {
            if permission_id.is_none() && permission_name.is_none() {
                push_command_error(inner, "a permission needs an id or a name");
                return true;
            }
            let part = c2s::OutServerGroupAddPermPart {
                server_group_id: ServerGroupId(group_id.max(0) as u64),
                permission_id: permission_id.map(|id| Permission(id as u32)),
                permission_name_id: permission_name.map(std::borrow::Cow::Owned),
                permission_value: value,
                permission_negated: negated,
                permission_skip: skip,
            };
            send_message(inner, connection, part, "servergroupaddperm");
        }

        Command::ServerGroupDelPerm {
            group_id,
            permission_id,
            permission_name,
        } => {
            if permission_id.is_none() && permission_name.is_none() {
                push_command_error(inner, "a permission needs an id or a name");
                return true;
            }
            let part = c2s::OutServerGroupDelPermPart {
                server_group_id: ServerGroupId(group_id.max(0) as u64),
                permission_id: permission_id.map(|id| Permission(id as u32)),
                permission_name_id: permission_name.map(std::borrow::Cow::Owned),
            };
            send_message(inner, connection, part, "servergroupdelperm");
        }

        Command::ChannelGroupAddPerm {
            group_id,
            permission_id,
            permission_name,
            value,
        } => {
            if permission_id.is_none() && permission_name.is_none() {
                push_command_error(inner, "a permission needs an id or a name");
                return true;
            }
            let part = c2s::OutChannelGroupAddPermPart {
                channel_group: ChannelGroupId(group_id.max(0) as u64),
                permission_id: permission_id.map(|id| Permission(id as u32)),
                permission_name_id: permission_name.map(std::borrow::Cow::Owned),
                permission_value: value,
            };
            send_message(inner, connection, part, "channelgroupaddperm");
        }

        Command::ChannelGroupDelPerm {
            group_id,
            permission_id,
            permission_name,
        } => {
            if permission_id.is_none() && permission_name.is_none() {
                push_command_error(inner, "a permission needs an id or a name");
                return true;
            }
            let part = c2s::OutChannelGroupDelPermPart {
                channel_group: ChannelGroupId(group_id.max(0) as u64),
                permission_id: permission_id.map(|id| Permission(id as u32)),
                permission_name_id: permission_name.map(std::borrow::Cow::Owned),
            };
            send_message(inner, connection, part, "channelgroupdelperm");
        }

        Command::ChannelAddPerm {
            channel_id,
            permission_id,
            permission_name,
            value,
        } => {
            if permission_id.is_none() && permission_name.is_none() {
                push_command_error(inner, "a permission needs an id or a name");
                return true;
            }
            let part = c2s::OutChannelAddPermPart {
                channel_id: ChannelId(channel_id.max(0) as u64),
                permission_id: permission_id.map(|id| Permission(id as u32)),
                permission_name_id: permission_name.map(std::borrow::Cow::Owned),
                permission_value: value,
            };
            send_message(inner, connection, part, "channeladdperm");
        }

        Command::ChannelDelPerm {
            channel_id,
            permission_id,
            permission_name,
        } => {
            if permission_id.is_none() && permission_name.is_none() {
                push_command_error(inner, "a permission needs an id or a name");
                return true;
            }
            let part = c2s::OutChannelDelPermPart {
                channel_id: ChannelId(channel_id.max(0) as u64),
                permission_id: permission_id.map(|id| Permission(id as u32)),
                permission_name_id: permission_name.map(std::borrow::Cow::Owned),
            };
            send_message(inner, connection, part, "channeldelperm");
        }

        Command::ClientDbDelete { client_db_id } => {
            let part = c2s::OutClientDbDeletePart {
                client_db_id: ClientDbId(client_db_id.max(0) as u64),
            };
            send_message(inner, connection, part, "clientdbdelete");
        }

        Command::GlobalMessage { message } => {
            let part = c2s::OutGlobalMessagePart {
                message: std::borrow::Cow::Owned(message),
            };
            send_message(inner, connection, part, "globalmessage");
        }

        Command::PluginInvoke {
            name,
            data,
            target,
            client_id,
        } => {
            let target_mode = match target.as_str() {
                "server" => PluginTargetMode::Server,
                "client" => PluginTargetMode::Client,
                _ => PluginTargetMode::CurrentChannel,
            };
            let part = c2s::OutPluginCommandRequestPart {
                name: std::borrow::Cow::Owned(name),
                data: std::borrow::Cow::Owned(data),
                target: target_mode,
                target_client_id: client_id.map(|id| ClientId(id as u16)),
            };
            send_message(inner, connection, part, "plugincmd");
        }

        Command::RecordStart { path } => {
            match session.audio.start_recording(std::path::Path::new(&path)) {
                Ok(path) => inner.push_event(
                    QueuedEvent::new("recording_started")
                        .str("path", path.to_string_lossy().to_string()),
                ),
                Err(message) => push_command_error(inner, &message),
            }
        }

        Command::RecordStop => match session.audio.stop_recording() {
            None => push_command_error(inner, "no recording is running"),
            Some(Ok((path, frames))) => inner.push_event(
                QueuedEvent::new("recording_stopped")
                    .str("path", path.to_string_lossy().to_string())
                    .long("frames", frames as i64)
                    .long("seconds", (frames / 48_000) as i64)
                    .bool("failed", false),
            ),
            Some(Err(message)) => push_command_error(inner, &message),
        },

        Command::ClientSetServerQueryLogin {
            login_name,
            password,
            client_db_id,
        } => {
            let part = c2s::OutClientSetServerQueryLoginRequestPart {
                login_name: std::borrow::Cow::Owned(login_name),
                login_password: password.map(std::borrow::Cow::Owned),
                client_db_id: client_db_id.map(|id| ClientDbId(id.max(0) as u64)),
            };
            send_message(inner, connection, part, "clientsetserverquerylogin");
        }

        Command::SetUserPosition {
            client_id,
            position,
        } => {
            // Local audio only: the server has no idea where anyone is, so this
            // never reaches the network.
            let client = ClientId(client_id.max(0) as u16);
            let position =
                position.map(|(angle, distance)| crate::state::UserPosition { angle, distance });
            session.audio.set_position(
                client,
                position.map(|p| crate::audio::Position {
                    angle: p.angle,
                    distance: p.distance,
                }),
            );
            inner.with_state(|snapshot| snapshot.set_user_position(client_id, position));
        }

        Command::ClearPositions => {
            session.audio.clear_positions();
            inner.with_state(|snapshot| {
                let ids: Vec<i32> = snapshot.users.iter().map(|user| user.id).collect();
                for id in ids {
                    snapshot.set_user_position(id, None);
                }
            });
        }

        Command::CustomInfo { client_db_id } => {
            let part = c2s::OutCustomInfoRequestPart {
                client_db_id: ClientDbId(client_db_id.max(0) as u64),
            };
            send_expecting(inner, connection, part, "CustomInfoResponse", "custominfo");
        }

        Command::CustomSearch { ident, pattern } => {
            let part = c2s::OutCustomSearchPart {
                external_identity: std::borrow::Cow::Owned(ident),
                pattern: std::borrow::Cow::Owned(pattern),
            };
            send_expecting(
                inner,
                connection,
                part,
                "CustomSearchResponse",
                "customsearch",
            );
        }

        Command::LogAdd { level, message } => {
            let part = c2s::OutLogAddPart {
                log_level: log_level_of(&level),
                log_message: std::borrow::Cow::Owned(message),
            };
            send_message(inner, connection, part, "logadd");
        }

        Command::ClientFind { pattern } => {
            let part = c2s::OutClientFindRequestPart {
                pattern: std::borrow::Cow::Owned(pattern),
            };
            send_expecting(inner, connection, part, "ClientFind", "clientfind");
        }

        Command::PermGet { permission_id } => {
            let part = c2s::OutPermRequestPart {
                permission_id: Permission(permission_id.max(0) as u32),
            };
            send_expecting(inner, connection, part, "PermGet", "permget");
        }

        Command::ServerInfo => {
            let message = c2s::OutServerInfoMessage::new();
            send_expecting_packet(
                inner,
                connection,
                message,
                "ServerInfoResponse",
                "serverinfo",
            );
        }

        Command::ServerSnapshotCreate => {
            let message = c2s::OutServerSnapshotCreateMessage::new();
            send_expecting_packet(
                inner,
                connection,
                message,
                "ServerSnapshotCreateResponse",
                "serversnapshotcreate",
            );
        }

        Command::ServerSnapshotDeploy { snapshot } => {
            send_packet(
                inner,
                connection,
                snapshot_deploy_packet(&snapshot),
                "serversnapshotdeploy",
            );
        }

        Command::ServerCreate { name } => {
            let part = c2s::OutServerCreatePart {
                name: std::borrow::Cow::Owned(name),
            };
            send_message(inner, connection, part, "servercreate");
        }

        Command::ServerDelete { server_id } => {
            let part = c2s::OutServerDeletePart {
                server_id: server_id.clamp(0, i64::from(u32::MAX)) as u32,
            };
            send_message(inner, connection, part, "serverdelete");
        }

        Command::ServerStart { server_id } => {
            let part = c2s::OutServerStartPart {
                server_id: server_id.clamp(0, i64::from(u32::MAX)) as u32,
            };
            send_message(inner, connection, part, "serverstart");
        }

        Command::ServerStop { server_id, reason } => {
            let part = c2s::OutServerStopPart {
                server_id: server_id.clamp(0, i64::from(u32::MAX)) as u32,
                reason_message: reason.map(std::borrow::Cow::Owned),
            };
            send_message(inner, connection, part, "serverstop");
        }

        Command::ServerProcessStop { reason } => {
            let part = c2s::OutServerProcessStopPart {
                reason_message: reason.map(std::borrow::Cow::Owned),
            };
            send_message(inner, connection, part, "serverprocessstop");
        }

        Command::InstanceEdit {
            filetransfer_port,
            max_download_bandwidth,
            max_upload_bandwidth,
            guest_serverquery_group,
            serverquery_flood_commands,
            serverquery_flood_time,
            serverquery_ban_time,
            template_serveradmin_group,
            template_serverdefault_group,
            template_channeladmin_group,
            template_channeldefault_group,
            pending_connections_per_ip,
        } => {
            let settings = InstanceSettings {
                filetransfer_port,
                max_download_bandwidth,
                max_upload_bandwidth,
                guest_serverquery_group,
                serverquery_flood_commands,
                serverquery_flood_time,
                serverquery_ban_time,
                template_serveradmin_group,
                template_serverdefault_group,
                template_channeladmin_group,
                template_channeldefault_group,
                pending_connections_per_ip,
            };
            // `instanceedit` with no properties changes nothing, so refusing it
            // locally is better than a request that looks like it worked.
            if settings.is_empty() {
                push_command_error(inner, "instance_edit needs at least one setting");
                return true;
            }
            send_message(
                inner,
                connection,
                instance_edit_part(settings),
                "instanceedit",
            );
        }

        Command::ChannelSubscribeAll => {
            let message = c2s::OutChannelSubscribeAllMessage::new();
            send_packet(inner, connection, message, "channelsubscribeall");
        }

        Command::ChannelUnsubscribeAll => {
            let message = c2s::OutChannelUnsubscribeAllMessage::new();
            send_packet(inner, connection, message, "channelunsubscribeall");
        }

        Command::ClientDbEdit {
            client_db_id,
            description,
            icon_id,
            phonetic_name,
        } => {
            // py-ts3 documents the working form as
            // `clientdbedit cldbid=56 client_description=…`, so an edit with no
            // properties would change nothing; refuse it locally.
            if description.is_none() && icon_id.is_none() && phonetic_name.is_none() {
                push_command_error(inner, "client_db_edit needs at least one property");
                return true;
            }
            send_message(
                inner,
                connection,
                client_db_edit_part(client_db_id, description, icon_id, phonetic_name),
                "clientdbedit",
            );
        }

        Command::BanClient {
            client_id,
            seconds,
            reason,
        } => {
            let part = c2s::OutBanClientPart {
                client_id: ClientId(client_id.max(0) as u16),
                time: seconds
                    .filter(|v| *v > 0)
                    .map(|v| time::Duration::seconds(v.min(i64::MAX as u64 as i64))),
                ban_reason: reason.map(std::borrow::Cow::Owned),
            };
            send_message(inner, connection, part, "banclient");
        }

        Command::ChannelDescription { channel_id } => {
            let part = c2s::OutChannelDescriptionRequestPart {
                channel_id: ChannelId(channel_id.max(0) as u64),
            };
            send_message(inner, connection, part, "channelgetdescription");
        }

        Command::ChannelList => {
            let message = c2s::OutChannelListRequestMessage::new();
            send_packet(inner, connection, message, "channellist");
        }

        Command::ClientDbIdFromUid { uid } => match decode_uid(&uid) {
            Ok(uid) => {
                let part = c2s::OutClientDbIdFromUidRequestPart {
                    client_uid: std::borrow::Cow::Owned(uid),
                };
                send_message(inner, connection, part, "clientgetdbidfromuid");
            }
            Err(message) => push_command_error(inner, &message),
        },

        Command::PermOverview {
            channel_id,
            client_db_id,
            permission_id,
            permission_name,
        } => {
            let part = c2s::OutPermOverviewRequestPart {
                channel_id: ChannelId(channel_id.max(0) as u64),
                client_db_id: ClientDbId(client_db_id.max(0) as u64),
                permission_id: permission_id.map(|id| Permission(id as u32)),
                permission_name_id: permission_name.map(std::borrow::Cow::Owned),
            };
            send_message(inner, connection, part, "permoverview");
        }

        Command::ClientInfo { client_id } => {
            let part = c2s::OutClientInfoRequestPart {
                client_id: ClientId(client_id.max(0) as u16),
            };
            send_expecting(inner, connection, part, "ClientInfo", "clientinfo");
        }

        Command::ChannelInfo { channel_id } => {
            let part = c2s::OutChannelInfoRequestPart {
                channel_id: ChannelId(channel_id.max(0) as u64),
            };
            send_expecting(
                inner,
                connection,
                part,
                "ChannelInfoResponse",
                "channelinfo",
            );
        }

        Command::ChannelFind { pattern } => {
            let part = c2s::OutChannelFindRequestPart {
                pattern: std::borrow::Cow::Owned(pattern),
            };
            send_expecting(inner, connection, part, "ChannelFind", "channelfind");
        }

        Command::ClientList => {
            let message = c2s::OutClientListRequestMessage::new();
            send_expecting_packet(inner, connection, message, "ClientList", "clientlist");
        }

        Command::ServerList => {
            let message = c2s::OutServerListRequestMessage::new();
            send_expecting_packet(
                inner,
                connection,
                message,
                "ServerListResponse",
                "serverlist",
            );
        }

        Command::WhoAmI => {
            let message = c2s::OutWhoAmIRequestMessage::new();
            send_expecting_packet(inner, connection, message, "WhoAmI", "whoami");
        }

        Command::Version => {
            let message = c2s::OutVersionRequestMessage::new();
            send_packet(inner, connection, message, "version");
        }

        Command::HostInfo => {
            let message = c2s::OutHostInfoRequestMessage::new();
            send_packet(inner, connection, message, "hostinfo");
        }

        Command::InstanceInfo => {
            let message = c2s::OutInstanceInfoMessage::new();
            send_packet(inner, connection, message, "instanceinfo");
        }

        Command::BindingList { subsystem } => {
            let part = c2s::OutBindingListPart {
                subsystem: subsystem.map(std::borrow::Cow::Owned),
            };
            send_message(inner, connection, part, "bindinglist");
        }

        Command::PermIdByName { permission_name } => {
            let part = c2s::OutPermIdByNameRequestPart {
                permission_name_id: std::borrow::Cow::Owned(permission_name),
            };
            send_message(inner, connection, part, "permidbyname");
        }

        Command::PermReset => {
            let message = c2s::OutPermResetMessage::new();
            send_packet(inner, connection, message, "permreset");
        }

        Command::ServerIdByPort { port } => {
            let part = c2s::OutServerIdGetByPortPart {
                port: port.clamp(0, i32::from(u16::MAX)) as u16,
            };
            send_message(inner, connection, part, "serveridgetbyport");
        }

        Command::ChannelMove {
            channel_id,
            parent_id,
            order,
        } => {
            let part = c2s::OutChannelMovePart {
                channel_id: ChannelId(channel_id.max(0) as u64),
                parent_id: ChannelId(parent_id.max(0) as u64),
                order: order.map(|id| ChannelId(id.max(0) as u64)),
            };
            send_message(inner, connection, part, "channelmove");
        }

        Command::ServerGroupCopy {
            source_group_id,
            target_group_id,
            name,
            query,
        } => {
            let part = c2s::OutServerGroupCopyPart {
                source_server_group_id: ServerGroupId(source_group_id.max(0) as u64),
                target_server_group_id: ServerGroupId(target_group_id.max(0) as u64),
                name: std::borrow::Cow::Owned(name),
                group_type: group_type_of(u8::from(query)),
            };
            send_message(inner, connection, part, "servergroupcopy");
        }

        Command::ChannelGroupCopy {
            source_group_id,
            target_group_id,
            name,
            query,
        } => {
            let part = c2s::OutChannelGroupCopyPart {
                source_channel_group_id: ChannelGroupId(source_group_id.max(0) as u64),
                target_channel_group_id: ChannelGroupId(target_group_id.max(0) as u64),
                name: std::borrow::Cow::Owned(name),
                group_type: group_type_of(u8::from(query)),
            };
            send_message(inner, connection, part, "channelgroupcopy");
        }

        Command::ServerGroupAutoAddPerm {
            query,
            permission_id,
            permission_name,
            value,
            negated,
            skip,
        } => {
            if permission_id.is_none() && permission_name.is_none() {
                push_command_error(inner, "a permission needs an id or a name");
                return true;
            }
            let part = c2s::OutServerGroupAutoAddPermPart {
                server_group_type: u32::from(query),
                permission_id: permission_id.map(|id| Permission(id as u32)),
                permission_name_id: permission_name.map(std::borrow::Cow::Owned),
                permission_value: value,
                permission_negated: negated,
                permission_skip: skip,
            };
            send_message(inner, connection, part, "servergroupautoaddperm");
        }

        Command::ServerGroupAutoDelPerm {
            query,
            permission_id,
            permission_name,
        } => {
            if permission_id.is_none() && permission_name.is_none() {
                push_command_error(inner, "a permission needs an id or a name");
                return true;
            }
            let part = c2s::OutServerGroupAutoDelPermPart {
                server_group_type: u32::from(query),
                permission_id: permission_id.map(|id| Permission(id as u32)),
                permission_name_id: permission_name.map(std::borrow::Cow::Owned),
            };
            send_message(inner, connection, part, "servergroupautodelperm");
        }

        Command::ClientAddPerm {
            client_db_id,
            permission_id,
            permission_name,
            value,
            skip,
        } => {
            if permission_id.is_none() && permission_name.is_none() {
                push_command_error(inner, "a permission needs an id or a name");
                return true;
            }
            let part = c2s::OutClientAddPermPart {
                client_db_id: ClientDbId(client_db_id.max(0) as u64),
                permission_id: permission_id.map(|id| Permission(id as u32)),
                permission_name_id: permission_name.map(std::borrow::Cow::Owned),
                permission_value: value,
                permission_skip: skip,
            };
            send_message(inner, connection, part, "clientaddperm");
        }

        Command::ClientDelPerm {
            client_db_id,
            permission_id,
            permission_name,
        } => {
            if permission_id.is_none() && permission_name.is_none() {
                push_command_error(inner, "a permission needs an id or a name");
                return true;
            }
            let part = c2s::OutClientDelPermPart {
                client_db_id: ClientDbId(client_db_id.max(0) as u64),
                permission_id: permission_id.map(|id| Permission(id as u32)),
                permission_name_id: permission_name.map(std::borrow::Cow::Owned),
            };
            send_message(inner, connection, part, "clientdelperm");
        }

        Command::CustomSet {
            client_db_id,
            ident,
            value,
        } => {
            let part = c2s::OutCustomSetPart {
                client_db_id: ClientDbId(client_db_id.max(0) as u64),
                external_identity: std::borrow::Cow::Owned(ident),
                value: std::borrow::Cow::Owned(value),
            };
            send_message(inner, connection, part, "customset");
        }

        Command::CustomDelete {
            client_db_id,
            ident,
        } => {
            let part = c2s::OutCustomDeletePart {
                client_db_id: ClientDbId(client_db_id.max(0) as u64),
                external_identity: std::borrow::Cow::Owned(ident),
            };
            send_message(inner, connection, part, "customdelete");
        }

        Command::TokenUse { token } => {
            let part = c2s::OutTokenUsePart {
                token: std::borrow::Cow::Owned(token),
            };
            send_message(inner, connection, part, "tokenuse");
        }

        Command::PrivilegeKeyDelete { key } => {
            let part = c2s::OutPrivilegeKeyDeletePart {
                token: std::borrow::Cow::Owned(key),
            };
            send_message(inner, connection, part, "privilegekeydelete");
        }

        Command::ServerGroupClientList { group_id } => {
            let part = c2s::OutServerGroupClientListRequestPart {
                server_group_id: ServerGroupId(group_id.max(0) as u64),
            };
            send_message(inner, connection, part, "servergroupclientlist");
        }

        Command::ServerGroupPermList { group_id } => {
            let part = c2s::OutServerGroupPermListRequestPart {
                server_group_id: ServerGroupId(group_id.max(0) as u64),
            };
            send_message(inner, connection, part, "servergrouppermlist");
        }

        Command::ChannelGroupClientList {
            channel_id,
            client_db_id,
            group_id,
        } => {
            let part = c2s::OutChannelGroupClientListRequestPart {
                channel_id: channel_id.map(|id| ChannelId(id.max(0) as u64)),
                client_db_id: client_db_id.map(|id| ClientDbId(id.max(0) as u64)),
                channel_group: group_id.map(|id| ChannelGroupId(id.max(0) as u64)),
            };
            send_message(inner, connection, part, "channelgroupclientlist");
        }

        Command::ChannelGroupPermList { group_id } => {
            let part = c2s::OutChannelGroupPermListRequestPart {
                channel_group: ChannelGroupId(group_id.max(0) as u64),
            };
            send_message(inner, connection, part, "channelgrouppermlist");
        }

        Command::ChannelClientPermList {
            channel_id,
            client_db_id,
        } => {
            let part = c2s::OutChannelClientPermListRequestPart {
                channel_id: ChannelId(channel_id.max(0) as u64),
                client_db_id: ClientDbId(client_db_id.max(0) as u64),
            };
            send_message(inner, connection, part, "channelclientpermlist");
        }

        Command::ServerGroupsByClient { client_db_id } => {
            let part = c2s::OutServerGroupsByClientIdRequestPart {
                client_db_id: ClientDbId(client_db_id.max(0) as u64),
            };
            send_message(inner, connection, part, "servergroupsbyclientid");
        }

        Command::ClientIds { uid } => match decode_uid(&uid) {
            Ok(uid) => {
                let part = c2s::OutClientIdsRequestPart {
                    client_uid: std::borrow::Cow::Owned(uid),
                };
                send_message(inner, connection, part, "clientgetids");
            }
            Err(message) => push_command_error(inner, &message),
        },

        Command::ClientNameFromDbId { client_db_id } => {
            let part = c2s::OutClientNameFromDbIdRequestPart {
                client_db_id: ClientDbId(client_db_id.max(0) as u64),
            };
            send_message(inner, connection, part, "clientgetnamefromdbid");
        }

        Command::ClientNameFromUid { uid } => match decode_uid(&uid) {
            Ok(uid) => {
                let part = c2s::OutClientNameFromUidRequestPart {
                    client_uid: std::borrow::Cow::Owned(uid),
                };
                send_message(inner, connection, part, "clientgetnamefromuid");
            }
            Err(message) => push_command_error(inner, &message),
        },

        Command::ClientUidFromClid { client_id } => {
            let part = c2s::OutClientUidFromClidRequestPart {
                client_id: ClientId(client_id.max(0) as u16),
            };
            send_message(inner, connection, part, "clientgetuidfromclid");
        }

        Command::ClientConnectionInfo { client_id } => {
            let part = c2s::OutClientConnectionInfoRequestPart {
                client_id: ClientId(client_id.max(0) as u16),
            };
            send_message(inner, connection, part, "getconnectioninfo");
        }

        Command::ServerConnectionInfo => {
            let message = c2s::OutServerConnectionInfoRequestMessage::new();
            send_packet(inner, connection, message, "serverrequestconnectioninfo");
        }

        Command::FileInfo {
            channel_id,
            path,
            password,
        } => {
            let part = c2s::OutFileInfoRequestPart {
                channel_id: ChannelId(channel_id.max(0) as u64),
                channel_password: std::borrow::Cow::Owned(password.unwrap_or_default()),
                name: std::borrow::Cow::Owned(path),
            };
            send_message(inner, connection, part, "ftgetfileinfo");
        }

        Command::PermFind {
            permission_id,
            permission_name,
        } => {
            if permission_id.is_none() && permission_name.is_none() {
                push_command_error(inner, "a permission needs an id or a name");
                return true;
            }
            let part = c2s::OutPermFindRequestPart {
                permission_id: permission_id.map(|id| Permission(id as u32)),
                permission_name_id: permission_name.map(std::borrow::Cow::Owned),
            };
            send_message(inner, connection, part, "permfind");
        }

        Command::PermList => {
            let message = c2s::OutPermListRequestMessage::new();
            send_packet(inner, connection, message, "permissionlist");
        }

        Command::LogView {
            lines,
            reverse,
            instance_log,
            offset,
        } => {
            let part = c2s::OutLogViewPart {
                lines: lines.map(|v| v.max(0) as u32),
                reverse,
                instance_log,
                offset: offset.map(|v| v.max(0) as u64),
            };
            send_message(inner, connection, part, "logview");
        }

        Command::TokenAdd {
            group_id,
            channel_id,
            description,
        } => {
            let part = c2s::OutTokenAddRequestPart {
                token_type: if channel_id > 0 {
                    TokenType::ChannelGroup
                } else {
                    TokenType::ServerGroup
                },
                token_id1: group_id.max(0) as u64,
                token_id2: ChannelId(channel_id.max(0) as u64),
                token_description: description.map(std::borrow::Cow::Owned),
                token_custom_set: None,
            };
            send_message(inner, connection, part, "tokenadd");
        }

        Command::TokenList => {
            let message = c2s::OutTokenListRequestMessage::new();
            send_packet(inner, connection, message, "tokenlist");
        }

        Command::TokenDelete { token } => {
            let part = c2s::OutTokenDeletePart {
                token: std::borrow::Cow::Owned(token),
            };
            send_message(inner, connection, part, "tokendelete");
        }

        Command::ComplainList { client_db_id } => {
            let part = c2s::OutComplainListRequestPart {
                target_client_db_id: client_db_id.map(|id| ClientDbId(id.max(0) as u64)),
            };
            send_message(inner, connection, part, "complainlist");
        }

        Command::ClientChatClose { client_id } => {
            // The protocol wants the uid as well as the id, and the snapshot is
            // where it lives; a client that already left has no entry, and then
            // the close is moot anyway.
            let uid = inner.with_state(|snapshot| {
                snapshot
                    .users
                    .iter()
                    .find(|user| user.id == client_id)
                    .map(|user| user.uid.clone())
            });
            let Some(uid) = uid else {
                push_command_error(inner, "that client is no longer connected");
                return true;
            };
            match decode_uid(&uid) {
                Ok(uid) => {
                    let part = c2s::OutClientChatClosePart {
                        client_id: ClientId(client_id.max(0) as u16),
                        client_uid: std::borrow::Cow::Owned(uid),
                    };
                    send_message(inner, connection, part, "clientchatclose");
                }
                Err(message) => push_command_error(inner, &message),
            }
        }

        Command::FiletransferList => {
            let message = c2s::OutListFiletransfersMessage::new();
            send_packet(inner, connection, message, "ftlist");
        }

        Command::StopFiletransfer { server_id, delete } => {
            let part = c2s::OutStopFiletransferPart {
                server_filetransfer_id: server_id.clamp(0, i64::from(u16::MAX)) as u16,
                delete,
            };
            send_message(inner, connection, part, "ftstop");
        }

        Command::FetchIcon { icon_id } => {
            if icon_id <= 0 {
                return true;
            }
            // Cached or already failed: a shell asks for every id it renders,
            // and re-downloading a picture it has would be one request per
            // frame on a busy server.
            let known = inner.with_session_icons(|cache| cache.has(icon_id));
            if known {
                return true;
            }
            let path = format!("/icon_{icon_id}");
            match connection.download_file(ChannelId(0), &path, None, None) {
                Ok(handle) => {
                    session.icon_fetches.insert(handle.0, icon_id);
                }
                Err(e) => {
                    log::warn!("Fetching icon {icon_id} failed: {e}");
                    inner.with_session_icons(|cache| {
                        cache.mark_failed(icon_id, e.to_string());
                    });
                    inner.push_event(
                        QueuedEvent::new("icon_failed")
                            .long("icon_id", icon_id)
                            .str("message", e.to_string()),
                    );
                }
            }
        }
    }
    true
}

/// Asks for both group lists. They arrive as `notify…grouplist` batches and
/// replace the snapshot fields; a permission failure only leaves them empty.
/// Asks the server what this client may do with files in one channel.
///
/// The reply arrives as `notifypermoverview`, which tsclientlib does not put
/// into the book, so it surfaces as a plain message and is turned into
/// `permissionHints` on that channel.
fn request_file_permissions(connection: &mut Connection, channel_id: i64) {
    let database_id = match connection.get_state() {
        Ok(book) => match book.clients.get(&book.own_client) {
            Some(client) => client.database_id.0,
            None => {
                log::warn!("No own client data; skipping the permission query");
                return;
            }
        },
        Err(e) => {
            log::warn!("No book state for the permission query: {e}");
            return;
        }
    };
    let mut command = OutCommand::new(
        Direction::C2S,
        Flags::empty(),
        PacketType::Command,
        "permoverview",
    );
    command.write_arg("cldbid", &database_id);
    command.write_arg("cid", &(channel_id as u64));
    command.write_arg("permid", &0u32);
    if let Err(e) = command.send(connection) {
        log::warn!("Could not ask for channel permissions: {e}");
    }
}

/// Announces this connection's myTeamSpeak identity, if the session has one.
///
/// The six parameters go out on `updatemytsid`, the command the official client
/// uses when it signs in *while connected*. Sending them inside `clientinit`
/// itself would need control over the packet `tsclientlib` builds; the server
/// treats a later `updatemytsid` the same way, and its log line is the one the
/// captured handshake shows ("client connected … using a myTeamSpeak ID").
///
/// Silent when there is nothing to send: no account login, no identity, or a
/// login whose key did not open the blob. That is the normal state of a client
/// that is not signed in, not a failure.
fn request_group_lists(connection: &mut Connection) {
    for (name, command) in [
        (
            "servergrouplist",
            c2s::OutServerGroupListRequestMessage::new(),
        ),
        (
            "channelgrouplist",
            c2s::OutChannelGroupListRequestMessage::new(),
        ),
    ] {
        if let Err(e) = command.send(connection) {
            log::warn!("Requesting {name} failed: {e}");
        }
    }
}

/// Subscribes this client to every channel, including ones it is not in.
///
/// Returns whether the command was sent, not the error: `tsclientlib::Error`
/// is large enough that returning it here trips `clippy::result_large_err`.
fn subscribe_all(connection: &mut Connection) -> bool {
    let command = match connection.get_state() {
        Ok(book) => book.server.set_subscribed(true),
        Err(e) => {
            log::warn!("No book state to subscribe from: {e}");
            return false;
        }
    };
    match command.send(connection) {
        Ok(()) => true,
        Err(e) => {
            log::warn!("Failed to subscribe to all channels: {e}");
            false
        }
    }
}

fn own_id(connection: &Connection) -> u16 {
    connection
        .get_state()
        .map(|book| book.own_client.0)
        .unwrap_or(0)
}

fn file_name(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_string()
}

/// A group's type from the protocol's numeric value.
///
/// `0` is a regular group, `1` a query group. Anything else is treated as
/// regular: the server rejects an unknown type itself, and guessing a third
/// kind here would only move the failure.
/// Decodes a base64 uid from JSON into the byte form the protocol wants.
///
/// A uid is opaque bytes, so JSON can only carry it base64-encoded. Failing
/// here rather than sending a garbled value means the caller gets a sentence
/// about the field instead of a server error about an unknown client.
fn decode_uid(uid: &str) -> Result<UidBuf, String> {
    BASE64_STANDARD
        .decode(uid.as_bytes())
        .map(UidBuf)
        .map_err(|e| format!("bad uid: {e}"))
}

/// The numeric client type the snapshot already uses: 0 regular, 1 query.
fn client_type_code(kind: ClientType) -> i32 {
    match kind {
        ClientType::Normal => 0,
        ClientType::Query { .. } => 1,
    }
}

/// A permission is named by id or by name, never both; this picks whichever the
/// server sent so a shell sees one `name` key either way.
fn permission_name(id: Option<Permission>, name: &Option<String>) -> String {
    name.clone()
        .unwrap_or_else(|| id.map(|id| id.0.to_string()).unwrap_or_default())
}

/// The scope a `permfind` result applies to.
fn permission_type_name(kind: PermissionType) -> &'static str {
    match kind {
        PermissionType::ServerGroup => "server_group",
        PermissionType::GlobalClient => "client",
        PermissionType::Channel => "channel",
        PermissionType::ChannelGroup => "channel_group",
        PermissionType::ChannelClient => "channel_client",
    }
}

fn token_type_name(kind: TokenType) -> &'static str {
    match kind {
        TokenType::ServerGroup => "server_group",
        TokenType::ChannelGroup => "channel_group",
    }
}

/// A signed duration in whole milliseconds, with `None` becoming 0.
///
/// Ping is a `time::SignedDuration` rather than a `std::time::Duration`
/// because the server may report a negative deviation when a sample lands
/// early.
fn signed_millis_of(value: Option<time::SignedDuration>) -> i64 {
    value.map_or(0, |d| d.whole_milliseconds() as i64)
}

/// Packet loss as hundredths of a percent.
///
/// The wire sends a float, but every shell renders it as a percentage and a
/// float in JSON is a value some decoders round differently; an integer in
/// hundredths keeps `1.5 %` and `0.0 %` distinct without a decimal type.
fn percent_of(loss: Option<f32>) -> i32 {
    let loss = loss.unwrap_or(0.0);
    if loss.is_finite() {
        (loss * 100.0).round() as i32
    } else {
        0
    }
}

/// The log level a shell names, as the protocol enum.
///
/// An unknown name falls back to `Info` rather than refusing: a log line is
/// diagnostic, and losing one because a shell spelled the level differently is
/// a worse outcome than filing it under the wrong severity.
fn log_level_of(name: &str) -> LogLevel {
    match name {
        "error" => LogLevel::Error,
        "warning" => LogLevel::Warning,
        "debug" => LogLevel::Debug,
        _ => LogLevel::Info,
    }
}

fn group_type_of(value: u8) -> GroupType {
    if value == 1 {
        GroupType::Query
    } else {
        GroupType::Regular
    }
}

/// Sends one multi-part command and reports a local failure the same way the
/// server's refusal is reported.
///
/// Every write command in [`Command`] has the same shape: build a `c2s` part,
/// turn it into a packet, send. Keeping that in one place means a new command
/// cannot forget to surface a send error — the earlier code had three copies of
/// this and two of them logged instead of reporting.
/// The settings `instance_edit` may change.
///
/// Every field is `Option` because `instanceedit` sends only what the caller
/// sets; an absent field keeps its current value on the server.
#[derive(Debug, Default, Clone)]
pub(crate) struct InstanceSettings {
    pub filetransfer_port: Option<i32>,
    pub max_download_bandwidth: Option<i64>,
    pub max_upload_bandwidth: Option<i64>,
    pub guest_serverquery_group: Option<i64>,
    pub serverquery_flood_commands: Option<i64>,
    pub serverquery_flood_time: Option<i64>,
    pub serverquery_ban_time: Option<i64>,
    pub template_serveradmin_group: Option<i64>,
    pub template_serverdefault_group: Option<i64>,
    pub template_channeladmin_group: Option<i64>,
    pub template_channeldefault_group: Option<i64>,
    pub pending_connections_per_ip: Option<i64>,
}

impl InstanceSettings {
    /// Whether anything would actually be sent.
    pub fn is_empty(&self) -> bool {
        self.filetransfer_port.is_none()
            && self.max_download_bandwidth.is_none()
            && self.max_upload_bandwidth.is_none()
            && self.guest_serverquery_group.is_none()
            && self.serverquery_flood_commands.is_none()
            && self.serverquery_flood_time.is_none()
            && self.serverquery_ban_time.is_none()
            && self.template_serveradmin_group.is_none()
            && self.template_serverdefault_group.is_none()
            && self.template_channeladmin_group.is_none()
            && self.template_channeldefault_group.is_none()
            && self.pending_connections_per_ip.is_none()
    }
}

/// Builds the `instanceedit` part, keeping only the settings the caller set.
///
/// Split out so the encoded arguments can be asserted without a connection: the
/// failure mode is a bare `instanceedit` that the server accepts and ignores.
pub(crate) fn instance_edit_part(settings: InstanceSettings) -> c2s::OutInstanceEditPart {
    c2s::OutInstanceEditPart {
        filetransfer_port: settings
            .filetransfer_port
            .map(|v| v.clamp(0, i32::from(u16::MAX)) as u16),
        max_download_total_bandwidth: settings.max_download_bandwidth.map(|v| v.max(0) as u64),
        max_upload_total_bandwidth: settings.max_upload_bandwidth.map(|v| v.max(0) as u64),
        guest_serverquery_group: settings
            .guest_serverquery_group
            .map(|v| ServerGroupId(v.max(0) as u64)),
        serverquery_flood_commands: settings.serverquery_flood_commands.map(|v| v.max(0) as u32),
        serverquery_flood_time: settings.serverquery_flood_time.map(|v| v.max(0) as u32),
        serverquery_ban_time: settings.serverquery_ban_time.map(|v| v.max(0) as u32),
        template_serveradmin_group: settings
            .template_serveradmin_group
            .map(|v| ServerGroupId(v.max(0) as u64)),
        template_serverdefault_group: settings
            .template_serverdefault_group
            .map(|v| ServerGroupId(v.max(0) as u64)),
        template_channeladmin_group: settings
            .template_channeladmin_group
            .map(|v| ChannelGroupId(v.max(0) as u64)),
        template_channeldefault_group: settings
            .template_channeldefault_group
            .map(|v| ChannelGroupId(v.max(0) as u64)),
        pending_connections_per_ip: settings.pending_connections_per_ip.map(|v| v.max(0) as u32),
    }
}

/// Builds the `clientdbedit` part.
pub(crate) fn client_db_edit_part(
    client_db_id: i64,
    description: Option<String>,
    icon_id: Option<i64>,
    phonetic_name: Option<String>,
) -> c2s::OutClientDbEditPart<'static> {
    c2s::OutClientDbEditPart {
        client_db_id: ClientDbId(client_db_id.max(0) as u64),
        description: description.map(std::borrow::Cow::Owned),
        icon: icon_id.map(|id| tsclientlib::IconId(id as u32)),
        phonetic_name: phonetic_name.map(std::borrow::Cow::Owned),
    }
}

/// Builds `serversnapshotdeploy` with the snapshot appended as raw content.
///
/// The snapshot is *not* a named argument. It is the argument list the server
/// itself produced, and it must reach the wire byte for byte: a `name=value`
/// wrapper adds an `=` the server rejects, and escaping it double-escapes the
/// `\s` and `\p` the snapshot already contains. py-ts3 hit exactly this and
/// documented it (issue #49); the working form is
/// `serversnapshotdeploy <snapshot>` with nothing else.
pub(crate) fn snapshot_deploy_packet(snapshot: &str) -> OutCommand {
    let mut packet = c2s::OutServerSnapshotDeployMessage::new();
    if !snapshot.is_empty() {
        // A single space separates the command word from its argument list.
        packet.0.data_mut().push(b' ');
        packet.0.data_mut().extend_from_slice(snapshot.as_bytes());
    }
    packet
}

/// Sends a command whose reply arrives without a command name.
///
/// The protocol answers a few requests with a bare argument list — no leading
/// command word — so there is nothing for a name-based parser to match. The
/// reply type has to be declared up front, and `return_code` is what ties the
/// answer to the request.
fn send_expecting<P>(
    inner: &Arc<Inner>,
    connection: &mut Connection,
    part: P,
    reply: &'static str,
    name: &str,
) where
    P: tsclientlib::messages::OutMessageTrait,
{
    let packet = part.to_packet();
    if let Err(e) = connection.send_expecting(packet, reply) {
        push_command_error(inner, &format!("{name} failed: {e}"));
    }
}

/// [`send_expecting`] for a message that takes no parts.
fn send_expecting_packet(
    inner: &Arc<Inner>,
    connection: &mut Connection,
    packet: OutCommand,
    reply: &'static str,
    name: &str,
) {
    if let Err(e) = connection.send_expecting(packet, reply) {
        push_command_error(inner, &format!("{name} failed: {e}"));
    }
}

fn send_message<P>(inner: &Arc<Inner>, connection: &mut Connection, part: P, name: &str)
where
    P: tsclientlib::messages::OutMessageTrait,
{
    let packet = part.to_packet();
    send_packet(inner, connection, packet, name);
}

fn send_packet(inner: &Arc<Inner>, connection: &mut Connection, packet: OutCommand, name: &str) {
    if let Err(e) = packet.send(connection) {
        push_command_error(inner, &format!("{name} failed: {e}"));
    }
}

fn push_command_error(inner: &Arc<Inner>, message: &str) {
    log::warn!("Command failed locally: {message}");
    inner.push_event(
        QueuedEvent::new("command_error")
            .str("message", message)
            // Present but empty, like the server-side path: the document says
            // this key is always there so a shell can read it unconditionally.
            // `command_id` is the one that is genuinely absent here — a locally
            // detected error never had a request to match.
            .str("missing_permission", ""),
    );
}

/// `clientupdate` with only the fields the caller cares about set.
fn send_update(
    inner: &Arc<Inner>,
    connection: &mut Connection,
    apply: impl FnOnce(&mut c2s::OutClientUpdatePart<'_>),
) {
    let mut part = c2s::OutClientUpdatePart {
        name: None,
        input_muted: None,
        output_muted: None,
        is_away: None,
        away_message: None,
        input_hardware_enabled: None,
        output_hardware_enabled: None,
        is_channel_commander: None,
        avatar_hash: None,
        phonetic_name: None,
        talk_power_request: None,
        talk_power_request_message: None,
        is_recording: None,
        badges: None,
    };
    apply(&mut part);

    let command = c2s::OutClientUpdateMessage::new(&mut std::iter::once(part));
    if let Err(e) = command.send(connection) {
        push_command_error(inner, &e.to_string());
    }
}

/// Resolves the shell's version choice to the tuple announced in `clientinit`.
///
/// The choice is a version number + platform; the table provides the full
/// version text (with its build suffix) and the signature, which are bound
/// together. A choice that does not resolve falls back to the standard tuple so
/// a bad setting does not strand the connection — the shell is expected to
/// refuse saving an unresolvable choice, and this is the belt to that braces.
fn client_version(choice: &crate::VersionChoice) -> tsproto_types::versions::Version {
    let resolved = choice.resolve().unwrap_or_else(|| {
        crate::VersionChoice::default()
            .resolve()
            .expect("standard resolves")
    });
    tsproto_types::versions::Version::Custom {
        platform: resolved.platform,
        version: resolved.version,
        signature: resolved.signature,
    }
}

/// Turns a connection failure into something a person can act on.
///
/// `Error::ConnectTs` carries the server's own error code. The password and
/// version cases are translated because they name a setting the user can
/// change; the rest are rare enough that the English enum name is more useful
/// than a guess at Chinese wording.
fn describe_stream_error(error: &tsclientlib::Error) -> (String, &'static str) {
    use tsproto_types::errors::Error as TsError;

    if let tsclientlib::Error::ConnectTs(kind) = error {
        return match kind {
            TsError::ServerInvalidPassword => (
                "服务器需要密码，或者密码不正确。检查「服务器密码」后重试。".to_string(),
                "server_password",
            ),
            TsError::ClientInvalidPassword => (
                "客户端身份密码错误（服务器已占用这个身份）".to_string(),
                "client_password",
            ),
            TsError::ChannelInvalidPassword => ("频道密码不正确".to_string(), "channel_password"),
            // The server compares the announced version against its own
            // signature table. An old build is refused outright, and the only
            // fix is to announce a newer one — so this must name the setting,
            // not the protocol error.
            TsError::ClientVersionOutdated => (
                "服务器不接受这个客户端版本，请在设置里换一个更新的版本号".to_string(),
                "client_version",
            ),
            TsError::ClientHacked => (
                "服务器拒绝了客户端版本签名，请在设置里重新选择版本号和平台".to_string(),
                "client_version",
            ),
            other => (format!("服务器拒绝连接：{other}"), "connect"),
        };
    }

    (format!("{error}"), "stream")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tsclientlib::messages::OutMessageTrait;

    /// The deploy body is the command word, one space, and the snapshot
    /// verbatim — no `name=`, no escaping.
    ///
    /// py-ts3 shipped a version that wrapped the snapshot as
    /// `virtualserver_snapshot=…` and escaped it, and the server answered
    /// "expected more arguments" (issue #49). Asserting the exact bytes is the
    /// only way to catch a regression, because a wrong body still sends fine and
    /// still looks like a string containing the snapshot.
    #[test]
    fn snapshot_deploy_appends_the_snapshot_raw() {
        let snapshot = "virtualserver_name=My\\sServer virtualserver_port=9987";
        let packet = snapshot_deploy_packet(snapshot);
        let body = String::from_utf8(packet.0.content().to_vec()).expect("utf-8");

        assert_eq!(body, format!("serversnapshotdeploy {snapshot}"));
        // The escapes the snapshot already carries must survive untouched.
        assert!(body.contains("My\\sServer"), "{body}");
        // A `name=` wrapper is exactly the bug py-ts3 hit.
        assert!(!body.contains("virtualserver_snapshot="), "{body}");
        assert!(!body.contains("snapshot="), "{body}");
    }

    /// An empty snapshot sends the bare command rather than a trailing space,
    /// so the server rejects it as a missing argument instead of an empty one.
    #[test]
    fn an_empty_snapshot_sends_no_argument_list() {
        let packet = snapshot_deploy_packet("");
        let body = String::from_utf8(packet.0.content().to_vec()).expect("utf-8");
        assert_eq!(body, "serversnapshotdeploy");
    }

    /// `instanceedit` must carry the settings it was given, not just its name.
    ///
    /// The failure this guards against is a bare `instanceedit`: the server
    /// accepts it, answers `ok`, and changes nothing.
    #[test]
    fn instance_edit_encodes_the_settings_it_was_given() {
        let part = instance_edit_part(InstanceSettings {
            filetransfer_port: Some(30033),
            ..InstanceSettings::default()
        });
        let body =
            String::from_utf8(part.to_packet().into_packet().content().to_vec()).expect("utf-8");

        assert!(body.starts_with("instanceedit "), "{body}");
        assert!(
            body.contains("serverinstance_filetransfer_port=30033"),
            "{body}"
        );
        // Only the field that was set appears.
        assert!(
            !body.contains("serverinstance_max_download_total_bandwidth"),
            "{body}"
        );
    }

    /// Several settings at once, each under its protocol name.
    #[test]
    fn instance_edit_encodes_every_setting() {
        let part = instance_edit_part(InstanceSettings {
            filetransfer_port: Some(30033),
            max_download_bandwidth: Some(1_000_000),
            max_upload_bandwidth: Some(2_000_000),
            guest_serverquery_group: Some(1),
            serverquery_flood_commands: Some(10),
            serverquery_flood_time: Some(3),
            serverquery_ban_time: Some(600),
            template_serveradmin_group: Some(3),
            template_serverdefault_group: Some(5),
            template_channeladmin_group: Some(1),
            template_channeldefault_group: Some(4),
            pending_connections_per_ip: Some(0),
        });
        let body =
            String::from_utf8(part.to_packet().into_packet().content().to_vec()).expect("utf-8");

        for expected in [
            "serverinstance_filetransfer_port=30033",
            "serverinstance_max_download_total_bandwidth=1000000",
            "serverinstance_max_upload_total_bandwidth=2000000",
            "serverinstance_guest_serverquery_group=1",
            "serverinstance_serverquery_flood_commands=10",
            "serverinstance_serverquery_flood_time=3",
            "serverinstance_serverquery_ban_time=600",
            "serverinstance_template_serveradmin_group=3",
            "serverinstance_template_serverdefault_group=5",
            "serverinstance_template_channeladmin_group=1",
            "serverinstance_template_channeldefault_group=4",
            "serverinstance_pending_connections_per_ip=0",
        ] {
            assert!(body.contains(expected), "missing {expected} in {body}");
        }
    }

    /// Nothing set means nothing to send, which is what the handler refuses.
    #[test]
    fn an_empty_instance_edit_is_detected() {
        assert!(InstanceSettings::default().is_empty());
        assert!(!InstanceSettings {
            serverquery_flood_time: Some(1),
            ..InstanceSettings::default()
        }
        .is_empty());
    }

    /// `clientdbedit` carries the description, not just the id.
    ///
    /// py-ts3 documents `clientdbedit cldbid=56 client_description=…`; sending
    /// only `cldbid` is the version that changes nothing.
    #[test]
    fn client_db_edit_encodes_the_properties() {
        let part = client_db_edit_part(56, Some("Best guy ever!".to_string()), None, None);
        let body =
            String::from_utf8(part.to_packet().into_packet().content().to_vec()).expect("utf-8");

        assert!(body.starts_with("clientdbedit "), "{body}");
        assert!(body.contains("cldbid=56"), "{body}");
        assert!(
            body.contains("client_description=Best\\sguy\\sever!"),
            "the description must be escaped the way the protocol wants: {body}"
        );
        // Unset properties are omitted entirely.
        assert!(!body.contains("client_icon_id"), "{body}");
        assert!(!body.contains("client_nickname_phonetic"), "{body}");
    }

    /// An icon and a phonetic name travel under their own names.
    #[test]
    fn client_db_edit_encodes_the_icon_and_phonetic_name() {
        let part = client_db_edit_part(56, None, Some(1234), Some("an".to_string()));
        let body =
            String::from_utf8(part.to_packet().into_packet().content().to_vec()).expect("utf-8");

        assert!(body.contains("cldbid=56"), "{body}");
        assert!(body.contains("client_icon_id=1234"), "{body}");
        assert!(body.contains("client_nickname_phonetic=an"), "{body}");
        assert!(!body.contains("client_description"), "{body}");
    }

    /// The command name is what the server dispatches on, and the body is a
    /// single space-separated token after it.
    #[test]
    fn the_command_word_is_separated_by_one_space() {
        let packet = snapshot_deploy_packet("a=1");
        let body = String::from_utf8(packet.0.content().to_vec()).expect("utf-8");
        assert_eq!(body, "serversnapshotdeploy a=1");
        assert_eq!(body.matches(' ').count(), 1, "{body}");
    }
}
