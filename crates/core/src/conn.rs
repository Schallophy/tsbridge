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

use futures::StreamExt;
use tokio::sync::mpsc::UnboundedReceiver;
use tsclientlib::messages::c2s;
use tsclientlib::{
    ChannelId, ClientId, Connection, DisconnectOptions, Identity, InMessage, MessageTarget,
    OutCommandExt, StreamItem,
};
use tsproto_packets::packets::{Direction, Flags, OutCommand, PacketType};

use crate::audio::{AudioEngine, WhisperTargets};
use crate::events::QueuedEvent;
use crate::handle::{Command, ConnectParams, Inner, TextTarget};
use crate::state::{compute_file_permission_hints, FileEntry, GroupEntry};

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
                        .str("kind", "identity"),
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
    // The key is single-use; a retried connect (nickname taken) must send the
    // same one, so it is cloned per attempt rather than moved.
    let privilege_key = privilege_key;
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
            // report only that one was supplied.
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
                        .str("kind", "connect"),
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
                    .str("kind", "nickname"),
            );
            return;
        }
    };
    log::info!("Connected to {address}; waiting for the first book events");

    let mut session = Session {
        audio: AudioEngine::new(),
        downloads: HashMap::new(),
        uploads: HashMap::new(),
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
                        .str("kind", kind),
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
                        })
                        .collect();
                    snapshot.set_server_groups(groups);
                    let channel_groups = book
                        .channel_groups
                        .values()
                        .map(|group| GroupEntry {
                            id: group.id.0 as i64,
                            name: group.name.clone(),
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
            if let Some(pending) = session.downloads.remove(&handle.0) {
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
                })
                .collect();
            inner.with_state(|snapshot| snapshot.set_channel_groups(groups));
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
        } => session.audio.set_whisper_targets(WhisperTargets {
            clients,
            channels,
            groups,
        }),
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

fn push_command_error(inner: &Arc<Inner>, message: &str) {
    log::warn!("Command failed locally: {message}");
    inner.push_event(QueuedEvent::new("command_error").str("message", message));
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
