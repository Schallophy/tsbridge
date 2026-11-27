//! Snapshot of what the server told us, plus the diffing that turns it into
//! semantic events.
//!
//! The UI reads this on every frame, so it must never touch the socket. The
//! connection thread refreshes it as book events arrive; shell readers borrow it
//! under a lock.
//!
//! Translation strategy: rather than matching on ~30 `PropertyId` variants (which
//! is where the previous client implementation grew to 1454 lines), every book
//! event triggers a full snapshot refresh, and the *difference* against the
//! previous snapshot is what becomes events. A few hundred clients make that
//! cheap, and it cannot silently miss a field that a new server version adds.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Serialize;
use tsclientlib::data;
use tsclientlib::{ClientType, MaxClients};

use crate::events::QueuedEvent;

/// The channel codec as the name the protocol uses.
///
/// The snapshot is JSON, and a serialized enum variant would read as
/// `OpusMusic` while every other field on the wire is the server's own
/// lowercase spelling. Keeping the same vocabulary here means a shell that
/// already knows TeamSpeak's names does not need a second table.
pub(crate) fn codec_name(codec: &tsclientlib::Codec) -> String {
    use tsclientlib::Codec;
    match codec {
        Codec::SpeexNarrowband => "speex_narrowband",
        Codec::SpeexWideband => "speex_wideband",
        Codec::SpeexUltrawideband => "speex_ultrawideband",
        Codec::CeltMono => "celt_mono",
        Codec::OpusVoice => "opus_voice",
        Codec::OpusMusic => "opus_music",
    }
    .to_string()
}

/// One client as the UI sees it.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserEntry {
    pub id: i32,
    pub uid: String,
    pub nickname: String,
    pub channel_id: i64,
    pub input_muted: bool,
    pub output_muted: bool,
    /// `false` when the client itself disabled its capture device (the red
    /// prohibition sign over the microphone in TeamSpeak), which is a separate
    /// flag from `input_muted`: a hardware-muted mic sends no audio even though
    /// the server still reports it as un-muted. Without this the member list
    /// showed such a client as open-mic and it looked like a broken audio path.
    pub input_hardware_enabled: bool,
    pub output_hardware_enabled: bool,
    pub client_type: i32,
    pub away: bool,
    pub away_message: String,
    pub description: String,
    pub talking: bool,
    /// Server group ids this client is a member of (`client_servergroups`).
    ///
    /// The ids are what "is an admin" actually means: a shell resolves them
    /// against `server_groups` to print a title, and without them every member
    /// looks like a Guest no matter what the server granted.
    pub server_groups: Vec<i64>,
    /// The channel group this client sits in (`client_channel_group_id`).
    ///
    /// Every client has exactly one, so unlike [server_groups] this is a single
    /// id rather than a list. It is the group the desktop client draws next to
    /// a member's name, to the left of the server groups.
    pub channel_group: i64,
    /// Raw `client_badges` from the server (e.g. `overwolf=0`). Empty when the
    /// server reported none, which is also what a client without a myTeamSpeak
    /// proof gets.
    pub badges: String,
    /// `true` when the server granted this client priority speaker: their voice
    /// ducks everyone else's. A shell draws a different icon for them.
    pub is_priority_speaker: bool,
    /// Unread offline messages the server counts for this client.
    pub unread_messages: u32,
    /// `true` when the client muted its output device but the server still
    /// reports it as connected to audio. Distinct from `output_muted`, which is
    /// the client's own choice.
    pub output_only_muted: bool,
    /// The channel this client's channel group is inherited from, or `0` when
    /// the group is set directly on the client.
    pub inherited_channel_group_from_channel: i64,
    /// Avatar hash from `client_flag_avatar`, empty when there is none. The
    /// image itself is a server file fetched by this hash.
    pub avatar_hash: String,
    /// Two-letter country code, empty when the server reports none.
    pub country: String,
    /// `true` when this client may direct others into channels.
    pub is_channel_commander: bool,
    /// `true` when the client is recording locally; the server relays the flag
    /// so others can be told.
    pub recording: bool,
    /// Free-form metadata the client set on itself.
    pub metadata: String,
    /// `true` when the server granted this client the right to talk despite the
    /// channel's talk power.
    pub talk_power_granted: bool,
    /// Where this client sits in the 3D field, when the shell placed it.
    ///
    /// `None` is the ordinary case and means "mixed centred"; a shell that draws
    /// a spatial view sets it for the clients it has a position for. The angle
    /// is a compass bearing (0 ahead, 90 right) and the distance is in whatever
    /// unit the shell draws, so the snapshot never has to agree on metres.
    pub position: Option<UserPosition>,
}

/// A client's place in the 3D field.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserPosition {
    pub angle: f32,
    pub distance: f32,
}

impl Default for UserEntry {
    fn default() -> Self {
        Self {
            id: 0,
            uid: String::new(),
            nickname: String::new(),
            channel_id: 0,
            input_muted: false,
            output_muted: false,
            // Derived `Default` would be `false`, i.e. "device switched off",
            // which is the opposite of what an unknown client should read as.
            input_hardware_enabled: true,
            output_hardware_enabled: true,
            client_type: 0,
            away: false,
            away_message: String::new(),
            description: String::new(),
            talking: false,
            server_groups: Vec::new(),
            channel_group: 0,
            badges: String::new(),
            is_priority_speaker: false,
            unread_messages: 0,
            output_only_muted: false,
            inherited_channel_group_from_channel: 0,
            avatar_hash: String::new(),
            country: String::new(),
            is_channel_commander: false,
            recording: false,
            metadata: String::new(),
            talk_power_granted: false,
            position: None,
        }
    }
}

/// One channel as the UI sees it.
#[derive(Debug, Default, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelEntry {
    pub id: i64,
    pub parent_id: i64,
    pub name: String,
    pub order: i64,
    pub has_password: bool,
    pub is_default: bool,
    pub topic: String,
    /// -1 means unlimited, which is what the UI wants to render directly.
    /// -2 means "inherited from the parent", which is a third state and not a
    /// count: a channel with no limit of its own is not the same as an
    /// unlimited one.
    pub max_clients: i32,
    /// Whether this client is subscribed to the channel.
    ///
    /// The server only reports clients for subscribed channels, so an
    /// unsubscribed channel shows an empty member list even when people are in
    /// it. The desktop client draws that difference with the red/yellow/green
    /// channel marks; without the flag a shell cannot.
    pub subscribed: bool,
    /// The channel's own icon id, or `0` when it has none.
    ///
    /// The icon itself is a server-side file (`/icon_<id>`) fetched through the
    /// file-transfer path; see [`Snapshot::channel_icons`] for the cache.
    pub icon_id: i64,
    /// `true` for a private channel, which the server hides from non-members.
    pub is_private: bool,
    /// Talk power required to speak here. `0` means no requirement.
    pub needed_talk_power: i32,
    /// The channel's codec as a lowercase name (`opus_music`, `opus_voice`, …).
    pub codec: String,
    /// Codec quality 0–10. Higher is better and costs bandwidth.
    pub codec_quality: i32,
    /// How many 20 ms frames one packet carries (1–10). Higher trades latency
    /// for overhead.
    pub codec_latency_factor: i32,
    /// Seconds before an empty temporary channel is deleted; `0` means it is
    /// permanent.
    pub delete_delay: i64,
    /// `true` when the server silences everyone here unless they have talk power.
    pub forced_silence: bool,
    /// `true` when this channel's voice is not encrypted.
    pub is_unencrypted: bool,
    /// `-1` for unlimited, `-2` for inherited.
    pub max_family_clients: i32,
    /// File-operation bits this client may perform here, as a mask: 0 until
    /// the server has answered a `permoverview` request for this channel, then
    /// [`HINT_JOIN`] plus any of the `HINT_FILE_*` bits. A shell hides the
    /// corresponding buttons instead of letting the user hit a permission
    /// error; the server still enforces the real check.
    pub permission_hints: u64,
}

/// One channel in display order. `id` indexes [`ChannelEntry`]; `depth` is 0
/// for a root and grows for nested channels.
#[derive(Debug, Default, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelNode {
    pub id: i64,
    pub depth: i32,
}

/// One server or channel group: what the whisper and member panels list.
#[derive(Debug, Default, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupEntry {
    pub id: i64,
    pub name: String,
    /// The group's icon id, or `0` when it has none.
    ///
    /// The desktop client shows this next to a member's name, which is how a
    /// server communicates "this person is an admin" without a text title. The
    /// icon itself is a server file (`/icon_<id>`), so a shell that wants the
    /// picture fetches it through [`Snapshot::icons`].
    pub icon_id: i64,
    /// The group's sort id, which orders it above or below its siblings.
    pub sort_id: i32,
    /// `true` for a permanent group, `false` for a temporary one.
    pub is_permanent: bool,
    /// Which kind of group this is: `"template"`, `"regular"` or `"query"`.
    ///
    /// `servergrouplist` returns all three, and template groups carry the same
    /// names as the regular ones they were copied from — two `Server Admin`
    /// entries, one of which no client can ever be a member of. A shell that
    /// lists groups has to tell them apart, and the id cannot: they are
    /// different ids with the same name.
    pub group_type: String,
}

/// One file in a channel's file browser.
#[derive(Debug, Default, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEntry {
    pub channel_id: i64,
    pub path: String,
    pub name: String,
    pub size: u64,
    pub is_file: bool,
    /// Unix seconds.
    pub date_time: i64,
}

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerEntry {
    pub name: String,
    pub version: String,
    pub platform: String,
    pub clients_online: u32,
    pub max_clients: u32,
    pub welcome_message: String,
    /// Whether the server requires a privilege key (`token=…`) to grant the
    /// client its groups. Reported in the `initserver` notification as
    /// `virtualserver_ask_for_privilegekey`; the official client pops its
    /// token dialog on exactly this flag.
    #[serde(default)]
    pub ask_privilege_key: bool,
}

/// What the connection's own packet counters say.
#[derive(Debug, Default, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkEntry {
    /// Round-trip time in milliseconds; `0` until one has been measured.
    pub rtt_ms: i32,
    /// Deviation of the round trip, in milliseconds.
    pub rtt_dev_ms: i32,
    /// Bytes sent and received since the connection started.
    pub bytes_sent: u64,
    pub bytes_received: u64,
    /// Packets that should have arrived and did not, as a fraction of the
    /// packets expected. `0.0` while nothing has been sent yet.
    pub packet_loss: f32,
    /// Whether a round trip has been measured at all.
    pub measured: bool,
}

/// What the recorder is doing.
#[derive(Debug, Default, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordingEntry {
    pub active: bool,
    /// Where the file is being written, empty when nothing is running.
    pub path: String,
    /// Whole seconds recorded so far.
    pub seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    /// Bumped whenever anything the UI renders changed; the cached JSON is
    /// invalidated by comparing this, so an unchanged server costs a lock and an
    /// integer compare per frame.
    pub rev: u64,
    pub own_client_id: Option<i32>,
    pub own_channel_id: Option<i64>,
    pub nickname: String,
    pub input_muted: bool,
    pub output_muted: bool,
    /// See `UserEntry::input_hardware_enabled`.
    pub input_hardware_enabled: bool,
    pub output_hardware_enabled: bool,
    pub away: bool,
    pub away_message: String,
    /// Whether this client is currently sending voice. The server never echoes
    /// our own audio, so this is computed from the capture path by the core and
    /// is the same signal on every platform.
    pub own_talking: bool,
    pub users: Vec<UserEntry>,
    pub channels: Vec<ChannelEntry>,
    /// Channels in the server's display order, flattened; `id` indexes
    /// `channels`. Built here so every shell renders the same tree instead of
    /// each one having to interpret the linked `order` field itself.
    pub channel_tree: Vec<ChannelNode>,
    /// Requested once per connection; empty until the server answers (or when
    /// the account lacks permission to list them).
    pub server_groups: Vec<GroupEntry>,
    pub channel_groups: Vec<GroupEntry>,
    /// The group titles **this** client holds, resolved from its
    /// `client_servergroups` against [server_groups].
    ///
    /// A shell that wants to say "you are Server Admin" needs both lists
    /// joined; doing it here keeps every shell's answer identical and saves
    /// each of them from reimplementing the lookup. Empty until both the client
    /// list and the group list have arrived.
    pub own_server_groups: Vec<GroupEntry>,
    /// Kept across `sync_from` calls: a file listing is a one-off response, not
    /// part of the book, so the next member update must not wipe it.
    pub files: Vec<FileEntry>,
    /// Icons fetched from this server, keyed by `icon_id`.
    ///
    /// A group or channel carries an `icon_id`; the picture lives in a server
    /// file (`/icon_<id>`) that has to be downloaded. This is the cache of what
    /// has arrived so far — empty until a fetch completes, and never
    /// re-requested once it has.
    pub icons: Vec<crate::icons::CachedIcon>,
    pub server: ServerEntry,
    /// Round-trip time and packet counts, refreshed on every tick.
    ///
    /// `None` until the connection has measured a round trip, which takes one
    /// ping interval; a shell draws the disconnected mark for that window
    /// rather than a zero, because "no answer yet" and "0 ms" are different.
    pub network: NetworkEntry,
    /// The whisper targets this client currently has, as ids.
    ///
    /// Empty means ordinary channel talk. A shell uses this to light the
    /// whisper mark next to the people and channels being spoken to.
    pub whisper_clients: Vec<i32>,
    pub whisper_channels: Vec<i64>,
    /// Whether the playback mix is being written to disk, and where.
    pub recording: RecordingEntry,
    /// Group add/rename/remove events waiting for the caller to push.
    ///
    /// The setters have no event queue, so they accumulate here and
    /// [`Snapshot::take_group_events`] hands them over after the update.
    #[serde(skip)]
    pending_group_events: Vec<QueuedEvent>,
    pub connected: bool,
    /// True once `tsbridge_identity` has a value. The key itself is kept out
    /// of this JSON on purpose: snapshots end up in logs.
    pub identity_ready: bool,
    /// The myTeamSpeak account side. Always present, even when nobody is signed
    /// in: a shell renders the `loggedIn` flag rather than testing for `null`,
    /// and the account survives a server disconnect (it does not belong to the
    /// connection).
    pub account: crate::account::AccountReport,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self {
            rev: 0,
            own_client_id: None,
            own_channel_id: None,
            nickname: String::new(),
            input_muted: false,
            output_muted: false,
            // Derived `Default` would say `false` here, which means "every
            // device is switched off". Before the first sync there is nothing
            // to report, and the documented meaning of a missing flag is
            // "device on", so the empty snapshot must say the same.
            input_hardware_enabled: true,
            output_hardware_enabled: true,
            away: false,
            away_message: String::new(),
            own_talking: false,
            users: Vec::new(),
            channels: Vec::new(),
            channel_tree: Vec::new(),
            server_groups: Vec::new(),
            channel_groups: Vec::new(),
            own_server_groups: Vec::new(),
            files: Vec::new(),
            icons: Vec::new(),
            server: ServerEntry::default(),
            network: NetworkEntry::default(),
            whisper_clients: Vec::new(),
            whisper_channels: Vec::new(),
            recording: RecordingEntry::default(),
            pending_group_events: Vec::new(),
            connected: false,
            identity_ready: false,
            account: crate::account::AccountReport::default(),
        }
    }
}

impl Snapshot {
    /// Rebuilds the snapshot from the book and returns the events implied by the
    /// difference. Call it once per book event batch.
    pub fn sync_from(&mut self, book: &data::Connection, talking: &[i32]) -> Vec<QueuedEvent> {
        let mut events = Vec::new();

        let prev_users: BTreeMap<i32, UserEntry> =
            self.users.iter().map(|u| (u.id, u.clone())).collect();
        let prev_channels: BTreeMap<i64, ChannelEntry> =
            self.channels.iter().map(|c| (c.id, c.clone())).collect();

        let own_id = book.own_client.0 as i32;
        let was_connected = self.connected;
        self.own_client_id = Some(own_id);

        // ── own state ───────────────────────────────────────────────────────
        // `own_client` is only an id; the data lives in the client map.
        if let Some(own) = book.clients.get(&book.own_client) {
            self.nickname = own.name.clone();
            self.input_muted = own.input_muted;
            self.output_muted = own.output_muted;
            self.input_hardware_enabled = own.input_hardware_enabled;
            self.output_hardware_enabled = own.output_hardware_enabled;
            self.away_message = own.away_message.clone().unwrap_or_default();
            // `away_message` is `Some` whenever the client is away, even with
            // an empty message — see the clients loop below.
            self.away = own.away_message.is_some();
        }

        // ── channels ────────────────────────────────────────────────────────
        let mut next_channels: BTreeMap<i64, ChannelEntry> = BTreeMap::new();
        for (id, channel) in &book.channels {
            next_channels.insert(
                id.0 as i64,
                ChannelEntry {
                    id: id.0 as i64,
                    parent_id: channel.parent.0 as i64,
                    name: channel.name.clone(),
                    order: channel.order.0 as i64,
                    has_password: channel.has_password.unwrap_or(false),
                    is_default: channel.is_default.unwrap_or(false),
                    topic: channel.topic.clone().unwrap_or_default(),
                    max_clients: match channel.max_clients {
                        Some(MaxClients::Limited(value)) => i32::from(value),
                        Some(MaxClients::Inherited) => -2,
                        Some(MaxClients::Unlimited) | None => -1,
                    },
                    subscribed: channel.subscribed,
                    icon_id: channel.icon.map(|icon| icon.0 as i64).unwrap_or(0),
                    is_private: channel.is_private.unwrap_or(false),
                    needed_talk_power: channel.needed_talk_power.unwrap_or(0),
                    codec: codec_name(&channel.codec),
                    // A permission answer is not part of the book, so a synced
                    // rebuild would otherwise wipe it on every client event.
                    permission_hints: prev_channels
                        .get(&(id.0 as i64))
                        .map_or(0, |old| old.permission_hints),
                    codec_quality: channel.codec_quality.map_or(0, i32::from),
                    codec_latency_factor: channel.codec_latency_factor.unwrap_or(0),
                    delete_delay: channel.delete_delay.map_or(0, |d| d.whole_seconds()),
                    forced_silence: channel.forced_silence,
                    is_unencrypted: channel.is_unencrypted.unwrap_or(false),
                    max_family_clients: match channel.max_family_clients {
                        Some(MaxClients::Limited(value)) => i32::from(value),
                        Some(MaxClients::Inherited) => -2,
                        Some(MaxClients::Unlimited) => -1,
                        None => -2,
                    },
                },
            );
        }
        for (id, channel) in &next_channels {
            match prev_channels.get(id) {
                None => events.push(
                    QueuedEvent::new("channel_created")
                        .long("channel_id", *id)
                        .long("parent_id", channel.parent_id)
                        .str("name", &channel.name),
                ),
                Some(old) if old.name != channel.name => events.push(
                    QueuedEvent::new("channel_renamed")
                        .long("channel_id", *id)
                        .str("name", &channel.name)
                        .str("old_name", &old.name),
                ),
                Some(old) => {
                    // Everything else about a channel can change too — topic,
                    // password, limits, codec, subscription — and a shell that
                    // only hears about renames would show a stale row. The
                    // changed field names are listed so a shell can refresh just
                    // those; the snapshot already has the new values.
                    let changed = changed_channel_fields(old, channel);
                    if !changed.is_empty() {
                        events.push(
                            QueuedEvent::new("channel_updated")
                                .long("channel_id", *id)
                                .str("changed", changed.join(",")),
                        );
                    }
                }
            }
        }
        for id in prev_channels.keys() {
            if !next_channels.contains_key(id) {
                events.push(QueuedEvent::new("channel_removed").long("channel_id", *id));
            }
        }

        // ── clients ─────────────────────────────────────────────────────────
        let mut next_users: BTreeMap<i32, UserEntry> = BTreeMap::new();
        for (id, client) in &book.clients {
            let away_message = client.away_message.clone().unwrap_or_default();
            next_users.insert(
                id.0 as i32,
                UserEntry {
                    id: id.0 as i32,
                    uid: client
                        .uid
                        .as_ref()
                        .map(|u| u.to_string())
                        .unwrap_or_default(),
                    nickname: client.name.clone(),
                    channel_id: client.channel.0 as i64,
                    input_muted: client.input_muted,
                    output_muted: client.output_muted,
                    input_hardware_enabled: client.input_hardware_enabled,
                    output_hardware_enabled: client.output_hardware_enabled,
                    client_type: if client.client_type == ClientType::Normal {
                        0
                    } else {
                        1
                    },
                    // ts-bookkeeping has no separate `client_away` flag: it folds
                    // the boolean into `away_message`, `Some` even when the
                    // message is empty. `is_empty()` would hide everyone who
                    // went away without typing a reason.
                    away: client.away_message.is_some(),
                    away_message,
                    description: client.description.clone(),
                    talking: talking.contains(&(id.0 as i32)),
                    server_groups: client
                        .server_groups
                        .iter()
                        .map(|group| group.0 as i64)
                        .collect(),
                    channel_group: client.channel_group.0 as i64,
                    badges: client.badges.clone(),
                    is_priority_speaker: client.is_priority_speaker,
                    unread_messages: client.unread_messages,
                    output_only_muted: client.output_only_muted,
                    inherited_channel_group_from_channel: client
                        .inherited_channel_group_from_channel
                        .0 as i64,
                    avatar_hash: client.avatar_hash.clone(),
                    country: client.country_code.clone(),
                    is_channel_commander: client.is_channel_commander,
                    recording: client.is_recording,
                    metadata: client.metadata.clone(),
                    talk_power_granted: client.talk_power_granted,
                    // A position is something the shell set, not something the
                    // server sends, so a client update must not wipe it.
                    position: prev_users.get(&(id.0 as i32)).and_then(|old| old.position),
                },
            );
        }
        for (id, user) in &next_users {
            match prev_users.get(id) {
                None => events.push(
                    QueuedEvent::new("user_joined")
                        .int("client_id", *id)
                        .str("nickname", &user.nickname)
                        .str("uid", &user.uid)
                        .long("channel_id", user.channel_id),
                ),
                Some(old) => diff_user(*id, old, user, &mut events),
            }
        }
        for (id, old) in &prev_users {
            if !next_users.contains_key(id) {
                events.push(
                    QueuedEvent::new("user_left")
                        .int("client_id", *id)
                        .str("nickname", &old.nickname),
                );
            }
        }

        // ── server ──────────────────────────────────────────────────────────
        let server = ServerEntry {
            name: book.server.name.clone(),
            version: book.server.version.clone(),
            platform: book.server.platform.clone(),
            clients_online: book.clients.len() as u32,
            max_clients: u32::from(book.server.max_clients),
            welcome_message: book.server.welcome_message.clone(),
            ask_privilege_key: book.server.ask_for_privilegekey,
        };
        if !was_connected && !server.name.is_empty() {
            self.connected = true;
            events.push(
                QueuedEvent::new("connected")
                    .int("client_id", own_id)
                    .str("server_name", &server.name)
                    .str("server_version", &server.version),
            );
        }

        let own_channel_id = next_users.get(&own_id).map(|u| u.channel_id);
        let next_tree = channel_tree(&next_channels);
        let changed = prev_users != next_users
            || prev_channels != next_channels
            || self.server != server
            || self.own_channel_id != own_channel_id
            || self.channel_tree != next_tree;
        if changed || !events.is_empty() {
            self.rev = self.rev.wrapping_add(1);
        }

        // A renamed server or a changed client count is a fact a shell draws;
        // without an event it waits for the next full rebuild.
        let server_changed = changed_server_fields(&self.server, &server);
        if !server_changed.is_empty() {
            events.push(
                QueuedEvent::new("server_updated")
                    .str("changed", server_changed.join(","))
                    .str("name", &server.name)
                    .str("welcome_message", &server.welcome_message),
            );
        }
        self.server = server;
        self.own_channel_id = own_channel_id;
        self.users = next_users.into_values().collect();
        self.channels = next_channels.into_values().collect();
        self.channel_tree = next_tree;
        // The client list just changed, so this client's memberships may have
        // too — a token redeemed on this very connection lands here.
        self.refresh_own_groups();

        events
    }

    /// Replaces the server group list, sorted by name so every shell shows the
    /// same order.
    pub fn set_server_groups(&mut self, mut groups: Vec<GroupEntry>) {
        groups.sort_by_key(|group| group.name.to_lowercase());
        if self.server_groups == groups {
            return;
        }
        let events = diff_groups("server", &self.server_groups, &groups);
        self.server_groups = groups;
        self.refresh_own_groups();
        self.rev = self.rev.wrapping_add(1);
        // The caller pushes these; a group list arrives from two places (the
        // book and the group-list reply) and only the caller knows where the
        // event queue is.
        self.pending_group_events.extend(events);
    }

    /// Joins this client's group ids with the group names.
    ///
    /// Called from both sides of the join because the two lists arrive in no
    /// fixed order: the client list can be complete before the group names, and
    /// the reverse happens after a reconnect.
    fn refresh_own_groups(&mut self) {
        let own = self
            .own_client_id
            .and_then(|id| self.users.iter().find(|user| user.id == id));
        let resolved: Vec<GroupEntry> = match own {
            Some(own) => self
                .server_groups
                .iter()
                .filter(|group| own.server_groups.contains(&group.id))
                .cloned()
                .collect(),
            None => Vec::new(),
        };
        if self.own_server_groups != resolved {
            self.own_server_groups = resolved;
        }
    }

    /// See [`Snapshot::set_server_groups`].
    pub fn set_channel_groups(&mut self, mut groups: Vec<GroupEntry>) {
        groups.sort_by_key(|group| group.name.to_lowercase());
        if self.channel_groups == groups {
            return;
        }
        let events = diff_groups("channel", &self.channel_groups, &groups);
        self.channel_groups = groups;
        self.rev = self.rev.wrapping_add(1);
        self.pending_group_events.extend(events);
    }

    /// Takes the group events accumulated since the last call.
    ///
    /// The setters cannot push to the queue themselves — they do not have it —
    /// so they accumulate here and the caller drains after the update.
    pub fn take_group_events(&mut self) -> Vec<QueuedEvent> {
        std::mem::take(&mut self.pending_group_events)
    }

    /// Stores the file-operation bits computed from a `permoverview` answer.
    pub fn set_channel_permission_hints(&mut self, channel_id: i64, hints: u64) {
        if let Some(channel) = self.channels.iter_mut().find(|c| c.id == channel_id) {
            if channel.permission_hints != hints {
                channel.permission_hints = hints;
                self.rev = self.rev.wrapping_add(1);
            }
        }
    }

    /// Marks this client as speaking. Bumps the revision only on change, so the
    /// 50 Hz poll does not repaint the member list for every captured frame.
    pub fn set_own_talking(&mut self, talking: bool) {
        if self.own_talking != talking {
            self.own_talking = talking;
            self.rev = self.rev.wrapping_add(1);
        }
    }

    /// Marks the identity as readable. Bumps `rev` so a cached snapshot string
    /// from before the identity was built cannot hide the flag.
    pub fn set_identity_ready(&mut self) {
        if !self.identity_ready {
            self.identity_ready = true;
            self.rev = self.rev.wrapping_add(1);
        }
    }

    /// Places one client in the 3D field, or clears its position.
    ///
    /// Bumping `rev` only on a real change keeps a shell that redraws at 50 Hz
    /// from republishing the same snapshot while nothing moves.
    pub fn set_user_position(&mut self, client_id: i32, position: Option<UserPosition>) {
        let Some(user) = self.users.iter_mut().find(|user| user.id == client_id) else {
            return;
        };
        if user.position != position {
            user.position = position;
            self.rev = self.rev.wrapping_add(1);
        }
    }

    /// Whether any client has a position, i.e. whether 3D sound is in use.
    pub fn is_spatial(&self) -> bool {
        self.users.iter().any(|user| user.position.is_some())
    }

    /// Records what the recorder is doing.
    ///
    /// Refreshed from the tick so the elapsed seconds move; a shell that draws
    /// a timer needs it to, and the value is cheap to compare.
    pub fn set_recording(&mut self, recording: RecordingEntry) {
        if self.recording != recording {
            self.recording = recording;
            self.rev = self.rev.wrapping_add(1);
        }
    }

    /// Records what the packet counters say.
    ///
    /// Called from the tick, not from a book event: the numbers change whether
    /// or not the server says anything, and a shell that shows a ping needs
    /// them to move.
    pub fn set_network(&mut self, network: NetworkEntry) {
        if self.network != network {
            self.network = network;
            self.rev = self.rev.wrapping_add(1);
        }
    }

    /// Records the whisper targets currently in force.
    pub fn set_whisper_targets(&mut self, clients: Vec<i32>, channels: Vec<i64>) {
        let mut clients = clients;
        let mut channels = channels;
        clients.sort_unstable();
        channels.sort_unstable();
        if self.whisper_clients != clients || self.whisper_channels != channels {
            self.whisper_clients = clients;
            self.whisper_channels = channels;
            self.rev = self.rev.wrapping_add(1);
        }
    }

    /// Replaces the icon cache the UI reads.
    ///
    /// Called after a fetch lands and once at startup with what a previous run
    /// wrote, so a reconnect shows the icons it already had before any download
    /// finishes.
    pub fn set_icons(&mut self, icons: Vec<crate::icons::CachedIcon>) {
        let mut icons = icons;
        icons.sort_by_key(|icon| icon.id);
        if self.icons != icons {
            self.icons = icons;
            self.rev = self.rev.wrapping_add(1);
        }
    }

    /// Replaces the cached file listing of one channel and returns the event that
    /// tells the UI its spinner can stop.
    pub fn set_files(&mut self, channel_id: i64, entries: Vec<FileEntry>) -> QueuedEvent {
        self.files.retain(|file| file.channel_id != channel_id);
        // One order for every shell: directories first, then case-insensitive
        // name. Sorting in each UI is how two clients end up disagreeing.
        let mut entries = entries;
        entries.sort_by(|a, b| {
            a.is_file
                .cmp(&b.is_file)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        let count = entries.len() as i32;
        self.files.extend(entries);
        self.rev = self.rev.wrapping_add(1);
        QueuedEvent::new("file_list")
            .long("channel_id", channel_id)
            .int("count", count)
    }

    /// Marks who is transmitting right now, bumping the revision only on change.
    pub fn set_talking(&mut self, talking: &[i32]) -> bool {
        let mut changed = false;
        for user in &mut self.users {
            let now = talking.contains(&user.id);
            if user.talking != now {
                user.talking = now;
                changed = true;
            }
        }
        if changed {
            self.rev = self.rev.wrapping_add(1);
        }
        changed
    }

    /// Replaces the account report. Called from the account runtime, and bumps
    /// the revision only when something a shell would render changed — a `busy`
    /// flag that flips on every command must not repaint the whole member list.
    pub fn set_account(&mut self, report: crate::account::AccountReport) {
        if self.account != report {
            self.account = report;
            self.rev = self.rev.wrapping_add(1);
        }
    }
}

/// This client is known to be in (or able to enter) the channel.
pub const HINT_JOIN: u64 = 1;
pub const HINT_FILE_UPLOAD: u64 = 64;
pub const HINT_FILE_DOWNLOAD: u64 = 128;
pub const HINT_FILE_DELETE: u64 = 256;
pub const HINT_FILE_RENAME: u64 = 512;
pub const HINT_FILE_BROWSE: u64 = 1024;
pub const HINT_FILE_DIRECTORY_CREATE: u64 = 2048;

const PERM_FT_FILE_UPLOAD_POWER: u32 = 235;
const PERM_FT_NEEDED_FILE_UPLOAD_POWER: u32 = 236;
const PERM_FT_FILE_DOWNLOAD_POWER: u32 = 237;
const PERM_FT_NEEDED_FILE_DOWNLOAD_POWER: u32 = 238;
const PERM_FT_FILE_DELETE_POWER: u32 = 239;
const PERM_FT_NEEDED_FILE_DELETE_POWER: u32 = 240;
const PERM_FT_FILE_RENAME_POWER: u32 = 241;
const PERM_FT_NEEDED_FILE_RENAME_POWER: u32 = 242;
const PERM_FT_FILE_BROWSE_POWER: u32 = 243;
const PERM_FT_NEEDED_FILE_BROWSE_POWER: u32 = 244;
const PERM_FT_DIRECTORY_CREATE_POWER: u32 = 245;
const PERM_FT_NEEDED_DIRECTORY_CREATE_POWER: u32 = 246;

/// Turns a `permoverview` answer into the bits a shell renders.
///
/// A permission missing from the answer means "not explicitly restricted", so
/// the button stays visible; the server is still the one that decides.
pub fn compute_file_permission_hints(perms: &HashMap<u32, i32>) -> u64 {
    let can = |power_id: u32, needed_id: u32| match perms.get(&power_id) {
        // -1 is "unlimited", which outranks any required power.
        Some(&-1) => true,
        Some(&power) => power >= perms.get(&needed_id).copied().unwrap_or(0),
        None => true,
    };

    let mut hints = HINT_JOIN;
    if can(PERM_FT_FILE_UPLOAD_POWER, PERM_FT_NEEDED_FILE_UPLOAD_POWER) {
        hints |= HINT_FILE_UPLOAD;
    }
    if can(
        PERM_FT_FILE_DOWNLOAD_POWER,
        PERM_FT_NEEDED_FILE_DOWNLOAD_POWER,
    ) {
        hints |= HINT_FILE_DOWNLOAD;
    }
    if can(PERM_FT_FILE_DELETE_POWER, PERM_FT_NEEDED_FILE_DELETE_POWER) {
        hints |= HINT_FILE_DELETE;
    }
    if can(PERM_FT_FILE_RENAME_POWER, PERM_FT_NEEDED_FILE_RENAME_POWER) {
        hints |= HINT_FILE_RENAME;
    }
    if can(PERM_FT_FILE_BROWSE_POWER, PERM_FT_NEEDED_FILE_BROWSE_POWER) {
        hints |= HINT_FILE_BROWSE;
    }
    if can(
        PERM_FT_DIRECTORY_CREATE_POWER,
        PERM_FT_NEEDED_DIRECTORY_CREATE_POWER,
    ) {
        hints |= HINT_FILE_DIRECTORY_CREATE;
    }
    hints
}

/// Flattens the channel graph into the server's display order.
///
/// `order` is a linked-list position — the id of the sibling this channel is
/// placed after, `0` first — not a sort index. Sorting by the raw value only
/// matches servers that were never reordered.
fn channel_tree(channels: &BTreeMap<i64, ChannelEntry>) -> Vec<ChannelNode> {
    let mut by_parent: BTreeMap<i64, Vec<&ChannelEntry>> = BTreeMap::new();
    for channel in channels.values() {
        by_parent
            .entry(channel.parent_id)
            .or_default()
            .push(channel);
    }

    let mut nodes = Vec::with_capacity(channels.len());
    let mut visited = BTreeSet::new();
    walk_tree(0, 0, &by_parent, &mut nodes, &mut visited);
    // Channels whose parent is missing from the book are shown as roots; the
    // recursive walk keeps their own subtrees in order.
    for parent_id in by_parent.keys() {
        if *parent_id != 0 && !channels.contains_key(parent_id) {
            walk_tree(*parent_id, 0, &by_parent, &mut nodes, &mut visited);
        }
    }
    nodes
}

fn walk_tree(
    parent_id: i64,
    depth: i32,
    by_parent: &BTreeMap<i64, Vec<&ChannelEntry>>,
    out: &mut Vec<ChannelNode>,
    visited: &mut BTreeSet<i64>,
) {
    let Some(siblings) = by_parent.get(&parent_id) else {
        return;
    };
    for channel in ordered_siblings(siblings) {
        if !visited.insert(channel.id) {
            continue;
        }
        out.push(ChannelNode {
            id: channel.id,
            depth,
        });
        walk_tree(channel.id, depth + 1, by_parent, out, visited);
    }
}

fn ordered_siblings<'a>(siblings: &[&'a ChannelEntry]) -> Vec<&'a ChannelEntry> {
    if siblings.len() <= 1 {
        return siblings.to_vec();
    }
    let mut after: BTreeMap<i64, &'a ChannelEntry> = BTreeMap::new();
    for channel in siblings {
        after.insert(channel.order, channel);
    }

    let mut result = Vec::with_capacity(siblings.len());
    let mut seen = BTreeSet::new();
    let mut current = after.get(&0).copied();
    while let Some(channel) = current {
        if !seen.insert(channel.id) {
            break;
        }
        result.push(channel);
        current = after.get(&channel.id).copied();
    }
    // Duplicate or dangling order values leave channels outside the chain;
    // showing them at the end beats hiding them.
    for channel in siblings {
        if !seen.contains(&channel.id) {
            result.push(channel);
        }
    }
    result
}

/// Emits the events implied by one client changing between two snapshots.
///
/// Split out of `sync_from` so the loop there stays a loop; the interesting
/// part of this file is the set of questions asked, not the bookkeeping around
/// them.
///
/// Hardware flags ride on the same event as the mute flags: both answer "can
/// this person be heard", and a client turning its microphone off in its own
/// settings produces no `client_input_muted` change at all, so without them the
/// member list kept showing such a client as open-mic.
/// Which server fields differ between two snapshots.
///
/// `clients_online` is in the list on purpose: it changes constantly, and a
/// shell that shows "8 / 32" needs it to move. The event carries the new name
/// and welcome message so a shell can redraw without a snapshot read.
fn changed_server_fields(old: &ServerEntry, new: &ServerEntry) -> Vec<&'static str> {
    let mut changed = Vec::new();
    if old.name != new.name {
        changed.push("name");
    }
    if old.version != new.version {
        changed.push("version");
    }
    if old.platform != new.platform {
        changed.push("platform");
    }
    if old.clients_online != new.clients_online {
        changed.push("clients_online");
    }
    if old.max_clients != new.max_clients {
        changed.push("max_clients");
    }
    if old.welcome_message != new.welcome_message {
        changed.push("welcome_message");
    }
    if old.ask_privilege_key != new.ask_privilege_key {
        changed.push("ask_privilege_key");
    }
    changed
}

/// Group changes between two lists, as events.
///
/// A group list is replaced wholesale by each update, so the diff is by id:
/// present in both and equal is nothing, present in both and different is an
/// edit, absent from the new list is a removal.
fn diff_groups(kind: &str, old: &[GroupEntry], new: &[GroupEntry]) -> Vec<QueuedEvent> {
    let mut events = Vec::new();
    let old_by_id: std::collections::BTreeMap<i64, &GroupEntry> =
        old.iter().map(|group| (group.id, group)).collect();
    let new_by_id: std::collections::BTreeMap<i64, &GroupEntry> =
        new.iter().map(|group| (group.id, group)).collect();

    for (id, group) in &new_by_id {
        match old_by_id.get(id) {
            None => events.push(
                QueuedEvent::new("group_created")
                    .str("group_kind", kind)
                    .long("group_id", *id)
                    .str("name", &group.name)
                    .str("group_type", &group.group_type),
            ),
            Some(before) => {
                let changed = changed_group_fields(before, group);
                if !changed.is_empty() {
                    events.push(
                        QueuedEvent::new("group_updated")
                            .str("group_kind", kind)
                            .long("group_id", *id)
                            .str("name", &group.name)
                            .str("changed", changed.join(",")),
                    );
                }
            }
        }
    }
    for (id, group) in &old_by_id {
        if !new_by_id.contains_key(id) {
            events.push(
                QueuedEvent::new("group_removed")
                    .str("group_kind", kind)
                    .long("group_id", *id)
                    .str("name", &group.name),
            );
        }
    }
    events
}

/// Which group fields differ. `id` identifies the group and cannot change.
fn changed_group_fields(old: &GroupEntry, new: &GroupEntry) -> Vec<&'static str> {
    let mut changed = Vec::new();
    if old.name != new.name {
        changed.push("name");
    }
    if old.icon_id != new.icon_id {
        changed.push("icon_id");
    }
    if old.sort_id != new.sort_id {
        changed.push("sort_id");
    }
    if old.is_permanent != new.is_permanent {
        changed.push("is_permanent");
    }
    if old.group_type != new.group_type {
        changed.push("group_type");
    }
    changed
}

/// Which channel fields differ between two snapshots.
///
/// Names rather than a generic "something changed", because a shell that knows
/// what moved can redraw one label instead of the whole tree. `id` is excluded:
/// it identifies the channel and cannot change while the channel exists.
fn changed_channel_fields(old: &ChannelEntry, new: &ChannelEntry) -> Vec<&'static str> {
    let mut changed = Vec::new();
    if old.parent_id != new.parent_id {
        changed.push("parent_id");
    }
    if old.order != new.order {
        changed.push("order");
    }
    if old.has_password != new.has_password {
        changed.push("has_password");
    }
    if old.is_default != new.is_default {
        changed.push("is_default");
    }
    if old.topic != new.topic {
        changed.push("topic");
    }
    if old.max_clients != new.max_clients {
        changed.push("max_clients");
    }
    if old.subscribed != new.subscribed {
        changed.push("subscribed");
    }
    if old.icon_id != new.icon_id {
        changed.push("icon_id");
    }
    if old.is_private != new.is_private {
        changed.push("is_private");
    }
    if old.needed_talk_power != new.needed_talk_power {
        changed.push("needed_talk_power");
    }
    if old.codec != new.codec {
        changed.push("codec");
    }
    if old.codec_quality != new.codec_quality {
        changed.push("codec_quality");
    }
    if old.codec_latency_factor != new.codec_latency_factor {
        changed.push("codec_latency_factor");
    }
    if old.delete_delay != new.delete_delay {
        changed.push("delete_delay");
    }
    if old.forced_silence != new.forced_silence {
        changed.push("forced_silence");
    }
    if old.is_unencrypted != new.is_unencrypted {
        changed.push("is_unencrypted");
    }
    if old.max_family_clients != new.max_family_clients {
        changed.push("max_family_clients");
    }
    // Set by a `permoverview` answer rather than by the book, so it changes
    // without any server event — a shell that caches the mask needs to know.
    if old.permission_hints != new.permission_hints {
        changed.push("permission_hints");
    }
    changed
}

fn diff_user(id: i32, old: &UserEntry, user: &UserEntry, events: &mut Vec<QueuedEvent>) {
    if old.channel_id != user.channel_id {
        events.push(
            QueuedEvent::new("user_moved")
                .int("client_id", id)
                .str("nickname", &user.nickname)
                .long("channel_id", user.channel_id)
                .long("old_channel_id", old.channel_id),
        );
    }
    if old.nickname != user.nickname {
        events.push(
            QueuedEvent::new("user_renamed")
                .int("client_id", id)
                .str("nickname", &user.nickname)
                .str("old_nickname", &old.nickname),
        );
    }

    // The device flags are reported separately from the mute flags, so a change
    // in either is a change in "can be heard" and must reach the shell.
    let input_changed = old.input_muted != user.input_muted
        || old.input_hardware_enabled != user.input_hardware_enabled;
    let output_changed = old.output_muted != user.output_muted
        || old.output_hardware_enabled != user.output_hardware_enabled;
    for (changed, scope) in [(input_changed, "input"), (output_changed, "output")] {
        if changed {
            events.push(
                QueuedEvent::new("user_mute_changed")
                    .int("client_id", id)
                    .str("nickname", &user.nickname)
                    .bool("input_muted", user.input_muted)
                    .bool("output_muted", user.output_muted)
                    .bool("input_hardware_enabled", user.input_hardware_enabled)
                    .bool("output_hardware_enabled", user.output_hardware_enabled)
                    .str("scope", scope),
            );
        }
    }

    if old.is_priority_speaker != user.is_priority_speaker {
        events.push(
            QueuedEvent::new("user_priority_speaker_changed")
                .int("client_id", id)
                .str("nickname", &user.nickname)
                .bool("priority_speaker", user.is_priority_speaker),
        );
    }

    if old.unread_messages != user.unread_messages {
        events.push(
            QueuedEvent::new("user_unread_messages_changed")
                .int("client_id", id)
                .str("nickname", &user.nickname)
                .long("unread_messages", i64::from(user.unread_messages)),
        );
    }

    if old.away != user.away || old.away_message != user.away_message {
        events.push(
            QueuedEvent::new("user_away_changed")
                .int("client_id", id)
                .str("nickname", &user.nickname)
                .bool("away", user.away)
                .str("away_message", &user.away_message),
        );
    }

    // The profile fields a client can edit on itself. One event with the changed
    // names, like `channel_updated`: a shell redraws the row, and the snapshot
    // already holds the new values.
    let changed = changed_user_fields(old, user);
    if !changed.is_empty() {
        events.push(
            QueuedEvent::new("user_updated")
                .int("client_id", id)
                .str("nickname", &user.nickname)
                .str("changed", changed.join(",")),
        );
    }

    // The group membership is a list, so it gets its own event with the new
    // list rather than a name in `changed`: a shell needs the members to
    // resolve titles, not just the fact that it moved.
    //
    // The channel group is reported here too: a client sits in exactly one, so
    // it is a single id rather than a list, but it is the same question — "which
    // titles does this member wear" — and a shell resolves both against the same
    // group tables.
    if old.server_groups != user.server_groups || old.channel_group != user.channel_group {
        events.push(
            QueuedEvent::new("user_groups_changed")
                .int("client_id", id)
                .str("nickname", &user.nickname)
                .long("channel_group", user.channel_group)
                .str(
                    "server_groups",
                    user.server_groups
                        .iter()
                        .map(i64::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
        );
    }
}

/// Which client fields differ, excluding the ones that already have an event.
///
/// Kept separate from `diff_user` so the completeness test can read the names
/// out of one function. The fields with a dedicated event — `channel_id`,
/// `nickname`, the four mute/device flags, `is_priority_speaker`,
/// `unread_messages`, `away`, `away_message` — are not listed again here.
fn changed_user_fields(old: &UserEntry, new: &UserEntry) -> Vec<&'static str> {
    let mut changed = Vec::new();
    if old.client_type != new.client_type {
        changed.push("client_type");
    }
    if old.description != new.description {
        changed.push("description");
    }
    if old.talking != new.talking {
        changed.push("talking");
    }
    if old.badges != new.badges {
        changed.push("badges");
    }
    if old.output_only_muted != new.output_only_muted {
        changed.push("output_only_muted");
    }
    if old.inherited_channel_group_from_channel != new.inherited_channel_group_from_channel {
        changed.push("inherited_channel_group_from_channel");
    }
    if old.avatar_hash != new.avatar_hash {
        changed.push("avatar_hash");
    }
    if old.country != new.country {
        changed.push("country");
    }
    if old.is_channel_commander != new.is_channel_commander {
        changed.push("is_channel_commander");
    }
    if old.recording != new.recording {
        changed.push("recording");
    }
    if old.metadata != new.metadata {
        changed.push("metadata");
    }
    if old.talk_power_granted != new.talk_power_granted {
        changed.push("talk_power_granted");
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::Value;

    /// Every field a channel can change is named by the diff.
    ///
    /// A field that changes without appearing in `changed_channel_fields` is
    /// invisible to a shell until the next full snapshot rebuild, which is the
    /// same silent staleness the per-field event exists to prevent. The list
    /// below is read from `ChannelEntry`, so adding a field fails this test
    /// until it is either handled or listed as identity.
    #[test]
    fn every_mutable_channel_field_is_reported() {
        // Fields that cannot change while the channel exists: `id` identifies it.
        const IDENTITY: &[&str] = &["id", "name"];

        let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/state.rs"))
            .expect("read state.rs");
        let body = source
            .split("pub struct ChannelEntry {")
            .nth(1)
            .expect("ChannelEntry")
            .split("\n}")
            .next()
            .expect("closing brace");

        let fields: Vec<String> = body
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim_start();
                let rest = trimmed.strip_prefix("pub ")?;
                let field: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                (!field.is_empty()).then_some(field)
            })
            .collect();

        assert!(
            fields.len() > 15,
            "the field scan found only {} entries",
            fields.len()
        );

        // The names the diff can report, read from the function itself.
        let diff = source
            .split("fn changed_channel_fields")
            .nth(1)
            .expect("changed_channel_fields")
            .split("\nfn ")
            .next()
            .expect("end of the function");
        let reported: Vec<String> = diff
            .split("changed.push(\"")
            .skip(1)
            .filter_map(|rest| rest.split('"').next())
            .map(str::to_string)
            .collect();

        let missing: Vec<&String> = fields
            .iter()
            .filter(|field| !IDENTITY.contains(&field.as_str()))
            .filter(|field| !reported.contains(field))
            .collect();
        assert!(
            missing.is_empty(),
            "these channel fields can change but are never reported: {missing:?}"
        );
    }

    /// Every field a client can change is reported.
    ///
    /// The same check as [`every_mutable_channel_field_is_reported`], for the
    /// other diff. A `UserEntry` field that changes without an event leaves a
    /// member row stale until the next full rebuild — and the snapshot diff is
    /// the only thing that turns a book update into a UI change.
    #[test]
    fn every_mutable_user_field_is_reported() {
        // Fields that identify the client or never change while it is connected.
        // `id` and `uid` are identity; `position` is set by the shell, not the
        // server, and is carried in the snapshot rather than diffed.
        const IDENTITY: &[&str] = &["id", "uid", "position"];

        let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/state.rs"))
            .expect("read state.rs");
        let body = source
            .split("pub struct UserEntry {")
            .nth(1)
            .expect("UserEntry")
            .split("\n}")
            .next()
            .expect("closing brace");

        let fields: Vec<String> = body
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim_start();
                let rest = trimmed.strip_prefix("pub ")?;
                let field: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                (!field.is_empty()).then_some(field)
            })
            .collect();
        assert!(
            fields.len() > 14,
            "the field scan found only {}",
            fields.len()
        );

        // The fields `diff_user` compares, plus the ones `changed_user_fields`
        // names. Both are read from source: the second exists precisely so the
        // long tail of profile fields has one place to live.
        let diff = source
            .split("fn diff_user(")
            .nth(1)
            .expect("diff_user")
            .split("\nfn ")
            .next()
            .expect("end of the function");
        let named = source
            .split("fn changed_user_fields(")
            .nth(1)
            .expect("changed_user_fields")
            .split("\nfn ")
            .next()
            .expect("end of the function");
        let diff = format!("{diff}{named}");
        let mut compared: Vec<String> = diff
            .split("old.")
            .skip(1)
            .filter_map(|rest| {
                let field: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                (!field.is_empty()).then_some(field)
            })
            .collect();
        // `changed.push("field")` names the field a second way.
        compared.extend(
            diff.split("changed.push(\"")
                .skip(1)
                .filter_map(|rest| rest.split('"').next())
                .map(str::to_string),
        );

        let missing: Vec<&String> = fields
            .iter()
            .filter(|field| !IDENTITY.contains(&field.as_str()))
            .filter(|field| !compared.contains(field))
            .collect();
        assert!(
            missing.is_empty(),
            "these client fields can change but are never compared, so no event fires: {missing:?}"
        );
    }

    /// A change to any single field produces a non-empty list.
    #[test]
    fn one_changed_field_is_detected() {
        let base = ChannelEntry::default();
        let mut changed = base.clone();
        changed.topic = "new topic".to_string();
        assert_eq!(changed_channel_fields(&base, &changed), vec!["topic"]);

        let mut changed = base.clone();
        changed.forced_silence = !base.forced_silence;
        assert_eq!(
            changed_channel_fields(&base, &changed),
            vec!["forced_silence"]
        );
    }

    /// No change yields nothing, so an unrelated client event does not spam.
    #[test]
    fn an_unchanged_channel_reports_nothing() {
        let base = ChannelEntry::default();
        assert!(changed_channel_fields(&base, &base).is_empty());
    }

    /// Several changes are reported together, in field order.
    #[test]
    fn several_changes_are_reported_together() {
        let base = ChannelEntry::default();
        let mut changed = base.clone();
        changed.topic = "t".to_string();
        changed.max_clients = 42;
        let fields = changed_channel_fields(&base, &changed);
        assert!(fields.contains(&"topic") && fields.contains(&"max_clients"));
        assert_eq!(fields.len(), 2);
    }

    /// Every group field that can change is named by the diff.
    ///
    /// `id` identifies the group; the rest can be edited from the server's
    /// group editor, and a shell that never hears about it keeps the old name
    /// until the next full rebuild.
    #[test]
    fn every_mutable_group_field_is_reported() {
        const IDENTITY: &[&str] = &["id"];

        let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/state.rs"))
            .expect("read state.rs");
        let body = source
            .split("pub struct GroupEntry {")
            .nth(1)
            .expect("GroupEntry")
            .split("\n}")
            .next()
            .expect("closing brace");
        let fields: Vec<String> = body
            .lines()
            .filter_map(|line| {
                let rest = line.trim_start().strip_prefix("pub ")?;
                let field: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                (!field.is_empty()).then_some(field)
            })
            .collect();

        let diff = source
            .split("fn changed_group_fields(")
            .nth(1)
            .expect("changed_group_fields")
            .split("\nfn ")
            .next()
            .expect("end of the function");
        let named: Vec<String> = diff
            .split("changed.push(\"")
            .skip(1)
            .filter_map(|rest| rest.split('"').next())
            .map(str::to_string)
            .collect();

        let missing: Vec<&String> = fields
            .iter()
            .filter(|field| !IDENTITY.contains(&field.as_str()))
            .filter(|field| !named.contains(field))
            .collect();
        assert!(
            missing.is_empty(),
            "these group fields can change but are never reported: {missing:?}"
        );
    }

    /// Adding, renaming and removing a group each produce an event.
    #[test]
    fn group_lifecycle_is_reported() {
        let before = vec![GroupEntry {
            id: 6,
            name: "Normal".into(),
            ..GroupEntry::default()
        }];

        // Rename.
        let mut renamed = before.clone();
        renamed[0].name = "Regular".into();
        let events = diff_groups("server", &before, &renamed);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "group_updated");

        // Add.
        let mut added = before.clone();
        added.push(GroupEntry {
            id: 8,
            name: "Admin".into(),
            ..GroupEntry::default()
        });
        let events = diff_groups("server", &before, &added);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "group_created");

        // Remove.
        let events = diff_groups("server", &before, &[]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "group_removed");

        // Unchanged.
        assert!(diff_groups("server", &before, &before).is_empty());
    }

    /// The setter hands the events over exactly once.
    #[test]
    fn group_events_are_drained_once() {
        let mut snapshot = Snapshot::default();
        snapshot.set_server_groups(vec![GroupEntry {
            id: 6,
            name: "Normal".into(),
            ..GroupEntry::default()
        }]);
        let first = snapshot.take_group_events();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].kind, "group_created");

        // A second drain has nothing: the queue was taken, not copied.
        assert!(snapshot.take_group_events().is_empty());

        // Setting the same list again produces nothing.
        snapshot.set_server_groups(vec![GroupEntry {
            id: 6,
            name: "Normal".into(),
            ..GroupEntry::default()
        }]);
        assert!(snapshot.take_group_events().is_empty());
    }

    /// Every server field that can change is named by the diff.
    #[test]
    fn every_mutable_server_field_is_reported() {
        let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/state.rs"))
            .expect("read state.rs");
        let body = source
            .split("pub struct ServerEntry {")
            .nth(1)
            .expect("ServerEntry")
            .split("\n}")
            .next()
            .expect("closing brace");
        let fields: Vec<String> = body
            .lines()
            .filter_map(|line| {
                let rest = line.trim_start().strip_prefix("pub ")?;
                let field: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                (!field.is_empty()).then_some(field)
            })
            .collect();

        let diff = source
            .split("fn changed_server_fields(")
            .nth(1)
            .expect("changed_server_fields")
            .split("\nfn ")
            .next()
            .expect("end of the function");
        let named: Vec<String> = diff
            .split("changed.push(\"")
            .skip(1)
            .filter_map(|rest| rest.split('"').next())
            .map(str::to_string)
            .collect();

        // Every field is mutable here: a server entry is replaced wholesale by
        // each update, and none of these is an identity.
        let missing: Vec<&String> = fields
            .iter()
            .filter(|field| !named.contains(field))
            .collect();
        assert!(
            missing.is_empty(),
            "these server fields can change but are never reported: {missing:?}"
        );
    }

    /// A profile change is reported once, naming the field.
    #[test]
    fn a_profile_change_is_reported() {
        let base = UserEntry::default();
        let mut changed = base.clone();
        changed.description = "new".to_string();
        assert_eq!(changed_user_fields(&base, &changed), vec!["description"]);

        let mut changed = base.clone();
        changed.recording = !base.recording;
        assert_eq!(changed_user_fields(&base, &changed), vec!["recording"]);
    }

    /// A group membership change is its own event, because the shell needs the
    /// new list rather than the fact that it moved.
    #[test]
    fn a_group_change_carries_the_new_list() {
        let old = UserEntry {
            server_groups: vec![6],
            ..UserEntry::default()
        };
        let mut new = old.clone();
        new.server_groups = vec![6, 8];

        let mut events = Vec::new();
        diff_user(7, &old, &new, &mut events);
        let event = events
            .iter()
            .find(|e| e.kind == "user_groups_changed")
            .expect("a group change must emit an event");
        let groups = event
            .data
            .iter()
            .find(|(key, _)| key == "server_groups")
            .map(|(_, value)| value.clone());
        assert_eq!(groups, Some(Value::Str("6,8".to_string())));
    }

    /// A channel group change is reported by the same event as a server group
    /// change, because a shell resolves both against the same group tables.
    ///
    /// Without this the title simply stops updating after the first sync: the
    /// id in the snapshot is right, but nothing told the shell to redraw.
    #[test]
    fn a_channel_group_change_carries_the_new_id() {
        let old = UserEntry {
            channel_group: 5,
            server_groups: vec![6],
            ..UserEntry::default()
        };
        let mut new = old.clone();
        new.channel_group = 9;

        let mut events = Vec::new();
        diff_user(7, &old, &new, &mut events);
        let event = events
            .iter()
            .find(|e| e.kind == "user_groups_changed")
            .expect("a channel group change must emit an event");
        let group = event
            .data
            .iter()
            .find(|(key, _)| key == "channel_group")
            .map(|(_, value)| value.clone());
        assert_eq!(group, Some(Value::Long(9)));
    }

    /// An unchanged client emits nothing, so an unrelated book update does not
    /// spam the queue.
    #[test]
    fn an_unchanged_client_emits_nothing() {
        let base = UserEntry::default();
        let mut events = Vec::new();
        diff_user(7, &base, &base, &mut events);
        assert!(events.is_empty(), "{:?}", events);
    }

    fn user(enable_input: bool, enable_output: bool) -> UserEntry {
        UserEntry {
            id: 7,
            nickname: "ann".into(),
            input_hardware_enabled: enable_input,
            output_hardware_enabled: enable_output,
            ..UserEntry::default()
        }
    }

    /// The bug this exists for: the mute flag does not move when a client
    /// switches its microphone off in its own settings, so a diff that only
    /// looked at `input_muted` stayed silent and the UI kept drawing an open
    /// microphone.
    #[test]
    fn hardware_mute_is_reported_while_the_mute_flag_is_unchanged() {
        let events = {
            let mut events = Vec::new();
            diff_user(7, &user(true, true), &user(false, true), &mut events);
            events
        };
        assert_eq!(events.len(), 1, "expected exactly one event: {events:?}");
        assert_eq!(events[0].kind, "user_mute_changed");
        let fields = &events[0].data;
        assert!(
            fields.contains(&("input_hardware_enabled".into(), Value::Bool(false))),
            "the new flag must travel on the event: {fields:?}"
        );
        assert!(
            fields.contains(&("input_muted".into(), Value::Bool(false))),
            "the unchanged mute flag must still be present: {fields:?}"
        );
        assert_eq!(
            fields.iter().find(|(k, _)| k == "scope").map(|(_, v)| v),
            Some(&Value::Str("input".into())),
            "a hardware change must be scoped to the device it affects"
        );
    }

    /// Both directions report once, not twice: a client that turns its
    /// microphone off and its speakers off in the same update is one input and
    /// one output event, and the UI is told about both.
    #[test]
    fn input_and_output_hardware_changes_report_separately() {
        let mut events = Vec::new();
        diff_user(7, &user(true, true), &user(false, false), &mut events);
        let scopes: Vec<_> = events
            .iter()
            .filter(|e| e.kind == "user_mute_changed")
            .map(|e| e.data.iter().find(|(k, _)| k == "scope").unwrap().1.clone())
            .collect();
        assert_eq!(
            scopes,
            vec![Value::Str("input".into()), Value::Str("output".into())]
        );
    }

    /// An unrelated change (nickname only) must not emit mute events. A rewrite
    /// that fired on every diff would have the UI re-render the mute icon on
    /// every rename.
    #[test]
    fn unrelated_changes_do_not_emit_mute_events() {
        let mut old = user(true, true);
        old.nickname = "ann".into();
        let mut new = user(true, true);
        new.nickname = "beth".into();
        let mut events = Vec::new();
        diff_user(7, &old, &new, &mut events);
        assert!(
            events.iter().all(|e| e.kind != "user_mute_changed"),
            "no mute change happened, but events were emitted: {events:?}"
        );
    }

    /// Derived `Default` would mean "both devices off" for every client that has
    /// not synced yet; the documented meaning of an absent flag is "device on".
    #[test]
    fn empty_snapshot_reports_devices_as_available() {
        let snapshot = Snapshot::default();
        assert!(snapshot.input_hardware_enabled);
        assert!(snapshot.output_hardware_enabled);
        assert!(UserEntry::default().input_hardware_enabled);
        assert!(UserEntry::default().output_hardware_enabled);
    }

    fn channel(id: i64, parent_id: i64, order: i64) -> ChannelEntry {
        ChannelEntry {
            id,
            parent_id,
            order,
            ..ChannelEntry::default()
        }
    }

    fn tree_of(channels: Vec<ChannelEntry>) -> Vec<(i64, i32)> {
        let map: BTreeMap<i64, ChannelEntry> = channels.into_iter().map(|c| (c.id, c)).collect();
        channel_tree(&map)
            .into_iter()
            .map(|node| (node.id, node.depth))
            .collect()
    }

    /// `order` is the previous sibling's id, not a sort index: a channel moved
    /// in front keeps an order larger than the ones after it.
    #[test]
    fn sibling_order_is_followed_as_a_chain() {
        let tree = tree_of(vec![
            channel(1, 0, 0),
            channel(2, 0, 4),
            channel(3, 0, 2),
            channel(4, 0, 1),
        ]);
        assert_eq!(tree, vec![(1, 0), (4, 0), (2, 0), (3, 0)]);
    }

    #[test]
    fn nesting_uses_one_chain_per_parent() {
        let tree = tree_of(vec![
            channel(1, 0, 0),
            channel(2, 0, 1),
            channel(10, 1, 0),
            channel(11, 1, 10),
            channel(20, 2, 0),
        ]);
        assert_eq!(tree, vec![(1, 0), (10, 1), (11, 1), (2, 0), (20, 1)]);
    }

    /// A partial book (the parent was never received) must still show the
    /// channels, at root depth, with their own subtrees intact.
    #[test]
    fn channels_with_a_missing_parent_are_roots() {
        let tree = tree_of(vec![channel(1, 0, 0), channel(9, 8, 0), channel(90, 9, 0)]);
        assert_eq!(tree, vec![(1, 0), (9, 0), (90, 1)]);
    }

    /// Channels whose `order` values do not reach them from `0` (a dangling
    /// or cyclic chain) are appended instead of disappearing.
    #[test]
    fn channels_outside_the_order_chain_are_appended() {
        let tree = tree_of(vec![channel(1, 0, 0), channel(2, 0, 3), channel(3, 0, 2)]);
        assert_eq!(tree, vec![(1, 0), (2, 0), (3, 0)]);
    }

    #[test]
    fn identity_ready_bumps_the_revision_once() {
        let mut snapshot = Snapshot::default();
        let before = snapshot.rev;
        snapshot.set_identity_ready();
        assert!(snapshot.identity_ready);
        assert!(snapshot.rev > before);
        let after = snapshot.rev;
        snapshot.set_identity_ready();
        assert_eq!(snapshot.rev, after);
    }
    #[test]
    fn groups_are_sorted_by_name_case_insensitively() {
        let mut snapshot = Snapshot::default();
        snapshot.set_server_groups(vec![
            GroupEntry {
                id: 2,
                name: "zeta".into(),
                ..Default::default()
            },
            GroupEntry {
                id: 1,
                name: "Alpha".into(),
                ..Default::default()
            },
        ]);
        let names: Vec<&str> = snapshot
            .server_groups
            .iter()
            .map(|g| g.name.as_str())
            .collect();
        assert_eq!(names, vec!["Alpha", "zeta"]);
    }

    #[test]
    fn file_listings_put_directories_first_and_ignore_case() {
        let mut snapshot = Snapshot::default();
        let file = |name: &str, is_file: bool| FileEntry {
            channel_id: 1,
            name: name.into(),
            is_file,
            ..FileEntry::default()
        };
        snapshot.set_files(
            1,
            vec![file("b.txt", true), file("Zed", false), file("a.txt", true)],
        );
        let names: Vec<&str> = snapshot.files.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["Zed", "a.txt", "b.txt"]);
    }
    #[test]
    fn file_hints_follow_the_required_power() {
        let mut perms = HashMap::new();
        // Upload: power 50 against a requirement of 50 -> allowed.
        perms.insert(PERM_FT_FILE_UPLOAD_POWER, 50);
        perms.insert(PERM_FT_NEEDED_FILE_UPLOAD_POWER, 50);
        // Delete: power 10 against a requirement of 30 -> denied.
        perms.insert(PERM_FT_FILE_DELETE_POWER, 10);
        perms.insert(PERM_FT_NEEDED_FILE_DELETE_POWER, 30);
        // Rename: unlimited beats any requirement.
        perms.insert(PERM_FT_FILE_RENAME_POWER, -1);
        perms.insert(PERM_FT_NEEDED_FILE_RENAME_POWER, 100);
        // Download is absent: not explicitly restricted, so it stays.
        let hints = compute_file_permission_hints(&perms);
        assert_ne!(hints & HINT_FILE_UPLOAD, 0);
        assert_eq!(hints & HINT_FILE_DELETE, 0);
        assert_ne!(hints & HINT_FILE_RENAME, 0);
        assert_ne!(hints & HINT_FILE_DOWNLOAD, 0);
        assert_ne!(hints & HINT_JOIN, 0);
    }

    #[test]
    fn channel_hints_are_stored_and_revision_follows_changes() {
        let mut snapshot = Snapshot::default();
        snapshot.channels.push(ChannelEntry {
            id: 7,
            ..ChannelEntry::default()
        });
        let before = snapshot.rev;
        snapshot.set_channel_permission_hints(7, HINT_JOIN | HINT_FILE_UPLOAD);
        assert_eq!(
            snapshot.channels[0].permission_hints,
            HINT_JOIN | HINT_FILE_UPLOAD
        );
        assert!(snapshot.rev > before);
        let after = snapshot.rev;
        snapshot.set_channel_permission_hints(7, HINT_JOIN | HINT_FILE_UPLOAD);
        assert_eq!(snapshot.rev, after);
    }
}

#[cfg(test)]
mod own_group_tests {
    use super::*;

    /// "Am I an admin" is the join of two lists that arrive in no fixed order:
    /// this client's group ids and the server's group names. A shell that got
    /// only one of them would draw everyone as a Guest.
    #[test]
    fn own_groups_resolve_once_both_lists_are_known() {
        let mut snapshot = Snapshot {
            own_client_id: Some(5),
            users: vec![UserEntry {
                id: 5,
                server_groups: vec![6, 7],
                ..UserEntry::default()
            }],
            ..Snapshot::default()
        };
        snapshot.refresh_own_groups();
        assert!(snapshot.own_server_groups.is_empty(), "names not known yet");

        snapshot.set_server_groups(vec![
            GroupEntry {
                id: 7,
                name: "Normal".to_string(),
                ..Default::default()
            },
            GroupEntry {
                id: 6,
                name: "Server Admin".to_string(),
                ..Default::default()
            },
            GroupEntry {
                id: 8,
                name: "Guest".to_string(),
                ..Default::default()
            },
        ]);
        let names: Vec<&str> = snapshot
            .own_server_groups
            .iter()
            .map(|group| group.name.as_str())
            .collect();
        // `set_server_groups` sorts by name, and the join follows that order.
        assert_eq!(names, ["Normal", "Server Admin"], "Guest must not appear");
    }

    #[test]
    fn a_client_with_no_groups_has_none() {
        let mut snapshot = Snapshot {
            own_client_id: Some(5),
            users: vec![UserEntry {
                id: 5,
                ..UserEntry::default()
            }],
            ..Snapshot::default()
        };
        snapshot.set_server_groups(vec![GroupEntry {
            id: 6,
            name: "Server Admin".to_string(),
            ..Default::default()
        }]);
        assert!(snapshot.own_server_groups.is_empty());
    }
}
