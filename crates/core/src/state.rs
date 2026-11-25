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
    /// Raw `client_badges` from the server (e.g. `overwolf=0`). Empty when the
    /// server reported none, which is also what a client without a myTeamSpeak
    /// proof gets.
    pub badges: String,
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
            badges: String::new(),
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
    pub max_clients: i32,
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

#[derive(Debug, Serialize)]
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
    pub server: ServerEntry,
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
            server: ServerEntry::default(),
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
                    // A permission answer is not part of the book, so a synced
                    // rebuild would otherwise wipe it on every client event.
                    permission_hints: prev_channels
                        .get(&(id.0 as i64))
                        .map_or(0, |old| old.permission_hints),
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
                Some(_) => {}
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
                    badges: client.badges.clone(),
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
        if self.server_groups != groups {
            self.server_groups = groups;
            self.refresh_own_groups();
            self.rev = self.rev.wrapping_add(1);
        }
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
        if self.channel_groups != groups {
            self.channel_groups = groups;
            self.rev = self.rev.wrapping_add(1);
        }
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

    if old.away != user.away || old.away_message != user.away_message {
        events.push(
            QueuedEvent::new("user_away_changed")
                .int("client_id", id)
                .str("nickname", &user.nickname)
                .bool("away", user.away)
                .str("away_message", &user.away_message),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::Value;

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
            },
            GroupEntry {
                id: 1,
                name: "Alpha".into(),
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
            },
            GroupEntry {
                id: 6,
                name: "Server Admin".to_string(),
            },
            GroupEntry {
                id: 8,
                name: "Guest".to_string(),
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
        }]);
        assert!(snapshot.own_server_groups.is_empty());
    }
}
