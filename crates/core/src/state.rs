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

use std::collections::BTreeMap;

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
    pub users: Vec<UserEntry>,
    pub channels: Vec<ChannelEntry>,
    /// Kept across `sync_from` calls: a file listing is a one-off response, not
    /// part of the book, so the next member update must not wipe it.
    pub files: Vec<FileEntry>,
    pub server: ServerEntry,
    pub connected: bool,
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
            users: Vec::new(),
            channels: Vec::new(),
            files: Vec::new(),
            server: ServerEntry::default(),
            connected: false,
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
        let changed = prev_users != next_users
            || prev_channels != next_channels
            || self.server != server
            || self.own_channel_id != own_channel_id;
        if changed || !events.is_empty() {
            self.rev = self.rev.wrapping_add(1);
        }

        self.server = server;
        self.own_channel_id = own_channel_id;
        self.users = next_users.into_values().collect();
        self.channels = next_channels.into_values().collect();

        events
    }

    /// Replaces the cached file listing of one channel and returns the event that
    /// tells the UI its spinner can stop.
    pub fn set_files(&mut self, channel_id: i64, entries: Vec<FileEntry>) -> QueuedEvent {
        self.files.retain(|file| file.channel_id != channel_id);
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
}
