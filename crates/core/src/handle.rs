//! The client handle a shell holds as an opaque pointer.
//!
//! One handle owns one connection thread. Every entry point borrows the handle
//! for the duration of the call and never blocks on the network: work is handed
//! to the connection thread through a command channel, and its results come back
//! through the event queue and the snapshot.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::runtime::Runtime;
use tokio::sync::mpsc;

use crate::events::QueuedEvent;
use crate::state::Snapshot;

/// Who a text message goes to.
#[derive(Debug, Clone, Copy)]
pub enum TextTarget {
    Server,
    Channel,
    Client(i32),
}

/// Work the host thread asks the connection thread to perform.
#[derive(Debug)]
pub enum Command {
    /// Close the connection and stop the thread.
    Disconnect,
    SendText {
        target: TextTarget,
        message: String,
    },
    Poke {
        client_id: i32,
        message: String,
    },
    JoinChannel {
        channel_id: i64,
        password: Option<String>,
    },
    SetInputMuted(bool),
    SetOutputMuted(bool),
    SetAway {
        away: bool,
        message: Option<String>,
    },
    SetNickname(String),
    ListFiles {
        channel_id: i64,
        path: String,
        password: Option<String>,
    },
    Download {
        channel_id: i64,
        path: String,
        local: String,
        password: Option<String>,
    },
    Upload {
        channel_id: i64,
        path: String,
        local: String,
        password: Option<String>,
        overwrite: bool,
    },
    /// Gate for the transmit path; capture keeps running either way.
    SetAudioEnabled(bool),
    /// Linear capture gain, applied before the silence gate and encoder.
    SetMicGain(f32),
    /// Linear playback volume for one remote client.
    SetUserVolume {
        client_id: i32,
        volume: f32,
    },
    /// Empty targets restore ordinary channel talk.
    SetWhisperTargets {
        clients: Vec<u16>,
        channels: Vec<u64>,
        /// `(GroupWhisperType, GroupWhisperTarget, group id)`.
        groups: Vec<(u8, u8, u64)>,
    },
    /// Kick a client off the server or out of its channel.
    KickClient {
        client_id: i32,
        /// 4 = channel kick, 5 = server kick, matching `Reason`.
        reason: u8,
        message: Option<String>,
    },
    /// Move a client to another channel.
    MoveClient {
        client_id: i32,
        channel_id: i64,
        password: Option<String>,
    },
    /// Ban by unique id, IP or nickname. At least one identifier is required.
    BanAdd {
        uid: Option<String>,
        ip: Option<String>,
        name: Option<String>,
        /// Ban duration in seconds; 0 means permanent.
        seconds: u64,
        reason: Option<String>,
    },
    /// Remove a ban by its id, or every ban when `ban_id` is 0.
    BanDelete {
        ban_id: i64,
    },
    /// Create a channel, optionally under `parent_id`.
    ChannelCreate {
        parent_id: Option<i64>,
        name: String,
        topic: Option<String>,
        description: Option<String>,
        password: Option<String>,
        max_clients: Option<i32>,
        order: Option<i64>,
    },
    /// Rename a channel or change its topic, description or limits.
    ChannelEdit {
        channel_id: i64,
        name: Option<String>,
        topic: Option<String>,
        description: Option<String>,
        max_clients: Option<i32>,
    },
    /// Delete a channel; `force` removes it even when clients are inside.
    ChannelDelete {
        channel_id: i64,
        force: bool,
    },
    /// Subscribe to or unsubscribe from a channel's events.
    ChannelSubscribe {
        channel_id: i64,
        subscribed: bool,
    },
    /// File the server-side complaint about a client.
    ComplainAdd {
        client_db_id: i64,
        message: String,
    },
    /// Drop a complaint, or every complaint when `client_db_id` is 0.
    ComplainDelete {
        client_db_id: i64,
        message: Option<String>,
    },
    /// Create a privilege key for a group. `group_id` is a server group id;
    /// `channel_id` is 0 for a server group token.
    PrivilegeKeyCreate {
        group_id: i64,
        channel_id: i64,
        description: Option<String>,
    },
    /// Redeem a privilege key.
    PrivilegeKeyUse {
        key: String,
    },
    /// List the privilege keys this client may see.
    PrivilegeKeyList,
    /// Give a client a channel group.
    SetClientChannelGroup {
        client_db_id: i64,
        channel_id: i64,
        group_id: i64,
    },
    /// Fetch the ban list.
    BanList,
    /// List the offline messages waiting for this client's uid.
    OfflineMessageList,
    /// Read one offline message by id.
    OfflineMessageGet {
        message_id: i64,
    },
    /// Delete one offline message, or every one when `message_id` is 0.
    OfflineMessageDelete {
        message_id: i64,
    },
    /// Send an offline message to a client uid.
    OfflineMessageSend {
        uid: String,
        subject: String,
        message: String,
    },
    /// Ask the server for its own variables (uptime, bandwidth, defaults).
    ServerVariables,
    /// Ask for one client's full variable set, which the book does not carry.
    ClientVariables {
        client_id: i32,
    },
    /// Create a temporary server password.
    TempPasswordAdd {
        password: String,
        description: String,
        /// Lifetime in seconds; 0 means the server default.
        seconds: u64,
        channel_id: i64,
        channel_password: String,
    },
    /// Delete a temporary password by its value.
    TempPasswordDelete {
        password: String,
    },
    /// List the temporary passwords this client may see.
    TempPasswordList,
    /// Ask for the permission list of one client.
    ClientPermissionList {
        client_db_id: i64,
        /// Ask for permission names as well as ids.
        permsid: bool,
    },
    /// Ask for the permission list of one channel.
    ChannelPermissionList {
        channel_id: i64,
        /// Ask for permission names as well as ids.
        permsid: bool,
    },
    /// Change another client's description, or grant/revoke its talk power.
    ClientEdit {
        client_id: i32,
        description: Option<String>,
        talk_power_granted: Option<bool>,
    },
    /// Update this client's own flags: channel commander, recording, phonetic
    /// name, hardware devices, avatar hash.
    ClientUpdate {
        channel_commander: Option<bool>,
        recording: Option<bool>,
        phonetic_name: Option<String>,
        input_hardware_enabled: Option<bool>,
        output_hardware_enabled: Option<bool>,
        avatar_hash: Option<String>,
    },
    /// Request talk power in the current channel.
    TalkPowerRequest {
        message: Option<String>,
    },
    /// Change the server's name, welcome message or client limit.
    ServerEdit {
        name: Option<String>,
        welcome_message: Option<String>,
        max_clients: Option<i32>,
    },
    /// Delete a file or an empty directory in a channel.
    DeleteFile {
        channel_id: i64,
        path: String,
        password: Option<String>,
    },
    /// Rename a file in place, or move it to another channel.
    RenameFile {
        channel_id: i64,
        path: String,
        new_name: String,
        target_channel_id: Option<i64>,
        target_password: Option<String>,
        password: Option<String>,
    },
    /// Create a directory inside a channel's file area.
    CreateDirectory {
        channel_id: i64,
        path: String,
        password: Option<String>,
    },
    /// Create a server group.
    ///
    /// `group_type` is the protocol's `type`: `0` template, `1` regular,
    /// `2` query. `None` lets the server use its default, which is regular.
    ServerGroupCreate {
        name: String,
        group_type: Option<u8>,
    },
    /// Delete a server group; `force` removes it even while clients hold it.
    ServerGroupDelete {
        group_id: i64,
        force: bool,
    },
    /// Rename a server group.
    ServerGroupRename {
        group_id: i64,
        name: String,
    },
    /// Add a client to a server group.
    ServerGroupAddClient {
        group_id: i64,
        client_db_id: i64,
    },
    /// Remove a client from a server group.
    ServerGroupDelClient {
        group_id: i64,
        client_db_id: i64,
    },
    /// Create a channel group.
    ChannelGroupCreate {
        name: String,
        group_type: Option<u8>,
    },
    /// Delete a channel group.
    ChannelGroupDelete {
        group_id: i64,
        force: bool,
    },
    /// Rename a channel group.
    ChannelGroupRename {
        group_id: i64,
        name: String,
    },
    /// Grant a permission to one client in one channel.
    ChannelClientAddPerm {
        channel_id: i64,
        client_db_id: i64,
        /// Either the numeric id or the name; the protocol takes one or the other.
        permission_id: Option<i64>,
        permission_name: Option<String>,
        value: i32,
    },
    /// Revoke a permission from one client in one channel.
    ChannelClientDelPerm {
        channel_id: i64,
        client_db_id: i64,
        permission_id: Option<i64>,
        permission_name: Option<String>,
    },
    /// List the client database, newest first.
    ClientDbList {
        offset: Option<i64>,
        limit: Option<i64>,
        /// Ask for the total count instead of the entries.
        count: bool,
    },
    /// Find client database entries whose last nickname matches a pattern.
    ///
    /// With `uid` the pattern is matched against unique ids instead, which is
    /// how a caller resolves a uid to a database id.
    ClientDbFind {
        pattern: String,
        uid: bool,
    },
    /// Ask for one client database entry.
    ClientDbInfo {
        client_db_id: i64,
    },
    /// Mark an offline message read or unread.
    OfflineMessageFlag {
        message_id: i64,
        read: bool,
    },
    /// Grant a permission to a server group.
    ServerGroupAddPerm {
        group_id: i64,
        permission_id: Option<i64>,
        permission_name: Option<String>,
        value: i32,
        negated: bool,
        skip: bool,
    },
    /// Revoke a permission from a server group.
    ServerGroupDelPerm {
        group_id: i64,
        permission_id: Option<i64>,
        permission_name: Option<String>,
    },
    /// Grant a permission to a channel group.
    ChannelGroupAddPerm {
        group_id: i64,
        permission_id: Option<i64>,
        permission_name: Option<String>,
        value: i32,
    },
    /// Revoke a permission from a channel group.
    ChannelGroupDelPerm {
        group_id: i64,
        permission_id: Option<i64>,
        permission_name: Option<String>,
    },
    /// Grant a permission to everyone in a channel.
    ChannelAddPerm {
        channel_id: i64,
        permission_id: Option<i64>,
        permission_name: Option<String>,
        value: i32,
    },
    /// Revoke a permission from everyone in a channel.
    ChannelDelPerm {
        channel_id: i64,
        permission_id: Option<i64>,
        permission_name: Option<String>,
    },
    /// Delete a client database entry.
    ClientDbDelete {
        client_db_id: i64,
    },
    /// Send a message to every server on this instance.
    GlobalMessage {
        message: String,
    },
    /// Invoke a plugin command.
    PluginInvoke {
        name: String,
        data: String,
        /// `channel`, `server` or `client`.
        target: String,
        client_id: Option<i32>,
    },
    /// Start writing the playback mix to a WAV file.
    ///
    /// Recording lives on the audio engine rather than on the connection: what
    /// is recorded is what the phone hears, which is produced by the playback
    /// tick and not by anything the server sends directly.
    RecordStart {
        path: String,
    },
    /// Stop the recording and patch its header.
    RecordStop,
    /// Create or change a server query login. Only a query client can do this.
    ClientSetServerQueryLogin {
        login_name: String,
        password: Option<String>,
        /// The database id to set it for; `None` means this client.
        client_db_id: Option<i64>,
    },
    /// Place one client in the 3D field, or clear it with `None`.
    ///
    /// This is a local audio setting, not a protocol message: the server has no
    /// concept of where a listener is. Setting it changes the mix only.
    SetUserPosition {
        client_id: i32,
        /// `None` clears the position and mixes the client centred again.
        position: Option<(f32, f32)>,
    },
    /// Clear every position, turning 3D sound off.
    ClearPositions,
    /// Write one line to the server log.
    ///
    /// The level is a string (`error`, `warning`, `debug`, `info`) mapped to the
    /// protocol enum in one place, the same way the group type and the plugin
    /// target are.
    LogAdd {
        level: String,
        message: String,
    },
    /// Read the custom entries stored on one client.
    ///
    /// The reply is nameless on the wire, so it is declared by type and matched
    /// back on `return_code` — see `Connection::send_expecting`.
    CustomInfo {
        client_db_id: i64,
    },
    /// Find clients by one of their custom entries.
    CustomSearch {
        ident: String,
        pattern: String,
    },
    /// Find connected clients whose nickname matches a pattern.
    ClientFind {
        pattern: String,
    },
    /// Ask for one permission's value on the server.
    PermGet {
        permission_id: i64,
    },
    /// Ask for this server's full record: the settings `serverinfo` reports.
    ServerInfo,
    /// Serialise the whole server into a text snapshot.
    ///
    /// There is no matching deploy command: `serversnapshotdeploy` is a
    /// ServerQuery operation and a client connection is refused with
    /// `invalid client type`. Restoring a snapshot needs the query transport,
    /// which this crate does not speak.
    ServerSnapshotCreate,
    /// Create a virtual server on this instance.
    ServerCreate {
        name: String,
    },
    /// Delete a virtual server.
    ServerDelete {
        server_id: i64,
    },
    /// Start a stopped virtual server.
    ServerStart {
        server_id: i64,
    },
    /// Stop a running virtual server without removing it.
    ServerStop {
        server_id: i64,
        reason: Option<String>,
    },
    /// Stop the whole server instance.
    ServerProcessStop {
        reason: Option<String>,
    },
    /// Change server-instance settings.
    ///
    /// Every field is optional because `instanceedit` only sends what the caller
    /// sets; an unset field keeps its current value. The properties are the
    /// `serverinstance_*` ones `instanceinfo` reports.
    InstanceEdit {
        filetransfer_port: Option<i32>,
        max_download_bandwidth: Option<i64>,
        max_upload_bandwidth: Option<i64>,
        guest_serverquery_group: Option<i64>,
        serverquery_flood_commands: Option<i64>,
        serverquery_flood_time: Option<i64>,
        serverquery_ban_time: Option<i64>,
        template_serveradmin_group: Option<i64>,
        template_serverdefault_group: Option<i64>,
        template_channeladmin_group: Option<i64>,
        template_channeldefault_group: Option<i64>,
        pending_connections_per_ip: Option<i64>,
    },
    /// Subscribe to every channel, so the tree shows members everywhere.
    ///
    /// The connection subscribes automatically once the first server event
    /// arrives; these two exist for a shell that wants to change it afterwards,
    /// e.g. to stop the traffic on a metered link.
    ChannelSubscribeAll,
    /// Stop receiving events for channels other than the current one.
    ChannelUnsubscribeAll,
    /// Edit a client's database entry: description, icon, phonetic name.
    ///
    /// Distinct from [`Command::ClientDbDelete`], which removes the record.
    /// `clientdbedit` only sends the properties the caller sets, so an empty
    /// edit is refused locally rather than sent as a no-op.
    ClientDbEdit {
        client_db_id: i64,
        description: Option<String>,
        icon_id: Option<i64>,
        phonetic_name: Option<String>,
    },
    /// Ban one connected client. Their connection id is what the server takes,
    /// so this is the ban you can issue without knowing their uid.
    BanClient {
        client_id: i32,
        /// Ban duration; `None` means permanent.
        seconds: Option<i64>,
        reason: Option<String>,
    },
    /// Ask for one channel's description.
    ///
    /// The description is not part of the channel tree the bookkeeping keeps,
    /// so it is fetched on demand; the answer arrives as `channel_edited`.
    ChannelDescription {
        channel_id: i64,
    },
    /// Ask for the full channel list.
    ///
    /// The flags are the protocol's `-topic`, `-flags`, `-voice`, `-limits`,
    /// `-icon` and `-secondsempty`: each asks the server to include more fields.
    ChannelList {
        topic: bool,
        flags: bool,
        voice: bool,
        limits: bool,
        icon: bool,
        seconds_empty: bool,
    },
    /// Resolve a client database id from a unique id.
    ClientDbIdFromUid {
        uid: String,
    },
    /// Ask which permission a client has in a channel, and at what value.
    PermOverview {
        channel_id: i64,
        client_db_id: i64,
        permission_id: Option<i64>,
        permission_name: Option<String>,
    },
    /// Ask for one connected client's full record.
    ClientInfo {
        client_id: i32,
    },
    /// Ask for one channel's full record, including its description.
    ChannelInfo {
        channel_id: i64,
    },
    /// Find channels whose name matches a pattern.
    ChannelFind {
        pattern: String,
    },
    /// List every client on the server, whether or not this client sees them.
    ///
    /// The flags are the protocol's `-uid`, `-away`, `-voice`, `-times`,
    /// `-groups`, `-info`, `-country` and `-ip`: each asks the server to include
    /// more fields in the reply. They are command options, not `name=value`
    /// arguments, so they are appended as bare tokens.
    ClientList {
        uid: bool,
        away: bool,
        voice: bool,
        times: bool,
        groups: bool,
        info: bool,
        country: bool,
        ip: bool,
    },
    /// List every virtual server on this instance.
    ///
    /// `all` lists every server in the database rather than only those on this
    /// instance; `short` trims the reply; `onlyoffline` filters to stopped ones.
    ServerList {
        uid: bool,
        all: bool,
        short: bool,
        only_offline: bool,
    },
    /// Ask who this connection is: ids, uid and the server it landed on.
    WhoAmI,
    /// Ask the server for its version banner.
    Version,
    /// Ask for the host's machine information.
    HostInfo,
    /// Ask for instance-wide settings: ports, quotas, template groups.
    InstanceInfo,
    /// List the server's listening addresses.
    BindingList {
        subsystem: Option<String>,
    },
    /// Resolve a permission's numeric id from its name.
    PermIdByName {
        permission_name: String,
    },
    /// Rebuild a server's permission set from its templates.
    PermReset,
    /// Resolve a virtual server's id from its port.
    ServerIdByPort {
        port: i32,
    },
    /// Move a channel under a new parent, or reorder it within the current one.
    ///
    /// Distinct from [`Command::ChannelEdit`], which cannot change a parent:
    /// the protocol puts the tree move in its own message.
    ChannelMove {
        channel_id: i64,
        parent_id: i64,
        /// The channel to sort after; `None` means "last".
        order: Option<i64>,
    },
    /// Copy a server group into a new one, or onto an existing one.
    ///
    /// `target_group_id` of 0 creates a new group; a real id overwrites that
    /// group's permissions instead, which is how the desktop client restores a
    /// group from a template.
    ServerGroupCopy {
        source_group_id: i64,
        target_group_id: i64,
        name: String,
        /// `true` copies the query template rather than the regular one.
        query: bool,
    },
    /// Copy a channel group, with the same create-or-overwrite rule as
    /// [`Command::ServerGroupCopy`].
    ChannelGroupCopy {
        source_group_id: i64,
        target_group_id: i64,
        name: String,
        query: bool,
    },
    /// Grant a permission to every group of one type, so future groups inherit
    /// it. `query` selects the template the permission is added to.
    ServerGroupAutoAddPerm {
        query: bool,
        permission_id: Option<i64>,
        permission_name: Option<String>,
        value: i32,
        negated: bool,
        skip: bool,
    },
    /// Remove an inherited permission from one group template.
    ServerGroupAutoDelPerm {
        query: bool,
        permission_id: Option<i64>,
        permission_name: Option<String>,
    },
    /// Grant a global permission to one client, independent of any group.
    ClientAddPerm {
        client_db_id: i64,
        permission_id: Option<i64>,
        permission_name: Option<String>,
        value: i32,
        skip: bool,
    },
    /// Revoke a global permission from one client.
    ClientDelPerm {
        client_db_id: i64,
        permission_id: Option<i64>,
        permission_name: Option<String>,
    },
    /// Store one custom key/value pair on a client's database entry.
    CustomSet {
        client_db_id: i64,
        ident: String,
        value: String,
    },
    /// Delete one custom entry from a client.
    CustomDelete {
        client_db_id: i64,
        ident: String,
    },
    /// Redeem a privilege key through the token API.
    ///
    /// Distinct from [`Command::PrivilegeKeyUse`], which redeems through the
    /// older `privilegekeyuse`. Both exist because a key's origin decides which
    /// one the server accepts.
    TokenUse {
        token: String,
    },
    /// Delete a privilege key created through the older `privilegekeyadd`.
    PrivilegeKeyDelete {
        key: String,
    },
    /// List the clients in a server group.
    ServerGroupClientList {
        group_id: i64,
        /// Ask the server to include each member's nickname and uid.
        names: bool,
    },
    /// List the permissions a server group carries.
    ServerGroupPermList {
        group_id: i64,
        /// Ask for permission names as well as ids.
        permsid: bool,
    },
    /// List channel-group memberships. All three filters are optional: the
    /// server returns every assignment when none is given, or narrows by
    /// channel, by client, or by group.
    ChannelGroupClientList {
        channel_id: Option<i64>,
        client_db_id: Option<i64>,
        group_id: Option<i64>,
    },
    /// List the permissions a channel group carries.
    ChannelGroupPermList {
        group_id: i64,
        /// Ask for permission names as well as ids.
        permsid: bool,
    },
    /// List the permissions one client holds in one channel.
    ChannelClientPermList {
        channel_id: i64,
        client_db_id: i64,
        /// Ask for permission names as well as ids.
        permsid: bool,
    },
    /// List the server groups one client belongs to.
    ServerGroupsByClient {
        client_db_id: i64,
    },
    /// Resolve client ids from unique ids.
    ClientIds {
        uid: String,
    },
    /// Resolve a client's nickname from its database id.
    ClientNameFromDbId {
        client_db_id: i64,
    },
    /// Resolve a client's nickname from its unique id.
    ClientNameFromUid {
        uid: String,
    },
    /// Resolve a client's unique id from its connection id.
    ClientUidFromClid {
        client_id: i32,
    },
    /// Ask for one client's connection statistics: ping, packet loss, traffic.
    ClientConnectionInfo {
        client_id: i32,
    },
    /// Ask for the server's own connection statistics.
    ServerConnectionInfo,
    /// Ask for one file's metadata without listing its directory.
    FileInfo {
        channel_id: i64,
        path: String,
        password: Option<String>,
    },
    /// Ask which groups and clients carry one permission.
    PermFind {
        permission_id: Option<i64>,
        permission_name: Option<String>,
    },
    /// Ask for the whole permission catalogue: id, name and description.
    PermList,
    /// Read the server log.
    LogView {
        lines: Option<i64>,
        reverse: Option<bool>,
        instance_log: Option<bool>,
        offset: Option<i64>,
    },
    /// Create a privilege key through the newer token API.
    ///
    /// Distinct from [`Command::PrivilegeKeyCreate`], which uses the older
    /// `privilegekeyadd`: the token API can also carry a custom set, and its
    /// keys show up in [`Command::TokenList`].
    TokenAdd {
        group_id: i64,
        channel_id: i64,
        description: Option<String>,
    },
    /// List the privilege keys created through the token API.
    TokenList,
    /// Delete one privilege key, whichever API created it.
    TokenDelete {
        token: String,
    },
    /// List complaints, optionally only those against one client.
    ComplainList {
        client_db_id: Option<i64>,
    },
    /// Close a client's chat tab, locally on their side.
    ClientChatClose {
        client_id: i32,
    },
    /// Ask for the transfers currently running on the server.
    FiletransferList,
    /// Abort one transfer, and optionally delete its partial file.
    StopFiletransfer {
        server_id: i64,
        delete: bool,
    },
    /// Download one server icon (`/icon_<id>`) into the cache.
    ///
    /// Icons are ordinary files in the root channel; the desktop client fetches
    /// them the same way. Ids already cached or already failed are ignored, so a
    /// shell can ask for every group and channel it renders without tracking
    /// which ones are done.
    FetchIcon {
        icon_id: i64,
    },
}

pub struct Handle {
    inner: Arc<Inner>,
    /// Dropping this shuts the runtime down; the connection thread is detached
    /// from it and exits when the command channel closes.
    ///
    /// `Option` only so [`Drop`] can take it: a `Runtime` cannot be dropped
    /// inside an async context, and which thread holds the last reference is not
    /// something this type controls.
    runtime: Option<Runtime>,
}

impl Drop for Handle {
    /// Shuts the runtime down off whichever thread happens to hold the last
    /// reference.
    ///
    /// Same hazard as [`crate::account::AccountEngine`]'s `Drop`, and it was
    /// solved there first: a multi-thread runtime panics when dropped from
    /// inside an async context ("Cannot drop a runtime in a context where
    /// blocking is not allowed"). The C and JNI shells drop sessions on a plain
    /// thread and never saw it, but a Rust shell that keeps a `Session` in a
    /// framework's state (Tauri, Dioxus) drops it from inside a command handler
    /// — that is, on a runtime worker. Moving the shutdown to its own thread
    /// makes it orderly regardless of who got there first.
    fn drop(&mut self) {
        // Nothing is joined: the caller must not wait for shutdown, and a
        // runtime that outlives this handle for a few milliseconds only delays
        // the exit.
        if let Some(runtime) = self.runtime.take() {
            std::thread::spawn(move || drop(runtime));
        }
    }
}

/// How many events may wait for a shell before the oldest droppable one goes.
///
/// A shell that stops draining — minimised window, blocked UI thread, a screen
/// that has no handler for the event — used to grow this queue without bound,
/// while the audio queues right below it had a cap for exactly that reason.
///
/// The cap is not "drop the oldest": events are not interchangeable. Losing
/// `user_joined` leaves the member list wrong until the next full snapshot,
/// while losing `text_message` loses something that exists nowhere else. So the
/// queue keeps the newest `MAX_QUEUED_EVENTS` and, when it has to make room,
/// prefers to discard the oldest event whose content the snapshot can
/// reconstruct (see [`is_recoverable_from_snapshot`]).
const MAX_QUEUED_EVENTS: usize = 512;

/// Whether an event only reports a difference the snapshot already holds.
///
/// The member and channel lists live in [`Snapshot`], so an event describing a
/// change to them can be reconstructed by re-reading it. Messages, pokes, file
/// transfers, errors and account results cannot: they carry content that was
/// never in the snapshot, and dropping one is a permanent loss.
fn is_recoverable_from_snapshot(kind: &str) -> bool {
    matches!(
        kind,
        "connected"
            | "disconnected"
            | "reconnecting"
            | "user_joined"
            | "user_left"
            | "user_moved"
            | "user_renamed"
            | "user_mute_changed"
            | "user_away_changed"
            | "channel_created"
            | "channel_renamed"
            | "channel_removed"
    )
}

pub struct Inner {
    connected: AtomicBool,
    events: Mutex<VecDeque<QueuedEvent>>,
    state: Mutex<Snapshot>,
    /// The identity in use, as the TS3 `counterVkey` string, once the connection
    /// thread has built or parsed one. Every shell reads this to persist it, and
    /// without it the server sees a new UID on every launch.
    identity: Mutex<Option<String>>,
    /// Snapshot JSON cached by revision, so a 20 ms poll that changes nothing
    /// does not re-serialize the member list.
    cached_json: Mutex<(u64, String)>,
    commands: mpsc::UnboundedSender<Command>,
    /// Captured PCM16 waiting for the encoder (written by the host thread).
    capture: Mutex<VecDeque<i16>>,
    /// Decoded PCM16 waiting for playback (written by the connection thread).
    playback: Mutex<VecDeque<i16>>,
    /// Client ids currently transmitting, for the speaking indicator.
    talking: Mutex<Vec<i32>>,
    /// The myTeamSpeak account side, once a shell has built it. Present on every
    /// session: the account is independent of the connection, so it can be
    /// logged into before the first server is joined and it survives a
    /// disconnect.
    account: Mutex<Option<Arc<crate::account::AccountEngine>>>,
    /// Group, channel and server icons fetched from this server.
    ///
    /// Kept off the snapshot on purpose: the snapshot is serialized on every
    /// frame, and a map of absolute paths does not belong in something a UI
    /// reads 60 times a second. The snapshot carries the same data as
    /// [`crate::state::Snapshot::icons`], refreshed when this changes.
    icons: Mutex<crate::icons::IconCache>,
}

/// 20 ms at 48 kHz mono — one Opus frame, and one AudioTrack buffer.
pub const FRAME_SAMPLES: usize = 960;

/// Half a second of audio. Beyond that the UI is not draining, and buffering
/// more would only add latency when it starts again.
const MAX_QUEUED_SAMPLES: usize = FRAME_SAMPLES * 25;

impl Inner {
    /// A fresh, disconnected inner state with a command channel whose receiver
    /// the caller owns.
    ///
    /// Both session constructors build exactly this, and a test needs it too;
    /// the field list is long enough that a second copy is how the two drift.
    fn new(commands: mpsc::UnboundedSender<Command>) -> Inner {
        Inner {
            connected: AtomicBool::new(false),
            events: Mutex::new(VecDeque::new()),
            state: Mutex::new(Snapshot::default()),
            cached_json: Mutex::new((u64::MAX, String::new())),
            commands,
            capture: Mutex::new(VecDeque::new()),
            playback: Mutex::new(VecDeque::new()),
            talking: Mutex::new(Vec::new()),
            identity: Mutex::new(None),
            account: Mutex::new(None),
            icons: Mutex::new(crate::icons::IconCache::default()),
        }
    }

    /// Runs `f` against the icon cache under the lock.
    pub fn with_session_icons<R>(&self, f: impl FnOnce(&mut crate::icons::IconCache) -> R) -> R {
        match self.icons.lock() {
            Ok(mut cache) => f(&mut cache),
            Err(poisoned) => f(&mut poisoned.into_inner()),
        }
    }

    /// Points the icon cache at `dir` and preloads what a previous run wrote.
    pub fn set_icon_dir(&self, dir: std::path::PathBuf) {
        let loaded = crate::icons::IconCache::load(&dir);
        self.with_session_icons(|cache| *cache = loaded);
        let entries: Vec<crate::icons::CachedIcon> =
            self.with_session_icons(|cache| cache.entries().values().cloned().collect());
        self.with_state(|snapshot| snapshot.set_icons(entries));
    }

    pub fn set_connected(&self, value: bool) {
        self.connected.store(value, Ordering::Release);
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Acquire)
    }

    pub fn push_event(&self, event: QueuedEvent) {
        let mut queue = match self.events.lock() {
            Ok(queue) => queue,
            Err(poisoned) => poisoned.into_inner(),
        };
        if queue.len() < MAX_QUEUED_EVENTS {
            queue.push_back(event);
            return;
        }

        // Full. Make room by discarding the oldest event the snapshot can
        // reconstruct; if the queue is entirely irreplaceable content, drop the
        // oldest anyway rather than grow without bound — a shell that has
        // stopped draining for this long is not going to read any of it.
        if let Some(index) = queue
            .iter()
            .position(|queued| is_recoverable_from_snapshot(&queued.kind))
        {
            queue.remove(index);
            if index == 0 {
                log::debug!("event queue full: dropped a state event the snapshot still holds");
            }
        } else {
            log::warn!(
                "event queue full of {} unrecoverable events: dropping the oldest",
                queue.len()
            );
            queue.pop_front();
        }
        queue.push_back(event);
    }

    /// Runs `f` against the snapshot under the lock. All snapshot access goes
    /// through here, so the lock discipline lives in one place.
    pub fn with_state<R>(&self, f: impl FnOnce(&mut Snapshot) -> R) -> R {
        match self.state.lock() {
            Ok(mut snapshot) => f(&mut snapshot),
            Err(poisoned) => f(&mut poisoned.into_inner()),
        }
    }

    pub fn talking(&self) -> Vec<i32> {
        match self.talking.lock() {
            Ok(ids) => ids.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Installs the account engine. Called once, while the handle is being built.
    pub fn set_account_engine(&self, engine: Arc<crate::account::AccountEngine>) {
        *self.account.lock().unwrap_or_else(|e| e.into_inner()) = Some(engine);
    }

    /// The account engine, if one was built.
    pub fn account_engine(&self) -> Option<Arc<crate::account::AccountEngine>> {
        self.account
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The six myTeamSpeak parameters for this connection, if the account can
    /// sign. Called from the connection thread, which owns the IV.
    pub fn myts_params(&self, shared_iv: &[u8]) -> Option<crate::account::mytsid::MytsParams> {
        self.account_engine()?.myts_params(shared_iv)
    }

    /// The account report as last published, for a quick read.
    pub fn account_snapshot(&self) -> Option<crate::account::AccountReport> {
        self.account_engine()?;
        Some(self.with_state(|snapshot| snapshot.account.clone()))
    }

    /// Records the identity the connection thread ended up using, so a shell can
    /// persist it. Called once per session, right after the identity is built.
    pub fn set_identity(&self, value: String) {
        let mut slot = self.identity.lock().unwrap_or_else(|e| e.into_inner());
        *slot = Some(value);
    }

    /// The identity in `counterVkey` form, or `None` before the session started.
    pub fn identity(&self) -> Option<String> {
        self.identity
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Returns true when the speaking set changed, so the caller can bump the
    /// revision and let the UI repaint exactly once.
    pub fn set_talking(&self, ids: Vec<i32>) -> bool {
        let changed = {
            let mut current = match self.talking.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            if *current == ids {
                false
            } else {
                *current = ids;
                true
            }
        };
        if changed {
            let ids = self.talking();
            self.with_state(|snapshot| {
                snapshot.set_talking(&ids);
            });
        }
        changed
    }

    // ── audio ───────────────────────────────────────────────────────────────

    pub fn push_capture(&self, samples: &[i16]) {
        let mut queue = self.capture.lock().unwrap_or_else(|e| e.into_inner());
        // A single call can be larger than the whole budget — a shell that hands
        // over a second of audio at once would otherwise push past the limit and
        // stay there. Only the newest `MAX_QUEUED_SAMPLES` survive, because
        // sending late audio is worse than a gap.
        let samples = if samples.len() > MAX_QUEUED_SAMPLES {
            &samples[samples.len() - MAX_QUEUED_SAMPLES..]
        } else {
            samples
        };
        if queue.len() + samples.len() > MAX_QUEUED_SAMPLES {
            let drop = (queue.len() + samples.len()).saturating_sub(MAX_QUEUED_SAMPLES);
            let drop = drop.min(queue.len());
            queue.drain(..drop);
        }
        queue.extend(samples.iter().copied());
    }

    /// Takes at most one frame; `None` when there is not enough captured audio.
    pub fn take_capture_frame(&self) -> Option<Vec<i16>> {
        let mut queue = self.capture.lock().unwrap_or_else(|e| e.into_inner());
        if queue.len() < FRAME_SAMPLES {
            return None;
        }
        Some(queue.drain(..FRAME_SAMPLES).collect())
    }

    /// Drops captured audio that piled up while the mic was muted.
    pub fn clear_capture(&self) {
        self.capture
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    pub fn push_playback(&self, samples: &[i16]) {
        let mut queue = self.playback.lock().unwrap_or_else(|e| e.into_inner());
        if queue.len() + samples.len() > MAX_QUEUED_SAMPLES {
            let drop = (queue.len() + samples.len()).saturating_sub(MAX_QUEUED_SAMPLES);
            let drop = drop.min(queue.len());
            queue.drain(..drop);
        }
        queue.extend(samples.iter().copied());
    }

    /// Fills `out` and returns how many samples were written. Never blocks.
    pub fn read_playback(&self, out: &mut [i16]) -> usize {
        let mut queue = self.playback.lock().unwrap_or_else(|e| e.into_inner());
        let count = out.len().min(queue.len());
        for slot in out.iter_mut().take(count) {
            *slot = queue.pop_front().unwrap_or(0);
        }
        count
    }

    pub fn clear_audio(&self) {
        self.clear_capture();
        self.playback
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    fn revision(&self) -> u64 {
        self.with_state(|snapshot| snapshot.rev)
    }

    pub fn snapshot_json(&self) -> String {
        let revision = self.revision();
        if let Ok(cache) = self.cached_json.lock() {
            if cache.0 == revision {
                return cache.1.clone();
            }
        }
        let json = self.with_state(|snapshot| {
            serde_json::to_string(snapshot).unwrap_or_else(|e| {
                log::error!("Failed to serialize the snapshot: {e}");
                "{}".to_string()
            })
        });
        if let Ok(mut cache) = self.cached_json.lock() {
            *cache = (revision, json.clone());
        }
        json
    }
}

/// Everything needed to open one connection, in one value.
///
/// Bundled rather than passed as six positional `String`s: that is exactly the
/// shape in which a caller silently swaps the server password for the channel
/// password, and the resulting bug reads as "the password is wrong".
#[derive(Clone, Default)]
pub struct ConnectParams {
    pub address: String,
    /// `counterVkey` form, or empty to generate a fresh identity.
    pub identity: String,
    pub nickname: String,
    pub server_password: Option<String>,
    pub channel: Option<String>,
    pub channel_password: Option<String>,
    /// The myTeamSpeak proof to send on `clientinit`, when the caller signed in
    /// first. `None` means the connection carries no identity, which is exactly
    /// what a client that is not signed in does.
    pub myts: Option<crate::MytsProvider>,
    /// Which signed version tuple to announce. The default (`3.6.3` + `Windows`)
    /// is resolved against the signed table at connect time.
    pub version_profile: crate::VersionChoice,
    /// Privilege key redeemed on `clientinit`, or empty.
    pub privilege_key: String,
    /// Whether the microphone starts muted.
    ///
    /// This has to be decided at `clientinit`, not with a later
    /// `clientupdate`: the initial declaration is what the server records, and
    /// a follow-up update of only this flag is not reliably reflected back in
    /// the client's own state. A shell that wants "join silently" must say so
    /// here.
    pub start_muted: bool,
}

impl std::fmt::Debug for ConnectParams {
    /// Hand-written: the myTeamSpeak provider is a closure, which has no `Debug`.
    /// Nothing sensitive is printed either way — the proof is computed later, per
    /// connection.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectParams")
            .field("address", &self.address)
            .field("nickname", &self.nickname)
            .field("myts", &self.myts.as_ref().map(|_| "<provider>"))
            .field("version_profile", &self.version_profile)
            .field("has_privilege_key", &!self.privilege_key.is_empty())
            .finish_non_exhaustive()
    }
}

impl Handle {
    /// A handle with the account side only — no connection, no socket.
    ///
    /// Every shell needs this: a login screen wants to show bookmarks before the
    /// user has joined anything, and a "sync my settings" button should not
    /// require a server address at all. [`Handle::create`] always spawns a
    /// connection task, which would sit there failing on a dummy address.
    ///
    /// Commands that only make sense over a connection (`send_text`, `upload`,
    /// …) are reported as `command_error` rather than silently dropped: a caller
    /// that wired a button to one gets an answer it can show.
    pub fn account_only(config: crate::account::AccountConfig) -> Result<Handle, String> {
        Handle::account_only_with_http(config, crate::account::http::Http::new())
    }

    /// [`Handle::account_only`] against a given HTTP client.
    ///
    /// The whole point is to reach the command surface — `exec` → dispatch →
    /// handler — from a test that stands up a recorded server, instead of calling
    /// the `account::*` free functions and skipping the handler that decides what
    /// to report. Production passes `Http::new()`; nothing else changes.
    pub fn account_only_with_http(
        config: crate::account::AccountConfig,
        http: crate::account::http::Http,
    ) -> Result<Handle, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("tslib-account-only")
            .build()
            .map_err(|e| format!("failed to start the tokio runtime: {e}"))?;

        let (commands, mut command_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner::new(commands));

        match crate::account::AccountEngine::with_http(&inner, config, http) {
            Ok(engine) => inner.set_account_engine(Arc::new(engine)),
            Err(e) => return Err(format!("the account side could not be started: {e}")),
        }

        let task_inner = inner.clone();
        runtime.spawn(async move {
            // Drains the queue so the sender never sees a closed channel (which
            // would log a warning on every call) and so a connection-only
            // command produces an event instead of vanishing.
            while let Some(command) = command_rx.recv().await {
                task_inner.push_event(
                    QueuedEvent::new("command_error")
                        .str(
                            "message",
                            format!(
                                "`{}` needs a server connection; this session has none",
                                command_name(&command)
                            ),
                        )
                        .str("missing_permission", ""),
                );
            }
        });

        Ok(Handle {
            inner,
            runtime: Some(runtime),
        })
    }

    /// Starts the connection thread and returns immediately.
    ///
    /// The parameters arrive as one [`ConnectParams`] value rather than six
    /// positionally-identical `String`s, so a caller cannot pass the channel
    /// password where the server password belongs.
    pub fn create(params: ConnectParams) -> Result<Handle, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("tslib")
            .build()
            .map_err(|e| format!("failed to start the tokio runtime: {e}"))?;

        let (commands, command_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner::new(commands));

        // No account side is created here.
        //
        // It used to be: every connection session started a second runtime with
        // two threads, even though most sessions never sign in. A desktop shell
        // that opens one session per server paid that per tab, and — worse —
        // each session carried its own account state, so switching servers meant
        // logging in again.
        //
        // The account belongs to the application, not to a connection. A shell
        // builds one with `Session::account_only`, signs in once, and either
        // keeps it separate (reading its snapshot and events) or hands it over
        // with `Handle::attach_account`, which is what makes a connection carry
        // the myTS proof and answer account commands. A shell that only wants to
        // talk needs neither.

        // The event queue, the snapshot and the identity all outlive every
        // connection attempt, so a shell keeps reading them across a reconnect.
        // Nothing here is language-specific.
        //
        // The task is wrapped in `catch_unwind`: tsclientlib and the codec sit
        // behind a lot of `unwrap`, and one of them panicking used to abort the
        // process. Now it ends this session and reports what happened, which is
        // the difference between "the app crashes" and "this server fails".
        let task_inner = inner.clone();
        runtime.spawn(async move {
            use futures::FutureExt;

            let outcome = std::panic::AssertUnwindSafe(crate::conn::run(
                task_inner.clone(),
                command_rx,
                params,
            ))
            .catch_unwind()
            .await;

            if let Err(payload) = outcome {
                let reason = panic_message(&*payload);
                log::error!("Connection thread panicked: {reason}");
                task_inner.set_connected(false);
                task_inner.push_event(
                    QueuedEvent::new("error")
                        .str("message", format!("connection thread crashed: {reason}"))
                        .str("kind", "panic")
                        .bool("terminal", true),
                );
            }
        });

        Ok(Handle {
            inner,
            runtime: Some(runtime),
        })
    }

    pub fn inner(&self) -> &Arc<Inner> {
        &self.inner
    }

    pub fn is_connected(&self) -> bool {
        self.inner.is_connected()
    }

    /// Takes every queued event. Never blocks: the queue is locked for the drain
    /// only, not while the caller turns it into its own type.
    pub fn drain_events(&self) -> Vec<QueuedEvent> {
        let mut queue = match self.inner.events.lock() {
            Ok(q) => q,
            Err(poisoned) => poisoned.into_inner(),
        };
        queue.drain(..).collect()
    }

    pub fn snapshot_json(&self) -> String {
        self.inner.snapshot_json()
    }

    /// The snapshot as a typed value, cloned out from under its lock.
    pub fn snapshot(&self) -> Snapshot {
        self.inner.with_state(|snapshot| snapshot.clone())
    }

    pub fn send(&self, command: Command) {
        if self.inner.commands.send(command).is_err() {
            log::warn!("Connection thread is gone; command dropped");
        }
    }
}

/// A stable name for a command, for the error an account-only session reports.
fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Disconnect => "disconnect",
        Command::SendText { .. } => "send_text",
        Command::Poke { .. } => "poke",
        Command::JoinChannel { .. } => "join_channel",
        Command::SetInputMuted(_) => "set_input_muted",
        Command::SetOutputMuted(_) => "set_output_muted",
        Command::SetAway { .. } => "set_away",
        Command::SetNickname(_) => "set_nickname",
        Command::ListFiles { .. } => "list_files",
        Command::Download { .. } => "download",
        Command::Upload { .. } => "upload",
        Command::KickClient { .. } => "kick_client",
        Command::MoveClient { .. } => "move_client",
        Command::BanAdd { .. } => "ban_add",
        Command::BanDelete { .. } => "ban_delete",
        Command::BanList => "ban_list",
        Command::ChannelCreate { .. } => "channel_create",
        Command::ChannelEdit { .. } => "channel_edit",
        Command::ChannelDelete { .. } => "channel_delete",
        Command::ChannelSubscribe { .. } => "channel_subscribe",
        Command::ComplainAdd { .. } => "complain_add",
        Command::ComplainDelete { .. } => "complain_delete",
        Command::PrivilegeKeyCreate { .. } => "privilege_key_create",
        Command::PrivilegeKeyUse { .. } => "privilege_key_use",
        Command::PrivilegeKeyList => "privilege_key_list",
        Command::SetClientChannelGroup { .. } => "set_client_channel_group",
        Command::OfflineMessageList => "offline_message_list",
        Command::OfflineMessageGet { .. } => "offline_message_get",
        Command::OfflineMessageDelete { .. } => "offline_message_delete",
        Command::OfflineMessageSend { .. } => "offline_message_send",
        Command::ServerVariables => "server_variables",
        Command::ClientVariables { .. } => "client_variables",
        Command::TempPasswordAdd { .. } => "temp_password_add",
        Command::TempPasswordDelete { .. } => "temp_password_delete",
        Command::TempPasswordList => "temp_password_list",
        Command::ClientPermissionList { .. } => "client_permission_list",
        Command::ChannelPermissionList { .. } => "channel_permission_list",
        Command::ClientEdit { .. } => "client_edit",
        Command::ClientUpdate { .. } => "client_update",
        Command::TalkPowerRequest { .. } => "talk_power_request",
        Command::ServerEdit { .. } => "server_edit",
        Command::DeleteFile { .. } => "delete_file",
        Command::RenameFile { .. } => "rename_file",
        Command::CreateDirectory { .. } => "create_directory",
        Command::ServerGroupCreate { .. } => "server_group_create",
        Command::ServerGroupDelete { .. } => "server_group_delete",
        Command::ServerGroupRename { .. } => "server_group_rename",
        Command::ServerGroupAddClient { .. } => "server_group_add_client",
        Command::ServerGroupDelClient { .. } => "server_group_del_client",
        Command::ChannelGroupCreate { .. } => "channel_group_create",
        Command::ChannelGroupDelete { .. } => "channel_group_delete",
        Command::ChannelGroupRename { .. } => "channel_group_rename",
        Command::ChannelClientAddPerm { .. } => "channel_client_add_perm",
        Command::ChannelClientDelPerm { .. } => "channel_client_del_perm",
        Command::ClientDbList { .. } => "client_db_list",
        Command::ClientDbFind { .. } => "client_db_find",
        Command::ClientDbInfo { .. } => "client_db_info",
        Command::OfflineMessageFlag { .. } => "offline_message_flag",
        Command::ServerGroupAddPerm { .. } => "server_group_add_perm",
        Command::ServerGroupDelPerm { .. } => "server_group_del_perm",
        Command::ChannelGroupAddPerm { .. } => "channel_group_add_perm",
        Command::ChannelGroupDelPerm { .. } => "channel_group_del_perm",
        Command::ChannelAddPerm { .. } => "channel_add_perm",
        Command::ChannelDelPerm { .. } => "channel_del_perm",
        Command::ClientDbDelete { .. } => "client_db_delete",
        Command::GlobalMessage { .. } => "global_message",
        Command::PluginInvoke { .. } => "plugin_command",
        Command::RecordStart { .. } => "record_start",
        Command::RecordStop => "record_stop",
        Command::ClientSetServerQueryLogin { .. } => "client_set_server_query_login",
        Command::SetUserPosition { .. } => "set_user_position",
        Command::ClearPositions => "clear_positions",
        Command::LogAdd { .. } => "log_add",
        Command::CustomInfo { .. } => "custom_info",
        Command::CustomSearch { .. } => "custom_search",
        Command::ClientFind { .. } => "client_find",
        Command::PermGet { .. } => "perm_get",
        Command::ServerInfo => "server_info",
        Command::ServerSnapshotCreate => "server_snapshot_create",
        Command::ServerCreate { .. } => "server_create",
        Command::ServerDelete { .. } => "server_delete",
        Command::ServerStart { .. } => "server_start",
        Command::ServerStop { .. } => "server_stop",
        Command::ServerProcessStop { .. } => "server_process_stop",
        Command::InstanceEdit { .. } => "instance_edit",
        Command::ChannelSubscribeAll => "channel_subscribe_all",
        Command::ChannelUnsubscribeAll => "channel_unsubscribe_all",
        Command::ClientDbEdit { .. } => "client_db_edit",
        Command::BanClient { .. } => "ban_client",
        Command::ChannelDescription { .. } => "channel_description",
        Command::ChannelList { .. } => "channel_list",
        Command::ClientDbIdFromUid { .. } => "client_db_id_from_uid",
        Command::PermOverview { .. } => "perm_overview",
        Command::ClientInfo { .. } => "client_info",
        Command::ChannelInfo { .. } => "channel_info",
        Command::ChannelFind { .. } => "channel_find",
        Command::ClientList { .. } => "client_list",
        Command::ServerList { .. } => "server_list",
        Command::WhoAmI => "who_am_i",
        Command::Version => "version",
        Command::HostInfo => "host_info",
        Command::InstanceInfo => "instance_info",
        Command::BindingList { .. } => "binding_list",
        Command::PermIdByName { .. } => "perm_id_by_name",
        Command::PermReset => "perm_reset",
        Command::ServerIdByPort { .. } => "server_id_by_port",
        Command::ChannelMove { .. } => "channel_move",
        Command::ServerGroupCopy { .. } => "server_group_copy",
        Command::ChannelGroupCopy { .. } => "channel_group_copy",
        Command::ServerGroupAutoAddPerm { .. } => "server_group_auto_add_perm",
        Command::ServerGroupAutoDelPerm { .. } => "server_group_auto_del_perm",
        Command::ClientAddPerm { .. } => "client_add_perm",
        Command::ClientDelPerm { .. } => "client_del_perm",
        Command::CustomSet { .. } => "custom_set",
        Command::CustomDelete { .. } => "custom_delete",
        Command::TokenUse { .. } => "token_use",
        Command::PrivilegeKeyDelete { .. } => "privilege_key_delete",
        Command::ServerGroupClientList { .. } => "server_group_client_list",
        Command::ServerGroupPermList { .. } => "server_group_perm_list",
        Command::ChannelGroupClientList { .. } => "channel_group_client_list",
        Command::ChannelGroupPermList { .. } => "channel_group_perm_list",
        Command::ChannelClientPermList { .. } => "channel_client_perm_list",
        Command::ServerGroupsByClient { .. } => "server_groups_by_client",
        Command::ClientIds { .. } => "client_ids",
        Command::ClientNameFromDbId { .. } => "client_name_from_db_id",
        Command::ClientNameFromUid { .. } => "client_name_from_uid",
        Command::ClientUidFromClid { .. } => "client_uid_from_clid",
        Command::ClientConnectionInfo { .. } => "client_connection_info",
        Command::ServerConnectionInfo => "server_connection_info",
        Command::FileInfo { .. } => "file_info",
        Command::PermFind { .. } => "perm_find",
        Command::PermList => "perm_list",
        Command::LogView { .. } => "log_view",
        Command::TokenAdd { .. } => "token_add",
        Command::TokenList => "token_list",
        Command::TokenDelete { .. } => "token_delete",
        Command::ComplainList { .. } => "complain_list",
        Command::ClientChatClose { .. } => "client_chat_close",
        Command::FiletransferList => "filetransfer_list",
        Command::StopFiletransfer { .. } => "stop_filetransfer",
        Command::FetchIcon { .. } => "fetch_icon",
        Command::SetAudioEnabled(_) => "audio_enabled",
        Command::SetMicGain(_) => "set_mic_gain",
        Command::SetUserVolume { .. } => "set_user_volume",
        Command::SetWhisperTargets { .. } => "set_whisper_targets",
    }
}

/// Turns a panic payload into something worth showing a user.
///
/// `panic!` carries either a `&str` or a formatted `String` depending on the
/// macro form used, and anything else (a custom `Box<dyn Any>`) is not readable
/// at all — in which case the honest answer is that we do not know.
pub fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "unknown cause (panic payload was not a string)".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The capture queue never grows past its budget.
    ///
    /// A shell that hands over more audio than the whole queue holds — a
    /// second of it, say — must not push the queue past the limit and leave it
    /// there: every later frame would then be dropped instead of sent.
    #[test]
    fn the_capture_queue_stays_within_its_budget() {
        let (inner, _rx) = inner();

        // More than the whole budget in one call.
        let oversized = vec![7i16; MAX_QUEUED_SAMPLES * 3];
        inner.push_capture(&oversized);

        let mut taken = 0usize;
        while inner.take_capture_frame().is_some() {
            taken += FRAME_SAMPLES;
        }
        assert_eq!(
            taken, MAX_QUEUED_SAMPLES,
            "the queue held more than its budget"
        );
    }

    /// Repeated pushes at the frame size also stay bounded.
    #[test]
    fn many_frames_are_bounded() {
        let (inner, _rx) = inner();
        let frame = vec![1i16; FRAME_SAMPLES];
        for _ in 0..100 {
            inner.push_capture(&frame);
        }
        let mut taken = 0usize;
        while inner.take_capture_frame().is_some() {
            taken += FRAME_SAMPLES;
        }
        assert_eq!(taken, MAX_QUEUED_SAMPLES);
    }

    /// The newest audio is what survives: a dropped oldest frame is a gap, a
    /// dropped newest one is latency.
    #[test]
    fn the_newest_audio_survives() {
        let (inner, _rx) = inner();
        // Fill with an old value, then push a distinguishable new block.
        inner.push_capture(&vec![1i16; MAX_QUEUED_SAMPLES]);
        inner.push_capture(&vec![9i16; FRAME_SAMPLES]);

        // The first frame out is old audio (the queue drains from the front),
        // and the last is the new block.
        let mut last = Vec::new();
        while let Some(frame) = inner.take_capture_frame() {
            last = frame;
        }
        assert!(last.iter().all(|s| *s == 9), "the newest frame was dropped");
    }

    fn inner() -> (Arc<Inner>, mpsc::UnboundedReceiver<Command>) {
        let (commands, rx) = mpsc::unbounded_channel();
        (Arc::new(Inner::new(commands)), rx)
    }

    fn kinds(inner: &Inner) -> Vec<String> {
        let queue = inner.events.lock().unwrap_or_else(|e| e.into_inner());
        queue.iter().map(|event| event.kind.clone()).collect()
    }

    #[test]
    fn a_small_burst_is_kept_in_order() {
        let (inner, _rx) = inner();
        for index in 0..10 {
            inner.push_event(QueuedEvent::new("text_message").int("n", index));
        }
        assert_eq!(kinds(&inner).len(), 10);
    }

    #[test]
    fn a_flood_drops_state_events_before_messages() {
        let (inner, _rx) = inner();
        // One message that must survive, then enough state events to overflow.
        inner.push_event(QueuedEvent::new("text_message").str("message", "keep me"));
        for _ in 0..MAX_QUEUED_EVENTS {
            inner.push_event(QueuedEvent::new("user_moved"));
        }

        let queue = kinds(&inner);
        assert!(
            queue.len() <= MAX_QUEUED_EVENTS,
            "queue must stay bounded, got {}",
            queue.len()
        );
        assert!(
            queue.contains(&"text_message".to_string()),
            "the message is unrecoverable and must survive a flood of state events"
        );
    }

    #[test]
    fn a_flood_of_unrecoverable_events_still_stays_bounded() {
        let (inner, _rx) = inner();
        // Nothing here can be reconstructed from the snapshot, so the oldest has
        // to go — growing without bound is the worse outcome.
        for index in 0..(MAX_QUEUED_EVENTS + 50) {
            inner.push_event(QueuedEvent::new("text_message").int("n", index as i32));
        }
        let queue = kinds(&inner);
        assert_eq!(queue.len(), MAX_QUEUED_EVENTS);
    }

    #[test]
    fn draining_empties_the_queue() {
        let (inner, _rx) = inner();
        inner.push_event(QueuedEvent::new("text_message"));
        let handle = Handle {
            inner: inner.clone(),
            runtime: None,
        };
        assert_eq!(handle.drain_events().len(), 1);
        assert!(handle.drain_events().is_empty());
    }

    #[test]
    fn only_state_events_count_as_recoverable() {
        for kind in [
            "connected",
            "disconnected",
            "user_joined",
            "user_left",
            "user_moved",
            "user_renamed",
            "user_mute_changed",
            "user_away_changed",
            "channel_created",
            "channel_renamed",
            "channel_removed",
        ] {
            assert!(
                is_recoverable_from_snapshot(kind),
                "{kind} should be recoverable"
            );
        }
        for kind in [
            "text_message",
            "poked",
            "error",
            "command_error",
            "transfer_started",
            "transfer_progress",
            "transfer_done",
            "transfer_error",
            "file_list",
            "account_status",
        ] {
            assert!(
                !is_recoverable_from_snapshot(kind),
                "{kind} carries content the snapshot does not have"
            );
        }
    }
}
