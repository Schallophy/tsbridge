//! Sync items: what the server stores per account, and what may be done to each.
//!
//! The important lesson from the research is that **`synchronizeItems` is an
//! upsert, not a diff query.** The two methods share messages and both return a
//! `SyncStatus`, which makes them look interchangeable; treating the second one
//! as a read empties every item blob on a real account. So this module only ever
//! *reads* through `requestServerItems`, and every write goes through
//! [`Sync::upsert_payload`] or [`Sync::delete_payload`], whose shapes are pinned
//! by byte-level tests.
//!
//! The second lesson is that items come in exactly two shapes, and the account
//! key settles both:
//!
//! | tier | blob shape | what is possible |
//! |---|---|---|
//! | `Plaintext` | the bare `Item_Data` | rewrite anything, any length, no key |
//! | `Encrypted` | `header16 \|\| ct \|\| sha512(plaintext)` | rewrite anything, any length, with the account key |
//! | `Locked` | encrypted, and this session has no usable key | nothing until a working login |
//!
//! The key is the **account key** from the login response, not anything on disk.
//! `ItemCipher` is that cipher: AES-256-CTR with a 32-bit little-endian counter in
//! word 0 of the header, and `sha512(plaintext)` trailing as the only integrity
//! check the format has.
//!
//! The research originally concluded the key was unrecoverable and built a
//! keystream-recovery model on the client's own `settings.db` instead. That model
//! worked, but only by accident: the sweep that "proved" the key was not the
//! account key used a 128-bit big-endian counter, which agrees with the real
//! cipher for block 0 and then diverges. See
//! `research/myts-login/explore/itemcipher_check.mjs` for the live proof (16/16).

use super::crypto;
use super::crypto::KEY_LEN;
use super::proto::{self, Message};

/// The sync item classes. Only five carry live data on the reference account;
/// the rest are listed because a client has to be able to name them (they are
/// read, and they are legitimately empty).
///
/// **Class 7 has two meanings.** TS3 calls it `ROOM_CATEGORY` (a named group of
/// channels); TS6 calls the same number `GROUP_CHATS` and adds `CONTACTS` as 8.
/// The enum value keeps the TS3 name because this core targets TS3 — the blob is
/// preserved either way, so a TS6 group-chat list is still read, written and
/// backed up, it is only *labelled* `ROOM_CATEGORY`. `parse` accepts the TS6
/// spelling too, so a shell can ask for it by the name its user knows.
///
/// The enum itself is from the server binaries' embedded descriptors, not from
/// documentation: TS3 3.13.9 stops at 7 with `ROOM_CATEGORY` and has no 8, and
/// TS6 6.0.0-beta14 reads `… ITEM_FOLDER = 6, GROUP_CHATS = 7, CONTACTS = 8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ItemClass {
    Bookmark = 0,
    Identity = 1,
    WhisperList = 2,
    HotkeyProfile = 3,
    AddOn = 4,
    Config = 5,
    ItemFolder = 6,
    /// TS3 room category; TS6 group chats. See the note on the enum.
    RoomCategory = 7,
    /// TS6 contacts. TS3 has no class 8: a TS3 server simply never sends one.
    Contacts = 8,
}

impl ItemClass {
    /// Every class this client knows how to name, including the TS6 one.
    ///
    /// Asking a TS3 server for class 8 is harmless — it has no such class and
    /// answers nothing for it — and asking a TS6 server for it is the only way
    /// contacts ever arrive.
    pub const ALL: [ItemClass; 9] = [
        ItemClass::Bookmark,
        ItemClass::Identity,
        ItemClass::WhisperList,
        ItemClass::HotkeyProfile,
        ItemClass::AddOn,
        ItemClass::Config,
        ItemClass::ItemFolder,
        ItemClass::RoomCategory,
        ItemClass::Contacts,
    ];

    pub fn from_id(id: u32) -> Option<ItemClass> {
        Some(match id {
            0 => ItemClass::Bookmark,
            1 => ItemClass::Identity,
            2 => ItemClass::WhisperList,
            3 => ItemClass::HotkeyProfile,
            4 => ItemClass::AddOn,
            5 => ItemClass::Config,
            6 => ItemClass::ItemFolder,
            7 => ItemClass::RoomCategory,
            8 => ItemClass::Contacts,
            _ => return None,
        })
    }

    /// Parses the wire name a shell would pass in (`"BOOKMARK"`, `"BOOKMARK"`,
    /// `"bookmark"` and `"0"` all land on the same class).
    pub fn parse(name: &str) -> Option<ItemClass> {
        let upper = name.trim().to_ascii_uppercase().replace('_', "");
        if let Ok(id) = upper.parse::<u32>() {
            return ItemClass::from_id(id);
        }
        Some(match upper.as_str() {
            "BOOKMARK" => ItemClass::Bookmark,
            "IDENTITY" => ItemClass::Identity,
            "WHISPERLIST" => ItemClass::WhisperList,
            "HOTKEYPROFILE" => ItemClass::HotkeyProfile,
            "ADDON" => ItemClass::AddOn,
            "CONFIG" => ItemClass::Config,
            "ITEMFOLDER" => ItemClass::ItemFolder,
            // The same number, named twice: see the note on `ItemClass`.
            "ROOMCATEGORY" | "GROUPCHATS" => ItemClass::RoomCategory,
            "CONTACTS" => ItemClass::Contacts,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            ItemClass::Bookmark => "BOOKMARK",
            ItemClass::Identity => "IDENTITY",
            ItemClass::WhisperList => "WHISPER_LIST",
            ItemClass::HotkeyProfile => "HOTKEY_PROFILE",
            ItemClass::AddOn => "ADD_ON",
            ItemClass::Config => "CONFIG",
            ItemClass::ItemFolder => "ITEM_FOLDER",
            ItemClass::RoomCategory => "ROOM_CATEGORY",
            ItemClass::Contacts => "CONTACTS",
        }
    }

    pub fn id(self) -> u32 {
        self as u32
    }
}

/// `SyncStatus` as the server reports it. Only `300` means "accepted"; `301` on a
/// read simply means the local copy is behind, and `103` on a write means the
/// request was rejected with no side effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncStatus {
    UnknownMethod,
    UnknownData,
    SessionExpired,
    Critical,
    InSync,
    NotInSync,
    NotInDb,
    Collision,
    OverLimit,
    Other(i32),
}

impl SyncStatus {
    pub fn from_code(code: i32) -> SyncStatus {
        match code {
            100 => SyncStatus::UnknownMethod,
            101 => SyncStatus::UnknownData,
            102 => SyncStatus::SessionExpired,
            103 => SyncStatus::Critical,
            300 => SyncStatus::InSync,
            301 => SyncStatus::NotInSync,
            302 => SyncStatus::NotInDb,
            303 => SyncStatus::Collision,
            304 => SyncStatus::OverLimit,
            other => SyncStatus::Other(other),
        }
    }

    pub fn code(self) -> i32 {
        match self {
            SyncStatus::UnknownMethod => 100,
            SyncStatus::UnknownData => 101,
            SyncStatus::SessionExpired => 102,
            SyncStatus::Critical => 103,
            SyncStatus::InSync => 300,
            SyncStatus::NotInSync => 301,
            SyncStatus::NotInDb => 302,
            SyncStatus::Collision => 303,
            SyncStatus::OverLimit => 304,
            SyncStatus::Other(code) => code,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            SyncStatus::UnknownMethod => "UNKNOWN_METHOD",
            SyncStatus::UnknownData => "UNKNOWN_DATA",
            SyncStatus::SessionExpired => "SESSION_EXPIRED",
            SyncStatus::Critical => "CRITICAL",
            SyncStatus::InSync => "IN_SYNC",
            SyncStatus::NotInSync => "NOT_IN_SYNC",
            SyncStatus::NotInDb => "NOT_IN_DB",
            SyncStatus::Collision => "COLLISION",
            SyncStatus::OverLimit => "OVERLIMIT",
            SyncStatus::Other(_) => "OTHER",
        }
    }

    /// Whether a write was accepted. Nothing else may be reported as success:
    /// a client that treats `301` as "fine" keeps a lie on the server.
    pub fn accepted(self) -> bool {
        self == SyncStatus::InSync
    }
}

/// One item as the server holds it.
#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    pub uuid: String,
    pub class: ItemClass,
    pub item_version: String,
    /// The raw server blob, envelope and all.
    pub blob: Vec<u8>,
    pub deleted: bool,
    /// `Item_Data.parent` (f7) and `sort_order` (f8).
    ///
    /// Filled only when the blob is a **bare** `Item_Data`; a sealed blob keeps
    /// these fields inside its ciphertext, so they are read through
    /// [`ItemMeta::parse`] once the key is in hand. Keeping the plaintext case on
    /// the item itself is what lets a report show placement for add-ons without
    /// an account key — and it is the case that has a live vector.
    pub meta: ItemMeta,
}

/// The full server state at one point in time. `globalversion` is what has to be
/// echoed back on a write; `class_version` is the per-class value, and a write
/// that carries a stale one is rejected for the whole request.
///
/// A state read with cursors is **partial on purpose**: the server omits a class
/// whose cursor still matches, and answers a stale class whole. Measured with
/// `examples/merge_probe.rs` (read-only, against the reference account):
///
/// | request | reply |
/// |---|---|
/// | no cursors | all 5 populated classes, 8862 B |
/// | all cursors current | no class messages at all, 59 B |
/// | BOOKMARK cursor stale | BOOKMARK whole (8 items), others omitted, 3768 B |
/// | `globalversion` stale, classes current | nothing, 59 B |
///
/// So an absent class means "unchanged since that cursor", which is why
/// [`MergeState::apply`] keeps the previous items instead of treating the read as
/// a delete-everything. A stale `globalversion` alone does not force a refresh.
#[derive(Debug, Clone)]
pub struct SyncState {
    pub status: SyncStatus,
    pub global_version: String,
    pub class_version: std::collections::BTreeMap<ItemClass, String>,
    pub items: Vec<Item>,
}

/// The authoritative, accumulated view of an account.
///
/// A [`SyncState`] from a cursor read is a *delta*: it names the classes that
/// changed and the items each of them now holds. Keeping those deltas in one
/// place — and applying them by class — is what lets the client send its cursors
/// instead of re-reading all 25 items (and then all 25 again) every time.
#[derive(Debug, Clone, Default)]
pub struct MergeState {
    /// The latest cursors, so the next read asks only for what moved.
    pub state: SyncState,
}

impl Default for SyncState {
    fn default() -> Self {
        SyncState {
            // "Nothing has been read yet" must not read as "in sync".
            status: SyncStatus::Other(0),
            global_version: String::new(),
            class_version: std::collections::BTreeMap::new(),
            items: Vec::new(),
        }
    }
}

impl SyncState {
    pub fn item(&self, uuid: &str) -> Option<&Item> {
        self.items.iter().find(|item| item.uuid == uuid)
    }

    pub fn of_class(&self, class: ItemClass) -> impl Iterator<Item = &Item> {
        self.items.iter().filter(move |item| item.class == class)
    }

    /// Folds a delta read into this state, by class.
    ///
    /// Rules, each of them measured rather than assumed:
    ///
    /// * **A class named in the delta replaces that class wholesale.** The server
    ///   answers a stale class with its complete current contents, so keeping the
    ///   old items alongside would resurrect anything deleted elsewhere.
    /// * **A class absent from the delta is untouched.** Its cursor still matched,
    ///   so nothing in it changed.
    /// * **Cursors are replaced only by values the reply actually carries.** A
    ///   reply that omits a class cannot tell us its version, and inventing one
    ///   would make the next read ask for the wrong thing.
    pub fn apply(&mut self, delta: &SyncState) {
        // Which classes the delta speaks about.
        let mut named: Vec<ItemClass> = Vec::new();
        for class in ItemClass::ALL {
            if delta.class_version.contains_key(&class) || delta.of_class(class).next().is_some() {
                named.push(class);
            }
        }

        if !named.is_empty() {
            self.items.retain(|item| !named.contains(&item.class));
            for class in &named {
                self.items.extend(delta.of_class(*class).cloned());
            }
        }

        for (class, version) in &delta.class_version {
            self.class_version.insert(*class, version.clone());
        }
        if !delta.global_version.is_empty() {
            self.global_version = delta.global_version.clone();
        }
        if delta.status != SyncStatus::Other(0) {
            self.status = delta.status;
        }
    }

    /// Whether every class this state knows about has a cursor.
    ///
    /// The first read has none, so it must ask for everything; later reads send
    /// what they have and let the server omit the classes that did not move.
    pub fn has_cursors(&self) -> bool {
        !self.class_version.is_empty()
    }
}

impl MergeState {
    /// Folds a freshly read delta in and returns the accumulated state.
    pub fn merge(&mut self, delta: &SyncState) -> &SyncState {
        self.state.apply(delta);
        &self.state
    }
}

/// What can be done with one item, decided by whether it is encrypted and whether
/// this session holds the key.
///
/// This replaced a three-tier model (`plaintext` / `keystream` / `opaque`) that
/// existed only because the item key was believed to be unrecoverable. It is not:
/// the key is the account key from the login response, so every wrapped item is
/// readable and writable at any length.
#[derive(Debug, Clone, PartialEq)]
pub enum Capability {
    /// A bare `Item_Data` with no envelope at all (`ADD_ON` items are stored this
    /// way). No key involved.
    Plaintext,
    /// `header16 || ct || sha512(plaintext)`, encrypted under the account key.
    Encrypted,
    /// Encrypted, but this session has no account key (a login whose `key` could
    /// not be unwrapped). Content is opaque until a working login happens.
    Locked,
    /// A zero-length blob.
    Empty,
}

impl Capability {
    /// The longest plaintext this item can carry. There is no ceiling for either
    /// writable tier: the cipher is a stream cipher over the whole item.
    pub fn max_plaintext(&self) -> Option<usize> {
        match self {
            Capability::Plaintext | Capability::Encrypted => None,
            Capability::Locked | Capability::Empty => Some(0),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Capability::Plaintext => "plaintext",
            Capability::Encrypted => "encrypted",
            Capability::Locked => "locked",
            Capability::Empty => "empty",
        }
    }

    /// Whether the content can be both read and rewritten by this session.
    pub fn writable(&self) -> bool {
        matches!(self, Capability::Plaintext | Capability::Encrypted)
    }
}

/// The item cipher, keyed by the account key.
///
/// `blob = header16 || ct || sha512(plaintext)`, and `plaintext` is
/// AES-256-CTR(accountKey, header)(ct). The trailing hash is the only check the
/// format carries, so a wrong key or a wrong counter rule fails it outright
/// rather than producing plausible garbage — see `crypto::item_cipher` for how
/// the counter advances, and `research/myts-login/explore/itemcipher_check.mjs`
/// for the live evidence.
#[derive(Clone)]
pub struct ItemCipher {
    key: [u8; KEY_LEN],
}

impl ItemCipher {
    pub fn new(key: [u8; KEY_LEN]) -> ItemCipher {
        ItemCipher { key }
    }

    /// Decrypts a blob. Fails when the header/trailer framing is wrong or when
    /// the trailing hash does not match, which is the same test the real client
    /// performs.
    pub fn open(&self, blob: &[u8]) -> Result<Vec<u8>, String> {
        if blob.len() < HEADER_LEN + TRAILER_LEN {
            return Err(format!(
                "blob is {} B; an encrypted item needs at least {}",
                blob.len(),
                ENVELOPE_LEN
            ));
        }
        let header: [u8; HEADER_LEN] = blob[..HEADER_LEN].try_into().expect("checked length above");
        let ct = &blob[HEADER_LEN..blob.len() - TRAILER_LEN];
        let plain = crypto::item_cipher(&self.key, &header, ct);
        if crypto::sha512(&plain) != blob[blob.len() - TRAILER_LEN..] {
            return Err("the item's trailing SHA-512 does not match its content \
                        (wrong key, or the blob is not this format)"
                .to_string());
        }
        Ok(plain)
    }

    /// Encrypts a plaintext under a fresh header. Any length; there is no
    /// equal-length requirement and no donor.
    pub fn seal(&self, plaintext: &[u8]) -> Vec<u8> {
        self.seal_with(plaintext, crypto::item_header())
    }

    /// Encrypts under a given header, for a caller rewriting an item in place.
    pub fn seal_with(&self, plaintext: &[u8], header: [u8; HEADER_LEN]) -> Vec<u8> {
        let mut blob = Vec::with_capacity(plaintext.len() + ENVELOPE_LEN);
        blob.extend_from_slice(&header);
        blob.extend_from_slice(&crypto::item_cipher(&self.key, &header, plaintext));
        blob.extend_from_slice(&crypto::sha512(plaintext));
        blob
    }

    /// The header of an encrypted blob, so a rewrite can reuse it.
    pub fn header_of(blob: &[u8]) -> Option<[u8; HEADER_LEN]> {
        blob.get(..HEADER_LEN)?.try_into().ok()
    }
}

/// `ctr16` in front of the wrapped payload.
pub const HEADER_LEN: usize = 16;
/// `sha512(plaintext)` behind it.
pub const TRAILER_LEN: usize = 64;
/// An envelope costs exactly this much: header plus trailer.
pub const ENVELOPE_LEN: usize = HEADER_LEN + TRAILER_LEN;

/// The read side and the write shapes. Holds no session of its own; the session
/// id is passed in with each call so a caller can rotate it without rebuilding.
///
/// There is deliberately no "batch" type here: every write is one item, one
/// request, one backup. A batch would have to share one `globalversion`, and the
/// only thing that buys is a partial failure nobody can attribute.
pub struct Sync;

impl Sync {
    /// Builds the `requestServerItems` payload for a full read: every class, no
    /// cursors. All eight classes are asked for, with `not_in_db = false`, because
    /// three of them are legitimately empty and "class missing" has to be
    /// distinguishable from "no details returned".
    ///
    /// Use [`Sync::delta_payload`] when a previous read supplied cursors; this one
    /// makes the server send everything.
    pub fn read_payload(session: &str) -> Vec<u8> {
        Self::delta_payload(session, None)
    }

    /// Builds a `requestServerItems` payload that carries the cursors from an
    /// earlier read.
    ///
    /// With cursors, the server omits every class that has not changed and sends
    /// the changed ones whole — so one request after a quiet minute is 59 bytes
    /// instead of 8862 (measured, see [`SyncState`]). The returned delta has to go
    /// through [`SyncState::apply`](crate::account::sync::SyncState::apply) before
    /// it is a state again.
    ///
    /// The cursor is the *class* version, not a per-item one: a class moves as a
    /// whole, and the server never sends partial class contents.
    pub fn delta_payload(session: &str, known: Option<&SyncState>) -> Vec<u8> {
        let mut payload = proto::field_string(1, session);
        for class in ItemClass::ALL {
            let mut message = proto::field_varint(1, class.id() as u64);
            if let Some(version) = known.and_then(|state| state.class_version.get(&class)) {
                message.extend(proto::field_string(2, version));
            }
            message.extend(proto::field_varint(4, 0));
            payload.extend(proto::field_bytes(2, &message));
        }
        // A stale globalversion alone does not force a refresh, but sending it is
        // what the official client does and the server expects it echoed.
        if let Some(state) = known {
            if !state.global_version.is_empty() {
                payload.extend(proto::field_string(3, &state.global_version));
            }
        }
        payload
    }

    /// Interprets a `requestServerItems` reply.
    pub fn decode_reply(reply: &[u8]) -> Result<SyncState, String> {
        let message = Message::parse(reply)?;
        let status = SyncStatus::from_code(message.varint(1).unwrap_or(0) as i32);
        let global_version = message.string(3).unwrap_or_default().to_string();
        let mut class_version = std::collections::BTreeMap::new();
        let mut items = Vec::new();

        for field in message.all(2) {
            let Some(bytes) = field.as_bytes() else {
                continue;
            };
            let class_message = Message::parse(bytes)?;
            // proto3 omits a zero value, so BOOKMARK's class message genuinely
            // has no `itemclass` key. Reading it as "missing means 0" is the
            // only correct reading; treating it as an error drops every bookmark.
            let class_id = class_message.varint(1).unwrap_or(0) as u32;
            let Some(class) = ItemClass::from_id(class_id) else {
                log::warn!("sync reply has class id {class_id}, which is not defined");
                continue;
            };
            if let Some(version) = class_message.string(2) {
                class_version.insert(class, version.to_string());
            }
            for detail in class_message.all(3) {
                let Some(bytes) = detail.as_bytes() else {
                    continue;
                };
                let detail = Message::parse(bytes)?;
                let Some(uuid) = detail.string(1) else {
                    continue;
                };
                let blob = detail.bytes(3).unwrap_or_default().to_vec();
                // f7/f8 are only readable on a bare `Item_Data`; a sealed blob
                // keeps them inside its ciphertext, where `ItemMeta::parse`
                // finds them once the key unlocks it. Skipping the parse here
                // also keeps a `header || ct || sha512` envelope from being
                // half-read as a message.
                let meta = if is_plain_item_data(&blob) {
                    ItemMeta::parse(&blob).unwrap_or_default()
                } else {
                    ItemMeta::default()
                };
                items.push(Item {
                    uuid: uuid.to_string(),
                    class,
                    item_version: detail.string(2).unwrap_or_default().to_string(),
                    blob,
                    deleted: detail.bool(4).unwrap_or(false),
                    meta,
                });
            }
        }

        Ok(SyncState {
            status,
            global_version,
            class_version,
            items,
        })
    }

    /// Builds a single-item upsert. **This is a write.**
    ///
    /// The shape is the whole point, and every part of it was measured:
    ///
    /// * `class.version` = the server's *current* value. A stale value rejects
    ///   the whole request with `103`.
    /// * `detail` carries `item_uuid`, `item_version` **and** `item_blob`. A
    ///   version without a blob erases the content; a blob without a version is
    ///   rejected. Both, always.
    /// * `globalversion` is required and is replaced by the server, never
    ///   honoured.
    /// * Exactly one detail per request: that is the reliable form, and it also
    ///   makes a partial failure impossible to misread.
    /// * `item_delte_on_server` must not appear next to a version.
    pub fn upsert_payload(
        session: &str,
        class: ItemClass,
        class_version: Option<&str>,
        uuid: &str,
        item_version: &str,
        blob: &[u8],
        global_version: &str,
    ) -> Vec<u8> {
        let mut detail = proto::field_string(1, uuid);
        detail.extend(proto::field_string(2, item_version));
        detail.extend(proto::field_bytes(3, blob));

        let mut class_message = proto::field_varint(1, class.id() as u64);
        if let Some(version) = class_version {
            class_message.extend(proto::field_string(2, version));
        }
        class_message.extend(proto::field_bytes(3, &detail));

        let mut payload = proto::field_string(1, session);
        payload.extend(proto::field_bytes(2, &class_message));
        if !global_version.is_empty() {
            payload.extend(proto::field_string(3, global_version));
        }
        payload
    }

    /// Builds a delete: `uuid` + `item_delte_on_server=1`, and **no** version.
    /// Adding a version to a delete rejects the whole request.
    pub fn delete_payload(
        session: &str,
        class: ItemClass,
        class_version: Option<&str>,
        uuid: &str,
        global_version: &str,
    ) -> Vec<u8> {
        let mut detail = proto::field_string(1, uuid);
        detail.extend(proto::field_varint(4, 1));

        let mut class_message = proto::field_varint(1, class.id() as u64);
        if let Some(version) = class_version {
            class_message.extend(proto::field_string(2, version));
        }
        class_message.extend(proto::field_bytes(3, &detail));

        let mut payload = proto::field_string(1, session);
        payload.extend(proto::field_bytes(2, &class_message));
        if !global_version.is_empty() {
            payload.extend(proto::field_string(3, global_version));
        }
        payload
    }

    /// The 41-byte write reply: `status`, and nothing else worth reading.
    pub fn decode_write_reply(reply: &[u8]) -> SyncStatus {
        match Message::parse(reply) {
            Ok(message) => SyncStatus::from_code(message.varint(1).unwrap_or(0) as i32),
            // A 2-byte body is what a rejected request looks like; a body that
            // will not parse is reported as critical rather than as success.
            Err(e) => {
                log::warn!("sync write reply could not be parsed: {e}");
                SyncStatus::Critical
            }
        }
    }
}

// ── capability ──────────────────────────────────────────────────────────────

/// Whether a blob is a bare `Item_Data` with no envelope at all.
///
/// The test is structural, not statistical: a plain blob is a protobuf message
/// whose field 2 is a 36-character uuid string. A wrapped blob starts with 16
/// bytes of counter, which cannot parse as that.
pub fn is_plain_item_data(blob: &[u8]) -> bool {
    let Ok(message) = Message::parse(blob) else {
        return false;
    };
    message
        .bytes(2)
        .map(|uuid| uuid.len() == 36 && uuid.contains(&b'-'))
        .unwrap_or(false)
}

/// What can be done with one item.
///
/// The tier is a property of the item and of whether this session holds the
/// account key — **not** of anything on disk. A logged-in client with a
/// password can read and rewrite every item; the only items it cannot are ones
/// whose blob is encrypted and whose login did not yield a usable key.
pub fn capability_of(item: &Item, cipher: Option<&ItemCipher>) -> Capability {
    if item.blob.is_empty() {
        return Capability::Empty;
    }
    if is_plain_item_data(&item.blob) {
        return Capability::Plaintext;
    }
    match cipher {
        Some(cipher) if cipher.open(&item.blob).is_ok() => Capability::Encrypted,
        _ => Capability::Locked,
    }
}

/// The plaintext of one item, if this session can read it.
pub fn read_plain(item: &Item, cipher: Option<&ItemCipher>) -> Result<Vec<u8>, String> {
    if is_plain_item_data(&item.blob) {
        return Ok(item.blob.clone());
    }
    let cipher = cipher.ok_or_else(|| {
        "this session has no account key, so the item's content cannot be read \
         (the login did not unwrap `key`)"
            .to_string()
    })?;
    cipher.open(&item.blob)
}

// ── Item_Data editing ───────────────────────────────────────────────────────

/// The bookmark fields a UI shows, read out of a plain `Item_Data`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Bookmark {
    pub name: String,
    pub address: String,
    pub port: u32,
    pub nickname: String,
    pub server_password: String,
    pub default_channel: String,
    pub default_channel_password: String,
    pub server_uid: String,
    pub autoconnect: bool,
    pub send_mytsid: bool,
    pub announce_to_chat: bool,
    /// The hotkey profile uuid this bookmark uses, or empty.
    pub hotkey_profile: String,
}

impl Bookmark {
    /// Reads field 16 of an `Item_Data`. `None` when the item is not a bookmark.
    pub fn parse(plain: &[u8]) -> Result<Option<Bookmark>, String> {
        let message = Message::parse(plain)?;
        let Some(field) = message.get(16) else {
            return Ok(None);
        };
        let Some(bytes) = field.as_bytes() else {
            return Ok(None);
        };
        let inner = Message::parse(bytes)?;
        Ok(Some(Bookmark {
            name: inner.string(1).unwrap_or_default().to_string(),
            address: inner.string(2).unwrap_or_default().to_string(),
            port: inner.varint(3).unwrap_or(0) as u32,
            nickname: inner.string(4).unwrap_or_default().to_string(),
            server_password: inner.string(7).unwrap_or_default().to_string(),
            default_channel: inner.string(8).unwrap_or_default().to_string(),
            default_channel_password: inner.string(9).unwrap_or_default().to_string(),
            server_uid: inner.string(15).unwrap_or_default().to_string(),
            autoconnect: inner.varint(14) == Some(1),
            // Field 22 defaults to *true* on the server side; a missing field
            // means "send the myTS id", not "do not". Getting this backwards
            // silently changes what the client sends when it joins.
            send_mytsid: inner.varint(22).unwrap_or(1) != 0,
            announce_to_chat: inner.varint(23) == Some(1),
            hotkey_profile: inner.string(13).unwrap_or_default().to_string(),
        }))
    }
}

// ── Item_Data shape: where an item sits, and what a folder is ──────────────

/// `Item_Data.parent` (field 7) and `Item_Data.sort_order` (field 8): the two
/// fields that give the item tree its shape.
///
/// `sort_order` is **not a number**, which is the part that matters. On the
/// reference account every bookmark carries the *uuid of its predecessor* there
/// and `""` for the first one:
///
/// ```text
/// localhost      sort_order = ""
/// Schallophy's   sort_order = fcfe1a38… (localhost)
/// Daiso          sort_order = 973984d8… (Schallophy's)
/// Woops'         sort_order = cad3333c… (Daiso)
/// …
/// ```
///
/// A client that sorted these as integers, or treated `sort_order` as a rank,
/// would reorder the user's list. The order is recovered by following the links,
/// which is what [`order_by_sort_order`] does.
///
/// `parent` names the `ITEM_FOLDER` item this one sits in, or is empty at the top
/// level. That is the whole hierarchy: folders (class 6) with a `parent` link,
/// and everything else pointing at a folder or at nothing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ItemMeta {
    pub parent: String,
    pub sort_order: String,
}

impl ItemMeta {
    /// Reads fields 7 and 8 of an `Item_Data`.
    ///
    /// Both are present-but-empty on every item of the reference account, which
    /// is why the empty string and "the field is absent" have to mean the same
    /// thing here: a JSON importer that wrote the empty string out and one that
    /// omitted it describe the same tree.
    pub fn parse(plain: &[u8]) -> Result<ItemMeta, String> {
        let message = Message::parse(plain)?;
        Ok(ItemMeta {
            parent: message.string(7).unwrap_or_default().to_string(),
            sort_order: message.string(8).unwrap_or_default().to_string(),
        })
    }

    /// Whether this item sits at the top level.
    pub fn is_root(&self) -> bool {
        self.parent.is_empty()
    }
}

/// `Item_Folder` (field 22 of a class-6 `Item_Data`): the folder's name and the
/// item class it groups.
///
/// `folder_type` is an `Item_Class`, so a folder of bookmarks says
/// `BOOKMARK` (0). The protocol has no "folder of folders" class: nesting happens
/// through `parent` on the folder itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemFolder {
    pub name: String,
    /// The class this folder holds. `None` when the reply names an unknown class,
    /// which is kept rather than guessed at.
    pub folder_type: Option<ItemClass>,
    /// The raw number, so an unknown class is still reportable.
    pub folder_type_id: u32,
}

impl ItemFolder {
    /// Reads field 22. `None` when the item is not a folder.
    pub fn parse(plain: &[u8]) -> Result<Option<ItemFolder>, String> {
        let message = Message::parse(plain)?;
        let Some(field) = message.get(22) else {
            return Ok(None);
        };
        let Some(bytes) = field.as_bytes() else {
            return Ok(None);
        };
        let inner = Message::parse(bytes)?;
        let folder_type_id = inner.varint(2).unwrap_or(0) as u32;
        Ok(Some(ItemFolder {
            name: inner.string(1).unwrap_or_default().to_string(),
            folder_type: ItemClass::from_id(folder_type_id),
            folder_type_id,
        }))
    }
}

/// Recovers the sibling order from `sort_order` links.
///
/// Input is `(uuid, sort_order)` for every item in one list; the link names the
/// item that comes *before* it, and an empty or unknown link is a chain head
/// (the reference account writes `""` for the first bookmark).
///
/// The walk is a chain, not a sort: following links is the only reading that
/// reproduces the order the official client draws. Three cases the naive version
/// gets wrong, all of them handled here:
///
/// * **a cycle** (a link pointing back into the chain) stops the walk for that
///   chain instead of looping forever;
/// * **a link to an item outside the list** (a bookmark whose predecessor is in
///   another folder) makes that item a head rather than dropping it;
/// * **leftovers** — anything no chain reached, because it is in a cycle or the
///   file came from something other than this client — is appended in the order
///   it was given, because losing a bookmark is worse than showing it last.
pub fn order_by_sort_order(links: &[(String, String)]) -> Vec<String> {
    let known: std::collections::BTreeSet<&str> =
        links.iter().map(|(uuid, _)| uuid.as_str()).collect();
    let mut ordered = Vec::with_capacity(links.len());
    let mut used = std::collections::BTreeSet::new();

    loop {
        let head = links.iter().find(|(uuid, link)| {
            !used.contains(uuid) && (link.is_empty() || !known.contains(link.as_str()))
        });
        let Some((head_uuid, _)) = head else { break };
        let mut current = head_uuid.clone();
        loop {
            if !used.insert(current.clone()) {
                // Already emitted: the links form a cycle. Stop here.
                break;
            }
            ordered.push(current.clone());
            match links.iter().find(|(_, link)| link == &current) {
                Some((next, _)) => current = next.clone(),
                None => break,
            }
        }
    }

    for (uuid, _) in links {
        if !used.contains(uuid) {
            ordered.push(uuid.clone());
        }
    }
    ordered
}

/// One node of the reconstructed tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeNode {
    pub uuid: String,
    /// Empty for a top-level item.
    pub parent: String,
    /// How deep the node sits, for a flat list a UI can indent.
    pub depth: usize,
    /// The folder's name, or the bookmark's name; empty for a class with neither.
    pub name: String,
    /// `Some(class)` when this node is an `ITEM_FOLDER` grouping that class.
    pub folder_for: Option<ItemClass>,
}

/// What [`hierarchy`] produced: the tree, and the items it could not place.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Hierarchy {
    /// Pre-order walk, so a caller can render one indented list.
    pub entries: Vec<TreeNode>,
    /// Items whose own content could not be read (a locked blob), or whose
    /// `parent` names something that is not a folder in this state.
    ///
    /// Reported instead of silently flattened: "this bookmark was not imported"
    /// is a thing a user can act on, and a bookmark that quietly moved to the top
    /// level is not.
    pub unplaced: Vec<String>,
}

/// Rebuilds the item tree from `parent` links and `sort_order` chains.
///
/// This is what an importer needs and what a renderer needs: without it every
/// bookmark is a flat row, and the folders the account holds are invisible. The
/// walk is depth-first so the output order is the order the client draws.
///
/// Items that cannot be decrypted are listed in [`Hierarchy::unplaced`] rather
/// than guessed at: a locked blob has no readable `parent`, so placing it
/// anywhere would be inventing a tree.
pub fn hierarchy(state: &SyncState, cipher: Option<&ItemCipher>) -> Hierarchy {
    /// What the walk needs to know about one item.
    struct Placed {
        uuid: String,
        parent: String,
        sort_order: String,
        name: String,
        folder_for: Option<ItemClass>,
    }

    // Read every placement first, so a folder's children are known before the
    // walk reaches it.
    let mut placements: Vec<Placed> = Vec::new();
    let mut unplaced = Vec::new();
    let mut folder_ids = std::collections::BTreeSet::new();

    for item in &state.items {
        let Ok(plain) = read_plain(item, cipher) else {
            // A sealed blob without the key has no readable parent, so placing it
            // anywhere would be inventing a tree. Name it instead.
            unplaced.push(item.uuid.clone());
            continue;
        };
        let meta = ItemMeta::parse(&plain).unwrap_or_default();
        let folder = ItemFolder::parse(&plain).ok().flatten();
        let name = match &folder {
            Some(folder) => folder.name.clone(),
            None => Bookmark::parse(&plain)
                .ok()
                .flatten()
                .map(|bookmark| bookmark.name)
                .unwrap_or_default(),
        };
        if folder.is_some() {
            folder_ids.insert(item.uuid.clone());
        }
        placements.push(Placed {
            uuid: item.uuid.clone(),
            parent: meta.parent,
            sort_order: meta.sort_order,
            name,
            folder_for: folder.and_then(|folder| folder.folder_type),
        });
    }

    // A parent that is not a folder in this state cannot be honoured. Treating it
    // as a root keeps the item visible — a wrong tree beats a lost row — and it is
    // reported so the caller can say so.
    let mut roots: Vec<(String, String)> = Vec::new();
    let mut children: std::collections::BTreeMap<String, Vec<(String, String)>> =
        std::collections::BTreeMap::new();
    for placed in &placements {
        if placed.parent.is_empty() {
            roots.push((placed.uuid.clone(), placed.sort_order.clone()));
        } else if folder_ids.contains(&placed.parent) {
            children
                .entry(placed.parent.clone())
                .or_default()
                .push((placed.uuid.clone(), placed.sort_order.clone()));
        } else {
            unplaced.push(placed.uuid.clone());
            roots.push((placed.uuid.clone(), placed.sort_order.clone()));
        }
    }

    fn walk(
        placements: &[Placed],
        children: &std::collections::BTreeMap<String, Vec<(String, String)>>,
        links: &[(String, String)],
        depth: usize,
        entries: &mut Vec<TreeNode>,
        seen: &mut std::collections::BTreeSet<String>,
    ) {
        for uuid in order_by_sort_order(links) {
            // A folder cycle would otherwise recurse forever.
            if !seen.insert(uuid.clone()) {
                continue;
            }
            let Some(placed) = placements.iter().find(|entry| entry.uuid == uuid) else {
                continue;
            };
            entries.push(TreeNode {
                uuid: uuid.clone(),
                parent: placed.parent.clone(),
                depth,
                name: placed.name.clone(),
                folder_for: placed.folder_for,
            });
            if let Some(inner) = children.get(&uuid) {
                walk(placements, children, inner, depth + 1, entries, seen);
            }
        }
    }

    let mut entries = Vec::with_capacity(placements.len());
    let mut seen = std::collections::BTreeSet::new();
    walk(&placements, &children, &roots, 0, &mut entries, &mut seen);
    // Whatever the walk did not reach sits in a folder cycle; keep the rows.
    for placed in &placements {
        if seen.insert(placed.uuid.clone()) {
            entries.push(TreeNode {
                uuid: placed.uuid.clone(),
                parent: placed.parent.clone(),
                depth: 0,
                name: placed.name.clone(),
                folder_for: placed.folder_for,
            });
        }
    }

    unplaced.sort();
    unplaced.dedup();
    Hierarchy { entries, unplaced }
}

/// What a caller wants a new bookmark to say.
///
/// A struct rather than a constructor call with four positional strings: name,
/// address, uuid and version are all strings, and a caller that swaps two of them
/// gets a bookmark that points somewhere else with no error at all.
#[derive(Debug, Clone)]
pub struct BookmarkDraft {
    pub uuid: String,
    pub item_version: String,
    pub name: String,
    pub address: String,
    pub port: u32,
    pub nickname: String,
}

/// `Item_Data.last_known_version` (field 5) on an item that has never been synced.
///
/// The official client writes all-ones here for a created item. Evidence: the two
/// ADD_ON rows it created on this machine and never uploaded
/// (`03d4b1c0`, `19a2b805`) both carry exactly this string, in a blob that is
/// otherwise just `item_uuid + manipulated + item_type + timestamp + add_on`.
/// A real version uuid would mean "this supersedes that revision", which is
/// nonsense for something the server has never seen.
pub const UNPUBLISHED_VERSION: &str = "ffffffff-ffff-ffff-ffff-ffffffffffff";

/// `Item_Data.Manipulation_Flag` (field 4).
pub const ITEM_ADDED: u64 = 0;
pub const ITEM_CHANGED: u64 = 1;
pub const ITEM_NOT_MANIPULATED: u64 = 3;

/// Marks a freshly built `Item_Data` as an add.
///
/// Both fields matter and neither is cosmetic:
///
/// * `manipulated = ITEM_ADDED`, because the item has never been synced. The
///   official client's never-uploaded rows prove it writes `0` here, and its
///   change upload writes `3` (not `1`) once the server has the item.
/// * `last_known_version = UNPUBLISHED_VERSION`, because a new item supersedes
///   nothing. Copying the template's value would claim the new bookmark replaces
///   some other item's revision, and a three-way sync would report a false
///   conflict the first time it compared them.
///
/// `sync_version_uuid` is *not* inherited from the template either: the earlier
/// `build_bookmark` did that and it is wrong twice over (see [`build_bookmark`]).
pub fn mark_added(message: &mut Message) {
    message.upsert_varint(4, ITEM_ADDED);
    message.upsert_string(5, UNPUBLISHED_VERSION);
}

/// Marks an edited `Item_Data` as a change of `previous_version`.
///
/// The official client's upload of a change carries `manipulated = 3` (it sends
/// committed state, not "I changed this") and `last_known_version` = the version
/// it had before. Our own live writes confirmed the server stores whatever flag
/// is sent — 9 of the 12 wrapped items it holds carry `3` — so sending `1` here
/// would be inventing a state no client of theirs produces.
pub fn mark_changed(message: &mut Message, previous_version: &str) {
    message.upsert_varint(4, ITEM_NOT_MANIPULATED);
    message.upsert_string(5, previous_version);
}

/// Builds a fresh `Item_Data` for a new bookmark out of an existing one.
///
/// The template supplies every field this code does not know how to fill
/// (profile references, flags, defaults), so the result has the same shape the
/// real client writes. What is replaced:
///
/// * `item_uuid` and `sync_version_uuid` — a new item is a new identity, and
///   carrying the template's versions would make two items claim the same revision.
/// * `manipulated` and `last_known_version` — see [`mark_added`]; a new bookmark
///   that arrives claiming "unmodified, supersedes X" is the bug this function
///   used to have.
/// * the four user-visible bookmark strings.
///
/// Everything else (`item_type`, `parent`, `sort_order`, `timestamp`, and the
/// bookmark's own profile/shorthand fields) comes from the template, which is the
/// only reason a template is used at all.
pub fn build_bookmark(template: &[u8], draft: &BookmarkDraft) -> Result<Vec<u8>, String> {
    let mut message = Message::parse(template)?;
    if message.get(2).is_none() || message.get(3).is_none() || message.get(16).is_none() {
        return Err(
            "the template is missing item_uuid, sync_version_uuid or bookmark (f2/f3/f16)"
                .to_string(),
        );
    }
    message.upsert_string(2, &draft.uuid);
    message.upsert_string(3, &draft.item_version);
    mark_added(&mut message);
    message.edit_nested(16, |bookmark| {
        bookmark.upsert_string(1, &draft.name);
        bookmark.upsert_string(2, &draft.address);
        bookmark.upsert_varint(3, u64::from(draft.port));
        bookmark.upsert_string(4, &draft.nickname);
        Ok(())
    })?;

    let out = message.encode();
    // The result must still look like a bookmark to anything that reads it — the
    // same check the reference tool runs before it will upload one.
    let parsed = Message::parse(&out)?;
    if parsed.get(16).is_none() {
        return Err("the rewritten item lost its bookmark field".to_string());
    }
    // And it must look like a *new* item, not a copy of the template.
    if parsed.varint(4) != Some(ITEM_ADDED) {
        return Err(format!(
            "the new bookmark does not read as an add (manipulated = {:?})",
            parsed.varint(4)
        ));
    }
    if parsed.string(5) != Some(UNPUBLISHED_VERSION) {
        return Err(
            "the new bookmark carries a last_known_version, which a new item must not".to_string(),
        );
    }
    Ok(out)
}

/// Changes one varint inside a nested message, e.g. `add_on.enabled`.
///
/// Returns the previous value so a caller can report what actually changed,
/// rather than claiming a write that was already true.
pub fn set_nested_varint(
    plain: &[u8],
    outer: u32,
    inner: u32,
    value: u64,
) -> Result<(u64, Vec<u8>), String> {
    let mut message = Message::parse(plain)?;
    let mut previous = None;
    message.edit_nested(outer, |child| {
        previous = child.varint(inner);
        child.set_varint(inner, value)?;
        Ok(())
    })?;
    let previous =
        previous.ok_or_else(|| format!("the item has no field {outer}.{inner} to change"))?;
    Ok((previous, message.encode()))
}

// ── backup ──────────────────────────────────────────────────────────────────

/// A snapshot of the server state, written before any write. This is the only
/// thing that makes a mistaken upsert recoverable: the blobs are copied verbatim,
/// so a restore is a byte-for-byte replay, not a reconstruction.
#[derive(Debug, Clone)]
pub struct Backup {
    pub taken_at: String,
    pub global_version: String,
    pub status: SyncStatus,
    pub items: Vec<Item>,
    pub class_version: std::collections::BTreeMap<ItemClass, String>,
}

impl Backup {
    pub fn of(state: &SyncState) -> Backup {
        Backup {
            taken_at: crate::account::now_iso8601(),
            global_version: state.global_version.clone(),
            status: state.status,
            items: state.items.clone(),
            class_version: state.class_version.clone(),
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        let classes: Vec<serde_json::Value> = self
            .class_version
            .iter()
            .map(|(class, version)| {
                serde_json::json!({
                    "classId": class.id(),
                    "className": class.name(),
                    "version": version,
                })
            })
            .collect();
        let items: Vec<serde_json::Value> = self
            .items
            .iter()
            .map(|item| {
                serde_json::json!({
                    "uuid": item.uuid,
                    "classId": item.class.id(),
                    "className": item.class.name(),
                    "itemVersion": item.item_version,
                    "deleted": item.deleted,
                    // The placement is derived from the blob, so it is written
                    // out for a reader that does not decrypt. A restore still
                    // replays the blob, not these two fields.
                    "parent": item.meta.parent,
                    "sortOrder": item.meta.sort_order,
                    "blobB64": base64_of(&item.blob),
                })
            })
            .collect();
        serde_json::json!({
            "takenAt": self.taken_at,
            "globalversion": self.global_version,
            "status": self.status.code(),
            "statusName": self.status.name(),
            "note": "synchronizeItems is a write; replay this file byte for byte to undo a write",
            "classes": classes,
            "items": items,
        })
    }

    /// Same shape as the reference tool's backups, so either side can restore a
    /// file written by the other.
    pub fn from_json(value: &serde_json::Value) -> Result<Backup, String> {
        let global_version = value
            .get("globalversion")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let status =
            SyncStatus::from_code(value.get("status").and_then(|v| v.as_i64()).unwrap_or(0) as i32);
        let mut class_version = std::collections::BTreeMap::new();
        for entry in value
            .get("classes")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            let id = entry.get("classId").and_then(|v| v.as_u64()).unwrap_or(99) as u32;
            let Some(class) = ItemClass::from_id(id) else {
                continue;
            };
            if let Some(version) = entry.get("version").and_then(|v| v.as_str()) {
                class_version.insert(class, version.to_string());
            }
        }
        let mut items = Vec::new();
        for entry in value
            .get("items")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
        {
            let Some(uuid) = entry.get("uuid").and_then(|v| v.as_str()) else {
                continue;
            };
            let id = entry.get("classId").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let Some(class) = ItemClass::from_id(id) else {
                continue;
            };
            let blob = entry
                .get("blobB64")
                .and_then(|v| v.as_str())
                .map(decode_base64)
                .unwrap_or_default();
            items.push(Item {
                uuid: uuid.to_string(),
                class,
                item_version: entry
                    .get("itemVersion")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                meta: if is_plain_item_data(&blob) {
                    ItemMeta::parse(&blob).unwrap_or_default()
                } else {
                    ItemMeta::default()
                },
                blob,
                deleted: entry
                    .get("deleted")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
            });
        }
        Ok(Backup {
            taken_at: value
                .get("takenAt")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            global_version,
            status,
            items,
            class_version,
        })
    }
}

/// The wrapper key out of a parsed `Account` protobuf: field 5.
pub fn field5(message: &proto::Message) -> Result<[u8; KEY_LEN], String> {
    let bytes = message
        .bytes(5)
        .ok_or_else(|| "the Account row has no field 5".to_string())?;
    let key: [u8; KEY_LEN] = bytes
        .try_into()
        .map_err(|_| format!("field 5 is {} B, expected {KEY_LEN}", bytes.len()))?;
    Ok(key)
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode_base64(text: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .unwrap_or_default()
}
