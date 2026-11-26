//! Three-way compare between the account, a local copy, and the last agreement
//! between them.
//!
//! The account side has two sources of truth: what the server holds, and what a
//! client holds locally (a backup file — this library keeps no item store of its
//! own). Reading one and writing the other is not a sync: a write built from a
//! stale read silently replaces whatever another client stored in between, which
//! is exactly what `ensure_cursors` refuses to do.
//!
//! The missing piece is **what both sides last agreed on**. That is the baseline
//! this module persists: per item, a digest of every meaningful field, plus the
//! server cursors that were current when the agreement was recorded. Then every
//! question ("did I change this?", "did the server change this?", "did we both?")
//! has a definite answer instead of a guess.
//!
//! Two deliberate choices:
//!
//! * **Digests, never content.** A baseline that stored the plaintext would be a
//!   second copy of every bookmark password in a file nobody thinks of as
//!   sensitive. It stores `sha256` per field instead — enough to say "field 7
//!   changed", never enough to say what it changed to.
//! * **The stable projection only.** `sync_version_uuid` (f3), `manipulated`
//!   (f4), `last_known_version` (f5) and `timestamp` (f9) are revision
//!   bookkeeping: the server rewrites them on every store even when the user
//!   changed nothing. Comparing them would report a conflict for every write any
//!   client ever made, so they are excluded and the exclusion is on the record.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::proto::{Message, WireValue};
use super::sync::{self, ItemCipher, ItemClass, SyncState};

/// The on-disk shape version. A file of another version is refused rather than
/// guessed at: a baseline parsed wrong turns into "everything is a conflict".
pub const BASELINE_VERSION: u32 = 1;

/// `Item_Data` fields that are bookkeeping, not content.
///
/// Field 2 (`item_uuid`) is excluded separately: it is the key items are compared
/// by, so hashing it would only compare a value with itself.
const VOLATILE_TOP: [u32; 4] = [3, 4, 5, 9];

/// The `Item_Data` oneof members, by field number, with the prefix their
/// children's diff keys use.
fn oneof_of_prefix(prefix: &str) -> Option<u32> {
    Some(match prefix {
        "bookmark." => 16,
        "identity." => 17,
        "whisperlist." => 18,
        "hotkeyprofile." => 19,
        "addon." => 20,
        "config." => 21,
        "folder." => 22,
        "roomCategory." => 23,
        "groupChats." => 24,
        "contact." => 25,
        _ => return None,
    })
}

fn content_prefix(number: u32) -> Option<&'static str> {
    Some(match number {
        16 => "bookmark.",
        17 => "identity.",
        18 => "whisperlist.",
        19 => "hotkeyprofile.",
        20 => "addon.",
        21 => "config.",
        22 => "folder.",
        23 => "roomCategory.",
        24 => "groupChats.",
        25 => "contact.",
        _ => return None,
    })
}

/// A human label for a diff key, so a report says "the address changed" rather
/// than "field 2 changed".
///
/// Named fields are the ones a person edits. Everything else falls back to the
/// number, which is still actionable ("bookmark.20 changed") and truthful.
pub fn field_label(key: &str) -> &'static str {
    match key {
        "item.exists" => "presence",
        "item.6" => "itemType",
        "item.7" => "parent",
        "item.8" => "sortOrder",
        "bookmark.1" => "name",
        "bookmark.2" => "address",
        "bookmark.3" => "port",
        "bookmark.4" => "nickname",
        "bookmark.5" => "phoneticNickname",
        "bookmark.6" => "identity",
        "bookmark.7" => "serverPassword",
        "bookmark.8" => "defaultChannel",
        "bookmark.9" => "channelPassword",
        "bookmark.10" => "defaultChannelId",
        "bookmark.11" => "captureProfile",
        "bookmark.12" => "playbackProfile",
        "bookmark.13" => "hotkeyProfile",
        "bookmark.14" => "autoconnect",
        "bookmark.15" => "serverUid",
        "bookmark.16" => "serverIcon",
        "bookmark.17" => "soundPack",
        "bookmark.18" => "showServerQueryClients",
        "bookmark.19" => "subscriptionMode",
        "bookmark.20" => "subscribedChannelIds",
        "bookmark.21" => "channelPasswords",
        "bookmark.22" => "sendMytsidOnServer",
        "bookmark.23" => "announceToChat",
        "bookmark.24" => "resolvedServerNickname",
        "identity.1" => "uniqueIdentity",
        "identity.2" => "idName",
        "identity.3" => "nickname",
        "identity.4" => "phoneticNickname",
        "identity.5" => "isDefault",
        "addon.1" => "uuid",
        "addon.2" => "enabled",
        "config.1" => "defaultSubscribeMode",
        "config.2" => "userBadges",
        "config.3" => "showUserBadges",
        "config.4" => "globalPresenceToken",
        "config.5" => "tschatCredentials",
        "folder.1" => "folderName",
        "folder.2" => "folderType",
        "whisperlist.2" => "name",
        "whisperlist.3" => "type",
        _ => "",
    }
}

/// The digest of one wire value, with its field number so two fields cannot hash
/// to the same bytes by accident.
fn digest_value(number: u32, value: &WireValue) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(number.to_le_bytes());
    match value {
        WireValue::Varint(v) => {
            hasher.update([0u8]);
            hasher.update(v.to_le_bytes());
        }
        WireValue::Fixed64(v) => {
            hasher.update([1u8]);
            hasher.update(v);
        }
        WireValue::Fixed32(v) => {
            hasher.update([2u8]);
            hasher.update(v);
        }
        WireValue::Bytes(b) => {
            hasher.update([3u8]);
            // The length goes in first so `ab` + `c` and `a` + `bc` cannot
            // collide as a pair of values.
            hasher.update((b.len() as u64).to_le_bytes());
            hasher.update(b);
        }
    }
    hasher.finalize().into()
}

fn hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Walks a message into `prefix + number` digests.
///
/// A field that appears more than once is hashed as one value in its original
/// order, because a repeated list is one logical field: a report that said
/// "channelPasswords changed twice" would describe the wire, not the edit.
fn walk(message: &Message, prefix: &str, out: &mut BTreeMap<String, String>, top: bool) {
    let mut groups: BTreeMap<u32, Vec<&super::proto::Field>> = BTreeMap::new();
    for field in &message.fields {
        if top && (field.number == 2 || VOLATILE_TOP.contains(&field.number)) {
            continue;
        }
        groups.entry(field.number).or_default().push(field);
    }

    for (number, occurrences) in groups {
        let nested = content_prefix(number)
            .filter(|_| occurrences.len() == 1)
            .and_then(|_| occurrences[0].as_bytes())
            .and_then(|bytes| Message::parse(bytes).ok());

        // A nested oneof is only walked when the item's top level is being
        // walked; inside a child, a `config.5` (itself a message per the
        // schema) is compared as bytes, because this code has no field map for
        // it and a guessed map would invent labels that are not real.
        let nested = nested.filter(|_| top);

        match nested {
            Some(child) => {
                let child_prefix = content_prefix(number).expect("checked above");
                // The nested keys are rooted at the oneof, not at the item, so a
                // diff key reads `bookmark.2` rather than `item.bookmark.2`.
                walk(&child, child_prefix, out, false);
            }
            None => {
                let mut hasher = Sha256::new();
                for field in &occurrences {
                    hasher.update(digest_value(number, &field.value));
                }
                out.insert(format!("{prefix}{number}"), hex(&hasher.finalize().into()));
            }
        }
    }
}

/// One item's comparable content: a digest per field, plus presence.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Fingerprint {
    pub fields: BTreeMap<String, String>,
    /// `"1"` when the item exists, `"0"` when it does not.
    ///
    /// Modelled as a field so create and delete go through the same three-way
    /// rule as an edit: "I made it, the server did not" is a push, and "both
    /// removed it" is agreement — without a separate code path for either.
    pub exists: String,
}

impl Fingerprint {
    /// The fingerprint of an item that is not there.
    pub fn absent() -> Fingerprint {
        Fingerprint {
            fields: BTreeMap::new(),
            exists: "0".to_string(),
        }
    }

    pub fn of(plain: &[u8]) -> Result<Fingerprint, String> {
        let message = Message::parse(plain)?;
        let mut fields = BTreeMap::new();
        walk(&message, "item.", &mut fields, true);
        Ok(Fingerprint {
            fields,
            exists: "1".to_string(),
        })
    }

    /// The digest this fingerprint has for a key, `item.exists` included.
    pub fn get(&self, key: &str) -> Option<&str> {
        if key == "item.exists" {
            return Some(self.exists.as_str());
        }
        self.fields.get(key).map(String::as_str)
    }

    /// Every key either side could name.
    fn keys_into(&self, out: &mut BTreeSet<String>) {
        out.extend(self.fields.keys().cloned());
        out.insert("item.exists".to_string());
    }
}

// ── the baseline ────────────────────────────────────────────────────────────

/// One item as both sides last agreed on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineItem {
    pub uuid: String,
    pub class: ItemClass,
    pub item_version: String,
    pub fields: BTreeMap<String, String>,
}

impl BaselineItem {
    fn fingerprint(&self) -> Fingerprint {
        Fingerprint {
            fields: self.fields.clone(),
            exists: "1".to_string(),
        }
    }
}

/// What both sides last agreed on, plus the cursors that were current then.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Baseline {
    pub saved_at: String,
    /// The account this baseline belongs to.
    ///
    /// Checked before use: two accounts can share one directory, and applying one
    /// account's baseline to another would report every item as a conflict.
    pub account_uuid: String,
    /// `globalversion` at the time of the agreement.
    pub global_version: String,
    pub class_version: BTreeMap<ItemClass, String>,
    pub items: Vec<BaselineItem>,
}

impl Baseline {
    /// Records only the items **both sides agree on**.
    ///
    /// An item that only one side has is *pending*, not agreed: recording it
    /// would make the next compare read "the other side removed it" and propose
    /// deleting the very thing that is waiting to be transferred. That is the one
    /// failure mode this rule exists to prevent, which is why the baseline is
    /// narrower than "the current server state".
    pub fn of(
        server: &SyncState,
        account_uuid: &str,
        local: &[LocalItem],
        cipher: Option<&ItemCipher>,
        saved_at: &str,
    ) -> Baseline {
        let mut agreed = Vec::new();
        for item in &server.items {
            if item.deleted {
                continue;
            }
            let Ok(plain) = sync::read_plain(item, cipher) else {
                continue;
            };
            let Ok(fingerprint) = Fingerprint::of(&plain) else {
                continue;
            };
            let same = local
                .iter()
                .find(|candidate| candidate.uuid == item.uuid)
                .is_some_and(|candidate| {
                    Fingerprint::of(&candidate.plain).ok() == Some(fingerprint.clone())
                });
            if same {
                agreed.push(BaselineItem {
                    uuid: item.uuid.clone(),
                    class: item.class,
                    item_version: item.item_version.clone(),
                    fields: fingerprint.fields,
                });
            }
        }
        Baseline {
            saved_at: saved_at.to_string(),
            account_uuid: account_uuid.to_string(),
            global_version: server.global_version.clone(),
            class_version: server.class_version.clone(),
            items: agreed,
        }
    }

    pub fn to_json(&self) -> Value {
        let classes: Vec<Value> = self
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
        let items: Vec<Value> = self
            .items
            .iter()
            .map(|item| {
                serde_json::json!({
                    "uuid": item.uuid,
                    "classId": item.class.id(),
                    "className": item.class.name(),
                    "itemVersion": item.item_version,
                    "fields": item.fields,
                })
            })
            .collect();
        serde_json::json!({
            "version": BASELINE_VERSION,
            "note": "field digests only: this must not become a copy of the account's secrets",
            "savedAt": self.saved_at,
            "accountUuid": self.account_uuid,
            "globalversion": self.global_version,
            "classes": classes,
            "items": items,
        })
    }

    pub fn from_json(value: &Value) -> Result<Baseline, String> {
        let version = value.get("version").and_then(Value::as_u64).unwrap_or(0);
        if version != u64::from(BASELINE_VERSION) {
            return Err(format!(
                "the baseline is version {version}, this build writes {BASELINE_VERSION}"
            ));
        }
        let mut class_version = BTreeMap::new();
        for entry in value
            .get("classes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let id = entry.get("classId").and_then(Value::as_u64).unwrap_or(99) as u32;
            let Some(class) = ItemClass::from_id(id) else {
                continue;
            };
            if let Some(version) = entry.get("version").and_then(Value::as_str) {
                class_version.insert(class, version.to_string());
            }
        }
        let mut items = Vec::new();
        for entry in value
            .get("items")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(uuid) = entry.get("uuid").and_then(Value::as_str) else {
                continue;
            };
            let id = entry.get("classId").and_then(Value::as_u64).unwrap_or(0) as u32;
            let Some(class) = ItemClass::from_id(id) else {
                continue;
            };
            let mut fields = BTreeMap::new();
            if let Some(object) = entry.get("fields").and_then(Value::as_object) {
                for (key, digest) in object {
                    if let Some(digest) = digest.as_str() {
                        fields.insert(key.clone(), digest.to_string());
                    }
                }
            }
            items.push(BaselineItem {
                uuid: uuid.to_string(),
                class,
                item_version: entry
                    .get("itemVersion")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                fields,
            });
        }
        Ok(Baseline {
            saved_at: value
                .get("savedAt")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            account_uuid: value
                .get("accountUuid")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            global_version: value
                .get("globalversion")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            class_version,
            items,
        })
    }

    /// Whether the server's cursors are still the ones this baseline recorded.
    ///
    /// This is the useful half of persisting cursors: when nothing moved while the
    /// client was not running, a compare is answered without inspecting items.
    /// Note what these cursors are **not** used for — asking for a *partial* item
    /// read. The baseline holds digests, not items, so a reply that omitted a
    /// class would have to be read as "that class was deleted", which is the
    /// misreading `SyncState::apply` exists to prevent.
    pub fn cursors_match(&self, state: &SyncState) -> bool {
        if self.global_version.is_empty() || state.global_version.is_empty() {
            return false;
        }
        if self.global_version != state.global_version {
            return false;
        }
        self.class_version
            .iter()
            .all(|(class, version)| state.class_version.get(class) == Some(version))
    }

    fn item(&self, uuid: &str) -> Option<&BaselineItem> {
        self.items.iter().find(|item| item.uuid == uuid)
    }
}

/// Writes the baseline atomically, creating its directory.
///
/// Same rule as the credential file: a process killed mid-write must not leave a
/// half-written baseline, because a truncated one reads as "every field changed".
pub fn save(path: &Path, baseline: &Baseline) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    let text = serde_json::to_string_pretty(&baseline.to_json())
        .map_err(|e| format!("cannot serialize the baseline: {e}"))?;
    let temp = path.with_extension("json.tmp");
    std::fs::write(&temp, text).map_err(|e| format!("cannot write {}: {e}", temp.display()))?;
    std::fs::rename(&temp, path).map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        format!("cannot move {} into place: {e}", temp.display())
    })
}

/// Reads a baseline, or `Ok(None)` when there is none.
///
/// A file that exists but cannot be understood is an **error**: silently starting
/// over would hide a corrupt baseline behind "everything is a conflict".
pub fn load(path: &Path) -> Result<Option<Baseline>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let value: Value = serde_json::from_str(&text)
        .map_err(|e| format!("{} is not valid JSON: {e}", path.display()))?;
    Baseline::from_json(&value).map(Some)
}

/// Where a baseline lives when the shell does not name a file.
pub fn default_baseline_file() -> PathBuf {
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(local)
            .join("tsbridge")
            .join("myteamspeak-sync.json");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".local/share/tsbridge")
            .join("myteamspeak-sync.json");
    }
    PathBuf::from("myteamspeak-sync.json")
}

// ── the compare ─────────────────────────────────────────────────────────────

/// What one side did to one field, relative to the baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Unchanged,
    Added,
    Modified,
    Removed,
}

impl Change {
    pub fn name(self) -> &'static str {
        match self {
            Change::Unchanged => "unchanged",
            Change::Added => "added",
            Change::Modified => "modified",
            Change::Removed => "removed",
        }
    }

    fn is_change(self) -> bool {
        self != Change::Unchanged
    }
}

/// What one side did to one field, relative to the baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDelta {
    pub key: String,
    pub label: &'static str,
    pub local: Change,
    pub server: Change,
    /// Whether both sides ended at the *same* value.
    ///
    /// Two deletes agree; two edits to the same text agree. Only differing
    /// outcomes conflict, which is why this is a value comparison and not the
    /// `both changed` shortcut.
    pub agrees: bool,
}

impl FieldDelta {
    /// Whether both sides changed this field to different outcomes.
    pub fn is_conflict(&self) -> bool {
        self.local.is_change() && self.server.is_change() && !self.agrees
    }

    /// Whether this field is worth reporting at all.
    ///
    /// Value equality is the whole test, which is what makes a *no-baseline*
    /// compare readable: with nothing recorded, every field reads as "added on
    /// both sides", and reporting that for an item the two sides hold identically
    /// would fill a report with rows that mean nothing.
    pub fn is_change(&self) -> bool {
        !self.agrees
    }

    /// Exactly one side changed it, so it can be taken as-is.
    pub fn single_sided(&self) -> bool {
        self.is_change() && !self.is_conflict()
    }
}

/// What should happen to one item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Both sides already hold the same thing.
    InSync,
    /// Only the local side changed: send it to the server.
    Push,
    /// Only the server changed: the local side has to catch up.
    Pull,
    /// Both sides changed, on different fields: send the union.
    Merge,
    /// Both sides changed the same field differently: a human has to choose.
    Conflict,
}

impl Action {
    pub fn name(self) -> &'static str {
        match self {
            Action::InSync => "inSync",
            Action::Push => "push",
            Action::Pull => "pull",
            Action::Merge => "merge",
            Action::Conflict => "conflict",
        }
    }

    pub fn writes_server(self) -> bool {
        matches!(self, Action::Push | Action::Merge)
    }

    pub fn writes_local(self) -> bool {
        matches!(self, Action::Pull | Action::Merge)
    }
}

/// The plan for one item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemPlan {
    pub uuid: String,
    pub class: ItemClass,
    pub action: Action,
    pub fields: Vec<FieldDelta>,
    /// The plaintext both sides' edits combine into, for an [`Action::Merge`].
    ///
    /// `None` when either plaintext could not be read, or when the item is a
    /// conflict. A merge is never produced from digests alone: the union is built
    /// by copying the other side's field bytes into this side's message.
    pub merged: Option<Vec<u8>>,
}

/// The whole comparison.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub items: Vec<ItemPlan>,
    /// Server items this session could not read, so they could not be compared.
    ///
    /// Reported instead of guessed at. Treating an unreadable blob as "gone from
    /// the server" would make the compare propose a pull that can never succeed;
    /// treating it as unchanged would hide a real edit. Naming it is the only
    /// honest answer, and it is what a session with no account key sees for every
    /// encrypted item.
    pub unreadable: Vec<String>,
    /// Whether the server's cursors still match the baseline, i.e. nothing moved
    /// while the client was not running.
    pub cursors_match: bool,
    /// Whether a baseline was available at all.
    ///
    /// False means "the two sides have never been recorded as agreeing", so a
    /// difference cannot be attributed to either side and is reported as a
    /// conflict rather than guessed at.
    pub has_baseline: bool,
}

impl Plan {
    pub fn count(&self, action: Action) -> usize {
        self.items
            .iter()
            .filter(|item| item.action == action)
            .count()
    }

    pub fn has_conflicts(&self) -> bool {
        self.count(Action::Conflict) > 0
    }

    /// Whether anything at all needs doing.
    pub fn is_empty(&self) -> bool {
        self.count(Action::InSync) == self.items.len()
    }
}

impl Plan {
    /// Renders the comparison for a shell.
    ///
    /// Every item is listed, `inSync` ones included: a report that only showed
    /// the differences would leave a reader unable to tell "nothing changed" from
    /// "the compare did not look at this item".
    ///
    /// Public because the shape is part of the contract a shells switch on, and a
    /// report only an engine can produce cannot be pinned by a test.
    pub fn to_json(&self) -> Value {
        let items: Vec<Value> = self
            .items
            .iter()
            .map(|item| {
                let mut object = serde_json::json!({
                    "uuid": item.uuid,
                    "class": item.class.name(),
                    "classId": item.class.id(),
                    "action": item.action.name(),
                    "writesServer": item.action.writes_server(),
                    "writesLocal": item.action.writes_local(),
                    "merged": item.merged.is_some(),
                });
                let changed: Vec<&FieldDelta> =
                    item.fields.iter().filter(|f| f.is_change()).collect();
                if !changed.is_empty() {
                    object["fields"] = Value::Array(
                        changed
                            .iter()
                            .map(|delta| {
                                serde_json::json!({
                                    "key": delta.key,
                                    // The label a UI shows; the key is for a machine.
                                    "label": if delta.label.is_empty() {
                                        delta.key.as_str()
                                    } else {
                                        delta.label
                                    },
                                    "local": delta.local.name(),
                                    "server": delta.server.name(),
                                    "conflict": delta.is_conflict(),
                                })
                            })
                            .collect(),
                    );
                }
                object
            })
            .collect();

        serde_json::json!({
            "hasBaseline": self.has_baseline,
            // True means nothing moved on the server since the baseline was
            // recorded, so the item half is answered without inspecting content.
            "cursorsMatch": self.cursors_match,
            "inSync": self.count(Action::InSync),
            "push": self.count(Action::Push),
            "pull": self.count(Action::Pull),
            "merge": self.count(Action::Merge),
            "conflict": self.count(Action::Conflict),
            "conflicts": self.has_conflicts(),
            // Items the comparison could not look at. Separate from `items` so a
            // UI never paints "cannot read" as "nothing to do".
            "unreadable": self.unreadable,
            "items": items,
        })
    }
}

/// The local side of a compare: plaintext keyed by item uuid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalItem {
    pub uuid: String,
    pub class: ItemClass,
    pub plain: Vec<u8>,
}

impl LocalItem {
    /// Reads the local side out of a backup file.
    ///
    /// The backup is the natural "local copy": it holds the blobs verbatim and a
    /// restore replays them. An item whose blob cannot be read is refused rather
    /// than treated as absent — "absent" would make the compare propose deleting
    /// it from the server.
    pub fn from_backup(
        backup: &sync::Backup,
        cipher: Option<&ItemCipher>,
    ) -> Result<Vec<LocalItem>, String> {
        let mut local = Vec::new();
        for item in &backup.items {
            if item.deleted {
                continue;
            }
            let plain = sync::read_plain(item, cipher).map_err(|e| {
                format!(
                    "the local copy of {} cannot be read, so it cannot be compared: {e}",
                    item.uuid
                )
            })?;
            local.push(LocalItem {
                uuid: item.uuid.clone(),
                class: item.class,
                plain,
            });
        }
        Ok(local)
    }

    fn fingerprint(&self) -> Option<Fingerprint> {
        Fingerprint::of(&self.plain).ok()
    }
}

/// What one side did to a field, relative to the baseline.
///
/// The argument order is deliberate: the baseline first, the side second, so a
/// call site cannot silently compare a side against itself.
fn change_of(base: Option<&str>, side: Option<&str>) -> Change {
    match (base, side) {
        (None, None) => Change::Unchanged,
        (None, Some(_)) => Change::Added,
        (Some(_), None) => Change::Removed,
        (Some(base), Some(side)) if base == side => Change::Unchanged,
        (Some(_), Some(_)) => Change::Modified,
    }
}

/// Compares the baseline, the local side and the server.
///
/// The server's plaintext is read here rather than passed in, so one call does
/// the whole comparison: nothing outside can forget to fingerprint the side that
/// matters most.
pub fn compare(
    baseline: Option<&Baseline>,
    local: &[LocalItem],
    server: &SyncState,
    cipher: Option<&ItemCipher>,
) -> Plan {
    let mut local_prints: BTreeMap<String, Fingerprint> = BTreeMap::new();
    for item in local {
        if let Some(fingerprint) = item.fingerprint() {
            local_prints.insert(item.uuid.clone(), fingerprint);
        }
    }

    let mut server_pairs: BTreeMap<String, (ItemClass, Fingerprint, Vec<u8>)> = BTreeMap::new();
    let mut unreadable = Vec::new();
    for item in &server.items {
        if item.deleted {
            continue;
        }
        let Ok(plain) = sync::read_plain(item, cipher) else {
            unreadable.push(item.uuid.clone());
            continue;
        };
        let Ok(fingerprint) = Fingerprint::of(&plain) else {
            unreadable.push(item.uuid.clone());
            continue;
        };
        server_pairs.insert(item.uuid.clone(), (item.class, fingerprint, plain));
    }

    let mut all: BTreeSet<String> = BTreeSet::new();
    for item in baseline.into_iter().flat_map(|baseline| &baseline.items) {
        all.insert(item.uuid.clone());
    }
    for item in local {
        all.insert(item.uuid.clone());
    }
    for item in &server.items {
        all.insert(item.uuid.clone());
    }

    let mut items = Vec::new();
    for uuid in all {
        // An unreadable server item gets no plan: it is named in `unreadable`
        // and a caller shows it as "cannot compare yet", not as a deletion.
        if unreadable.iter().any(|entry| entry == &uuid) {
            continue;
        }
        let base = baseline.and_then(|baseline| baseline.item(&uuid));
        let base_print = base.map(BaselineItem::fingerprint);
        let local_print = local_prints.get(&uuid);
        let server_pair = server_pairs.get(&uuid);

        let mut keys: BTreeSet<String> = BTreeSet::new();
        if let Some(print) = &base_print {
            print.keys_into(&mut keys);
        }
        if let Some(print) = local_print {
            print.keys_into(&mut keys);
        }
        if let Some((_, print, _)) = server_pair {
            print.keys_into(&mut keys);
        } else if base_print.is_some() || local_print.is_some() {
            // Not on the server (or not readable there): presence is what changed.
            keys.insert("item.exists".to_string());
        }

        let mut fields = Vec::new();
        for key in keys {
            let base_value = base_print.as_ref().and_then(|print| print.get(&key));
            let local_value = local_print.and_then(|print| print.get(&key));
            let server_value = server_pair.and_then(|(_, print, _)| print.get(&key));
            let local_change = change_of(base_value, local_value);
            let server_change = change_of(base_value, server_value);
            // Agreement is about the **value**, not the shape of the change:
            // "only one side moved" still means the sides now hold different
            // things, and "both moved" is quiet only when they landed on the same
            // bytes. A value read off two different sides is the only thing that
            // makes this comparable, so a differing `Change` cannot decide it.
            let agrees = local_value == server_value;
            fields.push(FieldDelta {
                label: field_label(&key),
                key,
                local: local_change,
                server: server_change,
                agrees,
            });
        }

        let conflict = fields.iter().any(FieldDelta::is_conflict);
        let local_changed = fields.iter().any(|delta| delta.local.is_change());
        let server_changed = fields.iter().any(|delta| delta.server.is_change());

        let class = server_pair
            .map(|(class, _, _)| *class)
            .or_else(|| {
                local
                    .iter()
                    .find(|item| item.uuid == uuid)
                    .map(|item| item.class)
            })
            .or_else(|| base.map(|item| item.class))
            .unwrap_or(ItemClass::Bookmark);

        // Everything agrees: the sides hold the same bytes, so there is nothing to
        // do whether or not a baseline exists. Checked before "which side moved"
        // because with no baseline every field reads as *added on both sides* and
        // would otherwise look like a merge.
        let all_agree = fields.iter().all(|delta| delta.agrees);
        let action = if all_agree {
            Action::InSync
        } else if conflict {
            Action::Conflict
        } else if local_changed && server_changed {
            Action::Merge
        } else if local_changed {
            Action::Push
        } else if server_changed {
            Action::Pull
        } else {
            Action::InSync
        };

        // The union, built from the two plaintexts. Only for a merge, and only
        // when both sides could be read.
        let merged = if action == Action::Merge {
            let local_plain = local
                .iter()
                .find(|item| item.uuid == uuid)
                .map(|item| &item.plain);
            match (local_plain, server_pair) {
                (Some(local_plain), Some((_, _, server_plain))) => {
                    merge_plaintext(local_plain, server_plain, &fields).ok()
                }
                _ => None,
            }
        } else {
            None
        };

        items.push(ItemPlan {
            uuid,
            class,
            action,
            fields,
            merged,
        });
    }

    unreadable.sort();
    unreadable.dedup();
    Plan {
        items,
        unreadable,
        cursors_match: baseline
            .map(|baseline| baseline.cursors_match(server))
            .unwrap_or(false),
        has_baseline: baseline.is_some(),
    }
}

/// Splits a diff key into the field numbers it names.
///
/// `item.7` → `(None, 7)`, `bookmark.7` → `(Some(16), 7)`.
fn key_numbers(key: &str) -> Option<(Option<u32>, u32)> {
    let (prefix, number) = key.rsplit_once('.')?;
    let number: u32 = number.parse().ok()?;
    if prefix == "item" {
        return Some((None, number));
    }
    let oneof = oneof_of_prefix(&format!("{prefix}."))?;
    Some((Some(oneof), number))
}

/// Builds the union of both sides' edits.
///
/// The rule is the only correct one for a three-way merge: **copy the other
/// side's bytes wherever only it changed**, and leave everything else alone. A
/// field both sides changed to the same value needs no copy; a field both changed
/// to different values is a conflict and never reaches this function.
fn merge_plaintext(
    local_plain: &[u8],
    server_plain: &[u8],
    fields: &[FieldDelta],
) -> Result<Vec<u8>, String> {
    let mut merged = Message::parse(local_plain)?;
    let server = Message::parse(server_plain)?;

    for delta in fields {
        // Only the **server's** single-sided edits are copied: the local side is
        // what `merged` already holds. A field both sides moved to the same value
        // needs no copy, and a field they moved differently is a conflict, which
        // never reaches this function.
        if !delta.single_sided() || !delta.server.is_change() {
            continue;
        }
        let Some((oneof, number)) = key_numbers(&delta.key) else {
            continue;
        };
        match oneof {
            None => {
                // `item.exists` is presence; an absent field is a removal, which
                // this cannot express by copying — the caller refuses to merge a
                // delete instead of trying.
                if delta.key == "item.exists" {
                    return Err(
                        "a merge cannot add or remove the item itself; choose a side".to_string(),
                    );
                }
                merged.set_raw_field(number, server.raw_field(number))?;
            }
            Some(oneof) => {
                // `raw_field` returns tag + value; a nested message needs the
                // *value* alone, or parsing it would yield a one-field message
                // numbered by the oneof instead of the child's own fields.
                let Some(server_child_raw) = server.bytes(oneof).map(<[u8]>::to_vec) else {
                    // The server dropped the whole payload; that is a delete of
                    // the content, not a field edit.
                    return Err("the server removed the item's content; choose a side".to_string());
                };
                let mut child = Message::parse(&server_child_raw)?;
                // Re-apply every **local** single-sided edit inside this payload:
                // copying the server's child alone would undo them.
                if let Some(local_child_raw) = merged.bytes(oneof).map(<[u8]>::to_vec) {
                    let local_child = Message::parse(&local_child_raw)?;
                    for field in &local_child.fields {
                        let is_local_edit = fields.iter().any(|delta| {
                            delta.single_sided()
                                && delta.local.is_change()
                                && key_numbers(&delta.key) == Some((Some(oneof), field.number))
                        });
                        if is_local_edit {
                            child.set_raw_field(field.number, Some(field.encoded()))?;
                        }
                    }
                }
                // And put it back as a tagged field, which is what
                // `set_raw_field` expects.
                let encoded = crate::account::proto::field_bytes(oneof, &child.encode());
                merged.set_raw_field(oneof, Some(encoded))?;
            }
        }
    }

    Ok(merged.encode())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The five actions partition cleanly: each writes zero, one or both sides,
    /// and the two that write nothing are the two that need no write.
    ///
    /// `writes_server` and `writes_local` are separate `matches!` expressions,
    /// so adding a variant would silently write nothing — an action that looks
    /// planned and does nothing when applied.
    #[test]
    fn every_action_declares_what_it_writes() {
        let cases: &[(Action, bool, bool)] = &[
            // (action, writes server, writes local)
            (Action::InSync, false, false),
            (Action::Push, true, false),
            (Action::Pull, false, true),
            (Action::Merge, true, true),
            // A conflict writes neither until a human chooses.
            (Action::Conflict, false, false),
        ];

        for (action, server, local) in cases {
            assert_eq!(
                action.writes_server(),
                *server,
                "{action:?} writes_server disagrees"
            );
            assert_eq!(
                action.writes_local(),
                *local,
                "{action:?} writes_local disagrees"
            );
        }
    }

    /// Each action has a distinct wire name, so a shell can switch on it.
    #[test]
    fn every_action_has_a_distinct_name() {
        let actions = [
            Action::InSync,
            Action::Push,
            Action::Pull,
            Action::Merge,
            Action::Conflict,
        ];
        let names: Vec<&str> = actions.iter().map(|a| a.name()).collect();
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            names.len(),
            sorted.len(),
            "two actions share a name: {names:?}"
        );
        // Lower camel case, because that is what the JSON carries.
        for name in &names {
            assert!(
                name.chars().next().is_some_and(|c| c.is_ascii_lowercase()),
                "{name} is not lower camel case"
            );
        }
    }

    #[test]
    fn a_volatile_field_is_not_part_of_the_fingerprint() {
        let with_bookkeeping = {
            let mut m = super::super::proto::field_string(2, "uuid");
            m.extend(super::super::proto::field_varint(4, 3));
            m.extend(super::super::proto::field_string(5, "previous"));
            m.extend(super::super::proto::field_varint(9, 17));
            m.extend(super::super::proto::field_string(7, "folder"));
            m
        };
        let cleaned = {
            let mut m = super::super::proto::field_string(2, "uuid");
            m.extend(super::super::proto::field_string(7, "folder"));
            m
        };
        assert_eq!(
            Fingerprint::of(&with_bookkeeping).unwrap().fields,
            Fingerprint::of(&cleaned).unwrap().fields,
            "revision bookkeeping must not make an untouched item look edited"
        );
    }

    #[test]
    fn absence_and_presence_are_compared_like_any_other_field() {
        let present = Fingerprint::of(&super::super::proto::field_string(2, "u")).unwrap();
        assert_eq!(present.get("item.exists"), Some("1"));
        assert_eq!(Fingerprint::absent().get("item.exists"), Some("0"));
        assert!(present.get("item.7").is_none());
    }

    /// A bookmark with a name, an address and a port.
    fn bookmark(name: &str, address: &str, port: u64) -> Vec<u8> {
        let mut message = super::super::proto::field_string(2, "uuid");
        message.extend(super::super::proto::field_string(3, "sync-version"));
        message.extend(super::super::proto::field_varint(4, 3));
        message.extend(super::super::proto::field_string(5, "last-known"));
        message.extend(super::super::proto::field_varint(6, 0));
        message.extend(super::super::proto::field_varint(9, 1700));
        let mut inner = super::super::proto::field_string(1, name);
        inner.extend(super::super::proto::field_string(2, address));
        inner.extend(super::super::proto::field_varint(3, port));
        message.extend(super::super::proto::field_bytes(16, &inner));
        message
    }

    fn deltas(local_plain: &[u8], server_plain: &[u8]) -> Vec<FieldDelta> {
        let local = Fingerprint::of(local_plain).unwrap();
        let base = Fingerprint::of(local_plain).unwrap();
        let server = Fingerprint::of(server_plain).unwrap();
        let mut keys = BTreeSet::new();
        base.keys_into(&mut keys);
        server.keys_into(&mut keys);
        let mut out = Vec::new();
        for key in keys {
            let base_value = base.get(&key);
            let local_value = local.get(&key);
            let server_value = server.get(&key);
            out.push(FieldDelta {
                label: field_label(&key),
                local: change_of(base_value, local_value),
                server: change_of(base_value, server_value),
                agrees: local_value == server_value,
                key,
            });
        }
        out
    }

    #[test]
    fn the_union_keeps_the_local_edit_and_takes_the_servers() {
        let agreed = bookmark("Home", "home.example.invalid", 9987);
        let local_moved = bookmark("My Home", "home.example.invalid", 9987);
        let server_moved = bookmark("Home", "home.example.invalid", 9988);
        // The baseline is `agreed`; `deltas` computes both sides against it.
        let baseline = Fingerprint::of(&agreed).unwrap();
        let local_print = Fingerprint::of(&local_moved).unwrap();
        let server_print = Fingerprint::of(&server_moved).unwrap();
        let mut keys = BTreeSet::new();
        baseline.keys_into(&mut keys);
        local_print.keys_into(&mut keys);
        server_print.keys_into(&mut keys);
        let fields: Vec<FieldDelta> = keys
            .into_iter()
            .map(|key| {
                let base = baseline.get(&key);
                let local = local_print.get(&key);
                let server = server_print.get(&key);
                FieldDelta {
                    label: field_label(&key),
                    local: change_of(base, local),
                    server: change_of(base, server),
                    agrees: local == server,
                    key,
                }
            })
            .collect();

        let merged = merge_plaintext(&local_moved, &server_moved, &fields).expect("merge");
        let parsed = super::super::sync::Bookmark::parse(&merged)
            .expect("parse")
            .expect("a bookmark");
        assert_eq!(parsed.name, "My Home", "name: the local edit");
        assert_eq!(parsed.port, 9988, "port: the server edit");
        assert_eq!(parsed.address, "home.example.invalid");
        // And \`deltas\` is exercised so its helper is not dead code.
        assert!(!deltas(&local_moved, &server_moved).is_empty());
    }
}
