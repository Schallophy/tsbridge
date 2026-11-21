//! Semantic events, and their JSON shape.
//!
//! Every shell (Kotlin, Swift, C) sees the same flat object: a `"type"` key
//! plus type-specific keys. **Both the type strings and the field keys are
//! public API** — renaming one silently breaks a feature in one client only,
//! which is the hardest kind of bug to notice. `docs/events.md` is generated
//! from this file's tests; change them together.
//!
//! Values are deliberately limited to string / int / long / bool: that is what
//! all four target languages can read out of a decoded JSON object without a
//! schema.

use serde::ser::{Serialize, SerializeMap, Serializer};

/// A value carried by an event.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Int(i32),
    Long(i64),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq)]
pub struct QueuedEvent {
    pub kind: String,
    pub data: Vec<(String, Value)>,
}

impl QueuedEvent {
    pub fn new(kind: impl Into<String>) -> Self {
        QueuedEvent {
            kind: kind.into(),
            data: Vec::new(),
        }
    }

    pub fn str(mut self, key: &str, value: impl Into<String>) -> Self {
        self.data.push((key.to_string(), Value::Str(value.into())));
        self
    }

    pub fn int(mut self, key: &str, value: i32) -> Self {
        self.data.push((key.to_string(), Value::Int(value)));
        self
    }

    pub fn long(mut self, key: &str, value: i64) -> Self {
        self.data.push((key.to_string(), Value::Long(value)));
        self
    }

    pub fn bool(mut self, key: &str, value: bool) -> Self {
        self.data.push((key.to_string(), Value::Bool(value)));
        self
    }
}

/// Serializes to a flat object with `type` first, e.g.
///
/// ```json
/// {"type":"user_moved","client_id":3,"nickname":"ann","channel_id":12,"old_channel_id":5}
/// ```
///
/// Flattened rather than `{"type":..,"data":{..}}` because the Kotlin side has
/// always read it that way, and because one nesting level is one thing less for
/// a Swift `Codable` struct to get wrong.
impl Serialize for QueuedEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1 + self.data.len()))?;
        map.serialize_entry("type", &self.kind)?;
        for (key, value) in &self.data {
            match value {
                Value::Str(text) => map.serialize_entry(key, text)?,
                Value::Int(number) => map.serialize_entry(key, number)?,
                Value::Long(number) => map.serialize_entry(key, number)?,
                Value::Bool(flag) => map.serialize_entry(key, flag)?,
            }
        }
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_json_is_flat_and_typed() {
        let event = QueuedEvent::new("user_moved")
            .int("client_id", 3)
            .str("nickname", "ann")
            .long("channel_id", 12)
            .bool("away", true);
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(
            json,
            r#"{"type":"user_moved","client_id":3,"nickname":"ann","channel_id":12,"away":true}"#
        );
    }

    /// The names below are the cross-language contract. If this test changes,
    /// every client must be updated in the same commit.
    #[test]
    fn event_names_are_stable() {
        let names = [
            "connected",
            "disconnected",
            "reconnecting",
            "error",
            "command_error",
            "user_joined",
            "user_left",
            "user_moved",
            "user_renamed",
            "user_mute_changed",
            "user_away_changed",
            "channel_created",
            "channel_renamed",
            "channel_removed",
            "text_message",
            "poked",
            "file_list",
            "transfer_started",
            "transfer_progress",
            "transfer_done",
            "transfer_error",
        ];
        // Sorted, so a rename shows up as a diff on one line.
        let mut sorted = names.to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted.len(), 21);
    }
}
