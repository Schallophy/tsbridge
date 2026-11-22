//! The command protocol between the host UI and the connection thread.
//!
//! Everything the UI can *do* arrives through one entry point ([`parse`]) as a
//! name plus a JSON object. That is deliberately a single entry point: the FFI
//! surface stays the same size no matter how many features exist, and adding one
//! is a match arm here plus a caller in each shell — no new symbol, no
//! regenerated headers, no chance of the two sides disagreeing about arity.

use serde_json::Value;

use crate::handle::{Command, TextTarget};

/// Parses one command. Errors are user-facing strings: they end up in the log
/// right next to the button that caused them.
pub fn parse(name: &str, args: &str) -> Result<Command, String> {
    let json: Value = if args.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(args).map_err(|e| format!("bad arguments: {e}"))?
    };

    match name {
        "disconnect" => Ok(Command::Disconnect),

        "send_text" => Ok(Command::SendText {
            target: match str_field(&json, "target")? {
                "server" => TextTarget::Server,
                "channel" => TextTarget::Channel,
                "client" => TextTarget::Client(int_field(&json, "clientId")?),
                other => return Err(format!("unknown message target: {other}")),
            },
            message: str_field(&json, "message")?.to_string(),
        }),

        "poke" => Ok(Command::Poke {
            client_id: int_field(&json, "clientId")?,
            message: str_field(&json, "message")?.to_string(),
        }),

        "join_channel" => Ok(Command::JoinChannel {
            channel_id: long_field(&json, "channelId")?,
            password: optional_str(&json, "password"),
        }),

        "set_input_muted" => Ok(Command::SetInputMuted(bool_field(&json, "muted")?)),
        "set_output_muted" => Ok(Command::SetOutputMuted(bool_field(&json, "muted")?)),

        "set_away" => Ok(Command::SetAway {
            away: bool_field(&json, "away")?,
            message: optional_str(&json, "message"),
        }),

        "set_nickname" => Ok(Command::SetNickname(
            str_field(&json, "nickname")?.to_string(),
        )),

        "list_files" => Ok(Command::ListFiles {
            channel_id: long_field(&json, "channelId")?,
            path: normalize_path(&optional_str(&json, "path").unwrap_or_else(|| "/".to_string())),
            password: optional_str(&json, "password"),
        }),

        "download" => Ok(Command::Download {
            channel_id: long_field(&json, "channelId")?,
            path: normalize_path(str_field(&json, "path")?),
            local: str_field(&json, "local")?.to_string(),
            password: optional_str(&json, "password"),
        }),

        "upload" => Ok(Command::Upload {
            channel_id: long_field(&json, "channelId")?,
            path: normalize_path(str_field(&json, "path")?),
            local: str_field(&json, "local")?.to_string(),
            password: optional_str(&json, "password"),
            overwrite: json
                .get("overwrite")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        }),

        "audio_enabled" => Ok(Command::SetAudioEnabled(bool_field(&json, "enabled")?)),

        "set_mic_gain" => Ok(Command::SetMicGain(f32_field(&json, "gain")?)),
        "set_user_volume" => Ok(Command::SetUserVolume {
            client_id: int_field(&json, "clientId")?,
            volume: f32_field(&json, "volume")?,
        }),
        "set_whisper_targets" => Ok(Command::SetWhisperTargets {
            clients: u16_array(&json, "clients")?,
            channels: u64_array(&json, "channels")?,
            groups: whisper_groups(&json)?,
        }),

        other => Err(format!("unknown command: {other}")),
    }
}

fn str_field<'a>(json: &'a Value, key: &str) -> Result<&'a str, String> {
    json.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field `{key}`"))
}

fn optional_str(json: &Value, key: &str) -> Option<String> {
    json.get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn int_field(json: &Value, key: &str) -> Result<i32, String> {
    json.get(key)
        .and_then(Value::as_i64)
        .map(|value| value as i32)
        .ok_or_else(|| format!("missing integer field `{key}`"))
}

fn long_field(json: &Value, key: &str) -> Result<i64, String> {
    json.get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| format!("missing integer field `{key}`"))
}

fn bool_field(json: &Value, key: &str) -> Result<bool, String> {
    json.get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("missing boolean field `{key}`"))
}

/// TeamSpeak file paths are always absolute. Accepting `name` as well as
/// `/name` keeps every shell from having to remember the leading slash.
fn normalize_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn f32_field(json: &Value, key: &str) -> Result<f32, String> {
    json.get(key)
        .and_then(Value::as_f64)
        .map(|value| value as f32)
        .ok_or_else(|| format!("missing number field `{key}`"))
}

fn u16_array(json: &Value, key: &str) -> Result<Vec<u16>, String> {
    let Some(value) = json.get(key) else {
        return Ok(Vec::new());
    };
    let items = value
        .as_array()
        .ok_or_else(|| format!("`{key}` must be an array"))?;
    items
        .iter()
        .map(|item| {
            item.as_u64()
                .and_then(|id| u16::try_from(id).ok())
                .ok_or_else(|| format!("`{key}` contains a non-client id"))
        })
        .collect()
}

fn u64_array(json: &Value, key: &str) -> Result<Vec<u64>, String> {
    let Some(value) = json.get(key) else {
        return Ok(Vec::new());
    };
    let items = value
        .as_array()
        .ok_or_else(|| format!("`{key}` must be an array"))?;
    items
        .iter()
        .map(|item| {
            item.as_u64()
                .ok_or_else(|| format!("`{key}` contains a non-integer id"))
        })
        .collect()
}

/// Group whisper targets use the new-protocol packet. Names are resolved here
/// so every shell sends the same protocol numbers.
fn whisper_groups(json: &Value) -> Result<Vec<(u8, u8, u64)>, String> {
    let Some(value) = json.get("groups") else {
        return Ok(Vec::new());
    };
    let items = value
        .as_array()
        .ok_or_else(|| "`groups` must be an array".to_string())?;
    items
        .iter()
        .map(|group| {
            let kind = match str_field(group, "type")? {
                "server_group" => 0,
                "channel_group" => 1,
                "channel_commander" => 2,
                "all_clients" => 3,
                other => return Err(format!("unknown whisper group type: {other}")),
            };
            let target = match group
                .get("target")
                .and_then(Value::as_str)
                .unwrap_or("all_channels")
            {
                "all_channels" => 0,
                "current_channel" => 1,
                "parent_channel" => 2,
                "all_parent_channel" => 3,
                "channel_family" => 4,
                "complete_channel_family" => 5,
                "subchannels" => 6,
                other => return Err(format!("unknown whisper target: {other}")),
            };
            let id = group.get("id").and_then(Value::as_u64).unwrap_or(0);
            Ok((kind, target, id))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_paths_get_a_leading_slash() {
        let command = parse("list_files", r#"{"channelId":1,"path":"docs"}"#).unwrap();
        match command {
            Command::ListFiles { path, .. } => assert_eq!(path, "/docs"),
            other => panic!("unexpected command: {other:?}"),
        }
    }
}
