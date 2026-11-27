//! The handshake body a real server sends must parse.
//!
//! `InitServer` is the one reply nothing else can recover from: if it fails to
//! parse the connection never becomes usable, and the only symptom is a timeout
//! that looks like a network problem. A required attribute the server does not
//! send is enough to cause it, and no offline test noticed until a live server
//! was in front of the code — `virtualserver_filebase` was declared required for
//! months of rounds and is sent by neither 3.11 nor 3.13.
//!
//! So the check here is not "does the declaration look right" but "does a body
//! captured from a server parse against it". Two captures are pinned: the 3.11
//! body the vendored tsclientlib ships as a fixture, and one taken from a 3.13.9
//! server. Between them they cover the versions a client is likely to meet.
//!
//! The second test is the general form: every attribute declared *required* must
//! appear in every captured body. That is what fails when a field is added to the
//! declaration because some other message carries it.

use std::collections::BTreeSet;

use tsclientlib::messages::s2c::InMessage;
use tsproto_packets::packets::{Direction, Flags, OutPacket, PacketType};

/// `initserver` as 3.11.0 sends it, copied from the fixture in
/// `vendor/tsclientlib/tsclientlib/src/tests.rs`.
///
/// That fixture ends in `virtualserver_icon_id={}` because it is a `format!`
/// template for the icon-id tests. On the wire the field is a number, so the
/// capture here substitutes one.
const INIT_3_11: &str = r#"initserver virtualserver_name=TeamSpeak\s]I[\sServer virtualserver_welcomemessage=Welcome\sto\sTeamSpeak,\scheck\s[URL]www.teamspeak.com[\/URL]\sfor\slatest\sinformation virtualserver_platform=Linux virtualserver_version=3.11.0\s[Build:\s1578903157] virtualserver_maxclients=32 virtualserver_created=1571572631 virtualserver_codec_encryption_mode=2 virtualserver_hostmessage virtualserver_hostmessage_mode=0 virtualserver_default_server_group=8 virtualserver_default_channel_group=8 virtualserver_hostbanner_url virtualserver_hostbanner_gfx_url virtualserver_hostbanner_gfx_interval=0 virtualserver_priority_speaker_dimm_modificator=-18.0000 virtualserver_id=1 virtualserver_hostbutton_tooltip virtualserver_hostbutton_url virtualserver_hostbutton_gfx_url virtualserver_name_phonetic virtualserver_ip=0.0.0.0,\s:: virtualserver_ask_for_privilegekey=0 virtualserver_hostbanner_mode=0 virtualserver_channel_temp_delete_delay_default=0 virtualserver_nickname client_nickname=TeamSpeakUser client_version=3.?.?\s[Build:\s5680278000] client_platform=Windows client_input_muted=0 client_output_muted=0 client_outputonly_muted=0 client_input_hardware=1 client_output_hardware=1 client_default_channel client_default_channel_password client_server_password client_meta_data client_version_sign=DX5NIYLvfJEUjuIbCidnoeozxIDRRkpq3I9vVMBmE9L2qnekOoBzSenkzsg2lC9CMv8K5hkEzhr2TYUYSwUXCg== client_security_hash client_key_offset=354 client_away=0 client_away_message client_nickname_phonetic client_default_token client_badges client_myteamspeak_id client_integrations client_active_integrations_info client_myteamspeak_avatar client_signed_badges acn=TeamSpeakUser aclid=2 pv=7 client_talk_power=75 client_needed_serverquery_view_power=75 virtualserver_icon_id=0"#;

/// `initserver` as 3.13.9 sends it, captured from a live server.
const INIT_3_13: &str = r#"initserver virtualserver_name=TeamSpeak\s]I[\sServer virtualserver_welcomemessage=Welcome\sto\sTeamSpeak,\scheck\s[URL]www.teamspeak.com[\/URL]\sfor\slatest\sinformation virtualserver_platform=OS\sX virtualserver_version=3.13.9\s[Build:\s1794240694] virtualserver_maxclients=32 virtualserver_created=1795682124 virtualserver_codec_encryption_mode=0 virtualserver_hostmessage virtualserver_hostmessage_mode=0 virtualserver_default_server_group=8 virtualserver_default_channel_group=8 virtualserver_hostbanner_url virtualserver_hostbanner_gfx_url virtualserver_hostbanner_gfx_interval=0 virtualserver_priority_speaker_dimm_modificator=-18.0000 virtualserver_id=1 virtualserver_hostbutton_tooltip virtualserver_hostbutton_url virtualserver_hostbutton_gfx_url virtualserver_name_phonetic virtualserver_icon_id=0 virtualserver_ip=0.0.0.0,\s:: virtualserver_ask_for_privilegekey=1 virtualserver_hostbanner_mode=0 virtualserver_channel_temp_delete_delay_default=0 virtualserver_nickname virtualserver_capability_extensions client_nickname=probe client_version=3.?.?\s[Build:\s5680278000] client_platform=Windows client_input_muted=0 client_output_muted=0 client_outputonly_muted=0 client_input_hardware=1 client_output_hardware=1 client_default_channel client_default_channel_password client_server_password client_meta_data client_version_sign=DX5NIYLvfJEUjuIbCidnoeozxIDRRkpq3I9vVMBmE9L2qnekOoBzSenkzsg2lC9CMv8K5hkEzhr2TYUYSwUXCg== client_security_hash client_key_offset=45 client_away=0 client_away_message client_nickname_phonetic client_default_token client_badges client_myteamspeak_id client_integrations client_active_integrations_info client_myteamspeak_avatar client_signed_badges acn=probe aclid=7 pv=7 client_talk_power=0 client_needed_serverquery_view_power=75"#;

fn header() -> OutPacket {
    OutPacket::new_with_dir(Direction::S2C, Flags::empty(), PacketType::Command)
}

/// The argument names a captured body carries.
///
/// A bare `name` with no `=` is still an argument — an empty string value, which
/// is how the server sends a field that has nothing to say. Splitting on `=`
/// would lose those, and they are the ones most likely to be declared required
/// and then missing.
fn body_keys(body: &str) -> BTreeSet<String> {
    body.split(' ')
        .skip(1)
        .filter(|token| !token.is_empty())
        .map(|token| token.split('=').next().unwrap_or(token).to_string())
        .collect()
}

/// The wire name of a declared attribute.
///
/// A declaration may scope a name to one message with `@<message>`, which is how
/// `client_nickname@initserver` and the plain `client_nickname` of other messages
/// can both exist. The part before the `@` is what the server sends.
fn wire_name(attribute: &str) -> String {
    attribute.split('@').next().unwrap_or(attribute).to_string()
}

/// The attributes `InitServer` declares, split into required and optional.
fn init_server_attributes() -> (BTreeSet<String>, BTreeSet<String>) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vendor/tsclientlib/utils/tsproto-structs/declarations/Messages.toml");
    let text = std::fs::read_to_string(path).expect("declarations");
    let start = text
        .find("{ name=\"InitServer\"")
        .expect("InitServer is declared");
    let rest = &text[start..];
    let open = rest.find('[').expect("an attributes list");
    let close = rest.find(']').expect("a closing bracket");

    let mut required = BTreeSet::new();
    let mut optional = BTreeSet::new();
    for item in rest[open + 1..close].split(',') {
        let item = item.trim().trim_matches('"');
        if item.is_empty() {
            continue;
        }
        match item.strip_suffix('?') {
            Some(name) => {
                optional.insert(wire_name(name));
            }
            None => {
                required.insert(wire_name(item));
            }
        }
    }
    (required, optional)
}

/// Both captures parse.
///
/// This is the check that would have caught `virtualserver_filebase`: it was
/// declared required, neither server sends it, and `InMessage::new` rejects the
/// whole body over one missing parameter.
#[test]
fn a_real_initserver_body_parses() {
    let packet = header();
    for (version, body) in [("3.11.0", INIT_3_11), ("3.13.9", INIT_3_13)] {
        match InMessage::new(&packet.header(), body.as_bytes()) {
            Ok(InMessage::InitServer(parts)) => {
                let part = parts.iter().next().expect("one entry");
                assert!(
                    !part.name.is_empty(),
                    "{version}: the server name came through empty"
                );
                assert_eq!(part.max_clients, 32, "{version}: max clients");
                assert_eq!(part.virtual_server_id, 1, "{version}: server id");
            }
            Ok(other) => panic!("{version}: parsed as {}", other.get_command_name()),
            Err(error) => panic!("{version}: initserver did not parse: {error}"),
        }
    }
}

/// Every attribute declared required is actually sent.
///
/// An optional attribute may be absent; a required one may not, and making a
/// field optional is the fix when a server does not send it. This reports the
/// offender by name instead of leaving a bare parse error.
#[test]
fn every_required_attribute_is_sent() {
    let (required, optional) = init_server_attributes();
    assert!(!required.is_empty(), "no required attributes were read");

    for (version, body) in [("3.11.0", INIT_3_11), ("3.13.9", INIT_3_13)] {
        let keys = body_keys(body);
        let missing: Vec<&String> = required.difference(&keys).collect();
        assert!(
            missing.is_empty(),
            "{version} does not send these attributes declared required: {missing:?}\n\
             Make them optional (`?`) rather than dropping them: an older server may still send them."
        );

        // The other direction, so a field that disappears from a capture is not
        // silently ignored: everything the body carries must be declared, or the
        // parser rejects the reply for the opposite reason.
        let undeclared: Vec<&String> = keys
            .iter()
            .filter(|key| !required.contains(*key) && !optional.contains(*key))
            .collect();
        assert!(
            undeclared.is_empty(),
            "{version} sends attributes InitServer does not declare: {undeclared:?}"
        );
    }
}

/// The capture-based check finds a required field that is absent.
///
/// The real comparison cannot be made to fail without editing the declarations,
/// so this pins the direction on inputs chosen to fail.
#[test]
fn the_check_finds_a_required_field_that_is_not_sent() {
    let required: BTreeSet<String> = ["virtualserver_name", "virtualserver_filebase"]
        .into_iter()
        .map(str::to_string)
        .collect();
    let keys = body_keys("initserver virtualserver_name=Test virtualserver_maxclients=32");
    let missing: Vec<&String> = required.difference(&keys).collect();
    assert_eq!(missing, vec!["virtualserver_filebase"]);
}
