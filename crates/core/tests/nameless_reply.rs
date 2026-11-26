//! The nameless-reply path, end to end.
//!
//! A reply declared `response=true` with no `notify` name arrives as a bare
//! argument list, so `InMessage::new` has no name to match and would drop it.
//! The request declares the reply type up front and the answer is matched back
//! by `return_code`. These tests drive the three pieces in the order the
//! connection does: what the request writes, how the code is recovered, and how
//! the body becomes a typed message.

use tsclientlib::messages::s2c::InMessage;
use tsproto_packets::commands::CommandParser;
use tsproto_packets::packets::{Direction, Flags, OutCommand, OutPacket, PacketType};

/// The `return_code` a nameless reply carries.
///
/// Duplicated from the private helper in `tsclientlib` so the test asserts the
/// behaviour rather than calling the code it is meant to check. If the two ever
/// disagree the connection would stop finding its answers, which is exactly the
/// failure this is here to catch.
fn return_code(content: &[u8]) -> Option<u16> {
    let (_, mut args) = CommandParser::new(content);
    for item in &mut args {
        if let tsproto_packets::commands::CommandItem::Argument(arg) = item {
            if arg.name() == b"return_code" {
                return arg.value().get_str().ok()?.parse().ok();
            }
        }
    }
    None
}

fn header() -> OutPacket {
    OutPacket::new_with_dir(Direction::S2C, Flags::empty(), PacketType::Command)
}

/// What `send_expecting` puts on the wire: the request's own arguments plus the
/// code the answer will be matched on.
fn request_with_code(name: &str, code: u16) -> Vec<u8> {
    let mut packet = OutCommand::new(Direction::C2S, Flags::empty(), PacketType::Command, name);
    packet.write_arg("cldbid", &1);
    packet.write_arg("return_code", &code);
    packet.into_packet().content().to_vec()
}

#[test]
fn a_request_carries_the_code_its_answer_will_echo() {
    let body = request_with_code("clientdbinfo", 7);
    assert_eq!(return_code(&body), Some(7));
    // The request keeps its own arguments; the code is appended, not substituted.
    let text = String::from_utf8(body).expect("utf-8");
    assert!(text.starts_with("clientdbinfo"), "{text}");
    assert!(text.contains("cldbid=1"), "{text}");
}

#[test]
fn a_code_is_recovered_from_a_reply_that_has_no_command_name() {
    // The real wire form: no leading command word at all.
    let body = b"client_nickname=ann client_database_id=3 return_code=11";
    assert_eq!(return_code(body), Some(11));
}

#[test]
fn a_reply_without_a_code_is_not_routed() {
    // Nothing to match on, so it stays an unrecognised packet.
    assert_eq!(return_code(b"client_nickname=ann"), None);
}

#[test]
fn the_declared_type_parses_the_body_and_the_name_path_still_refuses_it() {
    // Every attribute of `ClientDbInfo` is required, so the body has to carry
    // the whole set; a trimmed one fails on the first missing field.
    let body = "client_lastip=::1 clid=1 client_unique_identifier=abc= cid=2 \
client_database_id=3 client_nickname=ann client_type=0 client_flag_avatar= \
client_description=d client_icon_id=0 client_created=0 client_lastconnected=0 \
client_totalconnections=1 client_month_bytes_uploaded=0 client_month_bytes_downloaded=0 \
client_total_bytes_uploaded=0 client_total_bytes_downloaded=0 \
client_base64HashClientUID=x return_code=11";
    let packet = header();
    let header = packet.header();

    // By name: refused, because the wire carries no name.
    assert!(InMessage::new(&header, body.as_bytes()).is_err());

    // By declared type: parsed, and the code comes back with it.
    let msg = InMessage::new_response(&header, body.as_bytes(), &["ClientDbInfo"])
        .expect("a declared reply parses");
    match msg {
        InMessage::ClientDbInfo(info) => {
            assert_eq!(info.return_code.as_deref(), Some("11"));
            let part = info.iter().next().expect("one entry");
            assert_eq!(part.name, "ann");
            assert_eq!(part.database_id.0, 3);
        }
        other => panic!("wrong variant: {other:?}"),
    }
}

#[test]
fn a_type_that_was_not_declared_is_refused() {
    let packet = header();
    let header = packet.header();
    assert!(InMessage::new_response(&header, b"return_code=1", &["NoSuchMessage"]).is_none());
}

/// Reads the `# ->` sample a message's declaration documents.
///
/// Several declarations in `Messages.toml` carry the real wire form in the
/// comment above them. Using that as the test input ties the declaration to the
/// document it came from: if the attributes and the comment disagree, this
/// fails, which is the only way to notice a field the server never sends.
fn documented_reply_sample(message: &str) -> Option<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vendor/tsclientlib/utils/tsproto-structs/declarations/Messages.toml");
    let text = std::fs::read_to_string(path).ok()?;
    let lines: Vec<&str> = text.lines().collect();
    let index = lines.iter().position(|line| {
        line.trim_start()
            .starts_with(&format!("{{ name=\"{message}\""))
    })?;
    // Walk back over the comment block, collecting `->` samples.
    let mut sample = None;
    for line in lines[..index].iter().rev() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with('#') {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("# -> ") {
            sample = Some(rest.to_string());
        }
    }
    sample
}

/// `clientfind` and `permget` answer with the shapes their declarations
/// document, so the test reads those samples rather than restating them.
#[test]
fn replies_parse_the_sample_their_declaration_documents() {
    let packet = header();
    let header = packet.header();

    let client_find =
        documented_reply_sample("ClientFindRequest").expect("clientfind documents its reply");
    // The sample is `clid=1 client_nickname=Splamy`, plus the code the request
    // wrote, which the server echoes.
    let body = format!("{client_find} return_code=1");
    match InMessage::new_response(&header, body.as_bytes(), &["ClientFind"]) {
        Some(InMessage::ClientFind(found)) => {
            let part = found.iter().next().expect("one entry");
            assert_eq!(part.client_id.0, 1);
            assert_eq!(part.name, "Splamy");
        }
        other => panic!("ClientFind did not parse `{body}`: {other:?}"),
    }

    let perm_get = documented_reply_sample("PermRequest").expect("permget documents its reply");
    let body = format!("{perm_get} return_code=2");
    match InMessage::new_response(&header, body.as_bytes(), &["PermGet"]) {
        Some(InMessage::PermGet(perm)) => {
            let part = perm.iter().next().expect("one entry");
            assert_eq!(part.permission_id.0, 1);
            assert_eq!(
                part.permission_name_id.as_deref(),
                Some("b_serverinstance_help_view")
            );
            assert_eq!(part.permission_value, 1);
        }
        other => panic!("PermGet did not parse `{body}`: {other:?}"),
    }
}

/// The four replies this branch added declarations for.
///
/// Each body is the shape the server sends, written out rather than built, so a
/// wrong attribute name in the declaration shows up here as a parse failure.
#[test]
fn the_newly_declared_replies_parse() {
    let packet = header();
    let header = packet.header();

    let client_find = "clid=1 client_nickname=ann return_code=1";
    match InMessage::new_response(&header, client_find.as_bytes(), &["ClientFind"]) {
        Some(InMessage::ClientFind(found)) => {
            let part = found.iter().next().expect("one entry");
            assert_eq!(part.client_id.0, 1);
            assert_eq!(part.name, "ann");
        }
        other => panic!("ClientFind did not parse: {other:?}"),
    }

    let perm_get = "permsid=b_serverinstance_help_view permid=1 permvalue=75 return_code=2";
    match InMessage::new_response(&header, perm_get.as_bytes(), &["PermGet"]) {
        Some(InMessage::PermGet(perm)) => {
            let part = perm.iter().next().expect("one entry");
            assert_eq!(part.permission_id.0, 1);
            assert_eq!(
                part.permission_name_id.as_deref(),
                Some("b_serverinstance_help_view")
            );
            assert_eq!(part.permission_value, 75);
        }
        other => panic!("PermGet did not parse: {other:?}"),
    }

    let snapshot = "snapshot=abc return_code=4";
    match InMessage::new_response(
        &header,
        snapshot.as_bytes(),
        &["ServerSnapshotCreateResponse"],
    ) {
        Some(InMessage::ServerSnapshotCreateResponse(created)) => {
            let part = created.iter().next().expect("one entry");
            assert_eq!(part.snapshot, "abc");
        }
        other => panic!("ServerSnapshotCreateResponse did not parse: {other:?}"),
    }

    // `serverinfo` answers with the `initserver` shape. The body below is the
    // field set the protocol comment documents, trimmed of the connection
    // counters that belong to `serverrequestconnectioninfo`.
    let server_info = "virtualserver_unique_identifier=abc= virtualserver_name=S \
virtualserver_welcomemessage=w virtualserver_platform=Linux virtualserver_version=3.13 \
virtualserver_maxclients=32 virtualserver_password= virtualserver_clientsonline=1 \
virtualserver_channelsonline=1 virtualserver_created=0 virtualserver_uptime=10 \
virtualserver_codec_encryption_mode=0 virtualserver_hostmessage= virtualserver_hostmessage_mode=0 \
virtualserver_default_server_group=8 virtualserver_default_channel_group=8 \
virtualserver_flag_password=0 virtualserver_default_channel_admin_group=5 \
virtualserver_max_download_total_bandwidth=0 virtualserver_max_upload_total_bandwidth=0 \
virtualserver_hostbanner_url= virtualserver_hostbanner_gfx_url= \
virtualserver_hostbanner_gfx_interval=0 virtualserver_complain_autoban_count=5 \
virtualserver_complain_autoban_time=1200 virtualserver_complain_remove_time=3600 \
virtualserver_min_clients_in_channel_before_forced_silence=100 \
virtualserver_priority_speaker_dimm_modificator=-18.0 virtualserver_id=1 \
virtualserver_antiflood_points_tick_reduce=5 virtualserver_antiflood_points_needed_command_block=150 \
virtualserver_antiflood_points_needed_ip_block=250 virtualserver_client_connections=5 \
virtualserver_query_client_connections=4 virtualserver_hostbutton_tooltip= \
virtualserver_hostbutton_url= virtualserver_hostbutton_gfx_url= virtualserver_queryclientsonline=0 \
virtualserver_download_quota=0 virtualserver_upload_quota=0 virtualserver_month_bytes_downloaded=0 \
virtualserver_month_bytes_uploaded=0 virtualserver_total_bytes_downloaded=0 \
virtualserver_total_bytes_uploaded=0 virtualserver_port=9987 virtualserver_autostart=1 \
virtualserver_machine_id= virtualserver_needed_identity_security_level=8 \
virtualserver_log_client=1 virtualserver_log_query=1 virtualserver_log_channel=1 \
virtualserver_log_permissions=1 virtualserver_log_server=1 virtualserver_log_filetransfer=1 \
virtualserver_min_client_version=0 virtualserver_name_phonetic= virtualserver_icon_id=0 \
virtualserver_reserved_slots=0 virtualserver_total_packetloss_speech=0 \
virtualserver_total_packetloss_keepalive=0 virtualserver_total_packetloss_control=0 \
virtualserver_total_packetloss_total=0 virtualserver_total_ping=0 \
virtualserver_ip=0.0.0.0 virtualserver_weblist_enabled=1 \
virtualserver_ask_for_privilegekey=0 virtualserver_hostbanner_mode=0 \
virtualserver_channel_temp_delete_delay_default=0 virtualserver_min_android_version=0 \
virtualserver_min_ios_version=0 virtualserver_nickname= \
virtualserver_antiflood_points_needed_plugin_block=0 virtualserver_status=online return_code=3";
    match InMessage::new_response(&header, server_info.as_bytes(), &["ServerInfoResponse"]) {
        Some(InMessage::ServerInfoResponse(info)) => {
            let part = info.iter().next().expect("one entry");
            assert_eq!(part.name, "S");
            assert_eq!(part.platform, "Linux");
            assert_eq!(part.max_clients, 32);
            assert_eq!(part.port, 9987);
            assert_eq!(part.virtual_server_id, 1);
            assert!(part.autostart);
            assert_eq!(part.virtual_server_status, "online");
        }
        other => panic!("ServerInfoResponse did not parse: {other:?}"),
    }
}
