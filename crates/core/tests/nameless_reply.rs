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
    // Walk back over the comment block. Most samples are written `# -> …`; a
    // few (`custominfo`) omit the arrow and put the reply on a bare `# ` line,
    // so both are accepted and the nearest one wins.
    let mut sample = None;
    for line in lines[..index].iter().rev() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with('#') {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("# -> ") {
            sample = Some(rest.to_string());
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("# ") {
            // A prose line ("clientinfo cldbid=2") would also match; only take
            // it when it looks like a reply, i.e. it contains an `=`.
            if rest.contains('=') && rest.split(' ').next().unwrap_or("").contains('=') {
                sample = Some(rest.to_string());
                break;
            }
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

/// Splits a documented `# -> ` reply sample into the keys it carries.
///
/// Two shapes appear: `key=value` pairs, and bare `key` for a field the server
/// sent empty. Values themselves contain `\s`, so splitting on whitespace only
/// works at unescaped boundaries.
fn sample_keys(sample: &str) -> std::collections::BTreeSet<String> {
    let mut keys = std::collections::BTreeSet::new();
    for token in sample.split(' ').filter(|token| !token.is_empty()) {
        if let Some((key, _)) = token.split_once('=') {
            if is_field_name(key) {
                keys.insert(key.to_string());
            }
        } else if is_field_name(token) {
            // An empty value is sent as the bare key, not `key=`.
            keys.insert(token.to_string());
        }
    }
    keys
}

fn is_field_name(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        && text.starts_with(|c: char| c.is_ascii_lowercase())
}

/// The attributes `ServerInfoResponse` declares, read from the declaration.
fn server_info_attributes() -> Vec<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vendor/tsclientlib/utils/tsproto-structs/declarations/Messages.toml");
    let text = std::fs::read_to_string(path).expect("declarations");
    let start = text
        .find("{ name=\"ServerInfoResponse\"")
        .expect("ServerInfoResponse is declared");
    let rest = &text[start..];
    let open = rest.find('[').expect("an attributes list");
    let close = rest.find(']').expect("a closing bracket");
    rest[open + 1..close]
        .split(',')
        .map(|item| {
            item.trim()
                .trim_matches('"')
                .trim_end_matches('?')
                .to_string()
        })
        .filter(|item| !item.is_empty())
        .collect()
}

/// Every field `ServerInfoResponse` declares must appear in the reply sample the
/// protocol documents, and every `virtualserver_*` field in that sample must be
/// declared.
///
/// This is the check that would have caught `virtualserver_filebase`, which was
/// missing from the declaration. It matters more than a body written by hand:
/// `InMessage::new_response` returns `None` on an unknown field, so a field the
/// server does not send makes `serverinfo` look like it worked and then drop the
/// reply with only a warning.
/// What a declaration gets wrong relative to a documented reply sample.
///
/// Two directions, and they fail differently: a declared-but-absent field makes
/// `InMessage::new_response` return `None`, so the reply is dropped with only a
/// warning; an absent declaration silently loses data the server did send.
fn declaration_gaps(
    declared: &std::collections::BTreeSet<String>,
    sample: &std::collections::BTreeSet<String>,
) -> (Vec<String>, Vec<String>) {
    let invented = declared.difference(sample).cloned().collect();
    // Only the server fields belong to this message; the connection counters in
    // the same body answer `serverrequestconnectioninfo`.
    let server_fields: std::collections::BTreeSet<&String> = sample
        .iter()
        .filter(|key| key.starts_with("virtualserver_"))
        .collect();
    let undeclared = server_fields
        .into_iter()
        .filter(|key| !declared.contains(*key))
        .cloned()
        .collect();
    (invented, undeclared)
}

/// The check itself, on inputs chosen to fail.
///
/// The real comparison below cannot be made to fail without editing the
/// declarations, and the generator rejects most edits before the test runs. This
/// pins the two directions independently, so a change that quietly stops
/// detecting one of them is caught here.
#[test]
fn the_gap_check_finds_both_kinds_of_mistake() {
    let declared: std::collections::BTreeSet<String> =
        ["virtualserver_name", "virtualserver_made_up"]
            .into_iter()
            .map(str::to_string)
            .collect();
    let sample: std::collections::BTreeSet<String> = ["virtualserver_name", "virtualserver_port"]
        .into_iter()
        .map(str::to_string)
        .collect();

    let (invented, undeclared) = declaration_gaps(&declared, &sample);
    assert_eq!(invented, vec!["virtualserver_made_up".to_string()]);
    assert_eq!(undeclared, vec!["virtualserver_port".to_string()]);
}

/// A declaration that matches its sample reports nothing on either side.
#[test]
fn a_matching_declaration_reports_no_gaps() {
    let fields: std::collections::BTreeSet<String> = ["virtualserver_name", "virtualserver_port"]
        .into_iter()
        .map(str::to_string)
        .collect();
    let (invented, undeclared) = declaration_gaps(&fields, &fields);
    assert!(invented.is_empty(), "{invented:?}");
    assert!(undeclared.is_empty(), "{undeclared:?}");
}

#[test]
fn server_info_attributes_match_the_documented_sample() {
    let sample = documented_reply_sample("ServerInfo").expect("serverinfo documents its reply");
    let in_sample = sample_keys(&sample);
    let declared: std::collections::BTreeSet<String> =
        server_info_attributes().into_iter().collect();

    let (invented, undeclared) = declaration_gaps(&declared, &in_sample);
    assert!(
        invented.is_empty(),
        "ServerInfoResponse declares fields the documented reply does not send: {invented:?}"
    );
    assert!(
        undeclared.is_empty(),
        "the documented reply carries fields ServerInfoResponse does not declare: {undeclared:?}"
    );

    assert_eq!(declared.len(), 74, "attribute count drifted");
}

/// The sample parses once the request's `return_code` is appended.
///
/// The documented body is the real wire form, so this also proves the field
/// names are the ones the server uses rather than ones that happen to work.
#[test]
fn server_info_parses_the_documented_sample() {
    let sample = documented_reply_sample("ServerInfo").expect("serverinfo documents its reply");
    let body = format!("{sample} return_code=3");
    let packet = header();
    let header = packet.header();

    match InMessage::new_response(&header, body.as_bytes(), &["ServerInfoResponse"]) {
        Some(InMessage::ServerInfoResponse(info)) => {
            let part = info.iter().next().expect("one entry");
            assert_eq!(part.name, "TeamSpeak ]I[ Server");
            assert_eq!(part.platform, "Windows");
            assert_eq!(part.max_clients, 32);
            assert_eq!(part.port, 9987);
            assert_eq!(part.virtual_server_id, 1);
            assert_eq!(part.virtual_server_status, "online");
            assert_eq!(part.file_base, "files\\virtualserver_1");
        }
        None => panic!("the documented serverinfo sample did not parse"),
        Some(other) => panic!("wrong variant: {other:?}"),
    }
}

/// `custominfo` and `customsearch` answer with the entries they stored, and the
/// documented sample is the reply body.
///
/// These two were written and then removed earlier because the reply had no
/// parse arm. The routing added for `clientdbinfo` fixes that class, so they are
/// back and checked the same way: the declaration must match the documented
/// reply, or the answer is dropped with only a warning.
#[test]
fn custom_replies_parse_the_documented_sample() {
    let packet = header();
    let header = packet.header();

    let sample =
        documented_reply_sample("CustomInfoRequest").expect("custominfo documents its reply");
    assert!(
        sample.contains("cldbid=") && sample.contains("ident=") && sample.contains("value="),
        "the custominfo sample should carry cldbid/ident/value, got {sample:?}"
    );
    let body = format!("{sample} return_code=5");
    match InMessage::new_response(&header, body.as_bytes(), &["CustomInfoResponse"]) {
        Some(InMessage::CustomInfoResponse(info)) => {
            let part = info.iter().next().expect("one entry");
            assert_eq!(part.client_db_id.map(|id| id.0), Some(2));
            assert_eq!(part.external_identity, "s");
            assert_eq!(part.value, "1234");
        }
        other => panic!("CustomInfoResponse did not parse `{body}`: {other:?}"),
    }

    let sample = documented_reply_sample("CustomSearch").expect("customsearch documents its reply");
    let body = format!("{sample} return_code=6");
    match InMessage::new_response(&header, body.as_bytes(), &["CustomSearchResponse"]) {
        Some(InMessage::CustomSearchResponse(found)) => {
            let part = found.iter().next().expect("one entry");
            assert_eq!(part.client_db_id.0, 2);
            assert_eq!(part.external_identity, "s");
            assert_eq!(part.value, "1234");
        }
        other => panic!("CustomSearchResponse did not parse `{body}`: {other:?}"),
    }
}

/// The official `custominfo` sample carries `cldbid` once and the remaining
/// entries without it:
///
///   cldbid=3 ident=forum_account value=ScP|ident=forum_id value=123
///
/// The declaration has to accept that, or the second entry is dropped.
#[test]
fn custominfo_documented_sample_carries_cldbid_only_once() {
    let packet = header();
    let header = packet.header();
    let body = "cldbid=3 ident=forum_account value=ScP|ident=forum_id value=123 return_code=8";
    match InMessage::new_response(&header, body.as_bytes(), &["CustomInfoResponse"]) {
        Some(InMessage::CustomInfoResponse(info)) => {
            let mut entries = info.iter();
            let first = entries.next().expect("first entry");
            assert_eq!(first.client_db_id.map(|id| id.0), Some(3));
            assert_eq!(first.external_identity, "forum_account");
            assert_eq!(first.value, "ScP");
            let second = entries.next().expect("second entry");
            // The generated parser carries the last value for a missing
            // optional field, which is exactly the official sample's shape.
            assert_eq!(second.client_db_id.map(|id| id.0), Some(3));
            assert_eq!(second.external_identity, "forum_id");
            assert_eq!(second.value, "123");
            assert!(entries.next().is_none());
        }
        other => panic!("CustomInfoResponse did not parse the documented sample: {other:?}"),
    }
}

/// A search can match several clients, and the server separates them with `|`.
#[test]
fn a_multi_part_custom_reply_parses_every_entry() {
    let packet = header();
    let header = packet.header();
    let body = "cldbid=2 ident=a value=1|cldbid=3 ident=b value=2 return_code=7";
    match InMessage::new_response(&header, body.as_bytes(), &["CustomSearchResponse"]) {
        Some(InMessage::CustomSearchResponse(found)) => {
            let entries: Vec<(u64, String, String)> = found
                .iter()
                .map(|part| {
                    (
                        part.client_db_id.0,
                        part.external_identity.clone(),
                        part.value.clone(),
                    )
                })
                .collect();
            assert_eq!(
                entries,
                vec![
                    (2, "a".to_string(), "1".to_string()),
                    (3, "b".to_string(), "2".to_string()),
                ]
            );
        }
        other => panic!("multi-part reply did not parse: {other:?}"),
    }
}

/// `channelcreate` and `servergroupadd` answer with the new id.
///
/// Both were sent without asking for a reply, so the id was lost and a caller had
/// to re-list to find what it had just created.
#[test]
fn create_responses_carry_the_new_id() {
    let packet = header();
    let header = packet.header();

    match InMessage::new_response(&header, b"cid=42 return_code=1", &["ChannelCreateResponse"]) {
        Some(InMessage::ChannelCreateResponse(created)) => {
            let part = created.iter().next().expect("one entry");
            assert_eq!(part.channel_id.0, 42);
        }
        other => panic!("ChannelCreateResponse did not parse: {other:?}"),
    }

    match InMessage::new_response(
        &header,
        b"sgid=17 return_code=2",
        &["ServerGroupAddResponse"],
    ) {
        Some(InMessage::ServerGroupAddResponse(added)) => {
            let part = added.iter().next().expect("one entry");
            assert_eq!(part.server_group_id.0, 17);
        }
        other => panic!("ServerGroupAddResponse did not parse: {other:?}"),
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

    // The real reply is `version=3 data=…`, with `salt=` when it is password
    // protected. A `snapshot=` field was invented and never existed on the wire.
    let snapshot = "version=3 data=abc return_code=4";
    match InMessage::new_response(
        &header,
        snapshot.as_bytes(),
        &["ServerSnapshotCreateResponse"],
    ) {
        Some(InMessage::ServerSnapshotCreateResponse(created)) => {
            let part = created.iter().next().expect("one entry");
            assert_eq!(part.snapshot_version, 3);
            assert_eq!(part.data, "abc");
            assert_eq!(part.salt, None);
        }
        other => panic!("ServerSnapshotCreateResponse did not parse: {other:?}"),
    }

    // The documented password-protected form puts `salt` between version and
    // data: `version=3 salt=… data=…`.
    let snapshot = "version=3 salt=c2FsdA== data=abc return_code=4";
    match InMessage::new_response(
        &header,
        snapshot.as_bytes(),
        &["ServerSnapshotCreateResponse"],
    ) {
        Some(InMessage::ServerSnapshotCreateResponse(created)) => {
            let part = created.iter().next().expect("one entry");
            assert_eq!(part.snapshot_version, 3);
            assert_eq!(part.salt.as_deref(), Some("c2FsdA=="));
            assert_eq!(part.data, "abc");
        }
        other => panic!("password-protected snapshot did not parse: {other:?}"),
    }
}
