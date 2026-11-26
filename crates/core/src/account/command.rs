//! The command surface: the names a shell may send, and how their JSON arguments
//! become an [`AccountCommand`].
//!
//! Kept in its own file because it is the one part of the account side that is
//! pure data — no session, no cipher, no HTTP. That makes it the cheapest place
//! to keep exhaustive: one table of names, one parse arm per name, and a test
//! that walks every name in both directions.

use std::path::PathBuf;

use serde_json::Value;

use super::http::LoginRequest;
use super::sync::ItemClass;

// ── the command surface ─────────────────────────────────────────────────────

/// Every command name this crate accepts, in one list.
///
/// The name used to appear in four places — the `matches!` allowlist, the
/// `parse_known` arm, `AccountCommand::name`, and the handler's own report
/// string — so adding one meant editing four lists and a typo silently made a
/// command unreachable. `parse` gates on this table and `name` is tested against
/// it, so a name that is not here cannot be parsed and cannot be reported.
pub const NAMES: &[&str] = &[
    "account_login",
    "account_logout",
    "account_resume",
    "account_refresh",
    "sync_list",
    "sync_backup",
    "sync_bookmark_create",
    "sync_bookmark_edit",
    "sync_bookmark_move",
    "sync_addon_enabled",
    "sync_delete",
    "sync_restore",
    "sync_merge",
    "identity_pick",
    "identity_import",
];

/// One account command, already parsed.
///
/// A separate enum from the connection's own command type on purpose: those go to
/// the connection thread, and the account side has to work with no connection at
/// all. [`crate::Session::exec`] routes on [`AccountCommand::parse`] first.
#[derive(Debug, Clone)]
pub enum AccountCommand {
    Login {
        request: LoginRequest,
        /// Read the email and credential hash out of the client's `settings.db`
        /// instead of requiring them in the payload.
        from_ts3_client: bool,
    },
    Logout,
    /// Restores the remembered account with no network login.
    ///
    /// The file a login wrote already carries the session, the account key and the
    /// myTS identity, so the second launch is instant and works offline. A dead
    /// session is renewed by the first read instead of at startup.
    Resume,
    /// Re-read `/me` and the item list. `reveal_secrets` fills in bookmark
    /// passwords; see [`AccountCommand::List`].
    Refresh {
        reveal_secrets: bool,
    },
    /// Read the item list. `reveal_secrets` fills in the bookmark password
    /// fields, which are otherwise reported as presence only.
    List {
        reveal_secrets: bool,
    },
    Backup,
    CreateBookmark {
        name: String,
        address: String,
        port: u32,
        nickname: String,
    },
    /// Rewrites a bookmark's name/address/port/nickname. The item keeps its uuid
    /// and everything else (passwords, placement, profile) is left as it was.
    EditBookmark {
        uuid: String,
        name: String,
        address: String,
        port: u32,
        nickname: String,
    },
    /// Moves a bookmark to a new position among its siblings.
    ///
    /// `after` names the sibling it should follow, or empty for "first". This is
    /// the protocol's own model: `sort_order` is a link to the previous sibling,
    /// not an index, so a reorder is a few link rewrites.
    MoveBookmark {
        uuid: String,
        after: String,
    },
    SetAddOnEnabled {
        uuid: String,
        enabled: bool,
    },
    Delete {
        uuid: String,
        class: Option<ItemClass>,
    },
    Restore {
        file: PathBuf,
    },
    /// Compares a local backup against the account and reports what each side
    /// changed. **Read-only.**
    ///
    /// `baseline` names the file to compare against; its absence means "use the
    /// configured one", and neither present means the two sides have never been
    /// recorded as agreeing.
    Merge {
        local: PathBuf,
        baseline: Option<PathBuf>,
        /// Record the agreement instead of only reporting it. Writing a baseline
        /// is what makes the *next* compare able to tell whose change is whose.
        record: bool,
    },
    /// Answers "which identity does this server know me by", from the account.
    ///
    /// The shell calls this after login with the address it is about to join;
    /// the answer is a `counterVkey` it can connect with. When several identities
    /// exist and nothing decides between them, the report carries
    /// `{ ambiguous: true, candidates: [...] }` and the command returns an error
    /// naming the choice — the shell asks the user. The library does not guess,
    /// because handing a server the wrong UID silently costs the user their
    /// groups.
    PickIdentity {
        address: String,
    },
    /// Copies the account's stored identity into the `IDENTITY` sync item, so a
    /// fresh install keeps the UID its server groups are bound to.
    ///
    /// The identity is supplied by the shell (the `counterVkey` it already uses
    /// locally), because the library never invents one for the account. With no
    /// `IDENTITY` item on the account, the first one is created rather than
    /// refused: the people who need this are the ones arriving without the
    /// official client. With `uuid` it targets a specific item, otherwise the
    /// default (or the only) identity is updated.
    ImportIdentity {
        identity: String,
        uuid: Option<String>,
    },
}

impl AccountCommand {
    /// Parses an account command, or `None` when the name belongs to the
    /// connection instead. The `Result` inside the `Option` is the argument error,
    /// so a misspelled field fails loudly rather than falling through to
    /// "unknown command".
    pub fn parse(name: &str, args: &str) -> Option<Result<AccountCommand, String>> {
        if !NAMES.contains(&name) {
            return None;
        }
        Some(Self::parse_known(name, args))
    }

    fn parse_known(name: &str, args: &str) -> Result<AccountCommand, String> {
        let json: Value = if args.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(args).map_err(|e| format!("bad arguments: {e}"))?
        };
        let text = |key: &str| -> Result<String, String> {
            json.get(key)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| format!("missing string field `{key}`"))
        };
        let optional = |key: &str| -> Option<String> {
            json.get(key)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        };

        Ok(match name {
            "account_login" => {
                let from_ts3_client = json
                    .get("fromTs3Client")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let email = optional("email").unwrap_or_default();
                let hash = optional("hash");
                let password = optional("password");
                // A bare login is legitimate: it means "use whatever the client
                // already remembers". The remembered credential is consulted by
                // `resolve_remembered_login`, which is the only place that knows
                // whether there is one — rejecting here would make a silent
                // second launch impossible.
                let bare =
                    !from_ts3_client && email.is_empty() && hash.is_none() && password.is_none();
                if !from_ts3_client && !bare && email.is_empty() {
                    return Err(
                        "account_login needs an `email`, or `\"fromTs3Client\": true` to read it \
                         out of the client's settings.db"
                            .to_string(),
                    );
                }
                if !from_ts3_client && !bare && hash.is_none() && password.is_none() {
                    return Err(
                        "account_login needs `password` (hashed here) or `hash` (already \
                         hashed), or `\"fromTs3Client\": true`"
                            .to_string(),
                    );
                }
                AccountCommand::Login {
                    request: LoginRequest {
                        email,
                        hash,
                        password,
                        otp: optional("otp"),
                        recovery_key: optional("recoveryKey"),
                    },
                    from_ts3_client,
                }
            }
            "account_logout" => AccountCommand::Logout,
            "account_resume" => AccountCommand::Resume,
            "account_refresh" => AccountCommand::Refresh {
                reveal_secrets: json
                    .get("revealSecrets")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            },
            "sync_list" => AccountCommand::List {
                reveal_secrets: json
                    .get("revealSecrets")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            },
            "sync_backup" => AccountCommand::Backup,
            "sync_bookmark_create" => {
                let port = json
                    .get("port")
                    .and_then(Value::as_u64)
                    .map(|value| value as u32)
                    .unwrap_or(9987);
                if !(1..=65_535).contains(&port) {
                    return Err(format!("port {port} is not a UDP port number"));
                }
                AccountCommand::CreateBookmark {
                    name: text("name")?,
                    address: text("address")?,
                    port,
                    nickname: optional("nickname").unwrap_or_default(),
                }
            }
            "sync_bookmark_edit" => {
                let port = json
                    .get("port")
                    .and_then(Value::as_u64)
                    .map(|value| value as u32)
                    .unwrap_or(9987);
                if !(1..=65_535).contains(&port) {
                    return Err(format!("port {port} is not a UDP port number"));
                }
                AccountCommand::EditBookmark {
                    uuid: text("uuid")?,
                    name: text("name")?,
                    address: text("address")?,
                    port,
                    nickname: optional("nickname").unwrap_or_default(),
                }
            }
            "sync_bookmark_move" => AccountCommand::MoveBookmark {
                uuid: text("uuid")?,
                after: optional("after").unwrap_or_default(),
            },
            "sync_addon_enabled" => AccountCommand::SetAddOnEnabled {
                uuid: text("uuid")?,
                enabled: json
                    .get("enabled")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| "missing boolean field `enabled`".to_string())?,
            },
            "sync_delete" => AccountCommand::Delete {
                uuid: text("uuid")?,
                class: match optional("class") {
                    Some(class) => Some(
                        ItemClass::parse(&class)
                            .ok_or_else(|| format!("unknown item class `{class}`"))?,
                    ),
                    None => None,
                },
            },
            "sync_restore" => AccountCommand::Restore {
                file: PathBuf::from(text("file")?),
            },
            "identity_pick" => AccountCommand::PickIdentity {
                address: json
                    .get("address")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            },
            "identity_import" => AccountCommand::ImportIdentity {
                identity: text("identity")?,
                uuid: optional("uuid"),
            },
            "sync_merge" => AccountCommand::Merge {
                local: PathBuf::from(text("local")?),
                baseline: optional("baseline").map(PathBuf::from),
                record: json.get("record").and_then(Value::as_bool).unwrap_or(false),
            },
            other => return Err(format!("unknown account command: {other}")),
        })
    }

    pub fn name(&self) -> &'static str {
        match self {
            AccountCommand::Login { .. } => "account_login",
            AccountCommand::Logout => "account_logout",
            AccountCommand::Resume => "account_resume",
            AccountCommand::Refresh { .. } => "account_refresh",
            AccountCommand::List { .. } => "sync_list",
            AccountCommand::Backup => "sync_backup",
            AccountCommand::CreateBookmark { .. } => "sync_bookmark_create",
            AccountCommand::EditBookmark { .. } => "sync_bookmark_edit",
            AccountCommand::MoveBookmark { .. } => "sync_bookmark_move",
            AccountCommand::SetAddOnEnabled { .. } => "sync_addon_enabled",
            AccountCommand::Delete { .. } => "sync_delete",
            AccountCommand::Restore { .. } => "sync_restore",
            AccountCommand::Merge { .. } => "sync_merge",
            AccountCommand::PickIdentity { .. } => "identity_pick",
            AccountCommand::ImportIdentity { .. } => "identity_import",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every name in [`NAMES`] must parse, and the parsed value must report the
    /// same name back. This is the test that replaces four hand-kept lists: a
    /// command added to `NAMES` without a `parse_known` arm fails here, and so
    /// does a `name()` that disagrees.
    #[test]
    fn every_documented_command_round_trips_through_its_name() {
        // The minimum payload each command needs to parse. A command that is
        // added to `NAMES` without an entry here fails the "no sample" assert
        // rather than being silently skipped.
        let samples: &[(&str, &str)] = &[
            ("account_login", r#"{"email":"a@b.c","password":"p"}"#),
            ("account_logout", "{}"),
            ("account_resume", "{}"),
            ("account_refresh", "{}"),
            ("sync_list", "{}"),
            ("sync_backup", "{}"),
            ("sync_bookmark_create", r#"{"name":"n","address":"a"}"#),
            (
                "sync_bookmark_edit",
                r#"{"uuid":"u","name":"n","address":"a"}"#,
            ),
            ("sync_bookmark_move", r#"{"uuid":"u","after":""}"#),
            ("sync_addon_enabled", r#"{"uuid":"u","enabled":true}"#),
            ("sync_delete", r#"{"uuid":"u"}"#),
            ("sync_restore", r#"{"file":"/tmp/b.json"}"#),
            (
                "sync_merge",
                r#"{"local":"/tmp/b.json","baseline":"/tmp/s.json","record":false}"#,
            ),
            ("identity_pick", r#"{"address":"a"}"#),
            ("identity_import", r#"{"identity":"42V..."}"#),
        ];

        for name in NAMES {
            let sample = samples
                .iter()
                .find(|(n, _)| n == name)
                .unwrap_or_else(|| panic!("`{name}` is in NAMES but has no sample payload"));
            let cmd = AccountCommand::parse(name, sample.1)
                .unwrap_or_else(|| panic!("`{name}` is in NAMES but `parse` rejected it"))
                .unwrap_or_else(|e| panic!("`{name}` sample does not parse: {e}"));
            assert_eq!(cmd.name(), *name, "`{name}` reports a different name");
        }

        // A name that is not in the table is not an account command at all, so
        // it falls through to the connection parser.
        assert!(AccountCommand::parse("send_text", "").is_none());
        assert!(AccountCommand::parse("sync_nonsense", "").is_none());

        // And every sample names a command that exists: a stale entry here would
        // mean the test proves nothing about a real command.
        for (name, _) in samples {
            assert!(NAMES.contains(name), "sample for unknown command `{name}`");
        }
    }

    #[test]
    fn account_commands_parse_and_misspellings_fail() {
        assert!(AccountCommand::parse("send_text", "").is_none());
        let cmd = AccountCommand::parse("sync_list", "").unwrap().unwrap();
        assert_eq!(cmd.name(), "sync_list");

        let error = AccountCommand::parse("sync_bookmark_create", "{\"name\":\"x\"}")
            .unwrap()
            .unwrap_err();
        assert!(error.contains("address"), "{error}");

        let error = AccountCommand::parse("sync_addon_enabled", "{\"uuid\":\"x\",\"enabled\":1}")
            .unwrap()
            .unwrap_err();
        assert!(error.contains("enabled"), "{error}");

        let error = AccountCommand::parse("sync_delete", "{\"uuid\":\"x\",\"class\":\"NOPE\"}")
            .unwrap()
            .unwrap_err();
        assert!(error.contains("class"), "{error}");

        // These two are bookmarks too, and used to fall through the allowlist to
        // the connection parser as "unknown command".
        for name in ["sync_bookmark_edit", "sync_bookmark_move"] {
            let cmd = AccountCommand::parse(
            name,
            "{\"uuid\":\"x\",\"name\":\"n\",\"address\":\"a\",\"port\":1,\"nickname\":\"n\",\"after\":\"\"}",
        )
        .unwrap()
        .unwrap();
            assert_eq!(cmd.name(), name);
        }
    }

    #[test]
    fn a_bookmark_command_defaults_the_port_and_names_the_write() {
        let cmd = AccountCommand::parse(
            "sync_bookmark_create",
            "{\"name\":\"Lobby\",\"address\":\"ts.example.com\"}",
        )
        .unwrap()
        .unwrap();
        match cmd {
            AccountCommand::CreateBookmark { port, nickname, .. } => {
                assert_eq!(port, 9987);
                assert_eq!(nickname, "");
            }
            other => panic!("wrong variant: {other:?}"),
        }
        assert_eq!(
            AccountCommand::parse("sync_addon_enabled", "{\"uuid\":\"x\",\"enabled\":true}")
                .unwrap()
                .unwrap()
                .name(),
            "sync_addon_enabled"
        );
    }
}
