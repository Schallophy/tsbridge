//! The account side of a TeamSpeak client: myTeamSpeak login, the key chain, and
//! the synchronisation items.
//!
//! This module is the Rust implementation of what `research/myts-login` proved
//! out in Node. It exists as a library rather than a tool because the login
//! session and the account key have to be **reused**, not re-derived: a client
//! that logs in by hand once, per launch, has not implemented anything.
//!
//! The parts, and why each is its own file:
//!
//! | file | owns |
//! |---|---|
//! | [`crypto`] | the three derivations, the sjcl GCM blob, AES-CTR XOR, uuids |
//! | [`proto`] | a byte-preserving protobuf reader/writer |
//! | [`http`] | the REST surface and the `application/ts3cloud` envelope |
//! | [`sqlite`] | a read-only reader for the client's `settings.db` |
//! | [`sync`] | item classes, capability tiers, write shapes, backups |
//!
//! Two invariants worth stating up front:
//!
//! * **Nothing here blocks the caller.** Every command starts a task on the
//!   account's own runtime and reports through the snapshot plus an
//!   `account_status` event, exactly like a file transfer does. A 25-second HTTP
//!   call inside `exec` would freeze a UI thread on a mobile device.
//! * **Nothing here writes to disk except backup files**, and `settings.db` is
//!   only ever read. Every server write is preceded by a backup, because the one
//!   mistake that matters on this protocol — an upsert that replaces a blob with
//!   the wrong version — is only recoverable from a byte-for-byte copy. Backups
//!   land in a directory the shell configures (or a per-user default), and the
//!   path is reported back so it can be found again.
//!
//! The account is reachable without a TeamSpeak server, because it has nothing
//! to do with the connection: it lives on the handle and keeps working across a
//! disconnect and reconnect.

pub mod credentials;
pub mod crypto;
pub mod http;
pub mod merge;
pub mod mytsid;
pub mod proto;
pub mod sqlite;
pub mod sync;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::Value;

use crate::events::QueuedEvent;
use crate::handle::Inner;

use crypto::KEY_LEN;
use http::{Http, LoginRequest};
use sync::{Backup, Capability, Item, ItemCipher, ItemClass, Sync, SyncState, SyncStatus};

/// Where the account reads and writes its own files, as opposed to the server.
///
/// Both fields are optional and neither is probed: this library does not go
/// looking for another application's database. A shell that wants to import a
/// login from an installed TeamSpeak client names the file; every other client
/// leaves `legacy_db` empty and signs in with a password.
#[derive(Debug, Clone, Default)]
pub struct AccountConfig {
    /// An installed client's `settings.db`, used **only** by `fromTs3Client` to
    /// import a login. Never read for item content.
    pub legacy_db: Option<PathBuf>,
    /// Where pre-write backups go. `None` means a per-user directory.
    pub backup_dir: Option<PathBuf>,
    /// Where a successful login is remembered, so the next run does not ask again.
    ///
    /// **`None` by default**: a session that was not told to remember writes no
    /// credential at all. A shell that wants "stay signed in" names a path — or
    /// calls `Session::set_account_config` with
    /// [`credentials::default_credential_file`] — and gets the behaviour.
    pub credential_file: Option<PathBuf>,
    /// Whether a login should also read the remembered credential file when the
    /// payload carries no password and no hash.
    ///
    /// Defaults to `true`, because a shell's whole reason to have a credential
    /// file is that the next launch signs in from it. Set `false` to require an
    /// explicit password every time.
    pub remember_login: bool,
    /// Where the sync baseline lives: what both sides last agreed on, and the
    /// cursors that were current then.
    ///
    /// **`None` by default**, like `credential_file`: a session that was not told
    /// to keep one writes nothing. The file holds field *digests*, never content,
    /// so it is not a second copy of the account's secrets — but it is still an
    /// opt-in, because a client that only reads never needs it.
    pub baseline_file: Option<PathBuf>,
}

/// A logged-in account, as the session holds it.
#[derive(Clone, Default)]
pub struct Account {
    pub session: String,
    pub email: String,
    pub username: String,
    pub uuid: String,
    /// Which wrapper actually unwrapped the login `key`; empty when none did.
    pub unwrapped_with: String,
    /// The account key. Memory only: it is never serialized into a snapshot, an
    /// event, a log line or a backup.
    pub key: Option<[u8; KEY_LEN]>,
    /// The credential that created this session, so an expired session can be
    /// replaced without asking the user again. Memory only, and never part of a
    /// report: see [`Relogin`].
    pub(crate) relogin: Option<Relogin>,
    /// The myTeamSpeak ID and the key that signs `authSign`, when the login
    /// reply carried one and the account key could open it.
    ///
    /// Memory only, like the account key: it holds a private scalar, so it is
    /// never serialized into a snapshot, event or backup. A shell asks for the
    /// six `clientinit` parameters, not for the key.
    pub(crate) identity: Option<mytsid::MytsIdentity>,
}

impl Account {
    /// Whether an expired session can be replaced without asking the user again.
    ///
    /// Deliberately a yes/no: the credential itself never leaves this module,
    /// not even through an accessor a shell could print.
    pub fn can_renew(&self) -> bool {
        self.relogin.is_some()
    }

    /// Whether a server can be told which myTeamSpeak user this is.
    ///
    /// The public key as base64, so a shell can compare it with what the account
    /// shows, and `None` when the login reply had no identity or its key could
    /// not be opened.
    pub fn myts_public_key(&self) -> Option<String> {
        self.identity
            .as_ref()
            .map(mytsid::MytsIdentity::public_key_base64)
    }

    /// The six `clientinit` parameters for a connection with this `shared_iv`.
    ///
    /// Its length is the server's: 20 bytes on the AES-128/SHA-256 handshake,
    /// 64 on the other. The proof is signed over that value, so it cannot be
    /// assumed.
    ///
    /// `None` when this login cannot sign. The signature is per connection: it
    /// embeds the handshake's shared IV, so it cannot be cached or replayed.
    pub fn myts_params(&self, shared_iv: &[u8]) -> Option<mytsid::MytsParams> {
        self.identity
            .as_ref()
            .map(|identity| identity.params(shared_iv))
    }
}

impl std::fmt::Debug for Account {
    /// Redacted on purpose. A dropped `{:?}` on a state object is exactly where
    /// a bearer token and a credential hash leak into a log; the fields worth
    /// reading (who, and whether the key is present) are kept.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account")
            .field("email", &self.email)
            .field("username", &self.username)
            .field("uuid", &self.uuid)
            .field("unwrapped_with", &self.unwrapped_with)
            .field("key_bytes", &self.key.map(|_| KEY_LEN).unwrap_or(0))
            .field("session", &redacted(&self.session))
            .field("relogin", &self.relogin.as_ref().map(|_| "<redacted>"))
            .field(
                "identity",
                &self
                    .identity
                    .as_ref()
                    .map(|_| "<redacted, see myts_public_key>"),
            )
            .finish()
    }
}

fn redacted(secret: &str) -> &'static str {
    if secret.is_empty() {
        ""
    } else {
        "<redacted>"
    }
}

/// How to sign in again, kept in memory only.
///
/// The credential hash is the same value a remembered login stores: it replaces
/// the password at `/client/login`, so it is a credential and is treated like
/// one — never serialized into a snapshot or an event, and redacted in `Debug`.
/// Holding it here rather than on disk is what makes the recovery work for a
/// session that was signed in with a typed password and asked to remember
/// nothing.
#[derive(Clone)]
pub(crate) struct Relogin {
    pub email: String,
    pub hash: String,
}

impl std::fmt::Debug for Relogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Relogin")
            .field("email", &self.email)
            .field("hash", &"<redacted>")
            .finish()
    }
}

/// What every command reports back, both in the snapshot and in the event.
///
/// This is the only channel results travel on. It lives inside the snapshot, so a
/// shell that already reads the snapshot at 50 Hz pays nothing extra to render
/// the account pane.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountReport {
    pub logged_in: bool,
    pub email: String,
    pub username: String,
    pub uuid: String,
    pub unwrapped_with: String,
    /// Length of the account key, or 0 when it could not be unwrapped. The key
    /// itself never appears: a shell that needs it gets a dedicated call, not a
    /// snapshot a log might capture.
    pub key_bytes: usize,
    pub busy: bool,
    /// The last command that was accepted, e.g. `sync_bookmark_create`.
    pub command: String,
    /// Empty when the last command succeeded.
    pub last_error: String,
    /// Where the last write's pre-flight backup landed.
    pub last_backup: String,
    /// Human-readable progress for a multi-step command (`3/25 restored`).
    /// Empty when nothing is in progress. Deliberately not `last_error`: a
    /// successful restore that is 12 items in is not a failure, and a shell that
    /// painted `last_error` red would show it as one.
    pub progress: String,
    /// `SyncStatus` of the last `requestServerItems` reply.
    pub status: i32,
    pub status_name: String,
    pub global_version: String,
    pub item_count: usize,
    /// One object per server item, with the tier and how much room an edit has.
    pub items: Vec<Value>,
    /// The item tree, one flat pre-order list an importer can consume and a UI
    /// can indent.
    ///
    /// Separate from `items` because the two answer different questions: `items`
    /// is "what is on the server", `hierarchy` is "what shape it has". A folder
    /// appears in both, a bookmark appears in both, and the depth is the only
    /// thing that is not already derivable from `parent`/`sortOrder`.
    pub hierarchy: Value,
    /// The myTeamSpeak ID, base64, when this login recovered one. Empty means
    /// the account has no myTS identity or its key could not be opened — which a
    /// shell shows as "badge and name are not announced to servers", not as an
    /// error.
    pub myts_id: String,
    /// The Ed25519 public key that signs `authSign`, base64. Public on purpose:
    /// it is what the server shows. The private scalar never appears.
    pub myts_public_key: String,
    /// The last three-way comparison, when one was run. Empty otherwise.
    ///
    /// A comparison is a report, not a write: it says what *would* have to happen
    /// and which fields both sides changed differently. Nothing is applied until a
    /// caller asks, which is the point — a client that silently picked a side is
    /// how another machine's edit disappears.
    pub merge: Value,
    /// `/me` reduced to the fields a client shows. Never the push token or the
    /// wrapped key.
    pub profile: Value,
    /// The identities the account stores (`IDENTITY` items): the `counterVkey`
    /// strings a returning client must reuse to keep its UID — which is what
    /// server groups and admin rights are bound to. Readable only with the
    /// account key, so sealed items without one are simply absent here.
    pub identities: Vec<Value>,
    /// The identity `identity_pick` chose for the address it was asked about,
    /// with `value`/`name`/`nickname`. `{}` until one has been picked, and
    /// `{}` again when the account is ambiguous — a shell then explains rather
    /// than guessing.
    pub picked_identity: Value,
}

/// `profile` starts as an empty object, not `null`.
///
/// A shell that renders the account pane should not have to distinguish "no
/// profile has been read yet" from "the server sent nothing": both are "the
/// object has no keys", and every target language handles a missing key more
/// gracefully than a null one.
impl Default for AccountReport {
    fn default() -> Self {
        AccountReport {
            logged_in: false,
            email: String::new(),
            username: String::new(),
            uuid: String::new(),
            unwrapped_with: String::new(),
            key_bytes: 0,
            busy: false,
            command: String::new(),
            last_error: String::new(),
            last_backup: String::new(),
            progress: String::new(),
            status: 0,
            status_name: String::new(),
            global_version: String::new(),
            item_count: 0,
            items: Vec::new(),
            hierarchy: serde_json::json!({
                "entries": [],
                "unplaced": [],
                "folders": 0,
                "roots": 0,
            }),
            merge: Value::Object(serde_json::Map::new()),
            myts_id: String::new(),
            myts_public_key: String::new(),
            profile: Value::Object(serde_json::Map::new()),
            identities: Vec::new(),
            picked_identity: serde_json::json!({}),
        }
    }
}

/// The account's own runtime and the shared state commands mutate.
pub struct AccountEngine {
    /// `Some` for the engine's life; `None` only while `Drop` hands it to a
    /// thread that can shut it down. A separate placeholder runtime would itself
    /// need dropping from a non-async thread, which is the problem being avoided.
    runtime: Option<tokio::runtime::Runtime>,
    /// **Weak on purpose.** `Inner` owns the engine, so a strong reference here
    /// would close the cycle `Inner -> engine -> Inner` and neither the session
    /// state nor the account key in it would ever be freed. When the handle is
    /// gone there is nobody to publish to, and every accessor below handles that
    /// by doing nothing.
    inner: std::sync::Weak<Inner>,
    config: Mutex<AccountConfig>,
    /// One HTTP client for the whole engine: `reqwest::Client` is an `Arc` of a
    /// connection pool, so cloning it per command keeps TLS sessions and HTTP/2
    /// connections alive between `list`, `write` and `verify`. A fresh client per
    /// command would pay a handshake for each of the three.
    http: Http,
    busy: AtomicBool,
    /// The login, shared with the tasks that use its session id.
    account: Mutex<Option<Account>>,
    /// What the last read established, so the next one can ask only for the
    /// classes that moved instead of re-fetching all 25 items.
    ///
    /// This lives on the engine rather than on disk because it is only valid for
    /// this login's lifetime: the cursors belong to the account, and a re-login
    /// must not inherit a cursor from a session that saw a different state.
    known: Mutex<sync::MergeState>,
}

impl Drop for AccountEngine {
    /// Shuts the runtime down off whichever thread happens to hold the last
    /// reference.
    ///
    /// A multi-thread runtime panics when dropped from inside an async context
    /// ("Cannot drop a runtime in a context where blocking is not allowed"), and
    /// that is exactly where the last reference can die: `Session::account_only`
    /// parks an `Arc<Inner>` in a task that holds it until the command channel
    /// closes, so dropping the session drops the handle → drops the channel →
    /// wakes that task → drops the last `Inner` on a worker thread → drops the
    /// engine there. Moving the runtime to a plain thread makes the shutdown
    /// orderly regardless of who got there first.
    fn drop(&mut self) {
        // Nothing is joined: `exec` must not wait for shutdown, and a runtime that
        // outlives this engine for a few milliseconds only delays the exit.
        if let Some(runtime) = self.runtime.take() {
            std::thread::spawn(move || drop(runtime));
        }
    }
}

impl AccountEngine {
    pub fn new(inner: &Arc<Inner>, config: AccountConfig) -> Result<AccountEngine, String> {
        // Two threads: one is enough for HTTP work, the second keeps a
        // background restore from starving an interactive command. Named so a
        // thread dump says where it came from.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("tslib-acct")
            .build()
            .map_err(|e| format!("failed to start the account runtime: {e}"))?;
        Ok(AccountEngine {
            runtime: Some(runtime),
            inner: Arc::downgrade(inner),
            config: Mutex::new(config),
            http: Http::new(),
            busy: AtomicBool::new(false),
            account: Mutex::new(None),
            known: Mutex::new(sync::MergeState::default()),
        })
    }

    /// What the last read established, as a starting point for the next one.
    fn known_state(&self) -> sync::SyncState {
        self.known
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .state
            .clone()
    }

    /// Folds a delta read into the accumulated state and stores the cursors.
    fn remember(&self, delta: &sync::SyncState) -> sync::SyncState {
        let mut known = self.known.lock().unwrap_or_else(|e| e.into_inner());
        known.merge(delta).clone()
    }

    /// Forgets what was read, so the next read asks for everything. Used after a
    /// login (a fresh session must not trust cursors from the previous one) and
    /// after a write that changed the account's cursors.
    fn forget_reads(&self) {
        *self.known.lock().unwrap_or_else(|e| e.into_inner()) = sync::MergeState::default();
    }

    /// The handle, if the caller has not dropped it.
    fn handle(&self) -> Option<Arc<Inner>> {
        self.inner.upgrade()
    }

    fn config(&self) -> AccountConfig {
        self.config
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Replaces the configuration — used when a shell learns where the client's
    /// `settings.db` is after the session has already started.
    pub fn set_config(&self, config: AccountConfig) {
        *self.config.lock().unwrap_or_else(|e| e.into_inner()) = config;
    }

    fn account(&self) -> Option<Account> {
        self.account
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The six \`clientinit\` parameters for a connection with this IV, or
    /// \`None\` when this login has no myTeamSpeak identity.
    ///
    /// On the engine rather than on \`Account\` because the connection thread has
    /// no account handle, and the identity lives behind this engine's lock.
    pub fn myts_params(&self, shared_iv: &[u8]) -> Option<mytsid::MytsParams> {
        self.account()
            .and_then(|account| account.myts_params(shared_iv))
    }

    /// The myTeamSpeak identity this login recovered, if any.
    ///
    /// Handed to a connection that is started separately from the login: the
    /// official client signs in first and connects second, and `clientinit` is
    /// the first packet, so the proof cannot be fetched after connecting.
    pub fn identity(&self) -> Option<mytsid::MytsIdentity> {
        self.account().and_then(|account| account.identity)
    }

    /// The migrated-login database path in effect, if the shell named one.
    pub fn legacy_db(&self) -> Option<PathBuf> {
        self.context().legacy_db
    }

    /// The backup directory in effect.
    pub fn backup_dir(&self) -> PathBuf {
        self.context().backup_dir
    }

    fn set_account(&self, account: Option<Account>) {
        *self.account.lock().unwrap_or_else(|e| e.into_inner()) = account;
    }

    fn context(&self) -> AccountContext {
        let config = self.config();
        AccountContext {
            http: self.http.clone(),
            // No platform probing: a shell that wants to import from an
            // installed client names the file, and a client with no such file
            // never touches one.
            legacy_db: config.legacy_db.clone(),
            backup_dir: config.backup_dir.clone().unwrap_or_else(default_backup_dir),
            credential_file: config.credential_file.clone(),
            baseline_file: config.baseline_file.clone(),
        }
    }

    /// Publishes a report, bumping the snapshot revision only when it changed.
    fn publish(&self, report: AccountReport) {
        if let Some(inner) = self.handle() {
            inner.with_state(|snapshot| snapshot.set_account(report));
        }
    }

    /// Rebuilds the report from whatever the engine currently holds, keeping the
    /// item list unless the account went away.
    fn rebuild_report(&self, command: &str, error: &str) -> AccountReport {
        let account = self.account();
        let mut report = self
            .handle()
            .map(|inner| inner.with_state(|snapshot| snapshot.account.clone()))
            .unwrap_or_default();
        report.busy = self.busy.load(Ordering::Acquire);
        report.command = command.to_string();
        report.last_error = error.to_string();
        // `progress` belongs to a command in flight; this function only builds
        // settled reports, so it is cleared here and set explicitly by restore.
        report.progress.clear();
        if let Some(account) = &account {
            report.logged_in = true;
            report.email = account.email.clone();
            report.username = account.username.clone();
            report.uuid = account.uuid.clone();
            report.unwrapped_with = account.unwrapped_with.clone();
            report.key_bytes = account.key.map(|key| key.len()).unwrap_or(0);
            // The ID and the public key only: the scalar stays inside `Account`.
            report.myts_id = account
                .identity
                .as_ref()
                .map(|identity| mytsid::encode_id(&identity.my_teamspeak_id))
                .unwrap_or_default();
            report.myts_public_key = account.myts_public_key().unwrap_or_default();
        } else {
            report.logged_in = false;
            report.email.clear();
            report.username.clear();
            report.uuid.clear();
            report.unwrapped_with.clear();
            report.key_bytes = 0;
            report.myts_id.clear();
            report.myts_public_key.clear();
            report.items.clear();
            report.item_count = 0;
            // The profile and the item state belong to the session that just
            // went away. Leaving them behind would show the previous user's
            // name, uuid and limits to the next person at the same machine.
            report.profile = serde_json::json!({});
            report.status = 0;
            report.status_name.clear();
            report.global_version.clear();
        }
        report
    }

    /// Accepts one command and starts its task. Returns an error only for
    /// arguments this code can reject synchronously.
    pub fn dispatch(self: &Arc<Self>, command: AccountCommand) -> Result<(), String> {
        if self
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            let running = self
                .handle()
                .map(|inner| inner.with_state(|snapshot| snapshot.account.command.clone()))
                .unwrap_or_default();
            return Err(format!(
                "the account side is already running `{running}`; wait for it to finish"
            ));
        }

        let name = command.name();
        let report = self.rebuild_report(name, "");
        self.publish(report);
        log::info!("account command accepted: {name}");

        let engine = Arc::clone(self);
        let Some(runtime) = self.runtime.as_ref() else {
            return Err("the account side is shutting down".to_string());
        };
        runtime.spawn(async move {
            // Run the command in its own task so a panic becomes a reported
            // error instead of a dead task. Without this, one panicking
            // `unwrap` left `busy` set forever: nothing published, no event
            // fired, and every screen showed "signing in…" for the rest of the
            // process.
            let worker = Arc::clone(&engine);
            let outcome = match tokio::spawn(async move { worker.run(command).await }).await {
                Ok(result) => result,
                Err(e) if e.is_panic() => {
                    Err("the account command panicked; see the log for the location".to_string())
                }
                Err(e) => Err(format!("the account command was cancelled: {e}")),
            };
            let (ok, message) = match &outcome {
                Ok(message) => (true, message.clone()),
                Err(message) => (false, message.clone()),
            };
            // Clear `busy` *before* publishing: every report built while a
            // command runs says `busy: true`, so a successful command that
            // skipped this final publish would leave the pane showing a spinner
            // forever. The handler's own report supplied the results; this one
            // supplies the settled state around them.
            engine.busy.store(false, Ordering::Release);
            let report = engine.rebuild_report(name, if ok { "" } else { &message });
            engine.publish(report);
            if ok {
                log::info!("account command {name} finished: {message}");
            } else {
                log::warn!("account command {name} failed: {message}");
            }
            if let Some(inner) = engine.handle() {
                inner.push_event(
                    QueuedEvent::new("account_status")
                        .str("command", name)
                        .bool("ok", ok)
                        .str("message", message),
                );
            }
        });
        Ok(())
    }

    async fn run(&self, command: AccountCommand) -> Result<String, String> {
        let context = self.context();
        match command {
            AccountCommand::Login {
                request,
                from_ts3_client,
            } => {
                // Resolving the remembered login reads `settings.db` or the
                // credential file — the only places an email and credential-hash
                // pair can come from without the user typing a password.
                let resolved = resolve_remembered_login(
                    &context,
                    request,
                    from_ts3_client,
                    self.config().remember_login,
                )?;
                self.do_login(&context, resolved).await
            }
            AccountCommand::Logout => self.do_logout(&context).await,
            AccountCommand::Refresh { reveal_secrets } => {
                self.do_refresh(&context, reveal_secrets).await
            }
            AccountCommand::List { reveal_secrets } => self.do_list(&context, reveal_secrets).await,
            AccountCommand::Backup => self.do_backup(&context).await,
            AccountCommand::PickIdentity { address } => {
                self.pick_identity(&context, &address).await
            }
            AccountCommand::ImportIdentity { identity, uuid } => {
                self.import_identity(&context, &identity, uuid.as_deref())
                    .await
            }
            AccountCommand::CreateBookmark {
                name,
                address,
                port,
                nickname,
            } => {
                self.write_bookmark(&context, &name, &address, port, &nickname)
                    .await
            }
            AccountCommand::SetAddOnEnabled { uuid, enabled } => {
                self.set_addon(&context, &uuid, enabled).await
            }
            AccountCommand::Delete { uuid, class } => self.delete(&context, &uuid, class).await,
            AccountCommand::Restore { file } => self.restore(&context, &file).await,
            AccountCommand::Merge {
                local,
                baseline,
                record,
            } => {
                self.merge(&context, &local, baseline.as_deref(), record)
                    .await
            }
        }
    }

    // ── login ───────────────────────────────────────────────────────────────

    async fn do_login(
        &self,
        context: &AccountContext,
        resolved: ResolvedLogin,
    ) -> Result<String, String> {
        let ResolvedLogin {
            request,
            account_key: supplied_key,
        } = resolved;
        let outcome = login(context, &request).await?;
        if outcome.status != 200 || !outcome.error.is_empty() {
            // Keep the previous login: a failed re-login must not silently sign
            // the user out of a session that still works.
            let message = login_error_message(outcome.status, &outcome.error, &outcome.profile);
            let report = self.rebuild_report("account_login", &message);
            self.publish(report);
            return Err(message);
        }

        let mut account = outcome.account;
        // A remembered key fills the gap a hash login cannot close: without a
        // password there is no wrapper to derive, so the server's `key` blob
        // cannot be unwrapped and every item would report `locked`.
        if account.identity.is_none() {
            account.identity = self.account().and_then(|previous| previous.identity);
        }
        if account.relogin.is_none() && !outcome.login_hash.is_empty() {
            account.relogin = Some(Relogin {
                email: account.email.clone(),
                hash: outcome.login_hash.clone(),
            });
        }
        if account.key.is_none() {
            if let Some((key, name)) = supplied_key {
                account.key = Some(key);
                if account.unwrapped_with.is_empty() {
                    account.unwrapped_with = name.to_string();
                }
            }
        }
        let profile = outcome.profile;
        let label = if account.username.is_empty() {
            account.email.clone()
        } else {
            account.username.clone()
        };
        let key_note = if account.unwrapped_with.is_empty() {
            "not unwrapped".to_string()
        } else {
            format!("via {}", account.unwrapped_with)
        };
        // Store the login *before* building the report: `rebuild_report` fills in
        // the identity fields from the stored account, so publishing first would
        // duplicate that assignment here and let the two drift apart.
        self.set_account(Some(account.clone()));

        // Remember the login when the shell asked for that. Two fields are what
        // make the next launch silent: the credential hash (never the password)
        // and the account key, so items stay readable without a wrapper.
        let remembered = if let Some(path) = context.credential_file.as_deref() {
            match save_login(path, &account, &outcome.login_hash) {
                Ok(()) => format!("; login remembered in {}", path.display()),
                Err(e) => {
                    // Not fatal: the login worked, this run just will not be
                    // remembered. Saying so beats a silent "stay signed in" that
                    // does not.
                    log::warn!("could not remember the login: {e}");
                    format!("; the login could not be remembered: {e}")
                }
            }
        } else {
            String::new()
        };

        let mut report = self.rebuild_report("account_login", "");
        report.profile = profile.clone();
        self.publish(report);

        // A login is also a read: the pane should show the account's items
        // immediately rather than a blank list until the shell asks. This runs
        // inside the same command, so a failure here is reported with the login's
        // success (the session itself is already valid).
        //
        // A fresh session must not inherit cursors from whatever the previous
        // login saw, so `forget_reads` runs first and this read is a full one.
        self.forget_reads();
        match read_items_renewing(context, &account, None).await {
            Ok((delta, renewed)) => {
                if let Some(renewed) = renewed {
                    self.set_account(Some(renewed));
                }
                let state = self.remember(&delta);
                // Never reveals: an automatic read on sign-in is the last
                // place a bookmark password should appear.
                let views = self.render(&state, false);
                let mut report = self.rebuild_report("account_login", "");
                report.profile = profile;
                apply_item_state(&mut report, &state, self.cipher().as_ref());
                report.items = views;
                self.publish(report);
                Ok(format!(
                    "logged in as {label} (account key {key_note}); {} items, status {} {}{remembered}",
                    state.items.len(),
                    state.status.code(),
                    state.status.name()
                ))
            }
            Err(e) => Ok(format!(
                "logged in as {label} (account key {key_note}); the items could not be read yet: {e}{remembered}"
            )),
        }
    }

    async fn do_logout(&self, context: &AccountContext) -> Result<String, String> {
        let Some(account) = self.account() else {
            let report = self.rebuild_report("account_logout", "");
            self.publish(report);
            return Ok("not logged in".to_string());
        };
        let status = logout(context, &account.session).await;
        self.set_account(None);
        // The cursors belonged to that session's view of the account; the next
        // login must read fresh rather than trust them.
        self.forget_reads();
        // Signing out forgets the credential. A file left behind would sign the
        // next launch back in to the account the user just left.
        let forgotten = match context.credential_file.as_deref() {
            Some(path) => match credentials::forget(path) {
                Ok(()) => String::new(),
                Err(e) => {
                    log::warn!("could not remove the remembered login: {e}");
                    format!("; the remembered login could not be removed: {e}")
                }
            },
            None => String::new(),
        };
        let report = self.rebuild_report("account_logout", "");
        self.publish(report);
        Ok(format!(
            "logged out ({}); the session is no longer usable{forgotten}",
            if status == 204 || status == 200 {
                format!("HTTP {status}")
            } else {
                "the server did not confirm".to_string()
            }
        ))
    }

    async fn do_refresh(&self, context: &AccountContext, reveal: bool) -> Result<String, String> {
        let account = self.require_account()?;
        let mut me = context.http.rest_get("/me", &account.session).await?;
        if me.status != 200 {
            // `/me` is the cheap liveness check. A non-200 here is the same
            // signal the sync service gives with 102, so it recovers the same
            // way rather than surfacing "the session has probably expired".
            log::info!("/me answered HTTP {}; signing in again", me.status);
            let renewed = renew_session(context, &account).await?;
            self.set_account(Some(renewed.clone()));
            self.forget_reads();
            me = context.http.rest_get("/me", &renewed.session).await?;
            if me.status != 200 {
                return Err(format!(
                    "/me still answered HTTP {} after signing in again",
                    me.status
                ));
            }
        }
        let profile = profile_of(&me.json()?);
        let (state, views) = self.read_views(context, reveal).await?;
        let mut report = self.rebuild_report("account_refresh", "");
        report.profile = profile;
        apply_item_state(&mut report, &state, self.cipher().as_ref());
        report.items = views;
        self.publish(report);
        Ok(format!(
            "{} items, status {} {}",
            state.items.len(),
            state.status.code(),
            state.status.name()
        ))
    }

    // ── reads ───────────────────────────────────────────────────────────────

    async fn do_list(&self, context: &AccountContext, reveal: bool) -> Result<String, String> {
        self.require_account()?;
        let (state, views) = self.read_views(context, reveal).await?;
        let mut report = self.rebuild_report("sync_list", "");
        apply_item_state(&mut report, &state, self.cipher().as_ref());
        report.items = views;
        self.publish(report);
        Ok(format!(
            "{} items, status {} {}",
            state.items.len(),
            state.status.code(),
            state.status.name()
        ))
    }

    /// Reads the server state and renders each item for the shell.
    ///
    /// Carries the cursors from the previous read, so a quiet account costs a
    /// 59-byte reply instead of a full one; the delta is folded into what was
    /// already known, which is why an absent class is not an empty class.
    async fn read_views(
        &self,
        context: &AccountContext,
        reveal: bool,
    ) -> Result<(SyncState, Vec<Value>), String> {
        let known = self.known_state();
        // The read goes through the engine so an expired session is renewed
        // here, once, for every caller.
        let delta = self.read_renewing(context, Some(&known)).await?;
        let state = self.remember(&delta);
        let views = self.render(&state, reveal);
        Ok((state, views))
    }

    /// A read that survives an expired session by signing in again **once**.
    ///
    /// The server answers a dead session with `status=102 SESSION_EXPIRED` and no
    /// items, which is indistinguishable from an empty account unless it is
    /// handled. Handling it here rather than in each command is deliberate: every
    /// read path goes through this, so `list`, `refresh`, a write's verification
    /// and a backup all recover the same way, and none of them has to know that a
    /// session can expire.
    ///
    /// One retry, never a loop: a credential that is itself rejected (password
    /// changed, 2FA now required) returns that error to the caller instead of
    /// signing in forever.
    async fn read_renewing(
        &self,
        context: &AccountContext,
        known: Option<&SyncState>,
    ) -> Result<SyncState, String> {
        let account = self.require_account()?;
        let (delta, renewed) = read_items_renewing(context, &account, known).await?;
        if let Some(renewed) = renewed {
            log::info!(
                "signed in again after the session expired (still {})",
                renewed.username
            );
            self.set_account(Some(renewed));
            // The cursors belonged to the dead session's view.
            self.forget_reads();
        }
        Ok(delta)
    }

    /// Turns a server state into the per-item objects the shell renders.
    ///
    /// `reveal_secrets` is passed rather than stored on the engine, so the
    /// decision is per command: one `sync_list` may want the passwords, the
    /// automatic read after a login must not.
    fn render(&self, state: &SyncState, reveal_secrets: bool) -> Vec<Value> {
        let cipher = self.cipher();
        describe(state, cipher.as_ref(), reveal_secrets)
            .into_iter()
            .map(|view| view.to_json())
            .collect()
    }

    /// The item cipher for this session, or `None` when the login did not
    /// produce an account key.
    fn cipher(&self) -> Option<ItemCipher> {
        self.account()
            .and_then(|account| account.key)
            .map(ItemCipher::new)
    }

    /// The cipher, or an error that says why an item cannot be touched.
    fn require_cipher(&self) -> Result<ItemCipher, String> {
        self.cipher().ok_or_else(|| {
            "this session has no account key: the login response's `key` could not be unwrapped, \
             so items cannot be read or written. Sign in again with a password."
                .to_string()
        })
    }

    async fn do_backup(&self, context: &AccountContext) -> Result<String, String> {
        let state = self.read_renewing(context, None).await?;
        let path = write_backup(&state, &context.backup_dir, "manual")?;
        let mut report = self.rebuild_report("sync_backup", "");
        report.last_backup = path.display().to_string();
        apply_item_state(&mut report, &state, self.cipher().as_ref());
        self.publish(report);
        Ok(format!(
            "{} items backed up to {}",
            state.items.len(),
            path.display()
        ))
    }

    // ── writes ──────────────────────────────────────────────────────────────

    async fn write_bookmark(
        &self,
        context: &AccountContext,
        name: &str,
        address: &str,
        port: u32,
        nickname: &str,
    ) -> Result<String, String> {
        let state = self.read_renewing(context, None).await?;
        // The read may have replaced the session (an expiry is renewed there),
        // so the account is taken again: a plan built with the dead session would
        // be sent with it and renew a second time.
        let account = self.require_account()?;
        let cipher = self.require_cipher()?;

        // A new bookmark needs a template: every field this code does not know
        // how to fill (profile references, flags, defaults) comes from an
        // existing bookmark, so the result has the shape the real client writes.
        // Any bookmark will do — the cipher no longer constrains length, so there
        // is no "longest donor" to hunt for.
        let template = state
            .of_class(ItemClass::Bookmark)
            .find_map(|item| sync::read_plain(item, Some(&cipher)).ok())
            .ok_or_else(|| {
                "this account has no readable bookmark to use as a template, so the shape of a \
                 new one is unknown"
                    .to_string()
            })?;

        let draft = sync::BookmarkDraft {
            uuid: crypto::uuid_v4(),
            item_version: crypto::uuid_v4(),
            name: name.to_string(),
            address: address.to_string(),
            port,
            nickname: nickname.to_string(),
        };
        let built = sync::build_bookmark(&template, &draft)?;
        // `seal` picks a fresh counter and works at any length: the item cipher
        // is a stream cipher over the whole item, so nothing here is capped.
        let blob = cipher.seal(&built);
        // Read it back before sending. This is the same check the client would
        // run on receipt, so "the server accepted it" and "it is readable" stop
        // being two different claims.
        cipher.open(&blob)?;

        let plan = WritePlan::new(
            &state,
            &account.session,
            ItemClass::Bookmark,
            &draft.uuid,
            &draft.item_version,
            blob,
            format!("create bookmark {:?} -> {address}:{port}", draft.name),
        );
        let outcome = execute_write(context, &account, &state, plan).await?;
        let _ = &account;
        let detail = self
            .update_after_write(context, "sync_bookmark_create", outcome)
            .await?;
        Ok(format!("bookmark {} created ({detail})", draft.uuid))
    }

    async fn set_addon(
        &self,
        context: &AccountContext,
        uuid: &str,
        enabled: bool,
    ) -> Result<String, String> {
        let state = self.read_renewing(context, None).await?;
        // The read may have replaced the session (an expiry is renewed there),
        // so the account is taken again: a plan built with the dead session would
        // be sent with it and renew a second time.
        let account = self.require_account()?;
        let item = state
            .item(uuid)
            .ok_or_else(|| format!("{uuid} is not on the server"))?;
        // An add-on's payload is a bare `Item_Data` on the wire, so this needs no
        // key. Re-read it through the same helper the renderer uses rather than
        // assuming the blob is plain: the day an add-on arrives wrapped, this
        // branch still works.
        let plain = sync::read_plain(item, self.cipher().as_ref())
            .map_err(|e| format!("{uuid} cannot be read: {e}"))?;
        if !sync::is_plain_item_data(&plain) {
            return Err(format!(
                "{uuid} carries an encrypted `Item_Data`, so the add-on payload cannot be found"
            ));
        }
        // Field 20 is the add-on payload; field 2 inside it is `enabled`.
        let (previous, edited) = sync::set_nested_varint(&plain, 20, 2, u64::from(enabled))?;
        if !sync::is_plain_item_data(&edited) {
            return Err("the rewritten item no longer parses as an Item_Data; aborted".to_string());
        }
        // On the wire an add-on stays plain, so it is sent as-is. If the server
        // handed one back wrapped, wrap it again with a fresh header.
        let blob = if sync::is_plain_item_data(&item.blob) {
            edited
        } else {
            let cipher = self.require_cipher()?;
            cipher.seal(&edited)
        };
        let plan = WritePlan::new(
            &state,
            &account.session,
            item.class,
            uuid,
            &item.item_version,
            blob,
            format!("add-on {uuid} enabled {previous} -> {}", u8::from(enabled)),
        );
        let outcome = execute_write(context, &account, &state, plan).await?;
        let _ = &account;
        let detail = self
            .update_after_write(context, "sync_addon_enabled", outcome)
            .await?;
        Ok(format!(
            "add-on {uuid} is now {} ({detail})",
            if enabled { "enabled" } else { "disabled" }
        ))
    }

    async fn delete(
        &self,
        context: &AccountContext,
        uuid: &str,
        class: Option<ItemClass>,
    ) -> Result<String, String> {
        let state = self.read_renewing(context, None).await?;
        // The read may have replaced the session (an expiry is renewed there),
        // so the account is taken again: a plan built with the dead session would
        // be sent with it and renew a second time.
        let account = self.require_account()?;
        let item = state
            .item(uuid)
            .ok_or_else(|| format!("{uuid} is not on the server"))?;
        let class = match class {
            Some(class) if class != item.class => {
                return Err(format!(
                    "{uuid} is a {} item, not {}",
                    item.class.name(),
                    class.name()
                ))
            }
            Some(class) => class,
            None => item.class,
        };
        let (status, backup_path, gone, renewed) =
            execute_delete(context, &account, &state, class, uuid).await?;
        if let Some(renewed) = renewed {
            // Same rule as a write: do not replace a newer session with an older
            // renewal.
            let current = self.account().map(|a| a.session).unwrap_or_default();
            if current == account.session || current == renewed.session {
                self.set_account(Some(renewed));
                self.forget_reads();
            }
        }
        self.update_after_delete(context, status, backup_path, gone)
            .await
    }

    // ── comparing a local copy against the account ──────────────────────────

    /// Compares a local backup against the server and reports what each side
    /// changed.
    ///
    /// Read-only unless `record` is set: a comparison that *applied* its own
    /// conclusion would be the silent overwrite this whole feature exists to
    /// prevent. `record` writes the baseline — the set of items both sides agree
    /// on — which is what the next compare needs to attribute a change to one
    /// side instead of reporting a conflict.
    async fn merge(
        &self,
        context: &AccountContext,
        local_path: &Path,
        baseline_path: Option<&Path>,
        record: bool,
    ) -> Result<String, String> {
        let account = self.require_account()?;
        let cipher = self.cipher();

        // The local side first: a file that cannot be read must fail before a
        // network read is spent on it.
        let text = std::fs::read_to_string(local_path)
            .map_err(|e| format!("cannot read {}: {e}", local_path.display()))?;
        let json: Value = serde_json::from_str(&text)
            .map_err(|e| format!("{} is not JSON: {e}", local_path.display()))?;
        let backup = Backup::from_json(&json)?;
        if backup.items.is_empty() {
            return Err(format!(
                "{} contains no items to compare",
                local_path.display()
            ));
        }
        let local = merge::LocalItem::from_backup(&backup, cipher.as_ref())?;

        // The baseline: the named file, else the configured one, else none. A
        // present-but-corrupt file is an error rather than "no baseline": silently
        // starting over would make every item look like a two-sided edit.
        let path = baseline_path
            .map(Path::to_path_buf)
            .or_else(|| context.baseline_file.clone());
        let baseline = match path.as_deref() {
            Some(path) => merge::load(path)?,
            None => None,
        };
        if let Some(baseline) = &baseline {
            if !baseline.account_uuid.is_empty() && baseline.account_uuid != account.uuid {
                return Err(format!(
                    "the baseline at {} belongs to another account ({}), not {}",
                    path.as_deref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                    baseline.account_uuid,
                    account.uuid
                ));
            }
        }

        // A full read on purpose: the baseline's cursors are recorded, never used
        // to ask for a partial reply, because a baseline holds digests rather than
        // items and an omitted class would have to be read as a delete.
        let state = self.read_renewing(context, None).await?;
        let plan = merge::compare(baseline.as_ref(), &local, &state, cipher.as_ref());

        let json = plan.to_json();
        let mut report = self.rebuild_report("sync_merge", "");
        apply_item_state(&mut report, &state, cipher.as_ref());
        report.merge = json.clone();
        self.publish(report);

        // Recording the agreement is a local file write, not a server write, so
        // it is allowed without asking. What it records is only the items that
        // *both* sides already hold identically — a pending item recorded as
        // agreed would look like a deletion next time.
        let recorded = if record {
            let saved = merge::Baseline::of(
                &state,
                &account.uuid,
                &local,
                cipher.as_ref(),
                &now_iso8601(),
            );
            match path.as_deref() {
                Some(path) => {
                    merge::save(path, &saved)?;
                    format!(
                        "; recorded {} agreed items in {}",
                        saved.items.len(),
                        path.display()
                    )
                }
                None => {
                    return Err(
                        "no baseline file is configured; pass a baseline path or set one with \
                         account_config"
                            .to_string(),
                    )
                }
            }
        } else {
            String::new()
        };

        let conflicts = plan.count(merge::Action::Conflict);
        let push = plan.count(merge::Action::Push);
        let pull = plan.count(merge::Action::Pull);
        let merged = plan.count(merge::Action::Merge);
        let unreadable = plan.unreadable.len();
        let note = if unreadable > 0 {
            format!("; {unreadable} item(s) could not be read and were not compared")
        } else {
            String::new()
        };
        if conflicts > 0 {
            // Reported as a *result*, not an error: a conflict is a thing a user
            // decides, and an error would leave the report unread.
            Ok(format!(
                "{conflicts} conflict(s), {push} to push, {pull} to pull, {merged} to merge{note}; \
                 see the merge report{recorded}"
            ))
        } else {
            Ok(format!(
                "{push} to push, {pull} to pull, {merged} to merge, nothing conflicting{note}{recorded}"
            ))
        }
    }

    // ── restore ─────────────────────────────────────────────────────────────

    /// Replays a backup file, one item per request, verifying each one.
    ///
    /// One item per request is the only reliable shape; batching is how a single
    /// collision turns into "some of them were applied and nobody knows which".
    async fn restore(&self, context: &AccountContext, file: &Path) -> Result<String, String> {
        // The session is re-read on every item, below: a renewal during one item
        // must be picked up by the next, and holding a copy here would keep the
        // dead session alive for the rest of the replay.
        let text = std::fs::read_to_string(file)
            .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
        let json: Value = serde_json::from_str(&text)
            .map_err(|e| format!("{} is not JSON: {e}", file.display()))?;
        let backup = Backup::from_json(&json)?;
        if backup.items.is_empty() {
            return Err(format!("{} contains no items", file.display()));
        }

        let mut report = self.rebuild_report("sync_restore", "");
        report.busy = true;
        self.publish(report);

        let total = backup.items.len();
        let mut restored = 0usize;
        let mut failed = Vec::new();
        let mut last_backup = String::new();
        for item in &backup.items {
            let state = self.read_renewing(context, None).await?;
            // A renewal during the previous item's write left the engine with a
            // new session; take the live one so this plan is sent with it rather
            // than renewing a second time.
            let account = self.require_account()?;
            let plan = WritePlan::new(
                &state,
                &account.session,
                item.class,
                &item.uuid,
                &item.item_version,
                item.blob.clone(),
                format!("restore {} {}", item.class.name(), item.uuid),
            );
            match execute_write(context, &account, &state, plan).await {
                Ok(outcome) if outcome.verified => {
                    self.adopt_renewal(&outcome);
                    restored += 1;
                    last_backup = outcome.backup_path.display().to_string();
                    // One progress report per item, so a long restore is a moving
                    // bar rather than forty seconds of nothing.
                    let mut report = self.rebuild_report("sync_restore", "");
                    report.busy = true;
                    report.progress = format!("{restored}/{total} items restored");
                    report.last_backup = last_backup.clone();
                    self.publish(report);
                }
                Ok(outcome) => {
                    self.adopt_renewal(&outcome);
                    last_backup = outcome.backup_path.display().to_string();
                    failed.push(format!(
                        "{} ({}: {})",
                        item.uuid,
                        outcome.status.code(),
                        outcome.status.name()
                    ));
                }
                Err(e) => failed.push(format!("{} ({e})", item.uuid)),
            }
        }

        let mut report = self.rebuild_report("sync_restore", "");
        report.last_backup = last_backup;
        self.publish(report);

        if failed.is_empty() {
            Ok(format!("{restored}/{total} items restored"))
        } else {
            Err(format!(
                "{restored}/{total} restored; {} failed: {}",
                failed.len(),
                failed.join(", ")
            ))
        }
    }

    /// Publishes the identity a server knows this account by.
    ///
    /// The result lands in `snapshot.account.pickedIdentity` and is also the
    /// command's message. A read, not a write: nothing on the server changes, so
    /// it is safe to call before every connect.
    async fn pick_identity(
        &self,
        context: &AccountContext,
        address: &str,
    ) -> Result<String, String> {
        self.require_account()?;
        let state = self.read_renewing(context, None).await?;
        let cipher = self.cipher();
        let chosen = preferred_identity(&state, cipher.as_ref(), address);

        let mut report = self.rebuild_report("identity_pick", "");
        apply_item_state(&mut report, &state, cipher.as_ref());
        match chosen {
            Some(identity) => {
                report.picked_identity = serde_json::json!({
                    "value": identity.identity,
                    "name": identity.name,
                    "nickname": identity.nickname,
                });
                let label = if identity.name.is_empty() {
                    identity.nickname.clone()
                } else {
                    identity.name.clone()
                };
                self.publish(report);
                Ok(format!("identity `{label}` is the one this server knows"))
            }
            None => {
                // Two unmarked identities and no bookmark naming one: writing
                // either would be a guess, and a guess here hands a server the
                // wrong UID. Say so instead.
                report.picked_identity = serde_json::json!({});
                self.publish(report);
                Err(
                    "the account holds several identities and none is marked default for this                      server; connect once with the official client so its bookmark records                      which one it used"
                        .to_string(),
                )
            }
        }
    }

    /// Writes the shell's identity into the account's `IDENTITY` item.
    ///
    /// Two directions matter here. The **account** is where the official client
    /// keeps the key, which is why a reinstall on another machine comes back with
    /// the same UID and the same server groups. The **library** never generates
    /// one for the account, so the shell passes the `counterVkey` it already
    /// stores locally; this validates it and copies it into the item, keeping
    /// every other field (names, profiles, flags) as the server has them.
    ///
    /// A no-op guard: writing an identical string is reported as unchanged rather
    /// than spending a server write that would move the account's cursors.
    async fn import_identity(
        &self,
        context: &AccountContext,
        identity: &str,
        uuid: Option<&str>,
    ) -> Result<String, String> {
        let identity = identity.trim();
        if identity.is_empty() {
            return Err("an identity is required".to_string());
        }
        // Parse before writing: a malformed string stored in the account would
        // come back as a broken session on the next install, and the error here
        // is the only place that can say why.
        let parsed = tsclientlib::Identity::new_from_ts_str(identity)
            .map_err(|e| format!("the supplied identity does not parse: {e}"))?;
        let normalized = crate::identity_to_ts_str(&parsed);

        let state = self.read_renewing(context, None).await?;
        let account = self.require_account()?;
        let cipher = self.require_cipher()?;

        let identities: Vec<&sync::Item> = state.of_class(ItemClass::Identity).collect();
        if identities.is_empty() {
            return Err(
                "this account has no IDENTITY item to write; the official client creates one on                  first use, and this library does not invent its shape"
                    .to_string(),
            );
        }
        let item = match uuid {
            Some(uuid) => state
                .item(uuid)
                .filter(|item| item.class == ItemClass::Identity)
                .ok_or_else(|| format!("{uuid} is not an IDENTITY item on this account"))?,
            None => {
                // Prefer the default one; otherwise the only one. More than one
                // without a default is ambiguous, so say so instead of guessing.
                let mut chosen = None;
                let mut defaults = 0;
                for candidate in &identities {
                    let plain = sync::read_plain(candidate, Some(&cipher))?;
                    let Some(view) = sync::AccountIdentity::parse(&plain)? else {
                        continue;
                    };
                    if view.is_default {
                        defaults += 1;
                        chosen = Some(*candidate);
                    } else if chosen.is_none() {
                        chosen = Some(*candidate);
                    }
                }
                if defaults > 1 {
                    return Err(
                        "the account marks more than one identity as default; pass `uuid` to say                          which one to write"
                            .to_string(),
                    );
                }
                chosen.ok_or_else(|| {
                    "the IDENTITY items on this account cannot be read, so there is nothing to                      write into"
                        .to_string()
                })?
            }
        };

        let plain = sync::read_plain(item, Some(&cipher))?;
        let current = sync::AccountIdentity::parse(&plain)?
            .ok_or_else(|| format!("{} has no readable identity field", item.uuid))?;
        if current.identity == normalized {
            let mut report = self.rebuild_report("identity_import", "");
            let data = self.known_state();
            apply_item_state(&mut report, &data, self.cipher().as_ref());
            self.publish(report);
            return Ok(format!(
                "{} already holds this identity; nothing written",
                item.uuid
            ));
        }

        let edited = sync::set_identity_string(&plain, &normalized)?;
        // Wrap only when the server handed this one back sealed.
        let blob = if sync::is_plain_item_data(&item.blob) {
            edited
        } else {
            cipher.seal(&edited)
        };
        let plan = WritePlan::new(
            &state,
            &account.session,
            ItemClass::Identity,
            &item.uuid,
            &item.item_version,
            blob,
            format!("write identity into {}", item.uuid),
        );
        let outcome = execute_write(context, &account, &state, plan).await?;
        let _ = &account;
        let detail = self
            .update_after_write(context, "identity_import", outcome)
            .await?;
        Ok(format!("identity written to {} ({detail})", item.uuid))
    }

    /// Shared tail of every write: re-read and publish what is actually stored.
    async fn update_after_write(
        &self,
        context: &AccountContext,
        command: &str,
        outcome: WriteOutcome,
    ) -> Result<String, String> {
        // A write moves the account's cursors, so the accumulated view is no
        // longer trustworthy: forget it and read the whole thing back. This is
        // the one place a full read is correct by construction rather than by
        // luck, and it is also the verification the caller relies on.
        self.forget_reads();
        let delta = self.read_renewing(context, None).await?;
        let state = self.remember(&delta);
        // A write's read-back is automatic: presence only, never the values.
        let views = self.render(&state, false);
        let mut report = self.rebuild_report(command, "");
        report.last_backup = outcome.backup_path.display().to_string();
        apply_item_state(&mut report, &state, self.cipher().as_ref());
        report.items = views;
        self.adopt_renewal(&outcome);
        if !outcome.status.accepted() {
            report.last_error = format!(
                "the server refused the write: {} ({}); nothing was changed",
                outcome.status.code(),
                outcome.status.name()
            );
            let message = report.last_error.clone();
            self.publish(report);
            return Err(message);
        }
        if !outcome.verified {
            report.last_error =
                "the server accepted the write but the stored bytes differ; replay the backup"
                    .to_string();
            let message = report.last_error.clone();
            self.publish(report);
            return Err(message);
        }
        self.publish(report);
        Ok(format!(
            "{} ({}; backup {})",
            outcome.status.name(),
            outcome.status.code(),
            outcome.backup_path.display()
        ))
    }

    async fn update_after_delete(
        &self,
        context: &AccountContext,
        status: SyncStatus,
        backup_path: PathBuf,
        gone: bool,
    ) -> Result<String, String> {
        self.forget_reads();
        let delta = self.read_renewing(context, None).await?;
        let state = self.remember(&delta);
        // A write's read-back is automatic: presence only, never the values.
        let views = self.render(&state, false);
        let mut report = self.rebuild_report("sync_delete", "");
        report.last_backup = backup_path.display().to_string();
        apply_item_state(&mut report, &state, self.cipher().as_ref());
        report.items = views;
        if !status.accepted() {
            report.last_error = format!(
                "the server refused the delete: {} ({}); nothing was changed",
                status.code(),
                status.name()
            );
            let message = report.last_error.clone();
            self.publish(report);
            return Err(message);
        }
        if !gone {
            report.last_error =
                "the delete was accepted but the item is still there; replay the backup"
                    .to_string();
            let message = report.last_error.clone();
            self.publish(report);
            return Err(message);
        }
        self.publish(report);
        Ok(format!(
            "deleted ({}; backup {})",
            status.name(),
            backup_path.display()
        ))
    }

    /// Installs a session a write had to renew, unless something newer already
    /// landed.
    ///
    /// A write renews once for itself and once for its read-back, so the renewal
    /// in `WriteOutcome` can be older than what the engine holds by the time the
    /// command comes to install it. Comparing against the session the write
    /// replaced is what keeps an older renewal from overwriting a newer one —
    /// install it blindly and the next command sends on a session that has
    /// already died.
    fn adopt_renewal(&self, outcome: &WriteOutcome) {
        let Some(renewed) = outcome.renewed.clone() else {
            return;
        };
        let current = self
            .account()
            .map(|account| account.session)
            .unwrap_or_default();
        if current == outcome.previous_session || current == renewed.session {
            self.set_account(Some(renewed));
        }
    }

    fn require_account(&self) -> Result<Account, String> {
        self.account()
            .filter(|account| !account.session.is_empty())
            .ok_or_else(|| "not logged in: run account_login first".to_string())
    }
}

/// Everything the account side needs to run: an HTTP client, an optional migrated
/// login, and where backups go.
///
/// There is deliberately no "local database" here any more. The research once
/// believed the item key could only be recovered from the official client's
/// `settings.db`; it cannot — the key is in the login response. A `settings.db` is
/// now only used for one optional thing: importing a login from an already
/// installed client, which is a *migration* and not a dependency.
pub struct AccountContext {
    pub http: Http,
    pub legacy_db: Option<PathBuf>,
    pub backup_dir: PathBuf,
    /// Where the remembered login lives, when the shell asked for one.
    pub credential_file: Option<PathBuf>,
    /// Where the sync baseline lives, when the shell asked for one.
    pub baseline_file: Option<PathBuf>,
}

/// The outcome of a login.
pub struct LoginOutcome {
    pub account: Account,
    pub profile: Value,
    pub status: u16,
    pub error: String,
    /// The credential hash the server accepted, so a shell can remember the
    /// login without ever seeing the password again. Empty when the email was
    /// rejected.
    pub login_hash: String,
}

/// Logs in and unwraps the account key.
///
/// Wrapper candidates are tried in the order that mirrors what the client would
/// have: a derivation from a plaintext password, then the key already stored in
/// the local `settings.db`. The **GCM tag** is the only witness for which one was
/// right; a mismatch means the candidate is discarded, not that the login failed.
pub async fn login(
    context: &AccountContext,
    request: &LoginRequest,
) -> Result<LoginOutcome, String> {
    let email = request.email.trim();
    if email.is_empty() {
        return Err("an email address is required".to_string());
    }

    // Every wrapper shape the password admits, tried in order and judged by the
    // GCM tag. One derived value cannot distinguish "wrong password" from
    // "right password, email cased differently in the salt"; a list can.
    let mut wrapper_candidates: Vec<(&'static str, [u8; KEY_LEN])> = Vec::new();
    let hash = match (&request.hash, &request.password) {
        (Some(hash), _) if !hash.trim().is_empty() => hash.trim().to_string(),
        (_, Some(password)) if !password.is_empty() => {
            wrapper_candidates = crypto::wrapper_candidates(password, email);
            crypto::hashed_password(password, email)
        }
        _ => {
            return Err(
                "a credential hash or a password is required (a login from an existing client \
                 profile supplies the hash; otherwise the password is hashed here)"
                    .to_string(),
            )
        }
    };

    let mut body = serde_json::json!({ "email": email, "password": hash });
    if let Some(otp) = request.otp.as_deref().filter(|v| !v.trim().is_empty()) {
        body["otp"] = Value::String(otp.trim().to_string());
    }
    if let Some(code) = request
        .recovery_key
        .as_deref()
        .filter(|v| !v.trim().is_empty())
    {
        body["recoveryKey"] = Value::String(crypto::hash_recovery_key(code));
    }

    let reply = context.http.rest_post("/client/login", &body, None).await?;
    let json = reply.json().unwrap_or(Value::Null);
    let error = json
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if reply.status != 200 || error != "ERROR_LOGIN_OK" {
        return Ok(LoginOutcome {
            account: Account {
                email: email.to_string(),
                ..Account::default()
            },
            profile: profile_of(&json),
            status: reply.status,
            error: if error.is_empty() {
                format!("HTTP {}", reply.status)
            } else {
                error
            },
            // A rejected login must not hand back a credential to store.
            login_hash: String::new(),
        });
    }

    let session = json
        .get("session")
        .or_else(|| json.get("sessionId"))
        .and_then(Value::as_str)
        .ok_or_else(|| "the login reply carried no session id".to_string())?
        .to_string();

    // Prove the session works before reporting success: an accepted login whose
    // session is already dead would otherwise show up as "everything fails later".
    let me = context.http.rest_get("/me", &session).await?;
    if me.status != 200 {
        return Err(format!(
            "the login reply had a session but /me answered HTTP {}",
            me.status
        ));
    }

    let key_blob = json.get("key").and_then(Value::as_str).unwrap_or_default();
    let mut wrappers: Vec<(&str, [u8; KEY_LEN])> = Vec::new();
    wrappers.extend(wrapper_candidates);
    // The local database is checked last on purpose: a password-derived wrapper
    // is the one a standalone client has, so when it works the login reports it
    // and the `settings.db` path is not credited to a migration that did not
    // happen.
    if let Some(path) = context.legacy_db.as_deref() {
        match wrapper_key_from_db(path) {
            Ok(wrapper) => wrappers.push(("settings.db field5", wrapper)),
            Err(e) => log::debug!("no wrapper key in {}: {e}", path.display()),
        }
    }

    let mut key = None;
    let mut unwrapped_with = String::new();
    if !key_blob.is_empty() {
        for (name, wrapper) in &wrappers {
            match crypto::unwrap_key(key_blob, wrapper) {
                Ok(unwrapped) => {
                    key = Some(unwrapped);
                    unwrapped_with = (*name).to_string();
                    log::info!("account key unwrapped with: {name}");
                    break;
                }
                Err(e) => log::debug!("wrapper candidate {name} did not fit: {e}"),
            }
        }
        if key.is_none() {
            // Not fatal: reads only need the session, and every read path works
            // without the key. Only item *content* needs it, which is why a shell
            // shows this as "locked" rather than as a failed login.
            log::warn!(
                "the account key could not be unwrapped with any of {} candidates: {}",
                wrappers.len(),
                wrappers
                    .iter()
                    .map(|(name, _)| *name)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    let profile = profile_of(&json);
    Ok(LoginOutcome {
        account: Account {
            session,
            email: json
                .get("email")
                .and_then(Value::as_str)
                .unwrap_or(email)
                .to_string(),
            username: json
                .get("username")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            uuid: json
                .get("uuid")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            unwrapped_with,
            key,
            // Keep the accepted credential in memory so a session that expires
            // mid-command can be replaced without asking again. It is the same
            // value a remembered login stores; see `Relogin` for why it is not
            // serialized anywhere.
            relogin: if hash.is_empty() {
                None
            } else {
                Some(Relogin {
                    email: json
                        .get("email")
                        .and_then(Value::as_str)
                        .unwrap_or(email)
                        .to_string(),
                    hash: hash.clone(),
                })
            },
            // The myTeamSpeak identity, when the reply carried one and the
            // account key opened it. A failure here is logged rather than
            // returned: the login worked, the badge simply will not be announced.
            identity: match key {
                Some(key) => match mytsid::MytsIdentity::from_login(&json, &key) {
                    Ok(identity) => {
                        if identity.is_some() {
                            log::info!("myTeamSpeak identity recovered; authSign can be signed");
                        }
                        identity
                    }
                    Err(e) => {
                        log::warn!("the myTeamSpeak identity could not be recovered: {e}");
                        None
                    }
                },
                None => None,
            },
        },
        profile,
        status: 200,
        error: String::new(),
        login_hash: hash,
    })
}

/// Logs out. The session is dead afterwards whether or not this succeeds, so a
/// failure is logged rather than returned: a shell told "logout failed" would keep
/// a credential it has been asked to forget.
pub async fn logout(context: &AccountContext, session: &str) -> u16 {
    match context
        .http
        .rest_post("/logout", &Value::Null, Some(session))
        .await
    {
        Ok(reply) => reply.status,
        Err(e) => {
            log::warn!("logout request failed: {e}");
            0
        }
    }
}

/// Signs in again with the credential that created `account`.
///
/// This is what makes an expired session invisible to the user: the hash the
/// login already accepted is replayed, and the new session inherits the account
/// key the old one had (a hash login cannot derive a wrapper, so the key would
/// otherwise be lost). A login that has no credential — one made from a bare
/// session or a rejected attempt — says so instead of looping.
pub async fn renew_session(context: &AccountContext, account: &Account) -> Result<Account, String> {
    let Some(relogin) = account.relogin.as_ref() else {
        return Err(
            "the session expired and this login kept no credential to sign in again; \
             run account_login"
                .to_string(),
        );
    };
    let request = LoginRequest {
        email: relogin.email.clone(),
        hash: Some(relogin.hash.clone()),
        ..LoginRequest::default()
    };
    let outcome = login(context, &request).await?;
    if outcome.status != 200 || !outcome.error.is_empty() {
        return Err(login_error_message(
            outcome.status,
            &outcome.error,
            &outcome.profile,
        ));
    }
    let mut renewed = outcome.account;
    // A hash login has no wrapper to derive, so the server's `key` cannot be
    // unwrapped. Carrying the previous key over is what keeps items readable
    // across the renewal instead of turning them all `locked`.
    if renewed.key.is_none() {
        if let Some(key) = account.key {
            renewed.key = Some(key);
            if renewed.unwrapped_with.is_empty() {
                renewed.unwrapped_with = account.unwrapped_with.clone();
            }
        }
    }
    if renewed.relogin.is_none() {
        renewed.relogin = account.relogin.clone();
    }
    // The identity is not in the login reply again — a hash login carries no
    // key blob this session can open — so it has to survive the renewal too.
    if renewed.identity.is_none() {
        renewed.identity = account.identity.clone();
    }
    Ok(renewed)
}

/// A read that survives an expired session by signing in again **once**.
///
/// The server answers a dead session with `status=102 SESSION_EXPIRED` and no
/// items, which is indistinguishable from an empty account unless it is handled.
/// Every read path goes through this — `list`, `refresh`, a backup, a write's
/// cursor check and its verification — so all of them recover the same way and
/// none of them has to know that a session can expire.
///
/// **One retry, never a loop.** A credential that is itself refused (password
/// changed, 2FA now required) returns that error instead of signing in forever.
///
/// The renewed account is returned as well, because the caller has to adopt it:
/// the old session id is dead, and the account key and the credential live on
/// that value, not on the session string.
pub async fn read_items_renewing(
    context: &AccountContext,
    account: &Account,
    known: Option<&SyncState>,
) -> Result<(SyncState, Option<Account>), String> {
    let state = read_delta(context, account, known).await?;
    if state.status != SyncStatus::SessionExpired {
        return Ok((state, None));
    }
    log::info!("the account session expired; signing in again");
    let renewed = renew_session(context, account).await?;
    // The cursors described the old session's view of the account; the renewed
    // one has seen nothing, so this read is a full one.
    let state = read_delta(context, &renewed, None).await?;
    if state.status == SyncStatus::SessionExpired {
        return Err(
            "the session expired again immediately after signing in; the server is refusing \
             this credential"
                .to_string(),
        );
    }
    Ok((state, Some(renewed)))
}

/// A read of the whole server state: no cursors, so the server sends every class.
///
/// Used where a complete picture is required regardless of what was seen before —
/// a backup, and the first read of a session. **This does not renew an expired
/// session**; it reports `SyncStatus::SessionExpired` as it came. A caller that
/// wants the transparent behaviour uses [`read_items_renewing`], which can hand
/// back the account it signed in as.
pub async fn read_items(context: &AccountContext, account: &Account) -> Result<SyncState, String> {
    read_delta(context, account, None).await
}

/// One `requestServerItems`, carrying `known`'s cursors when there are any.
///
/// The reply is a delta: classes that did not move are omitted. Fold it into the
/// accumulated state with [`SyncState::apply`] rather than treating the omission
/// as a deletion.
pub async fn read_delta(
    context: &AccountContext,
    account: &Account,
    known: Option<&SyncState>,
) -> Result<SyncState, String> {
    let payload = Sync::delta_payload(&account.session, known);
    let reply = context
        .http
        .cloud("/synchronization", "requestServerItems", &payload)
        .await?;
    if reply.status != 200 {
        return Err(format!(
            "requestServerItems answered HTTP {} with {} B",
            reply.status,
            reply.body.len()
        ));
    }
    Sync::decode_reply(&reply.body)
}

/// One item, rendered for a shell.
pub struct ItemView {
    pub item: Item,
    pub capability: Capability,
    pub bookmark: Option<sync::Bookmark>,
    /// `parent`/`sort_order` as read from the plaintext, which is the only
    /// place a sealed item's placement is visible.
    pub meta: sync::ItemMeta,
    /// `Some` when this item is an `ITEM_FOLDER` (class 6).
    pub folder: Option<sync::ItemFolder>,
    /// `Some` when this item is an `IDENTITY` (class 1) and its key could be read.
    pub identity: Option<sync::AccountIdentity>,
    plain_len: usize,
    /// Whether the bookmark passwords may be rendered.
    ///
    /// A snapshot is read at 50 Hz and may end up in a log or a crash report, so
    /// the default is "presence only"; a shell that wants the values asks for
    /// them on the command that reads the item list.
    reveal_secrets: bool,
}

impl ItemView {
    pub fn to_json(&self) -> Value {
        let mut object = serde_json::json!({
            "uuid": self.item.uuid,
            "class": self.item.class.name(),
            "classId": self.item.class.id(),
            "itemVersion": self.item.item_version,
            "bytes": self.item.blob.len(),
            "capability": self.capability.kind(),
            "writable": self.capability.writable(),
            "deleted": self.item.deleted,
        });
        // `maxPlaintext` is deliberately absent: the item cipher is a stream
        // cipher over the whole item, so "the longest content this fits" is not a
        // meaningful question any more. A shell that offered a length limit would
        // be enforcing a constraint the protocol does not have.
        if self.plain_len > 0 {
            object["plaintextBytes"] = Value::from(self.plain_len);
        }
        // Placement is always present, empty strings included: a shell that
        // omitted an empty `parent` and one that wrote it both describe the top
        // level, and "absent" would be a third meaning nobody needs.
        object["parent"] = Value::from(self.meta.parent.clone());
        object["sortOrder"] = Value::from(self.meta.sort_order.clone());
        if let Some(folder) = &self.folder {
            object["folder"] = serde_json::json!({
                "name": folder.name,
                // The class this folder groups, and its raw number so an unknown
                // one (a TS6 class) is still visible rather than dropped.
                "type": folder.folder_type.map(|class| class.name()),
                "typeId": folder.folder_type_id,
            });
        }
        if let Some(identity) = &self.identity {
            object["identity"] = serde_json::json!({
                "value": identity.identity,
                "name": identity.name,
                "nickname": identity.nickname,
                "default": identity.is_default,
            });
        }
        if let Some(bookmark) = &self.bookmark {
            let mut view = serde_json::json!({
                "name": bookmark.name,
                "address": bookmark.address,
                "port": bookmark.port,
                "nickname": bookmark.nickname,
                "defaultChannel": bookmark.default_channel,
                "autoconnect": bookmark.autoconnect,
                "sendMytsid": bookmark.send_mytsid,
                "hotkeyProfile": bookmark.hotkey_profile,
                // Presence, never the value: a shell can draw a padlock
                // without a password ever reaching a snapshot a log might
                // capture.
                // The identity *name* this bookmark was created with (measured
                // on a real client: `Default`, the IDENTITY item's own name).
                "identityName": bookmark.identity_name,
                "hasServerPassword": !bookmark.server_password.is_empty(),
                "hasChannelPassword": !bookmark.default_channel_password.is_empty(),
            });
            // Listing with revealSecrets set is the only way these appear.
            // The account key follows the same rule for the same reason: an
            // explicit opt-in, never a default.
            if self.reveal_secrets {
                view["serverPassword"] = Value::from(bookmark.server_password.clone());
                view["channelPassword"] = Value::from(bookmark.default_channel_password.clone());
            }
            object["bookmark"] = view;
        }
        object
    }
}

/// Renders every item in the state, reading the content where this session holds
/// the key.
pub fn describe(
    state: &SyncState,
    cipher: Option<&ItemCipher>,
    reveal_secrets: bool,
) -> Vec<ItemView> {
    state
        .items
        .iter()
        .map(|item| {
            let capability = sync::capability_of(item, cipher);
            let plain = sync::read_plain(item, cipher).ok();
            let bookmark = plain
                .as_deref()
                .and_then(|p| sync::Bookmark::parse(p).ok().flatten());
            let folder = plain
                .as_deref()
                .and_then(|p| sync::ItemFolder::parse(p).ok().flatten());
            let identity = plain
                .as_deref()
                .and_then(|p| sync::AccountIdentity::parse(p).ok().flatten());
            // Prefer the placement read from the decrypted plaintext, and fall
            // back to what the detail carried: a sealed item's f7/f8 only exist
            // inside the ciphertext, and a locked one has neither.
            let meta = plain
                .as_deref()
                .and_then(|p| sync::ItemMeta::parse(p).ok())
                .unwrap_or_else(|| item.meta.clone());
            ItemView {
                item: item.clone(),
                capability,
                bookmark,
                meta,
                folder,
                identity,
                plain_len: plain.map(|p| p.len()).unwrap_or(0),
                reveal_secrets,
            }
        })
        .collect()
}

/// Copies the read's summary and its tree into a report.
///
/// The tree is built here rather than in each command because every command that
/// publishes items needs the same one, and a shell that got items without the tree
/// would have to rebuild it by hand — which is the "flat list" bug this exists to
/// prevent. Items whose content could not be read are listed in `unplaced`
/// instead of being silently put at the top level.
fn apply_item_state(report: &mut AccountReport, state: &SyncState, cipher: Option<&ItemCipher>) {
    report.identities = state
        .of_class(ItemClass::Identity)
        .filter_map(|item| {
            let plain = sync::read_plain(item, cipher).ok()?;
            let identity = sync::AccountIdentity::parse(&plain).ok().flatten()?;
            Some(serde_json::json!({
                "uuid": item.uuid,
                "name": identity.name,
                "nickname": identity.nickname,
                "default": identity.is_default,
                "value": identity.identity,
            }))
        })
        .collect();
    report.status = state.status.code();
    report.status_name = state.status.name().to_string();
    report.global_version = state.global_version.clone();
    report.item_count = state.items.len();

    let tree = sync::hierarchy(state, cipher);
    let folders = tree
        .entries
        .iter()
        .filter(|node| node.folder_for.is_some())
        .count();
    let roots = tree.entries.iter().filter(|node| node.depth == 0).count();
    report.hierarchy = serde_json::json!({
        "entries": tree
            .entries
            .iter()
            .map(|node| serde_json::json!({
                "uuid": node.uuid,
                "parent": node.parent,
                "depth": node.depth,
                "name": node.name,
                "folderFor": node.folder_for.map(|class| class.name()),
                "isFolder": node.folder_for.is_some(),
            }))
            .collect::<Vec<_>>(),
        "unplaced": tree.unplaced,
        "folders": folders,
        "roots": roots,
    });
}

/// Takes a backup into the configured directory and returns where it landed.
///
/// Called by every write, not by the shell: a write that could skip its backup is
/// a write that will, eventually.
pub fn write_backup(state: &SyncState, directory: &Path, label: &str) -> Result<PathBuf, String> {
    std::fs::create_dir_all(directory)
        .map_err(|e| format!("cannot create {}: {e}", directory.display()))?;
    let stamp = now_iso8601().replace([':', '.'], "-");
    let path = directory.join(format!("backup-{stamp}-{label}.json"));
    let text = serde_json::to_string_pretty(&Backup::of(state).to_json())
        .map_err(|e| format!("could not serialize the backup: {e}"))?;
    std::fs::write(&path, text).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(path)
}

/// A validated write, ready to send.
pub struct WritePlan {
    pub class: ItemClass,
    pub uuid: String,
    pub item_version: String,
    pub blob: Vec<u8>,
    pub payload: Vec<u8>,
    /// A human sentence describing what this write does, for the log.
    pub summary: String,
    /// The cursors this plan was built against.
    ///
    /// Kept so the write can check them again immediately before sending: the
    /// server ignores a stale `globalversion`, so a write built from an older
    /// snapshot silently overwrites whatever another client stored in between. The
    /// official client never sees this because it polls every minute; a client
    /// that acts on a snapshot from earlier needs the check.
    pub expect_global: String,
    pub expect_class: Option<String>,
}

impl WritePlan {
    pub fn new(
        state: &SyncState,
        session: &str,
        class: ItemClass,
        uuid: &str,
        item_version: &str,
        blob: Vec<u8>,
        summary: String,
    ) -> WritePlan {
        let class_version = state.class_version.get(&class).map(String::as_str);
        let payload = Sync::upsert_payload(
            session,
            class,
            class_version,
            uuid,
            item_version,
            &blob,
            &state.global_version,
        );
        WritePlan {
            class,
            uuid: uuid.to_string(),
            item_version: item_version.to_string(),
            blob,
            payload,
            summary,
            expect_global: state.global_version.clone(),
            expect_class: class_version.map(str::to_string),
        }
    }
}

/// Fails when the account moved since `state` was read.
///
/// The write is not sent when this returns an error: `synchronizeItems` accepts a
/// stale `globalversion` and simply overwrites, so "just try it" is how another
/// client's change disappears. Comparing the cursors first turns that into a
/// message the caller can act on ("read again and retry") instead of a silent
/// lost update.
pub async fn ensure_cursors(
    context: &AccountContext,
    account: &Account,
    state: &SyncState,
    class: ItemClass,
) -> Result<Option<Account>, String> {
    let (now, renewed) = read_items_renewing(context, account, None).await?;
    if !state.global_version.is_empty() && now.global_version != state.global_version {
        return Err(format!(
            "the account changed since this was read (globalversion {} -> {}); read again and \
             retry the write",
            short_version(&state.global_version),
            short_version(&now.global_version)
        ));
    }
    // A class cursor is only meaningful when both sides have one; a class the
    // first read never saw cannot be compared.
    if let (Some(expected), Some(actual)) = (
        state.class_version.get(&class),
        now.class_version.get(&class),
    ) {
        if expected != actual {
            return Err(format!(
                "the {} class changed since this was read ({} -> {}); read again and retry the \
                 write",
                class.name(),
                short_version(expected),
                short_version(actual)
            ));
        }
    }
    Ok(renewed)
}

/// Eight characters of a version string, for a message a person reads. The full
/// uuid adds nothing: a caller cannot type it, only recognise it.
fn short_version(version: &str) -> &str {
    version.get(..8).unwrap_or(version)
}

/// The result of one write.
pub struct WriteOutcome {
    pub status: SyncStatus,
    pub backup_path: PathBuf,
    pub verified: bool,
    pub stored_bytes: usize,
    /// The account to adopt when the session had to be renewed mid-write.
    ///
    /// `None` means the original session was used throughout, which is the
    /// normal case. `Some` carries the new session **and** the account key and
    /// credential, so the caller installs everything and not just the string.
    pub renewed: Option<Account>,
    /// The session the write started with.
    ///
    /// Kept so a caller can ask "is the engine still on this one?" before
    /// installing `renewed`. Without it, a read-back that renewed *again* would
    /// be overwritten by the older renewal and the next command would send on a
    /// session that has already died.
    pub previous_session: String,
}

/// Executes a write and reads the state back.
///
/// The read-back is not politeness: the reply is only a status, and `300 IN_SYNC`
/// has been observed on a request whose stored blob was not what the caller meant.
/// Comparing the bytes afterwards is how a caller gets to say "this is what is
/// stored now" instead of "the server said yes".
pub async fn execute_write(
    context: &AccountContext,
    account: &Account,
    state: &SyncState,
    plan: WritePlan,
) -> Result<WriteOutcome, String> {
    let original_session = account.session.clone();
    // The cursors were checked when the plan was built; check them again now,
    // because the backup below and the HTTP call leave a window in which another
    // client can store. A stale write is accepted by the server and overwrites
    // whatever landed first, with no error to the loser.
    let renewed = ensure_cursors(context, account, state, plan.class).await?;
    // Everything below has to use the session that is actually alive. The plan's
    // payload was built with the old one, so it is rebuilt from the same parts
    // rather than patched — one constructor, one shape.
    let account = renewed.as_ref().unwrap_or(account);
    let payload = if renewed.is_some() {
        Sync::upsert_payload(
            &account.session,
            plan.class,
            plan.expect_class.as_deref(),
            &plan.uuid,
            &plan.item_version,
            &plan.blob,
            &plan.expect_global,
        )
    } else {
        plan.payload.clone()
    };

    let backup_path = write_backup(state, &context.backup_dir, "pre-write")?;
    log::info!(
        "{} ({} B, backup {})",
        plan.summary,
        plan.blob.len(),
        backup_path.display()
    );

    let mut account = account.clone();
    let mut reply = context
        .http
        .cloud("/synchronization", "synchronizeItems", &payload)
        .await?;
    let mut status = Sync::decode_write_reply(&reply.body);
    // A session can still die between the cursor check and this request.
    // `102` refuses the write outright and changes nothing, so re-sending after
    // a renewal is safe; any other refusal is the server's answer, reported as
    // it is.
    if status == SyncStatus::SessionExpired {
        log::info!("the write found an expired session; signing in again and re-sending");
        let fresh = renew_session(context, &account).await?;
        let retry = Sync::upsert_payload(
            &fresh.session,
            plan.class,
            plan.expect_class.as_deref(),
            &plan.uuid,
            &plan.item_version,
            &plan.blob,
            &plan.expect_global,
        );
        reply = context
            .http
            .cloud("/synchronization", "synchronizeItems", &retry)
            .await?;
        status = Sync::decode_write_reply(&reply.body);
        account = fresh;
    }
    if !status.accepted() {
        return Ok(WriteOutcome {
            status,
            backup_path,
            verified: false,
            stored_bytes: 0,
            renewed: if account.session == original_session {
                None
            } else {
                Some(account)
            },
            previous_session: original_session,
        });
    }

    let (after, renewed_again) = read_items_renewing(context, &account, None).await?;
    if let Some(fresh) = renewed_again {
        account = fresh;
    }
    let stored = after.item(&plan.uuid);
    let verified = stored.map(|item| item.blob == plan.blob).unwrap_or(false);
    if !verified {
        log::error!(
            "write of {} was accepted but the read-back does not match (stored {} B, sent {} B)",
            plan.uuid,
            stored.map(|i| i.blob.len()).unwrap_or(0),
            plan.blob.len()
        );
    }
    Ok(WriteOutcome {
        status,
        backup_path,
        verified,
        stored_bytes: stored.map(|i| i.blob.len()).unwrap_or(0),
        renewed: if account.session == original_session {
            None
        } else {
            Some(account)
        },
        previous_session: original_session,
    })
}

/// Deletes one item and checks that it is gone.
pub async fn execute_delete(
    context: &AccountContext,
    account: &Account,
    state: &SyncState,
    class: ItemClass,
    uuid: &str,
) -> Result<(SyncStatus, PathBuf, bool, Option<Account>), String> {
    if !state.items.iter().any(|item| item.uuid == uuid) {
        return Err(format!(
            "{uuid} is not in the current state; nothing to delete"
        ));
    }
    let original_session = account.session.clone();
    // A delete is a write: it moves the cursors too, so it gets the same check.
    let renewed = ensure_cursors(context, account, state, class).await?;
    let account = renewed.as_ref().unwrap_or(account);
    let backup_path = write_backup(state, &context.backup_dir, "pre-delete")?;
    let class_version = state.class_version.get(&class).map(String::as_str);
    let payload = Sync::delete_payload(
        &account.session,
        class,
        class_version,
        uuid,
        &state.global_version,
    );
    log::info!("delete {class:?} {uuid} (backup {})", backup_path.display());
    let mut reply = context
        .http
        .cloud("/synchronization", "synchronizeItems", &payload)
        .await?;
    let mut status = Sync::decode_write_reply(&reply.body);
    let mut account = account.clone();
    if status == SyncStatus::SessionExpired {
        let fresh = renew_session(context, &account).await?;
        let retry = Sync::delete_payload(
            &fresh.session,
            class,
            class_version,
            uuid,
            &state.global_version,
        );
        reply = context
            .http
            .cloud("/synchronization", "synchronizeItems", &retry)
            .await?;
        status = Sync::decode_write_reply(&reply.body);
        account = fresh;
    }
    let gone = if status.accepted() {
        let (after, again) = read_items_renewing(context, &account, None).await?;
        if let Some(fresh) = again {
            account = fresh;
        }
        after.item(uuid).is_none()
    } else {
        false
    };
    let renewed = if account.session == original_session {
        None
    } else {
        Some(account)
    };
    Ok((status, backup_path, gone, renewed))
}

/// Reads the account row's field 5 out of `settings.db` — the wrapper key.
///
/// This is the "remembered login" path: the client's own database already holds
/// the AES key that wraps the account key, so a login from an existing client
/// profile needs no password at all.
pub fn wrapper_key_from_db(path: &Path) -> Result<[u8; KEY_LEN], String> {
    let (_, message) = account_row(path)?;
    sync::field5(&message)
}

/// Writes the credential for the next run.
///
/// The hash is the one the server just accepted (returned in [`LoginOutcome`]);
/// the key is the one this login unwrapped, if any. Nothing else is kept: see
/// [`credentials`] for why the password is not written.
fn save_login(path: &Path, account: &Account, login_hash: &str) -> Result<(), String> {
    if login_hash.is_empty() {
        return Err("the login produced no credential hash to remember".to_string());
    }
    let stored = credentials::StoredLogin {
        email: account.email.clone(),
        login_hash: login_hash.to_string(),
        account_key: account.key.as_ref().map(crypto::encode_key),
        username: account.username.clone(),
        uuid: account.uuid.clone(),
        saved_at: now_iso8601(),
    };
    credentials::save(path, &stored)
}

/// The credential hash for a remembered login, read out of `settings.db`.
///
/// Also returns the email, because the hash is over `email+ts3Login+password` and
/// is useless without the address it was derived for.
///
/// Field numbers were read off a real `AccountData.value` blob: `1` email,
/// `2` the 64-character base64 login hash, `3` the account uuid, `4` the
/// username, `5` the 32-byte wrapper key. Pinned by
/// `tests/account_contract.rs`.
pub fn remembered_login(db_path: &Path) -> Result<(String, String), String> {
    let (_, message) = account_row(db_path)?;
    let email = message.string(1).unwrap_or_default().to_string();
    let hash = message.string(2).unwrap_or_default().to_string();
    if hash.is_empty() {
        return Err("the Account row has no credential hash".to_string());
    }
    Ok((email, hash))
}

/// The parsed `Account` message plus the raw bytes it came from.
fn account_row(path: &Path) -> Result<(Vec<u8>, proto::Message), String> {
    let db = sqlite::Database::open(path)?;
    let rows = db.rows("AccountData")?;
    let row = rows
        .iter()
        .find(|row| row.get(&1).and_then(sqlite::Cell::as_text).as_deref() == Some("Account"))
        .ok_or_else(|| "settings.db has no Account row".to_string())?;
    let value = row
        .get(&2)
        .and_then(sqlite::Cell::as_bytes)
        .ok_or_else(|| "the Account row has no value".to_string())?
        .to_vec();
    let message = proto::Message::parse(&value)?;
    Ok((value, message))
}

/// `/me` (or the login reply) reduced to what a client shows.
///
/// The wrapped key and the push token are dropped here rather than filtered at
/// the point of display: once they are in a snapshot they end up in a log.
fn profile_of(reply: &Value) -> Value {
    let pick = |value: &Value| {
        serde_json::json!({
            "username": value.get("username").cloned().unwrap_or(Value::Null),
            "uuid": value.get("uuid").cloned().unwrap_or(Value::Null),
            "email": value.get("email").cloned().unwrap_or(Value::Null),
            "recoveryKeyCount": value.get("recoveryKeyCount").cloned().unwrap_or(Value::Null),
            "twoFactorEnabled": value
                .get("twoFactorAuthenticationEnabled")
                .or_else(|| value.get("twoFactorEnabled"))
                .cloned()
                .unwrap_or(Value::Null),
            "limitCount": value
                .get("limits")
                .and_then(Value::as_array)
                .map(|limits| limits.len())
                .unwrap_or(0),
            "hasMytsId": value.get("mytsIdData").is_some(),
            "hasAvatar": value.get("userAvatar").is_some(),
        })
    };
    // `/me` nests the account under `user`; the login reply does not. Handle both
    // so one renderer works for either source.
    match reply.get("user") {
        Some(user) => {
            let mut profile = pick(user);
            if let Some(count) = reply.get("recoveryKeyCount") {
                profile["recoveryKeyCount"] = count.clone();
            }
            profile
        }
        None => pick(reply),
    }
}

/// A one-line pointer at the failure a user can act on.
fn login_hint(profile: &Value) -> Option<String> {
    let two_factor = profile
        .get("twoFactorEnabled")
        .map(|value| !value.is_null() && value.as_i64().unwrap_or(1) != 0)
        .unwrap_or(false);
    if two_factor {
        return Some("this account uses 2FA: supply a one-time code or a recovery key".to_string());
    }
    None
}

/// Turns a failed login into the sentence a shell shows.
///
/// The service answers with an `error` code rather than a sentence, and
/// `ERROR_LOGIN_FAILED` is what a wrong credential or an unconfirmed address
/// looks like. Spelling that out saves the user from a loop of retries against a
/// code they cannot act on; the raw code is kept at the end so a bug report still
/// carries it.
fn login_error_message(status: u16, error: &str, profile: &Value) -> String {
    let mut message = match error {
        "ERROR_LOGIN_FAILED" => {
            "the server rejected the login: the credential hash or the email does not match \
             (a remembered hash goes stale after a password change)"
                .to_string()
        }
        "ERROR_LOGIN_TOTP_REQUIRED" | "ERROR_LOGIN_2FA_REQUIRED" => {
            "this account requires a one-time code or a recovery key".to_string()
        }
        "" => format!("login answered HTTP {status}"),
        other => format!("the server answered {other}"),
    };
    if !matches!(error, "" | "ERROR_LOGIN_OK") {
        message.push_str(&format!(" [{error}]"));
    }
    if let Some(hint) = login_hint(profile) {
        message.push_str(&format!(" — {hint}"));
    }
    message
}

/// Where backups go when the shell does not say. Deliberately a stable per-user
/// directory rather than the working directory: a backup next to a process's
/// `cwd` is a backup nobody finds again.
pub fn default_backup_dir() -> PathBuf {
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(local)
            .join("tsbridge")
            .join("account-backups");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".local/share/tsbridge")
            .join("account-backups");
    }
    PathBuf::from("tsbridge-account-backups")
}

/// Formats a timestamp the way the backup files and the reference tool do.
pub fn now_iso8601() -> String {
    // Hand-rolled UTC: `time` is not a direct dependency of this crate, and this
    // string is only a filename tag and a human label.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let seconds_of_day = secs % 86_400;
    let (hour, minute, second) = (
        seconds_of_day / 3_600,
        (seconds_of_day % 3_600) / 60,
        seconds_of_day % 60,
    );
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_index + 2) / 5 + 1) as u32;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    } as u32;
    (year + i64::from(month <= 2), month, day)
}

// ── the command surface ─────────────────────────────────────────────────────

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
    /// the answer is a `counterVkey` it can connect with, or empty when the
    /// account is ambiguous. This is the automatic choice a user cannot
    /// reasonably be asked to make.
    PickIdentity {
        address: String,
    },
    /// Copies the account's stored identity into the `IDENTITY` sync item, so a
    /// fresh install keeps the UID its server groups are bound to.
    ///
    /// The identity is supplied by the shell (the `counterVkey` it already uses
    /// locally), because the library never invents one for the account; with
    /// `uuid` it targets a specific item, otherwise the default (or the only)
    /// identity is updated.
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
        if !matches!(
            name,
            "account_login"
                | "account_logout"
                | "account_refresh"
                | "sync_list"
                | "sync_backup"
                | "sync_bookmark_create"
                | "sync_addon_enabled"
                | "sync_delete"
                | "sync_restore"
                | "sync_merge"
                | "identity_pick"
                | "identity_import"
        ) {
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
            AccountCommand::Refresh { .. } => "account_refresh",
            AccountCommand::List { .. } => "sync_list",
            AccountCommand::Backup => "sync_backup",
            AccountCommand::CreateBookmark { .. } => "sync_bookmark_create",
            AccountCommand::SetAddOnEnabled { .. } => "sync_addon_enabled",
            AccountCommand::Delete { .. } => "sync_delete",
            AccountCommand::Restore { .. } => "sync_restore",
            AccountCommand::Merge { .. } => "sync_merge",
            AccountCommand::PickIdentity { .. } => "identity_pick",
            AccountCommand::ImportIdentity { .. } => "identity_import",
        }
    }
}

/// Picks the identity a server knows this account by, from what the account
/// already records.
///
/// The official client stores the IDENTITY uuid on every bookmark it creates,
/// so "which key does this server know me by" is answered on the server side
/// and never needs the user to choose. Preference order:
///
/// 1. the identity **name** a bookmark for this address records (field 6), matched
///    against the IDENTITY item's own name;
/// 2. an identity marked `isDefault`;
/// 3. the only identity in the account.
///
/// `None` when several identities exist and neither rule decides: handing a
/// server the wrong UID silently costs the user their rights, so the answer is
/// "cannot decide" rather than a guess.
pub(crate) fn preferred_identity(
    state: &SyncState,
    cipher: Option<&ItemCipher>,
    address: &str,
) -> Option<sync::AccountIdentity> {
    // A plain item needs no key (`read_plain` handles both), so the search
    // runs even before the login has unwrapped one.

    // 1. A bookmark for this server records which identity it used.
    if !address.is_empty() {
        let host = address
            .split([':', '?'])
            .next()
            .unwrap_or(address)
            .to_ascii_lowercase();
        let named = state
            .of_class(ItemClass::Bookmark)
            .filter_map(|item| {
                let plain = sync::read_plain(item, cipher).ok()?;
                sync::Bookmark::parse(&plain).ok().flatten()
            })
            .find(|bookmark| bookmark.address.to_ascii_lowercase() == host)
            .map(|bookmark| bookmark.identity_name)
            .filter(|name| !name.is_empty());
        // The bookmark records the identity's **name** (field 6), not its item
        // uuid — measured on a real settings.db — so the match is against the
        // IDENTITY item's own `idName`.
        if let Some(name) = named {
            let matching: Vec<sync::AccountIdentity> = state
                .of_class(ItemClass::Identity)
                .filter_map(|item| {
                    let plain = sync::read_plain(item, cipher).ok()?;
                    sync::AccountIdentity::parse(&plain).ok().flatten()
                })
                .filter(|identity| identity.name == name)
                .collect();
            if let [only] = matching.as_slice() {
                return Some(only.clone());
            }
        }
    }

    let identities: Vec<sync::AccountIdentity> = state
        .of_class(ItemClass::Identity)
        .filter_map(|item| {
            let plain = sync::read_plain(item, cipher).ok()?;
            sync::AccountIdentity::parse(&plain).ok().flatten()
        })
        .collect();

    // 2. A single marked default. Three or four identities all flagged default
    //    is a real state — the official client copies a template — so "exactly
    //    one default" is the rule, not "any default".
    let defaults: Vec<&sync::AccountIdentity> =
        identities.iter().filter(|id| id.is_default).collect();
    if let [only] = defaults.as_slice() {
        return Some((*only).clone());
    }

    // 3. Nothing marked, nothing named: only an account with one identity is
    //    unambiguous.
    if identities.len() == 1 {
        return identities.into_iter().next();
    }
    None
}

/// Fills in the email and credential hash from an installed client's database,
/// for `"fromTs3Client": true`.
///
/// This is a **migration** path, not the normal one: a user who already runs the
/// official client can move to this library without typing a password. A client
/// that has never seen `settings.db` signs in with `email` + `password` and never
/// goes near this function.
/// A login request, plus a key that came with it.
///
/// The key is separate from the request because it is not sent to the server — it
/// is what a remembered credential already knows and what a hash login cannot
/// derive. Without it a remembered login would come back with every item
/// `locked`, which is the state this whole path exists to avoid.
pub struct ResolvedLogin {
    pub request: LoginRequest,
    /// The account key a stored credential carried, and where it came from.
    pub account_key: Option<([u8; KEY_LEN], String)>,
}

/// Fills in a login from wherever the shell keeps it, for a command that carries
/// no credentials of its own.
///
/// Three sources, in this order:
///
/// 1. `fromTs3Client` — the credential an installed TeamSpeak client already has
///    in its `settings.db`. A migration path.
/// 2. The remembered credential file, when the config names one and
///    `remember_login` is on. This is what makes the second launch silent, and it
///    also supplies the account key, since a hash login cannot derive a wrapper.
/// 3. Nothing — the request is returned unchanged and the login fails with the
///    message `login` produces ("a credential hash or a password is required").
///
/// A remembered login is used only when the payload carries **neither** a hash
/// nor a password: an explicit credential always wins, so a caller that types a
/// different password is not silently signed in as the remembered account.
pub fn resolve_remembered_login(
    context: &AccountContext,
    request: LoginRequest,
    from_ts3_client: bool,
    remember_login: bool,
) -> Result<ResolvedLogin, String> {
    let explicit = request
        .hash
        .as_deref()
        .is_some_and(|h| !h.trim().is_empty())
        || request.password.as_deref().is_some_and(|p| !p.is_empty());
    if explicit {
        return Ok(ResolvedLogin {
            request,
            account_key: None,
        });
    }

    if from_ts3_client {
        let path = context.legacy_db.as_deref().ok_or_else(|| {
            "`fromTs3Client` was set but no settings.db path was configured; pass \
             `account_config` with a `legacyDb`, or sign in with email and password instead"
                .to_string()
        })?;
        let (email, hash) = remembered_login(path)
            .map_err(|e| format!("cannot reuse the client login from {}: {e}", path.display()))?;
        if email.is_empty() {
            return Err(format!(
                "{} has no email in its Account row",
                path.display()
            ));
        }
        log::info!("reusing the login stored in {}", path.display());
        return Ok(ResolvedLogin {
            request: LoginRequest {
                email,
                hash: Some(hash),
                password: None,
                otp: request.otp,
                recovery_key: request.recovery_key,
            },
            account_key: None,
        });
    }

    if !remember_login {
        return Ok(ResolvedLogin {
            request,
            account_key: None,
        });
    }
    let Some(path) = context.credential_file.as_deref() else {
        return Ok(ResolvedLogin {
            request,
            account_key: None,
        });
    };
    let stored = match credentials::load(path) {
        Ok(Some(stored)) => stored,
        // A corrupt or unreadable file is reported rather than ignored: silently
        // signing out would leave the file in place and the next launch would
        // fail the same way with no explanation.
        Err(e) => return Err(e),
        Ok(None) => {
            return Err(format!(
                "no credential was supplied and none is remembered in {}; sign in with an \
                 email and password, or enable remembering a login",
                path.display()
            ))
        }
    };
    log::info!(
        "signing in with the credential remembered in {}",
        path.display()
    );
    let account_key = stored
        .key()
        .map(|key| (key, "remembered login".to_string()));
    Ok(ResolvedLogin {
        request: LoginRequest {
            email: stored.email,
            hash: Some(stored.login_hash),
            password: None,
            otp: request.otp,
            recovery_key: request.recovery_key,
        },
        account_key,
    })
}

/// Parses the two paths `account_config` accepts.
///
/// `legacyDb` is the installed client's database, used only for a `fromTs3Client`
/// import; `backupDir` is where pre-write backups go. An empty string means "not
/// set" rather than "the empty path", because a UI field left blank must not
/// resolve to the working directory.
pub fn parse_config(args: &str) -> Result<AccountConfig, String> {
    let json: Value = if args.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(args).map_err(|e| format!("bad arguments: {e}"))?
    };
    let path = |key: &str| -> Option<PathBuf> {
        json.get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    };
    Ok(AccountConfig {
        legacy_db: path("legacyDb"),
        backup_dir: path("backupDir"),
        credential_file: path("credentialFile"),
        baseline_file: path("baselineFile"),
        // Absent means "remember", matching the library default.
        remember_login: json
            .get("rememberLogin")
            .and_then(Value::as_bool)
            .unwrap_or(true),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_are_iso_shaped() {
        let stamp = now_iso8601();
        assert_eq!(stamp.len(), 20, "{stamp}");
        assert!(stamp.ends_with('Z'));
        assert_eq!(&stamp[4..5], "-");
        assert_eq!(&stamp[10..11], "T");
    }

    /// Civil-from-days is a knot of offsets; pin dates on both sides of a leap
    /// day so a transcription error shows up here rather than in a filename.
    #[test]
    fn civil_dates_are_correct() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
        assert_eq!(civil_from_days(19_783), (2024, 3, 1));
        assert_eq!(civil_from_days(20_993), (2027, 6, 24));
    }

    /// The wrapped key and the push token are the two secrets in a login reply.
    /// Neither may survive into a snapshot: a profile that reaches a crash log
    /// would hand over a renewable credential.
    #[test]
    fn a_profile_never_carries_the_key_or_the_push_token() {
        let reply = serde_json::json!({
            "username": "someone",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "key": "AqM8IsMiONFBZgpjZF0+r84QERITFBUWFxgZGhuVtHYK20GyupNzZx2UPbOk4kAP2/rppNpAgRgwmtlsCA==",
            "pushToken": "eyJhbGciOiJQUzUxMiJ9.payload.signature",
            "recoveryKeyCount": 8,
            "mytsIdData": { "myTeamspeakId": "x" }
        });
        let profile = profile_of(&reply);
        let text = profile.to_string();
        assert!(!text.contains("AqM8IsMi"), "the wrapped key leaked: {text}");
        assert!(!text.contains("eyJhbGci"), "the push token leaked: {text}");
        assert_eq!(profile["username"], "someone");
        assert_eq!(profile["recoveryKeyCount"], 8);
        assert_eq!(profile["hasMytsId"], true);
    }

    /// `/me` wraps the account in `user`; the login reply does not. One renderer
    /// has to read both, or half the account pane is blank depending on which
    /// call filled it.
    #[test]
    fn a_profile_reads_both_reply_shapes() {
        let flat = serde_json::json!({ "username": "a", "email": "a@b.c" });
        let nested = serde_json::json!({
            "user": { "username": "a", "email": "a@b.c" },
            "recoveryKeyCount": 3
        });
        assert_eq!(profile_of(&flat)["username"], "a");
        assert_eq!(profile_of(&nested)["username"], "a");
        assert_eq!(profile_of(&nested)["recoveryKeyCount"], 3);
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

    /// The report starts with `profile: {}` rather than `null`, so a shell can
    /// index into it before any login has happened. A `null` here is a
    /// null-dereference in a UI thread on a phone.
    #[test]
    fn an_empty_report_is_indexable() {
        let report = AccountReport::default();
        assert_eq!(report.profile, serde_json::json!({}));
        assert!(report.profile.is_object());
        let json = serde_json::to_value(AccountReport::default()).unwrap();
        for key in [
            "loggedIn",
            "email",
            "username",
            "uuid",
            "unwrappedWith",
            "keyBytes",
            "busy",
            "command",
            "lastError",
            "lastBackup",
            "progress",
            "status",
            "statusName",
            "globalVersion",
            "itemCount",
            "items",
            "profile",
        ] {
            assert!(json.get(key).is_some(), "account report is missing `{key}`");
        }
        // The key's *length* is reported; the key itself has no field at all.
        assert!(json.get("key").is_none());
    }

    /// The service answers a bad credential with a code, and a user cannot act
    /// on a code. The message has to say what to check while keeping the code
    /// for a bug report.
    #[test]
    fn a_rejected_login_is_explained_not_just_coded() {
        let message = login_error_message(200, "ERROR_LOGIN_FAILED", &serde_json::json!({}));
        assert!(message.contains("credential"), "{message}");
        assert!(message.contains("ERROR_LOGIN_FAILED"), "{message}");

        let message = login_error_message(200, "", &serde_json::json!({}));
        assert!(message.contains("HTTP 200"), "{message}");

        // A profile that says 2FA is on appends the hint.
        let message = login_error_message(
            200,
            "ERROR_LOGIN_FAILED",
            &serde_json::json!({ "twoFactorEnabled": true }),
        );
        assert!(message.contains("2FA"), "{message}");
    }

    /// A plan remembers the cursors it was built against, so the write can be
    /// refused when the account moved in between. The comparison lives here; the
    /// network half is `ensure_cursors`.
    #[test]
    fn a_plan_remembers_the_cursors_it_was_built_against() {
        let state = SyncState {
            global_version: "GLOBAL".to_string(),
            class_version: [(ItemClass::Bookmark, "CLASS".to_string())]
                .into_iter()
                .collect(),
            ..SyncState::default()
        };

        let plan = WritePlan::new(
            &state,
            "SESSION",
            ItemClass::Bookmark,
            "uuid",
            "version",
            vec![1, 2, 3],
            "a write".to_string(),
        );
        assert_eq!(plan.expect_global, "GLOBAL");
        assert_eq!(plan.expect_class.as_deref(), Some("CLASS"));

        // A class the state never saw has no expectation, which must not be
        // mistaken for "matches everything".
        let empty = SyncState::default();
        let plan = WritePlan::new(
            &empty,
            "SESSION",
            ItemClass::AddOn,
            "uuid",
            "version",
            vec![1],
            "another".to_string(),
        );
        assert!(plan.expect_global.is_empty());
        assert!(plan.expect_class.is_none());
    }

    #[test]
    fn a_short_version_is_eight_characters() {
        assert_eq!(
            // A made-up uuid: a real account's globalversion is a secret value,
            // and only its prefix is ever allowed in the tree.
            short_version("00000000-0000-4000-8000-000000000001"),
            "00000000"
        );
        assert_eq!(short_version("abc"), "abc", "short input is returned whole");
    }

    #[test]
    fn account_config_reads_either_path_and_defaults_the_rest() {
        let config =
            parse_config(r#"{"legacyDb":"C:\\db\\settings.db","backupDir":"C:\\bak"}"#).unwrap();
        assert_eq!(
            config.legacy_db.as_deref(),
            Some(std::path::Path::new("C:\\db\\settings.db"))
        );
        assert_eq!(
            config.backup_dir.as_deref(),
            Some(std::path::Path::new("C:\\bak"))
        );

        let empty = parse_config("").unwrap();
        assert!(empty.legacy_db.is_none());
        assert!(empty.backup_dir.is_none());

        // An empty string means "not set", not "the empty path" — a UI field left
        // blank must not resolve to the working directory.
        let blank = parse_config(r#"{"legacyDb":""}"#).unwrap();
        assert!(blank.legacy_db.is_none());
    }
}

#[cfg(test)]
mod preferred_identity_tests {
    use super::{preferred_identity, ItemClass, SyncState};
    use crate::account::proto::{field_bytes, field_string, field_varint};
    use crate::account::sync::Item;

    /// Plain items are readable without a key, which is what makes the pick
    /// testable without the real account cipher.
    /// `read_plain` only treats a blob as plain when its `item_uuid` looks like
    /// a uuid (36 chars, contains a dash), so fixtures must use real ones.
    fn uuid(n: u8) -> String {
        format!("{n:08}-0000-0000-0000-000000000000")
    }

    fn item(class: ItemClass, uuid: &str, blob: Vec<u8>) -> Item {
        Item {
            uuid: uuid.to_string(),
            class,
            item_version: "v".to_string(),
            blob,
            deleted: false,
            meta: Default::default(),
        }
    }

    fn identity_item(uuid: &str, key: &str, name: &str, default: bool) -> Item {
        let mut inner = Vec::new();
        inner.extend(field_string(1, key));
        inner.extend(field_string(2, name));
        inner.extend(field_varint(5, u64::from(default)));
        let mut data = Vec::new();
        data.extend(field_string(2, uuid));
        data.extend(field_bytes(17, &inner));
        item(ItemClass::Identity, uuid, data)
    }

    fn bookmark_item(address: &str, identity_name: &str) -> Item {
        let mut inner = Vec::new();
        inner.extend(field_string(2, address));
        inner.extend(field_string(6, identity_name));
        let mut data = Vec::new();
        data.extend(field_string(2, &uuid(9)));
        data.extend(field_bytes(16, &inner));
        item(ItemClass::Bookmark, &uuid(9), data)
    }

    fn state(items: Vec<Item>) -> SyncState {
        SyncState {
            items,
            ..SyncState::default()
        }
    }

    /// The case the user hit: two identities both flagged default, and nobody to
    /// ask. The bookmark records the identity's *name*, which is what the
    /// official client writes there, and that settles it.
    #[test]
    fn a_bookmark_decides_between_two_defaults() {
        let state = state(vec![
            identity_item(&uuid(1), "100VkeyA", "Schallophy", true),
            identity_item(&uuid(2), "200VkeyB", "AutumnKoi", true),
            bookmark_item("ts.example.com", "AutumnKoi"),
        ]);
        let picked = preferred_identity(&state, None, "ts.example.com:9987")
            .expect("the bookmark names id-b");
        assert_eq!(picked.identity, "200VkeyB");

        // A different server with no bookmark of its own falls back to the
        // default rule, which is ambiguous here.
        assert!(preferred_identity(&state, None, "other.example.com").is_none());
    }

    #[test]
    fn a_single_default_wins_without_a_bookmark() {
        let state = state(vec![
            identity_item(&uuid(1), "100VkeyA", "Schallophy", true),
            identity_item(&uuid(2), "200VkeyB", "AutumnKoi", false),
        ]);
        let picked = preferred_identity(&state, None, "").expect("one default");
        assert_eq!(picked.identity, "100VkeyA");
    }

    #[test]
    fn a_single_identity_needs_no_marker() {
        let state = state(vec![identity_item(
            &uuid(1),
            "100VkeyA",
            "Schallophy",
            false,
        )]);
        assert_eq!(
            preferred_identity(&state, None, "")
                .expect("only one")
                .identity,
            "100VkeyA"
        );
    }

    /// Several identities, none marked, no bookmark: a guess here would send a
    /// server the wrong UID and cost the user their rights.
    #[test]
    fn several_unmarked_identities_are_refused() {
        let state = state(vec![
            identity_item(&uuid(1), "100VkeyA", "A", false),
            identity_item(&uuid(2), "200VkeyB", "B", false),
        ]);
        assert!(preferred_identity(&state, None, "any.example.com").is_none());
    }
}
