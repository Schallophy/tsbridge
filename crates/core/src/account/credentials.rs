//! The remembered login: what a client keeps so it does not ask again.
//!
//! This is **not** the password. It is what a sign-in produces and what a
//! restart needs to be silent:
//!
//! * the credential hash — the same PBKDF2 token the official client stores in
//!   `settings.db` as `Account.password`, and what `/client/login` accepts in
//!   place of the plaintext;
//! * the account key, so items stay readable without deriving a wrapper;
//! * the session token, so `account_resume` can publish a signed-in account
//!   without any network call;
//! * the myTeamSpeak identity, so `clientinit` can still be signed — without it
//!   the server would stop showing the account's name and badge after a restart.
//!
//! The file is a credential: whoever reads it can act as the account until the
//! password changes. That is exactly the trust the official client already places
//! in `settings.db`, and it is why this module has three rules:
//!
//! 1. **The password is never written.** It is not needed after the hash exists,
//!    and storing it would turn a stolen file into a stolen account password.
//! 2. **The file is owner-only.** On Unix it is created `0600`. On Windows the
//!    protection is the per-user directory it lives in, which is why
//!    [`default_credential_file`] puts it under `%LOCALAPPDATA%` and never in a
//!    world-readable location. A shell that controls the path is responsible for
//!    the same property (Android's private app directory provides it).
//! 3. **Signing out deletes it.** A client told to forget a credential must
//!    forget it, not keep a copy for convenience.
//!
//! Persistence is opt-in at the library level: [`super::AccountConfig::credential_file`]
//! defaults to `None`, so a session that was not told to remember writes nothing.
//! A shell that wants "stay signed in" names a path and gets the behaviour.

use std::path::{Path, PathBuf};

use serde_json::Value;

/// The version of the on-disk shape. A file of another version is refused rather
/// than guessed at: a credential parsed wrong is a wrong account.
pub const FORMAT_VERSION: u32 = 1;

/// A sign-in as it is kept between runs.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StoredLogin {
    /// The address the credential hash was derived for. The hash is over
    /// `lower(email) + "ts3Login" + password`, so it is meaningless without it.
    pub email: String,
    /// The PBKDF2 token, base64. This is the secret, and it is what replaces the
    /// password in the login request.
    pub login_hash: String,
    /// The account key, base64 of 32 bytes, when that sign-in produced one.
    ///
    /// A login made from a hash cannot derive a wrapper, so without this the
    /// items would come back `locked`. Storing it is what makes a remembered
    /// login as capable as the one that created it.
    pub account_key: Option<String>,
    /// The session token from the last successful login/renewal. When present,
    /// startup can try it before reissuing a full login: saves a round-trip when
    /// the session is still valid, and the account pane appears instantly.
    pub session: Option<String>,
    /// The myTeamSpeak identity (public key, private scalar, ID, signature
    /// material) as [`super::mytsid::MytsIdentity::to_json`] writes it.
    ///
    /// Stored because `authSign` is signed per connection from the private
    /// scalar: without it a restarted process would show the account but not the
    /// name and badge on a server. `None` for an account with no myTS identity.
    pub identity: Option<Value>,
    /// For display only; the server is the authority.
    pub username: String,
    pub uuid: String,
    /// ISO-8601, for a shell to show "signed in since …".
    pub saved_at: String,
}

impl StoredLogin {
    /// The account key as bytes, when the stored value is a valid 32-byte key.
    ///
    /// A malformed value is ignored rather than fatal: the login still works, the
    /// items just report `locked`, which is the same state as having no key.
    pub fn key(&self) -> Option<[u8; 32]> {
        let decoded = super::crypto::decode_key(self.account_key.as_deref()?)?;
        Some(decoded)
    }

    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "version": FORMAT_VERSION,
            "email": self.email,
            "loginHash": self.login_hash,
            "accountKey": self.account_key,
            "session": self.session,
            "identity": self.identity,
            "username": self.username,
            "uuid": self.uuid,
            "savedAt": self.saved_at,
        })
    }

    pub fn from_json(value: &Value) -> Result<StoredLogin, String> {
        let version = value.get("version").and_then(Value::as_u64).unwrap_or(0);
        if version != u64::from(FORMAT_VERSION) {
            return Err(format!(
                "stored login is format {version}, this build reads {FORMAT_VERSION}"
            ));
        }
        let text = |key: &str| -> String {
            value
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let login = StoredLogin {
            email: text("email"),
            login_hash: text("loginHash"),
            account_key: value
                .get("accountKey")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            session: value
                .get("session")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            identity: value.get("identity").filter(|v| !v.is_null()).cloned(),
            username: text("username"),
            uuid: text("uuid"),
            saved_at: text("savedAt"),
        };
        if login.email.is_empty() || login.login_hash.is_empty() {
            return Err("stored login has no email or no hash".to_string());
        }
        Ok(login)
    }
}

/// Writes the file, creating the parent directory if needed.
///
/// The write goes through a temporary name first: a process killed mid-write must
/// not leave a half-written credential that the next run reads as a truncated
/// hash — that would look like "the password changed" rather than "the file is
/// corrupt".
pub fn save(path: &Path, login: &StoredLogin) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    let text = serde_json::to_string_pretty(&login.to_json())
        .map_err(|e| format!("cannot serialize the stored login: {e}"))?;

    let temp = path.with_extension("json.tmp");
    std::fs::write(&temp, text).map_err(|e| format!("cannot write {}: {e}", temp.display()))?;
    restrict_permissions(&temp)?;
    std::fs::rename(&temp, path).map_err(|e| {
        let _ = std::fs::remove_file(&temp);
        format!("cannot move {} into place: {e}", temp.display())
    })
}

/// Reads a stored login, or `Ok(None)` when the file is simply absent.
///
/// A file that exists but cannot be understood is an **error**, not `None`: silently
/// starting fresh would leave the corrupt file in place and the next run would
/// repeat the same failure with no explanation.
pub fn load(path: &Path) -> Result<Option<StoredLogin>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    let value: Value = serde_json::from_str(&text)
        .map_err(|e| format!("{} is not valid JSON: {e}", path.display()))?;
    StoredLogin::from_json(&value).map(Some)
}

/// Removes the file, treating "already gone" as success.
pub fn forget(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("cannot remove {}: {e}", path.display())),
    }
}

/// Owner-only where the platform has the concept.
#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)
        .map_err(|e| format!("cannot stat {}: {e}", path.display()))?
        .permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)
        .map_err(|e| format!("cannot chmod {}: {e}", path.display()))
}

/// Windows has no mode bits; a fixed ACL would need a dependency this crate does
/// not have, so the protection is the per-user directory.
#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// Where a shell that asks for a remembered login should put it.
///
/// Under the user's own application-data directory, never in a shared or world
/// readable location: on Windows the directory's ACL is the only protection this
/// file has.
pub fn default_credential_file() -> PathBuf {
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(local).join("litespeak").join("account.json");
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".local/share/litespeak")
            .join("account.json");
    }
    PathBuf::from("litespeak-account.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> StoredLogin {
        StoredLogin {
            email: "someone@example.com".to_string(),
            login_hash: "aGFzaC1oYXNoLWhhc2g=".to_string(),
            account_key: Some("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".to_string()),
            session: Some("c2Vzc2lvbi10b2k=".to_string()),
            identity: Some(serde_json::json!({
                "publicKey": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
                "privateKey": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            })),
            username: "someone".to_string(),
            uuid: "00000000-0000-4000-8000-000000000001".to_string(),
            saved_at: "2026-11-23T00:00:00Z".to_string(),
        }
    }

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "litespeak-cred-{tag}-{}.json",
            super::super::crypto::uuid_v4()
        ))
    }

    #[test]
    fn a_stored_login_round_trips_through_disk() {
        let path = temp_path("round-trip");
        let login = sample();
        save(&path, &login).expect("save");
        let back = load(&path).expect("load").expect("present");
        assert_eq!(back, login);
        assert_eq!(back.key().map(|k| k.len()), Some(32));
        assert!(back.session.is_some(), "the session token must survive");
        assert!(
            back.identity.is_some(),
            "the myTS identity must survive, or a restart cannot sign clientinit"
        );
        forget(&path).expect("forget");
        assert!(load(&path).expect("load after forget").is_none());
    }

    #[test]
    fn forgetting_a_file_that_is_not_there_is_not_an_error() {
        let path = temp_path("absent");
        forget(&path).expect("forget must be idempotent");
        assert!(load(&path).expect("load").is_none());
    }

    #[test]
    fn a_foreign_format_is_refused_rather_than_guessed_at() {
        let path = temp_path("version");
        std::fs::write(&path, r#"{"version":99,"email":"a@b.c","loginHash":"h"}"#).expect("write");
        let error = load(&path).unwrap_err();
        assert!(error.contains("format 99"), "{error}");
        assert!(error.contains("reads 1"), "{}", error);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_file_without_a_hash_is_an_error_not_an_empty_login() {
        let path = temp_path("no-hash");
        std::fs::write(&path, r#"{"version":1,"email":"a@b.c"}"#).expect("write");
        let error = load(&path).unwrap_err();
        assert!(error.contains("no hash"), "{error}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_corrupt_file_says_so_instead_of_starting_fresh() {
        let path = temp_path("corrupt");
        std::fs::write(&path, "{not json").expect("write");
        let error = load(&path).unwrap_err();
        assert!(error.contains("not valid JSON"), "{error}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_malformed_key_still_reads_but_reports_no_key() {
        let mut login = sample();
        login.account_key = Some("not-base64-32-bytes".to_string());
        assert!(login.key().is_none(), "a bad key is ignored, not fatal");
    }

    /// The password must never appear in the file, whatever a caller passes in.
    /// This is a shape test rather than a policy note: the struct has no field for
    /// it, and the JSON has no key that could carry it.
    #[test]
    fn the_file_has_no_room_for_a_password() {
        let json = StoredLogin::default().to_json();
        let text = json.to_string();
        for forbidden in ["password", "Password", "passwd"] {
            assert!(
                !text.contains(forbidden),
                "the stored-login JSON mentions {forbidden}: {text}"
            );
        }
    }
}
