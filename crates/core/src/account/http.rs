//! The two HTTP surfaces the account side talks to.
//!
//! They are different protocols that happen to share a host family:
//!
//! * **REST** on `https://www.myteamspeak.com/api` — plain JSON, used for
//!   `/client/login`, `/me` and `/logout`. Authenticated with
//!   `X-Authorization: Bearer <session>`.
//! * **`application/ts3cloud`** on `clientapi.myteamspeak.com` — protobuf
//!   payloads wrapped in a method-name envelope, used for everything under
//!   `/synchronization`. The reply is labelled `application/json` by the edge
//!   but the bytes are protobuf; trusting the header here silently breaks
//!   everything downstream.
//!
//! Both clients are `reqwest` with the feature set `tsclientlib` already pulls
//! in, so this adds no TLS stack of its own. That matters on Android, where
//! `rustls-platform-verifier` has to be initialized through the JVM once at
//! startup, and a second independent TLS client would have to repeat that
//! handshake.

use std::time::Duration;

use serde_json::Value;

use super::proto;

/// The web surface that owns the account session.
pub const REST_BASE: &str = "https://www.myteamspeak.com/api";
/// The protobuf RPC surface that owns the sync items.
pub const CLOUD_BASE: &str = "https://clientapi.myteamspeak.com";

/// Where the two surfaces live.
///
/// A value rather than two hardcoded constants so a test can point the client at
/// a recorded server on `127.0.0.1` and exercise the whole path — framing,
/// protobuf, crypto, status handling — with no account and no network. Production
/// code always takes `Endpoints::default()`.
#[derive(Debug, Clone, PartialEq)]
pub struct Endpoints {
    pub rest: String,
    pub cloud: String,
    /// Whether a `http://` base is acceptable.
    ///
    /// **False everywhere except a test.** A live session is a bearer token and a
    /// credential hash; sending either over cleartext would hand the account to
    /// anything on the path. The replay test points at `127.0.0.1` and says so
    /// explicitly, which keeps the exception visible in the one place it exists
    /// rather than implicit in "the URL happened to start with http".
    pub allow_plain_http: bool,
}

impl Default for Endpoints {
    fn default() -> Endpoints {
        Endpoints {
            rest: REST_BASE.to_string(),
            cloud: CLOUD_BASE.to_string(),
            allow_plain_http: false,
        }
    }
}

impl Endpoints {
    /// Whether every base is acceptable for a request that carries a credential.
    fn check(&self, path: &str) -> Result<(), String> {
        if self.allow_plain_http {
            return Ok(());
        }
        for base in [&self.rest, &self.cloud] {
            if !base.starts_with("https://") {
                return Err(format!(
                    "refusing to send {path} to {base}: the account session is a credential and \
                     only https is acceptable (a test may set Endpoints::allow_plain_http)"
                ));
            }
        }
        Ok(())
    }
}

/// The edge in front of `clientapi` rejects some client fingerprints and answers
/// others with a bodyless 500. This pair is the one that was measured to work
/// (`research/myts-login/myts-rpc.mjs`, the 200/500 transport matrix).
const CLOUD_CONTENT_TYPE: &str = "application/ts3cloud";
const CLOUD_USER_AGENT: &str = "cpp-httplib/0.11.1";

/// A login request as the shell supplies it. Exactly one of `password` and
/// `hash` is expected; the hash form exists so a remembered login can be reused
/// without the plaintext password ever entering this process.
#[derive(Debug, Clone, Default)]
pub struct LoginRequest {
    pub email: String,
    /// The credential hash (`hashed_password`), already base64.
    pub hash: Option<String>,
    /// Plaintext password, hashed here when `hash` is absent.
    pub password: Option<String>,
    pub otp: Option<String>,
    /// The user-typed recovery code; hashed before it leaves the process.
    pub recovery_key: Option<String>,
}

/// A reply from either surface, before it is interpreted.
#[derive(Debug)]
pub struct RawReply {
    pub status: u16,
    pub body: Vec<u8>,
}

impl RawReply {
    pub fn json(&self) -> Result<Value, String> {
        let text = String::from_utf8_lossy(&self.body);
        serde_json::from_str(&text).map_err(|e| {
            format!(
                "HTTP {} reply was not JSON ({e}): {}",
                self.status,
                truncate(&text)
            )
        })
    }
}

fn truncate(text: &str) -> String {
    // Enough to recognise a captive portal or a Cloudflare challenge page, not
    // enough to paste a page of HTML into a log.
    let cleaned: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if cleaned.chars().count() > 160 {
        cleaned.chars().take(160).collect::<String>() + "…"
    } else {
        cleaned
    }
}

#[derive(Clone)]
pub struct Http {
    client: reqwest::Client,
    endpoints: Endpoints,
}

impl Default for Http {
    fn default() -> Self {
        Self::new()
    }
}

impl Http {
    pub fn new() -> Self {
        // One client for the whole account side: connection reuse is what keeps
        // a "list, edit, verify" sequence from paying a TLS handshake per step.
        //
        // The user agent is **not** set here. The cloud surface needs the
        // `cpp-httplib/0.11.1` fingerprint (see `cloud`), but the REST surface in
        // front of `www.myteamspeak.com` answers a request carrying that string
        // with an edge error rather than a login reply — the two surfaces are
        // behind different edges, so the fingerprint belongs per-request.
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(25))
            // A redirect on an API call means the session is no longer
            // accepted; following it to the login page would turn "expired"
            // into a 200 with HTML in it.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_else(|e| {
                log::error!("could not build the account HTTP client: {e}");
                reqwest::Client::new()
            });
        Http {
            client,
            endpoints: Endpoints::default(),
        }
    }

    /// A client that talks to somewhere other than myTeamSpeak.
    ///
    /// Only tests use this: the recorded server answers the same envelopes, so
    /// the login, read, write and re-login paths can be exercised without an
    /// account. Everything else about the client is unchanged, which is the
    /// point — a test that reimplemented the transport would prove nothing.
    pub fn with_endpoints(endpoints: Endpoints) -> Http {
        let mut http = Http::new();
        http.endpoints = endpoints;
        http
    }

    pub fn endpoints(&self) -> &Endpoints {
        &self.endpoints
    }

    /// `GET` on the REST surface with an account session.
    pub async fn rest_get(&self, path: &str, session: &str) -> Result<RawReply, String> {
        self.endpoints.check(path)?;
        let response = self
            .client
            .get(format!("{}{path}", self.endpoints.rest))
            .header("Accept", "application/json")
            .header("X-Authorization", format!("Bearer {session}"))
            .send()
            .await
            .map_err(|e| format!("GET {path} failed: {e}"))?;
        read_reply(response, path).await
    }

    /// `POST` on the REST surface. `body` is serialized here so no caller has to
    /// remember the content type.
    pub async fn rest_post(
        &self,
        path: &str,
        body: &Value,
        session: Option<&str>,
    ) -> Result<RawReply, String> {
        self.endpoints.check(path)?;
        let mut request = self
            .client
            .post(format!("{}{path}", self.endpoints.rest))
            .header("Accept", "application/json")
            .json(body);
        if let Some(session) = session {
            request = request.header("X-Authorization", format!("Bearer {session}"));
        }
        let response = request
            .send()
            .await
            .map_err(|e| format!("POST {path} failed: {e}"))?;
        read_reply(response, path).await
    }

    /// One `application/ts3cloud` call: `<varint name length><method name><payload>`.
    ///
    /// The length prefix is a *bare* varint over the UTF-8 name, not a protobuf
    /// field. Sending a plain protobuf body makes the server answer
    /// `status=100 UNKNOWN_METHOD` (or drop the connection), because it never
    /// sees a method name at all.
    pub async fn cloud(
        &self,
        path: &str,
        method: &str,
        payload: &[u8],
    ) -> Result<RawReply, String> {
        self.endpoints.check(method)?;
        let mut body = Vec::with_capacity(method.len() + payload.len() + 1);
        body.extend_from_slice(&proto::varint(method.len() as u64));
        body.extend_from_slice(method.as_bytes());
        body.extend_from_slice(payload);

        let response = self
            .client
            .post(format!("{}{path}", self.endpoints.cloud))
            .header("Accept", "*/*")
            .header("Connection", "close")
            .header("Content-Type", CLOUD_CONTENT_TYPE)
            .header("User-Agent", CLOUD_USER_AGENT)
            .body(body)
            .send()
            .await
            .map_err(|e| format!("{method} failed: {e}"))?;
        read_reply(response, method).await
    }
}

async fn read_reply(response: reqwest::Response, what: &str) -> Result<RawReply, String> {
    let status = response.status().as_u16();
    let body = response
        .bytes()
        .await
        .map_err(|e| format!("{what}: could not read the reply body: {e}"))?
        .to_vec();
    Ok(RawReply { status, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every cloud call in the crate goes to the one path the server measured.
    ///
    /// The call sites pass the path literally, so this reads the sources rather
    /// than calling a helper: a typo in one call site would send that request to
    /// a 404 and the account would look empty rather than broken.
    #[test]
    fn every_cloud_call_uses_the_synchronization_path() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/account");
        let mut paths = std::collections::BTreeSet::new();
        let mut calls = 0;
        for entry in std::fs::read_dir(&dir)
            .expect("read the account dir")
            .flatten()
        {
            let Ok(text) = std::fs::read_to_string(entry.path()) else {
                continue;
            };
            for line in text.lines() {
                if let Some(pos) = line.find(".cloud(\"") {
                    let rest = &line[pos + ".cloud(\"".len()..];
                    let path: String = rest.chars().take_while(|c| *c != '"').collect();
                    paths.insert(path);
                    calls += 1;
                }
            }
        }
        assert!(
            calls > 0,
            "no cloud call was found; the transport changed shape"
        );
        assert_eq!(
            paths.into_iter().collect::<Vec<_>>(),
            vec!["/synchronization".to_string()],
            "a cloud call goes somewhere other than the measured path"
        );
    }

    #[test]
    fn error_bodies_are_truncated_to_something_readable() {
        let long = "x".repeat(400);
        let text = truncate(&long);
        assert!(text.ends_with('…'));
        assert!(text.chars().count() <= 161);
        assert_eq!(truncate("  a\n b "), "a b");
    }
}
