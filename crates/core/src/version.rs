//! The client version a shell announces, and the signed table behind it.
//!
//! A TeamSpeak server compares the announced `client_version` +
//! `client_platform` against `client_version_sign` byte for byte and refuses
//! anything that does not match with `ClientHacked`. The signature is issued by
//! TeamSpeak and is bound to the exact (platform, full version text) pair: it
//! cannot be derived from the text, and changing either half without the other
//! breaks the match.
//!
//! So a shell never types a version string. It picks a **version number** and a
//! **platform**, and this module resolves that pair to the newest signed entry
//! in the table that matches — the full version text (with its `[Build: …]`
//! suffix) and the signature to send. The version number is what the user
//! knows; the build suffix and the signature are what the table provides.
//!
//! The table is the TeamSpeak-published `Versions.csv` (decoded at build time by
//! `tsproto-structs`) plus the borrowed 3.6.x tuples that were never added to
//! the CSV. Every entry is a real TeamSpeak-issued signature; nothing here is
//! derived, and nothing is generated at runtime.

use std::collections::HashMap;
use std::sync::LazyLock;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use tsproto_structs::versions::DATA;

/// One signed entry in the version table.
#[derive(Debug, Clone)]
pub struct VersionEntry {
    /// The platform as it appears on the wire (`Windows`, `OS X`, `Android`, …).
    pub platform: String,
    /// The full version text, exactly as the signature covers it
    /// (`3.6.3 [Build: 1701166057]`).
    pub version: String,
    /// The version number the user picks: the text before the build suffix
    /// (`3.6.3`).
    pub version_number: String,
    /// The build number. Used to pick the newest entry when a version number
    /// matches several builds.
    pub build: u64,
    /// The raw signature bytes, base64-decoded from the CSV `hash` column.
    pub signature: Vec<u8>,
}

/// A version number + platform pair a shell chose.
///
/// This is the shell's vocabulary: the user picks a version number and a
/// platform, and [`VersionChoice::resolve`] maps it to the signed tuple the
/// server expects. The build suffix and the signature are never part of what the
/// shell stores or sends as a choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionChoice {
    /// The version number the user picked (`3.6.3`).
    pub version: String,
    /// The platform the user picked (`Windows`).
    pub platform: String,
}

/// Whether a version number is a release, not a pre-release build or placeholder.
///
/// `3.6.3` and `3.0.19.4` are releases; `5.0.0-beta73`, `5.0.0-qa-71-2` and
/// `3.?.?` are not. `0.0.1` is the table's sentinel for "no version", so it is
/// excluded even though it is shaped like a release.
fn is_release_number(version: &str) -> bool {
    if version == "0.0.1" {
        return false;
    }
    version
        .split('.')
        .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
}

impl VersionChoice {
    /// Builds a choice from the two fields.
    pub fn new(version: impl Into<String>, platform: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            platform: platform.into(),
        }
    }

    /// The default: `3.6.3` + `Windows`, the newest signed tuple that connects
    /// everywhere and is what this library has always announced.
    pub fn standard() -> Self {
        Self::new("3.6.3", "Windows")
    }
}

impl Default for VersionChoice {
    fn default() -> Self {
        Self::standard()
    }
}

/// The resolved, ready-to-announce entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedVersion {
    pub platform: String,
    /// Full version text, exactly what the signature covers.
    pub version: String,
    pub signature: Vec<u8>,
}

/// The version number: the text before the first space (the build suffix and
/// any trailing label, e.g. `DEBUG`, come after it).
fn version_number_of(full: &str) -> String {
    full.split_whitespace().next().unwrap_or("").to_string()
}

/// The build number inside `[Build: N]`, or 0 when the text has none.
fn build_of(full: &str) -> u64 {
    if let Some(start) = full.find("[Build:") {
        let rest = &full[start + "[Build:".len()..];
        let end = rest.find(']').unwrap_or(rest.len());
        rest[..end].trim().parse().unwrap_or(0)
    } else {
        0
    }
}

/// The borrowed 3.6.x signatures, copied from the tuples this library has always
/// announced. They are real TeamSpeak-issued signatures (measured against an
/// official 3.13.7 server) that were never added to the published CSV, so they
/// live here next to the table rather than in the connection code.
fn borrowed() -> Vec<VersionEntry> {
    vec![
        VersionEntry {
            platform: "Windows".to_string(),
            version: "3.6.3 [Build: 1701166057]".to_string(),
            version_number: "3.6.3".to_string(),
            build: 1701166057,
            signature: vec![
                48, 189, 242, 19, 170, 85, 209, 1, 178, 133, 207, 40, 238, 77, 91, 130, 160, 210,
                143, 238, 96, 100, 132, 5, 50, 48, 77, 133, 98, 122, 47, 65, 109, 39, 9, 226, 6,
                175, 37, 215, 8, 175, 199, 112, 243, 129, 85, 66, 191, 36, 91, 205, 248, 60, 50,
                199, 85, 254, 184, 229, 230, 193, 205, 11,
            ],
        },
        VersionEntry {
            platform: "OS X".to_string(),
            version: "3.6.2 [Build: 1690976575]".to_string(),
            version_number: "3.6.2".to_string(),
            build: 1690976575,
            signature: vec![
                209, 87, 160, 37, 155, 86, 35, 110, 126, 69, 115, 55, 39, 168, 205, 126, 201, 42,
                18, 3, 60, 127, 128, 178, 98, 186, 243, 208, 133, 238, 72, 175, 26, 205, 20, 55, 0,
                197, 135, 237, 136, 18, 158, 186, 45, 160, 133, 245, 171, 182, 131, 134, 116, 238,
                150, 79, 94, 10, 18, 146, 62, 130, 149, 9,
            ],
        },
        VersionEntry {
            platform: "Linux".to_string(),
            version: "3.6.2 [Build: 1695203293]".to_string(),
            version_number: "3.6.2".to_string(),
            build: 1695203293,
            signature: vec![
                167, 136, 133, 214, 54, 119, 100, 236, 253, 48, 73, 10, 73, 157, 155, 190, 113,
                109, 155, 213, 166, 81, 196, 50, 246, 96, 15, 255, 247, 171, 20, 78, 15, 23, 91, 1,
                232, 173, 66, 72, 3, 107, 175, 237, 215, 224, 29, 26, 101, 29, 46, 248, 173, 169,
                142, 123, 252, 146, 34, 172, 88, 164, 2, 5,
            ],
        },
    ]
}

/// The full signed table: the published CSV plus the borrowed 3.6.x tuples.
static TABLE: LazyLock<Vec<VersionEntry>> = LazyLock::new(|| {
    let mut entries: Vec<VersionEntry> = DATA
        .0
        .iter()
        .map(|v| VersionEntry {
            platform: v.platform.clone(),
            version: v.version.clone(),
            version_number: version_number_of(&v.version),
            build: build_of(&v.version),
            signature: B64.decode(&v.hash).unwrap_or_default(),
        })
        .collect();
    entries.extend(borrowed());
    entries
});

/// The oldest version a current server will accept.
///
/// Measured against a live server, not read from the table: `3.0.20` is refused
/// with `ClientVersionOutdated` while `3.1.0` connects. The table still carries
/// signatures for the older releases, which is why "the signature resolves" and
/// "the server accepts it" have to be two separate questions.
const OLDEST_SERVER_ACCEPTED: (u32, u32) = (3, 1);

/// Whether a release number is below [`OLDEST_SERVER_ACCEPTED`].
///
/// Compared as numbers, not strings: `3.0.20` sorts after `3.0.13` textually in
/// some orderings and `3.10` would sort before `3.9`. A number that is not
/// release-shaped is left to the caller's other filters.
fn is_older_than_supported(version: &str) -> bool {
    let mut parts = version.split('.').map(|p| p.parse::<u32>().unwrap_or(0));
    let major = parts.next().unwrap_or(0);
    let minor = parts.next().unwrap_or(0);
    (major, minor) < OLDEST_SERVER_ACCEPTED
}

impl VersionChoice {
    /// Every platform that has at least one signed entry, in table order, with
    /// duplicates removed. These are the only platforms a choice can use: a
    /// platform with no signature cannot be announced without `ClientHacked`.
    pub fn platforms() -> Vec<String> {
        let mut seen: Vec<String> = Vec::new();
        for e in TABLE.iter() {
            if !seen.contains(&e.platform) {
                seen.push(e.platform.clone());
            }
        }
        seen
    }

    /// Version numbers matching a prefix, for the platform, newest build first.
    ///
    /// Each (version number, platform) appears once: when several builds share a
    /// version number, only the newest is offered, because that is the one
    /// [`VersionChoice::resolve`] picks anyway. An empty prefix returns every
    /// version number the platform has.
    pub fn suggest(prefix: &str, platform: &str) -> Vec<String> {
        let prefix = prefix.trim().to_ascii_lowercase();
        let mut best: HashMap<String, VersionEntry> = HashMap::new();
        for e in TABLE.iter() {
            if e.platform != platform {
                continue;
            }
            if !prefix.is_empty() && !e.version_number.to_ascii_lowercase().starts_with(&prefix) {
                continue;
            }
            let entry = best
                .entry(e.version_number.clone())
                .or_insert_with(|| e.clone());
            if e.build > entry.build {
                *entry = e.clone();
            }
        }
        let mut numbered: Vec<(u64, String)> =
            best.into_iter().map(|(n, e)| (e.build, n)).collect();
        numbered.sort_by_key(|entry| std::cmp::Reverse(entry.0));
        numbered.into_iter().map(|(_, n)| n).collect()
    }

    /// The version numbers worth offering for a platform, newest first.
    ///
    /// [`suggest`] returns everything the table has, which includes several
    /// hundred pre-release builds (`5.0.0-beta73-rc1`, `5.0.0-qa-71-29`, …) and
    /// the `3.?.?` placeholder. Those are real signatures, but they are not what
    /// a person picks from a list: a QA build of a client that does not exist
    /// for this platform connects nowhere useful, and the placeholder is not a
    /// version at all.
    ///
    /// What is left is every release-shaped number (digits and dots only) except
    /// the `0.0.1` sentinel. `Windows3.` is a table quirk with a single `6.0`
    /// entry; it is kept because it is a real signed pair, and dropping it would
    /// make a platform the table offers unusable.
    ///
    /// Everything below [`OLDEST_SERVER_ACCEPTED`] is dropped as well. A valid
    /// signature is not the same as a server accepting the version: current
    /// servers refuse anything older than 3.1 with `ClientVersionOutdated`, so
    /// offering 3.0.x would only produce a connection that cannot work.
    pub fn choices(platform: &str) -> Vec<String> {
        Self::suggest("", platform)
            .into_iter()
            .filter(|v| is_release_number(v))
            .filter(|v| !is_older_than_supported(v))
            .collect()
    }

    /// Resolves the pair to the newest signed entry that matches.
    ///
    /// Returns `None` when the platform has no signature, or the version number
    /// has no matching entry for it. A `None` is what the shell shows as
    /// "this choice cannot be announced": the server would refuse it.
    pub fn resolve(&self) -> Option<ResolvedVersion> {
        let mut best: Option<&VersionEntry> = None;
        for e in TABLE.iter() {
            if e.platform != self.platform {
                continue;
            }
            if e.version_number.eq_ignore_ascii_case(&self.version) {
                match best {
                    Some(b) if b.build >= e.build => {}
                    _ => best = Some(e),
                }
            }
        }
        best.map(|e| ResolvedVersion {
            platform: e.platform.clone(),
            version: e.version.clone(),
            signature: e.signature.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_resolves_to_the_borrowed_3_6_3_windows_tuple() {
        let resolved = VersionChoice::default()
            .resolve()
            .expect("default must resolve");
        assert_eq!(resolved.platform, "Windows");
        assert_eq!(resolved.version, "3.6.3 [Build: 1701166057]");
        assert_eq!(resolved.signature.len(), 64);
    }

    #[test]
    fn the_offered_list_has_no_pre_releases_and_no_placeholders() {
        for platform in VersionChoice::platforms() {
            let choices = VersionChoice::choices(&platform);
            for version in &choices {
                assert!(
                    !version.contains('-') && !version.contains('?'),
                    "{platform} offers {version}, which is not a release"
                );
                assert_ne!(version, "0.0.1", "{platform} offers the sentinel");
                // Everything offered must be usable as-is, or the list would
                // contain rows that cannot be saved.
                assert!(
                    VersionChoice::new(version.clone(), platform.clone())
                        .resolve()
                        .is_some(),
                    "{platform} offers {version}, which does not resolve"
                );
            }
        }
    }

    #[test]
    fn the_offered_list_drops_versions_no_current_server_accepts() {
        // Measured: 3.0.20 is refused with ClientVersionOutdated, 3.1.0 connects.
        for platform in VersionChoice::platforms() {
            for version in VersionChoice::choices(&platform) {
                assert!(
                    !is_older_than_supported(&version),
                    "{platform} offers {version}, which a current server refuses"
                );
            }
        }
        let windows = VersionChoice::choices("Windows");
        assert!(!windows.contains(&"3.0.20".to_string()));
        assert!(!windows.contains(&"3.0.13".to_string()));
        // The Windows table spells the 3.1.0 release as `3.1`.
        assert!(windows.contains(&"3.1".to_string()));
        assert!(windows.contains(&"3.1.10".to_string()));
        // Numeric comparison, not textual: 3.10 is newer than 3.9, and 3.0.20
        // is newer than 3.0.13 — both would be wrong as strings.
        assert!(is_older_than_supported("3.0.20"));
        assert!(!is_older_than_supported("3.1.0"));
        assert!(!is_older_than_supported("3.10.0"));
    }

    #[test]
    fn the_offered_list_still_contains_the_standard_tuple() {
        let windows = VersionChoice::choices("Windows");
        assert!(windows.contains(&"3.6.3".to_string()));
        let android = VersionChoice::choices("Android");
        assert!(android.contains(&"3.6.0".to_string()));
        // The newest release is first, so the list opens on something sensible.
        assert_eq!(windows.first().map(String::as_str), Some("3.6.3"));
    }

    #[test]
    fn a_version_number_with_no_match_for_the_platform_does_not_resolve() {
        // 3.6.3 has no Android signature; the platform has entries, the pair does not.
        let choice = VersionChoice::new("3.6.3", "Android");
        assert!(choice.resolve().is_none(), "no Android 3.6.3 tuple exists");
    }

    #[test]
    fn a_platform_with_no_signature_at_all_does_not_resolve() {
        let choice = VersionChoice::new("3.6.3", "Solaris");
        assert!(choice.resolve().is_none());
    }

    #[test]
    fn suggest_filters_by_prefix_and_platform() {
        let all = VersionChoice::suggest("", "Windows");
        assert!(all.iter().any(|v| v == "3.6.3"));
        assert!(!all.iter().any(|v| v.contains("Android")));

        let filtered = VersionChoice::suggest("3.6", "Windows");
        assert!(filtered.iter().all(|v| v.starts_with("3.6")));
        assert!(filtered.iter().any(|v| v == "3.6.3"));
    }

    #[test]
    fn suggest_dedupes_to_the_newest_build_per_version_number() {
        // Android 3.5.0 has seven builds in the table; the suggestion list must
        // carry the version number once, resolved to the newest build.
        let numbers = VersionChoice::suggest("3.5", "Android");
        assert_eq!(numbers.iter().filter(|v| *v == "3.5.0").count(), 1);
        // And the resolved entry is the newest of the 3.5.0 builds.
        let resolved = VersionChoice::new("3.5.0", "Android").resolve().unwrap();
        assert!(resolved.version.starts_with("3.5.0 [Build:"));
    }

    #[test]
    fn platforms_lists_every_platform_with_a_signature() {
        let platforms = VersionChoice::platforms();
        assert!(platforms.iter().any(|p| p == "Windows"));
        assert!(platforms.iter().any(|p| p == "Android"));
        assert!(platforms.iter().any(|p| p == "OS X"));
        assert!(platforms.iter().any(|p| p == "macOS"));
    }

    #[test]
    fn every_table_entry_carries_a_non_empty_signature() {
        // A signature that decoded to nothing would make the entry unusable;
        // catch it here rather than at connect time.
        for e in TABLE.iter() {
            assert!(!e.signature.is_empty(), "empty signature for {}", e.version);
        }
    }
}
