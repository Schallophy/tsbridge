//! Server-side icon files (`/icon_<id>`).
//!
//! TeamSpeak stores group, channel and server icons as ordinary files in the
//! root channel, named `/icon_<id>` where the id is the `icon_id` a group or
//! channel carries. There is no dedicated download command: the desktop client
//! fetches them with the same file-transfer path as any other file, which is
//! why this lives beside [`crate::files`] rather than having its own protocol.
//!
//! The cache is a directory of `<id>.<ext>` files, plus a map from id to the
//! file that was stored. A shell asks for the picture by id and gets a path it
//! can hand to an image loader; nothing re-downloads an icon it already has.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::net::TcpStream;

use crate::handle::Inner;

/// How many bytes an icon may be before it is refused.
///
/// A TeamSpeak icon is a small PNG or SVG — the desktop client caps uploads at
/// 256 KB. A server that answers with something larger is not sending an icon,
/// and writing it to disk would be a way to fill the phone's storage.
const MAX_ICON_BYTES: u64 = 512 * 1024;

/// One cached icon.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CachedIcon {
    /// The `icon_id` this was fetched for.
    pub id: i64,
    /// Absolute path of the file on disk.
    pub path: String,
    /// The file's size in bytes.
    pub size: u64,
    /// `png`, `svg`, `jpg` or `bin` when the type could not be told.
    pub format: String,
}

/// The icon cache for one connection.
///
/// Lives on the session, not on the snapshot: the snapshot is serialized on
/// every frame, and a map of absolute paths does not belong in something a UI
/// reads 60 times a second. The snapshot exposes the same data through
/// [`crate::state::Snapshot::icons`], which is refreshed when the cache changes.
#[derive(Debug, Default)]
pub struct IconCache {
    dir: Option<PathBuf>,
    entries: BTreeMap<i64, CachedIcon>,
    /// Ids that were requested and failed, so a broken icon is not retried on
    /// every reconnect.
    failed: BTreeMap<i64, String>,
}

impl IconCache {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir: Some(dir),
            entries: BTreeMap::new(),
            failed: BTreeMap::new(),
        }
    }

    pub fn entries(&self) -> &BTreeMap<i64, CachedIcon> {
        &self.entries
    }

    pub fn failures(&self) -> &BTreeMap<i64, String> {
        &self.failed
    }

    pub fn has(&self, id: i64) -> bool {
        self.entries.contains_key(&id) || self.failed.contains_key(&id)
    }

    pub fn get(&self, id: i64) -> Option<&CachedIcon> {
        self.entries.get(&id)
    }

    /// Reads a cache directory written by an earlier run.
    ///
    /// The file name carries the id and the format, so the cache needs no index
    /// of its own: `<id>.<format>`. A file whose name does not parse is left
    /// alone rather than deleted — it may be a partial write from a crash, and
    /// the next fetch of that id overwrites it.
    pub fn load(dir: &Path) -> Self {
        let mut entries = BTreeMap::new();
        if let Ok(read) = std::fs::read_dir(dir) {
            for entry in read.flatten() {
                let path = entry.path();
                let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                let Some((id, format)) = name.split_once('.') else {
                    continue;
                };
                let Ok(id) = id.parse::<i64>() else {
                    continue;
                };
                let Ok(meta) = entry.metadata() else {
                    continue;
                };
                if !meta.is_file() {
                    continue;
                }
                entries.insert(
                    id,
                    CachedIcon {
                        id,
                        path: path.to_string_lossy().to_string(),
                        size: meta.len(),
                        format: format.to_string(),
                    },
                );
            }
        }
        Self {
            dir: Some(dir.to_path_buf()),
            entries,
            failed: BTreeMap::new(),
        }
    }

    /// Writes the bytes and records the entry.
    ///
    /// The format is sniffed from the first bytes rather than trusted from the
    /// server: the file name extension is what an image loader uses to pick a
    /// decoder, so guessing wrong makes a valid icon fail to draw.
    pub fn store(&mut self, id: i64, bytes: &[u8]) -> Result<CachedIcon, String> {
        let Some(dir) = self.dir.clone() else {
            return Err("icon cache has no directory".to_string());
        };
        if bytes.len() as u64 > MAX_ICON_BYTES {
            let message = format!("icon {id} is {} bytes, over the limit", bytes.len());
            self.failed.insert(id, message.clone());
            return Err(message);
        }
        let format = sniff_format(bytes);
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        let path = dir.join(format!("{id}.{format}"));
        std::fs::write(&path, bytes)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        let entry = CachedIcon {
            id,
            path: path.to_string_lossy().to_string(),
            size: bytes.len() as u64,
            format: format.to_string(),
        };
        self.entries.insert(id, entry.clone());
        self.failed.remove(&id);
        Ok(entry)
    }

    pub fn mark_failed(&mut self, id: i64, message: String) {
        self.failed.insert(id, message);
    }
}

/// The image format from the file's own header.
fn sniff_format(bytes: &[u8]) -> &'static str {
    const PNG: &[u8] = &[0x89, b'P', b'N', b'G'];
    const JPEG: &[u8] = &[0xFF, 0xD8, 0xFF];
    if bytes.starts_with(PNG) {
        return "png";
    }
    if bytes.starts_with(JPEG) {
        return "jpg";
    }
    // An SVG may start with a BOM, whitespace, an XML declaration or a comment,
    // so the tag is searched for rather than matched at offset zero.
    let head = &bytes[..bytes.len().min(512)];
    if head.windows(4).any(|window| window == b"<svg")
        || head.windows(9).any(|window| window == b"<svg:svg ")
    {
        return "svg";
    }
    "bin"
}

/// Receives one icon from the file-transfer stream and stores it.
///
/// Mirrors [`crate::files::download`] but keeps the bytes in memory: an icon is
/// small enough that a temporary file would be more moving parts than value,
/// and the size cap has to be enforced before anything reaches the disk anyway.
pub async fn receive(inner: Arc<Inner>, id: i64, total: u64, mut stream: TcpStream) {
    if total > MAX_ICON_BYTES {
        fail(
            &inner,
            id,
            &format!("server announced {total} bytes, over the limit"),
        );
        return;
    }

    let mut bytes = Vec::with_capacity(total as usize);
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        match tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await {
            Ok(0) => break,
            Ok(read) => {
                bytes.extend_from_slice(&buffer[..read]);
                if bytes.len() as u64 > MAX_ICON_BYTES {
                    fail(&inner, id, "stream exceeded the icon size limit");
                    return;
                }
            }
            Err(e) => {
                fail(&inner, id, &format!("read failed: {e}"));
                return;
            }
        }
    }

    let stored = inner.with_session_icons(|cache| cache.store(id, &bytes));
    match stored {
        Ok(entry) => {
            inner.push_event(
                crate::events::QueuedEvent::new("icon_ready")
                    .long("icon_id", id)
                    .str("path", &entry.path)
                    .str("format", &entry.format)
                    .long("size", entry.size as i64),
            );
        }
        Err(message) => fail(&inner, id, &message),
    }
}

fn fail(inner: &Arc<Inner>, id: i64, message: &str) {
    log::warn!("Icon {id} failed: {message}");
    inner.with_session_icons(|cache| cache.mark_failed(id, message.to_string()));
    inner.push_event(
        crate::events::QueuedEvent::new("icon_failed")
            .long("icon_id", id)
            .str("message", message),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn png_is_recognised_by_its_header() {
        assert_eq!(sniff_format(&[0x89, b'P', b'N', b'G', 0x0D]), "png");
    }

    #[test]
    fn jpeg_is_recognised_by_its_header() {
        assert_eq!(sniff_format(&[0xFF, 0xD8, 0xFF, 0xE0]), "jpg");
    }

    #[test]
    fn svg_is_recognised_after_an_xml_declaration() {
        let svg = br#"<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>"#;
        assert_eq!(sniff_format(svg), "svg");
    }

    #[test]
    fn an_unknown_header_is_stored_as_bin() {
        assert_eq!(sniff_format(b"not an image at all"), "bin");
    }

    #[test]
    fn an_oversized_icon_is_refused_and_remembered() {
        let dir = std::env::temp_dir().join(format!("tsbridge-icons-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut cache = IconCache::new(dir.clone());
        let big = vec![0u8; (MAX_ICON_BYTES + 1) as usize];
        let error = cache.store(7, &big).unwrap_err();
        assert!(error.contains("over the limit"), "{error}");
        assert!(cache.failures().contains_key(&7));
        assert!(!dir.join("7.bin").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stored_icon_is_found_again_after_a_reload() {
        let dir =
            std::env::temp_dir().join(format!("tsbridge-icons-reload-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut cache = IconCache::new(dir.clone());
        cache.store(42, &[0x89, b'P', b'N', b'G', 0x0D]).unwrap();
        drop(cache);

        let reloaded = IconCache::load(&dir);
        let entry = reloaded.get(42).expect("icon survived the reload");
        assert_eq!(entry.format, "png");
        assert!(Path::new(&entry.path).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
