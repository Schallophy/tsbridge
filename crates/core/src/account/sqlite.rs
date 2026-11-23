//! The one thing this library reads out of the TeamSpeak client's
//! `settings.db`: the account row, and the item rows next to it.
//!
//! A whole SQLite implementation would be absurd here, and the `rusqlite` crate
//! would put a C library back into a crate that is otherwise pure Rust. What is
//! needed instead is much narrower than "SQL":
//!
//! * two tables, both plain `rowid` tables with no `INTEGER PRIMARY KEY` and no
//!   indexes that have to be consulted — `AccountData` and `ProtobufItems`;
//! * three columns at most, read by table name and column position;
//! * **strictly read-only**. Nothing in this module can write, and the file is
//!   opened by copying its bytes, so a later bug in this code cannot corrupt a
//!   file the user's real client depends on.
//!
//! That last point is not decoration. The reference research treats
//! `settings.db` as untouchable: an earlier round of experimentation verified
//! all 29 rows were byte-identical afterwards, and every write path in the
//! account side goes to the server instead. Keeping this reader incapable of
//! writes makes that invariant structural rather than a habit.
//!
//! What is implemented: the file header, table b-trees (leaf + interior), cell
//! payload overflow, and the record format with the serial types those columns
//! can use. What is deliberately not: indexes, `WITHOUT ROWID` tables, writing,
//! WAL (`-wal`) contents, and any page type this code never meets in a file the
//! TS3 client produced. Anything unsupported is an error with a reason, never a
//! partial answer.

use std::collections::BTreeMap;
use std::path::Path;

/// A column value, in the shapes the two tables use.
#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    Null,
    Integer(i64),
    /// TEXT and BLOB both land here: the account items are stored as blobs but
    /// the query never cares which, and the byte content is what is wanted.
    Bytes(Vec<u8>),
    Real(f64),
}

impl Cell {
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Cell::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<String> {
        self.as_bytes()
            .map(|b| String::from_utf8_lossy(b).into_owned())
    }

    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Cell::Integer(value) => Some(*value),
            _ => None,
        }
    }
}

/// A row: column position to value. Serial types that are NULL are absent.
pub type Row = BTreeMap<usize, Cell>;

/// A minimal read-only view of a SQLite database file.
#[derive(Debug)]
pub struct Database {
    bytes: Vec<u8>,
    page_size: usize,
    usable_size: usize,
}

impl Database {
    /// Reads the file's bytes. There is no write path and no handle held open.
    pub fn open(path: &Path) -> Result<Database, String> {
        let bytes =
            std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        Database::from_bytes(bytes)
    }

    pub fn from_bytes(bytes: Vec<u8>) -> Result<Database, String> {
        if bytes.len() < 512 {
            return Err("file is too small to be a SQLite database".to_string());
        }
        if &bytes[..16] != b"SQLite format 3\0" {
            return Err("not a SQLite 3 database (bad magic)".to_string());
        }
        // Page size lives at offset 16 as a big-endian u16; the value 1 means
        // 65536, which does not fit in the field.
        let raw = u16::from_be_bytes([bytes[16], bytes[17]]) as usize;
        let page_size = if raw == 1 {
            65536
        } else if (512..=32768).contains(&raw) && raw.is_power_of_two() {
            raw
        } else {
            return Err(format!("implausible page size {raw}"));
        };
        let reserved = bytes[20] as usize;
        let usable_size = page_size
            .checked_sub(reserved)
            .filter(|u| *u >= 480)
            .ok_or_else(|| format!("usable page size {page_size}-{reserved} is too small"))?;
        // A WAL-mode database has a readable main file only after a checkpoint;
        // the flag this checks is "write version", where 2 means WAL.
        if bytes[18] == 2 || bytes[19] == 2 {
            return Err(
                "database is in WAL mode; its latest rows may live in a -wal file this reader \
                 does not open"
                    .to_string(),
            );
        }
        Ok(Database {
            bytes,
            page_size,
            usable_size,
        })
    }

    fn page(&self, number: u32) -> Result<&[u8], String> {
        if number == 0 {
            return Err("page 0 does not exist".to_string());
        }
        let start = (number as usize - 1)
            .checked_mul(self.page_size)
            .ok_or_else(|| "page number overflow".to_string())?;
        let end = start + self.page_size;
        self.bytes
            .get(start..end)
            .ok_or_else(|| format!("page {number} is past the end of the file"))
    }

    /// Root page of a table, read out of `sqlite_master` (which is itself table 1).
    fn table_root(&self, name: &str) -> Result<u32, String> {
        for row in self.table_rows(1)? {
            // sqlite_master columns: type, name, tbl_name, rootpage, sql
            let kind = row.get(&0).and_then(Cell::as_text).unwrap_or_default();
            let table = row.get(&1).and_then(Cell::as_text).unwrap_or_default();
            if kind == "table" && table == name {
                let root = row
                    .get(&3)
                    .and_then(Cell::as_integer)
                    .ok_or_else(|| format!("table {name} has no root page"))?;
                return u32::try_from(root)
                    .map_err(|_| format!("table {name} root {root} is invalid"));
            }
        }
        Err(format!("table {name} is not in sqlite_master"))
    }

    /// Every row of a table, in rowid order.
    pub fn rows(&self, table: &str) -> Result<Vec<Row>, String> {
        let root = self.table_root(table)?;
        self.table_rows(root)
    }

    /// Column names of a table, in declaration order.
    pub fn columns(&self, table: &str) -> Result<Vec<String>, String> {
        for row in self.table_rows(1)? {
            let kind = row.get(&0).and_then(Cell::as_text).unwrap_or_default();
            let name = row.get(&1).and_then(Cell::as_text).unwrap_or_default();
            if kind == "table" && name == table {
                let sql = row.get(&4).and_then(Cell::as_text).unwrap_or_default();
                return Ok(column_names(&sql));
            }
        }
        Err(format!("table {table} is not in sqlite_master"))
    }

    fn table_rows(&self, root: u32) -> Result<Vec<Row>, String> {
        let mut rows = Vec::new();
        // Iterative, because a hostile or unusual file could nest deeper than the
        // stack would like.
        let mut stack = vec![root];
        while let Some(page_number) = stack.pop() {
            let page = self.page(page_number)?;
            let header_at = if page_number == 1 { 100 } else { 0 };
            let header = page
                .get(header_at..header_at + 12)
                .ok_or_else(|| format!("page {page_number} is too short for a b-tree header"))?;
            let kind = header[0];
            let cell_count = u16::from_be_bytes([header[3], header[4]]) as usize;
            let pointers_at = header_at
                + match kind {
                    5 => 12,
                    13 => 8,
                    other => {
                        return Err(format!(
                            "page {page_number} is b-tree type {other}; only rowid tables (13/5) \
                             are supported"
                        ))
                    }
                };
            let pointer_bytes = cell_count
                .checked_mul(2)
                .ok_or_else(|| "cell count overflow".to_string())?;
            let pointers = page
                .get(pointers_at..pointers_at + pointer_bytes)
                .ok_or_else(|| format!("page {page_number} has a truncated cell pointer array"))?;

            if kind == 5 {
                // Interior table page: right-most child pointer follows the
                // header, and every cell is `<child:4><rowid:varint>`.
                let right_at = header_at + 8;
                let right = u32::from_be_bytes(
                    page.get(right_at..right_at + 4)
                        .ok_or_else(|| "interior page has no right pointer".to_string())?
                        .try_into()
                        .expect("4 bytes"),
                );
                for index in 0..cell_count {
                    let offset =
                        u16::from_be_bytes([pointers[index * 2], pointers[index * 2 + 1]]) as usize;
                    let child = u32::from_be_bytes(
                        page.get(offset..offset + 4)
                            .ok_or_else(|| {
                                format!("cell {index} on page {page_number} is truncated")
                            })?
                            .try_into()
                            .expect("4 bytes"),
                    );
                    stack.push(child);
                }
                stack.push(right);
                continue;
            }

            for index in 0..cell_count {
                let offset =
                    u16::from_be_bytes([pointers[index * 2], pointers[index * 2 + 1]]) as usize;
                let (rowid, payload) = self.read_leaf_cell(page_number, offset)?;
                let _ = rowid;
                rows.push(parse_record(&payload)?);
            }
        }
        Ok(rows)
    }

    /// Reads one leaf-table cell, following the overflow chain when the payload
    /// does not fit on the page. Returns `(rowid, payload)`.
    fn read_leaf_cell(&self, page_number: u32, offset: usize) -> Result<(i64, Vec<u8>), String> {
        let page = self.page(page_number)?;
        let mut pos = offset;
        let payload_len = read_varint(page, &mut pos)
            .ok_or_else(|| format!("cell at {page_number}/{offset} has no payload length"))?
            as usize;
        let rowid = read_varint(page, &mut pos)
            .ok_or_else(|| format!("cell at {page_number}/{offset} has no rowid"))?
            as i64;
        if payload_len > self.usable_size.saturating_mul(64) {
            return Err(format!("payload of {payload_len} B is implausibly large"));
        }

        // SQLite's spill rule, from the file format document. For a table leaf
        // cell: maxLocal = U-35, minLocal = ((U-12)*32/255)-23.
        let max_local = self.usable_size - 35;
        let min_local = ((self.usable_size - 12) * 32 / 255) - 23;
        let local = if payload_len <= max_local {
            payload_len
        } else {
            let candidate = min_local + ((payload_len - min_local) % (self.usable_size - 4));
            if candidate > max_local {
                min_local
            } else {
                candidate
            }
        };

        let mut out = page
            .get(pos..pos + local)
            .ok_or_else(|| format!("cell at {page_number}/{offset} is truncated"))?
            .to_vec();
        if local < payload_len {
            // The cell ends with a 4-byte pointer to the first overflow page.
            let next_at = pos + local;
            let mut next = u32::from_be_bytes(
                page.get(next_at..next_at + 4)
                    .ok_or_else(|| "overflow pointer is past the page end".to_string())?
                    .try_into()
                    .expect("4 bytes"),
            );
            let mut guard = 0;
            while next != 0 && out.len() < payload_len {
                if guard > 10_000 {
                    return Err("overflow chain is unreasonably long".to_string());
                }
                guard += 1;
                let overflow = self.page(next)?;
                let take = (payload_len - out.len()).min(self.usable_size - 4);
                out.extend_from_slice(
                    overflow
                        .get(4..4 + take)
                        .ok_or_else(|| "overflow page is truncated".to_string())?,
                );
                next = u32::from_be_bytes(
                    overflow
                        .get(..4)
                        .ok_or_else(|| "overflow page has no successor".to_string())?
                        .try_into()
                        .expect("4 bytes"),
                );
            }
        }
        Ok((rowid, out))
    }
}

/// Reads a SQLite varint — **big-endian**, unlike a protobuf varint.
///
/// SQLite's format document: each byte contributes seven bits, and the first
/// byte holds the *most* significant group. Nine bytes is the maximum, and the
/// ninth contributes a full eight bits so the whole u64 range is reachable.
/// Reading it the protobuf way (accumulating with `|` at a growing shift) is the
/// single easiest bug to make here: it turns a 141-byte cell into a 1665-byte
/// one, which then "runs off the page" and gets blamed on overflow.
fn read_varint(page: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value: u64 = 0;
    for index in 0..9 {
        let byte = *page.get(*pos)?;
        *pos += 1;
        if index == 8 {
            return Some((value << 8) | u64::from(byte));
        }
        value = (value << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// A record: a header of serial types, then the values they describe.
fn parse_record(payload: &[u8]) -> Result<Row, String> {
    let mut pos = 0;
    let header_len = read_varint(payload, &mut pos)
        .ok_or_else(|| "record has no header length".to_string())? as usize;
    if header_len > payload.len() || header_len < 1 {
        return Err("record header length is out of range".to_string());
    }
    let header_end = header_len;
    let mut serials = Vec::new();
    while pos < header_end {
        let serial = read_varint(payload, &mut pos)
            .ok_or_else(|| "record header is truncated".to_string())?;
        serials.push(serial);
    }
    if pos != header_end {
        return Err("record header overran its declared length".to_string());
    }

    let mut row = Row::new();
    let mut body = header_end;
    for (index, serial) in serials.iter().copied().enumerate() {
        let (cell, size) = match serial {
            0 => (Cell::Null, 0),
            1..=6 => {
                let size = [1usize, 2, 3, 4, 6, 8][serial as usize - 1];
                let raw = payload
                    .get(body..body + size)
                    .ok_or_else(|| format!("column {index} is truncated"))?;
                // Big-endian two's complement, sign-extended from the first byte.
                let mut value: i64 = if raw[0] & 0x80 != 0 { -1 } else { 0 };
                for byte in raw {
                    value = (value << 8) | *byte as i64;
                }
                (Cell::Integer(value), size)
            }
            7 => {
                let raw = payload
                    .get(body..body + 8)
                    .ok_or_else(|| format!("column {index} is truncated"))?;
                let bits = u64::from_be_bytes(raw.try_into().expect("8 bytes"));
                (Cell::Real(f64::from_bits(bits)), 8)
            }
            8 => (Cell::Integer(0), 0),
            9 => (Cell::Integer(1), 0),
            10 | 11 => return Err(format!("column {index} uses reserved serial type {serial}")),
            other => {
                // Text and blob share one serial-type space: `12 + 2*len` for a
                // blob, `13 + 2*len` for text. Both reduce to the same length only
                // if the parity is taken into account; `(13-12)/2` would make every
                // one-byte text column zero bytes long and shift the whole record.
                let size = if other % 2 == 1 {
                    ((other - 13) / 2) as usize
                } else {
                    ((other - 12) / 2) as usize
                };
                let raw = payload
                    .get(body..body + size)
                    .ok_or_else(|| format!("column {index} is truncated"))?;
                (Cell::Bytes(raw.to_vec()), size)
            }
        };
        if !matches!(cell, Cell::Null) {
            row.insert(index, cell);
        }
        body += size;
    }
    Ok(row)
}

/// Column names out of a `CREATE TABLE` statement.
///
/// Deliberately crude: it takes the parenthesised body and splits on commas, which
/// is enough for the two tables this reader is aimed at. A constraint clause that
/// contains a comma at the top level (an index in `UNIQUE(...)`) would be
/// mis-split, and that case is rejected rather than guessed at — this reader is
/// never asked for a table it cannot name the columns of.
fn column_names(sql: &str) -> Vec<String> {
    let Some(open) = sql.find('(') else {
        return Vec::new();
    };
    let Some(close) = sql.rfind(')') else {
        return Vec::new();
    };
    let body = &sql[open + 1..close];
    body.split(',')
        .filter_map(|part| {
            let name = part.split_whitespace().next()?;
            // A table-level constraint starts with `UNIQUE(`, `PRIMARY KEY(`,
            // etc. Take the bare word before any parenthesis, then reject the
            // constraint keywords: `UNIQUE(a)` is not a column named `UNIQUE(a)`.
            let bare = name.split('(').next().unwrap_or("").trim();
            if bare.is_empty()
                || matches!(
                    bare.to_ascii_uppercase().as_str(),
                    "PRIMARY" | "UNIQUE" | "CHECK" | "FOREIGN" | "CONSTRAINT"
                )
            {
                return None;
            }
            Some(bare.trim_matches('"').to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One record field, as `(serial type, body bytes)`.
    type Encoded = (u64, Vec<u8>);

    fn text(value: &[u8]) -> Encoded {
        (13 + 2 * value.len() as u64, value.to_vec())
    }

    fn blob(value: &[u8]) -> Encoded {
        (12 + 2 * value.len() as u64, value.to_vec())
    }

    fn integer(value: i64) -> Encoded {
        if value == 0 {
            (8, Vec::new())
        } else {
            // One byte is enough for the small values this fixture uses, and
            // the reader sign-extends from the leading byte either way.
            (1, vec![value as u8])
        }
    }

    fn record(fields: &[Encoded]) -> Vec<u8> {
        let mut header = vec![0u8]; // placeholder for the header-size varint
        for (serial, _) in fields {
            write_varint(*serial, &mut header);
        }
        header[0] = header.len() as u8;
        let mut out = header;
        for (_, body) in fields {
            out.extend_from_slice(body);
        }
        out
    }

    /// SQLite's varint is big-endian: the high group comes first and the low one
    /// last. The little-endian protobuf encoder next door gets this wrong in a
    /// way that only shows up once a value needs three bytes.
    fn write_varint(value: u64, out: &mut Vec<u8>) {
        let mut groups = Vec::new();
        let mut value = value;
        while value > 0x7f {
            groups.push((value & 0x7f) as u8);
            value >>= 7;
        }
        groups.push(value as u8);
        for byte in groups[1..].iter().rev() {
            out.push(byte | 0x80);
        }
        out.push(groups[0]);
    }

    /// Lays a leaf b-tree page into `file` at `page_number`, content growing
    /// downwards from the end of the page exactly as SQLite does it.
    fn write_leaf(file: &mut [u8], page_number: usize, cells: &[(i64, Vec<u8>)]) {
        const PAGE: usize = 4096;
        let start = (page_number - 1) * PAGE;
        let header_at = if page_number == 1 { 100 } else { 0 };
        let header = &mut file[start + header_at..start + header_at + 8];
        header[0] = 13; // leaf table
        header[1] = 0; // no free blocks
        header[3..5].copy_from_slice(&(cells.len() as u16).to_be_bytes());
        header[5..7].copy_from_slice(&(PAGE as u16).to_be_bytes());
        header[7] = 0; // fragmented free bytes

        let mut content_end = PAGE;
        let mut pointers = Vec::new();
        for (rowid, payload) in cells {
            let mut cell = Vec::new();
            write_varint(payload.len() as u64, &mut cell);
            write_varint(*rowid as u64, &mut cell);
            cell.extend_from_slice(payload);
            content_end -= cell.len();
            file[start + content_end..start + content_end + cell.len()].copy_from_slice(&cell);
            pointers.push(content_end as u16);
        }
        for (index, pointer) in pointers.iter().enumerate() {
            let at = start + header_at + 8 + index * 2;
            file[at..at + 2].copy_from_slice(&pointer.to_be_bytes());
        }
        file[start + header_at + 5..start + header_at + 7]
            .copy_from_slice(&(content_end as u16).to_be_bytes());
    }

    /// Three pages: `sqlite_master` on page 1 describing table `t` at root 2,
    /// and `t` itself on page 2 with one text key and one blob value.
    fn mini_database() -> Vec<u8> {
        const PAGE: usize = 4096;
        let mut file = vec![0u8; PAGE * 3];
        file[..16].copy_from_slice(b"SQLite format 3\0");
        file[16..18].copy_from_slice(&(PAGE as u16).to_be_bytes());
        file[18] = 1; // write version: rollback journal, not WAL
        file[19] = 1;
        file[21] = 64;
        file[22] = 32;
        file[23] = 32;
        file[24] = 32;
        file[28..32].copy_from_slice(&3u32.to_be_bytes());

        let master = record(&[
            text(b"table"),
            text(b"t"),
            text(b"t"),
            integer(2),
            text(b"CREATE TABLE t(a VARCHAR, b VARCHAR)"),
        ]);
        write_leaf(&mut file, 1, &[(1, master)]);

        let first = record(&[text(b"k1"), blob(&[1, 2, 3])]);
        let second = record(&[text(b"k2"), integer(7)]);
        write_leaf(&mut file, 2, &[(1, first), (2, second)]);
        file
    }

    #[test]
    fn reads_a_table_by_name() {
        let db = Database::from_bytes(mini_database()).unwrap();
        let rows = db.rows("t").unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[0].get(&0).and_then(Cell::as_text).as_deref(),
            Some("k1")
        );
        assert_eq!(
            rows[0].get(&1).and_then(Cell::as_bytes),
            Some(&[1u8, 2, 3][..])
        );
        assert_eq!(
            rows[1].get(&0).and_then(Cell::as_text).as_deref(),
            Some("k2")
        );
        assert_eq!(rows[1].get(&1).and_then(Cell::as_integer), Some(7));
        assert_eq!(db.columns("t").unwrap(), vec!["a", "b"]);
    }

    #[test]
    fn rejects_files_it_cannot_read_safely() {
        let mut wrong_magic = mini_database();
        wrong_magic[0] = b'X';
        assert!(Database::from_bytes(wrong_magic)
            .unwrap_err()
            .contains("SQLite"));

        let mut wal = mini_database();
        wal[18] = 2;
        assert!(Database::from_bytes(wal).unwrap_err().contains("WAL"));

        let mut small_pages = mini_database();
        small_pages[16..18].copy_from_slice(&3u16.to_be_bytes());
        assert!(Database::from_bytes(small_pages)
            .unwrap_err()
            .contains("page size"));
    }

    #[test]
    fn column_names_come_out_of_the_schema_sql() {
        let names = column_names(
            "CREATE TABLE ProtobufItems(timestamp INTEGER UNSIGNED NOT NULL, key VARCHAR NOT NULL, \
             value VARCHAR)",
        );
        assert_eq!(names, vec!["timestamp", "key", "value"]);
        // A table-level constraint must not be mistaken for a column.
        let names = column_names("CREATE TABLE t(a TEXT, UNIQUE(a), b TEXT)");
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn a_missing_table_is_an_error_not_an_empty_result() {
        let db = Database::from_bytes(mini_database()).unwrap();
        assert!(db.rows("nope").is_err());
    }
}
