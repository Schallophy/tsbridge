//! A protobuf wire-format reader/writer that keeps untouched bytes untouched.
//!
//! Why this exists instead of a generated codec:
//!
//! * **Item content is byte-sensitive.** A bookmark's decrypted plaintext is
//!   re-encrypted after an edit, and `sha512(plaintext)` is what the server
//!   checks. A decoder that re-encodes a message from a parsed field list
//!   (canonical varints, fields in schema order, dropped defaults) would change
//!   bytes the caller never asked to change. Every field therefore remembers the
//!   exact byte range it was read from, and serialisation emits those bytes until
//!   something actually replaces a value.
//! * There is no `.proto` file for these messages in the repository; the field
//!   numbers came from the recovered schema dump. A generic wire reader is a
//!   better fit than 40 hand-generated structs, and it cannot go stale when the
//!   server adds a field: unknown fields round-trip verbatim.
//!
//! This is a *suite* codec. It is deliberately strict about structure — a
//! truncated or malformed blob is an error, not a partial parse — because a
//! half-parsed item blob is indistinguishable from a corrupt account, and
//! guessing is the one thing that must not happen here.

/// Protobuf wire types. Only these four are legal in a well-formed message.
const WIRE_VARINT: u8 = 0;
const WIRE_64BIT: u8 = 1;
const WIRE_LENGTH: u8 = 2;
const WIRE_32BIT: u8 = 5;

/// One field value, as far as this code needs to understand it.
#[derive(Debug, Clone, PartialEq)]
pub enum WireValue {
    Varint(u64),
    Fixed64([u8; 8]),
    /// Length-delimited: sub-message, string, bytes, or a packed scalar list.
    /// The distinction is schema-level, so the value stays raw here.
    Bytes(Vec<u8>),
    Fixed32([u8; 4]),
}

/// One field of a message.
#[derive(Debug, Clone)]
pub struct Field {
    pub number: u32,
    pub value: WireValue,
    /// The field exactly as it appeared, tag included. `None` once a setter has
    /// replaced the value, at which point the field is re-encoded instead.
    original: Option<Vec<u8>>,
}

impl Field {
    fn from_varint(number: u32, value: u64, raw: Vec<u8>) -> Self {
        Field {
            number,
            value: WireValue::Varint(value),
            original: Some(raw),
        }
    }

    fn from_bytes(number: u32, value: Vec<u8>, raw: Vec<u8>) -> Self {
        Field {
            number,
            value: WireValue::Bytes(value),
            original: Some(raw),
        }
    }

    /// The field encoded with its tag, for a caller that is copying it.
    pub fn encoded(&self) -> Vec<u8> {
        self.to_bytes()
    }

    fn to_bytes(&self) -> Vec<u8> {
        if let Some(raw) = &self.original {
            return raw.clone();
        }
        encode_value(self.number, &self.value)
    }

    /// Replaces a varint. Refuses to change the wire type: a field that was
    /// length-delimited is a different field, and writing a varint into it would
    /// produce a message the client cannot parse.
    pub fn set_varint(&mut self, value: u64) -> Result<(), String> {
        match self.value {
            WireValue::Varint(_) => {
                self.value = WireValue::Varint(value);
                self.original = None;
                Ok(())
            }
            _ => Err(format!(
                "field {} is not a varint (wire type {})",
                self.number,
                self.wire_type()
            )),
        }
    }

    pub fn set_bytes(&mut self, value: Vec<u8>) -> Result<(), String> {
        match self.value {
            WireValue::Bytes(_) => {
                self.value = WireValue::Bytes(value);
                self.original = None;
                Ok(())
            }
            _ => Err(format!(
                "field {} is not length-delimited (wire type {})",
                self.number,
                self.wire_type()
            )),
        }
    }

    pub fn wire_type(&self) -> u8 {
        match self.value {
            WireValue::Varint(_) => WIRE_VARINT,
            WireValue::Fixed64(_) => WIRE_64BIT,
            WireValue::Bytes(_) => WIRE_LENGTH,
            WireValue::Fixed32(_) => WIRE_32BIT,
        }
    }

    pub fn as_varint(&self) -> Option<u64> {
        match self.value {
            WireValue::Varint(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match &self.value {
            WireValue::Bytes(value) => Some(value),
            _ => None,
        }
    }

    /// A length-delimited field read as text. Invalid UTF-8 is `None` rather than
    /// a replacement character: a mangled nickname must not look like a real one.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(self.as_bytes()?).ok()
    }
}

/// A decoded message: its fields, in the order they appeared.
#[derive(Debug, Clone, Default)]
pub struct Message {
    pub fields: Vec<Field>,
}

impl Message {
    pub fn parse(bytes: &[u8]) -> Result<Message, String> {
        let mut fields = Vec::new();
        let mut pos = 0;
        while pos < bytes.len() {
            let start = pos;
            let tag = read_varint(bytes, &mut pos)?;
            let number = (tag >> 3) as u32;
            let wire = (tag & 7) as u8;
            if number == 0 {
                return Err("field number 0 is not legal".to_string());
            }
            let field = match wire {
                WIRE_VARINT => {
                    let value = read_varint(bytes, &mut pos)?;
                    Field::from_varint(number, value, bytes[start..pos].to_vec())
                }
                WIRE_64BIT => {
                    let value = read_fixed::<8>(bytes, &mut pos)?;
                    Field {
                        number,
                        value: WireValue::Fixed64(value),
                        original: Some(bytes[start..pos].to_vec()),
                    }
                }
                WIRE_LENGTH => {
                    let len = read_varint(bytes, &mut pos)? as usize;
                    let end = pos
                        .checked_add(len)
                        .ok_or_else(|| "length overflow".to_string())?;
                    if end > bytes.len() {
                        return Err(format!(
                            "field {number} claims {len} B but only {} remain",
                            bytes.len() - pos
                        ));
                    }
                    let value = bytes[pos..end].to_vec();
                    pos = end;
                    Field::from_bytes(number, value, bytes[start..pos].to_vec())
                }
                WIRE_32BIT => {
                    let value = read_fixed::<4>(bytes, &mut pos)?;
                    Field {
                        number,
                        value: WireValue::Fixed32(value),
                        original: Some(bytes[start..pos].to_vec()),
                    }
                }
                other => {
                    return Err(format!(
                        "field {number} uses wire type {other}, which cannot be parsed"
                    ))
                }
            };
            fields.push(field);
        }
        Ok(Message { fields })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for field in &self.fields {
            out.extend_from_slice(&field.to_bytes());
        }
        out
    }

    /// First occurrence of `number`. protobuf says the last one wins for scalars;
    /// the messages in this protocol never repeat a scalar field, and refusing to
    /// guess is safer than picking either end.
    pub fn get(&self, number: u32) -> Option<&Field> {
        self.fields.iter().find(|f| f.number == number)
    }

    fn index(&self, number: u32) -> Result<usize, String> {
        self.fields
            .iter()
            .position(|f| f.number == number)
            .ok_or_else(|| format!("message has no field {number}"))
    }

    pub fn varint(&self, number: u32) -> Option<u64> {
        self.get(number).and_then(Field::as_varint)
    }

    pub fn bytes(&self, number: u32) -> Option<&[u8]> {
        self.get(number).and_then(Field::as_bytes)
    }

    pub fn string(&self, number: u32) -> Option<&str> {
        self.get(number).and_then(Field::as_str)
    }

    pub fn bool(&self, number: u32) -> Option<bool> {
        self.varint(number).map(|v| v != 0)
    }

    /// A length-delimited field as a nested message.
    pub fn message(&self, number: u32) -> Result<Message, String> {
        let bytes = self
            .bytes(number)
            .ok_or_else(|| format!("message has no length-delimited field {number}"))?;
        Message::parse(bytes)
    }

    pub fn all(&self, number: u32) -> impl Iterator<Item = &Field> {
        self.fields.iter().filter(move |f| f.number == number)
    }

    pub fn set_varint(&mut self, number: u32, value: u64) -> Result<(), String> {
        let index = self.index(number)?;
        self.fields[index].set_varint(value)
    }

    pub fn set_bytes(&mut self, number: u32, value: Vec<u8>) -> Result<(), String> {
        let index = self.index(number)?;
        self.fields[index].set_bytes(value)
    }

    pub fn set_string(&mut self, number: u32, value: &str) -> Result<(), String> {
        self.set_bytes(number, value.as_bytes().to_vec())
    }

    /// Sets a length-delimited field, appending it when the message does not have
    /// it yet. Appending is safe for protobuf (tag order carries no meaning), and
    /// it is what makes "add a server password to a bookmark whose template has
    /// none" work at all.
    pub fn upsert_bytes(&mut self, number: u32, value: Vec<u8>) {
        match self.index(number) {
            Ok(index) => {
                self.fields[index].value = WireValue::Bytes(value);
                self.fields[index].original = None;
            }
            Err(_) => self.fields.push(Field {
                number,
                value: WireValue::Bytes(value),
                original: None,
            }),
        }
    }

    pub fn upsert_string(&mut self, number: u32, value: &str) {
        self.upsert_bytes(number, value.as_bytes().to_vec());
    }

    pub fn upsert_varint(&mut self, number: u32, value: u64) {
        match self.index(number) {
            Ok(index) => {
                self.fields[index].value = WireValue::Varint(value);
                self.fields[index].original = None;
            }
            Err(_) => self.fields.push(Field {
                number,
                value: WireValue::Varint(value),
                original: None,
            }),
        }
    }

    /// Edits a nested message in place.
    ///
    /// The closure receives the decoded child; whatever it leaves behind is
    /// re-encoded and stored back. Returns the child's error unchanged, so a
    /// caller can report "the template has no field b7" rather than a generic
    /// failure.
    pub fn edit_nested(
        &mut self,
        number: u32,
        edit: impl FnOnce(&mut Message) -> Result<(), String>,
    ) -> Result<(), String> {
        let index = self.index(number)?;
        let child_bytes = self.fields[index]
            .as_bytes()
            .ok_or_else(|| format!("field {number} is not length-delimited"))?
            .to_vec();
        let mut child = Message::parse(&child_bytes)?;
        edit(&mut child)?;
        let encoded = child.encode();
        self.fields[index].set_bytes(encoded)
    }
}

impl Message {
    /// The encoded bytes of the first field with this number.
    ///
    /// For a merge: the other side's field is copied verbatim rather than being
    /// decoded and re-encoded, which would normalise a value this code does not
    /// know how to represent.
    pub fn raw_field(&self, number: u32) -> Option<Vec<u8>> {
        self.fields
            .iter()
            .find(|field| field.number == number)
            .map(|field| field.to_bytes())
    }

    /// Replaces a field with pre-encoded bytes, or removes it when `raw` is
    /// `None`.
    ///
    /// The replacement keeps the same position in the field order, so a merge
    /// produces a message shaped like the input rather than one with the field
    /// moved to the end.
    pub fn set_raw_field(&mut self, number: u32, raw: Option<Vec<u8>>) -> Result<(), String> {
        let index = self.fields.iter().position(|field| field.number == number);
        match (index, raw) {
            (Some(index), Some(raw)) => {
                let encoded = Message::parse_field_bytes(&raw)?;
                self.fields[index] = encoded;
                Ok(())
            }
            (Some(index), None) => {
                self.fields.remove(index);
                Ok(())
            }
            (None, Some(raw)) => {
                let encoded = Message::parse_field_bytes(&raw)?;
                self.fields.push(encoded);
                Ok(())
            }
            (None, None) => Ok(()),
        }
    }

    /// Re-reads one encoded field. Used so a copied field keeps its original
    /// bytes: `Field::original` is set, and `to_bytes` returns them unchanged.
    fn parse_field_bytes(raw: &[u8]) -> Result<Field, String> {
        let parsed = Message::parse(raw)?;
        parsed
            .fields
            .into_iter()
            .next()
            .ok_or_else(|| "the copied field was empty".to_string())
    }
}

fn encode_value(number: u32, value: &WireValue) -> Vec<u8> {
    let mut out = Vec::new();
    match value {
        WireValue::Varint(v) => {
            write_tag(number, WIRE_VARINT, &mut out);
            write_varint(*v, &mut out);
        }
        WireValue::Fixed64(v) => {
            write_tag(number, WIRE_64BIT, &mut out);
            out.extend_from_slice(v);
        }
        WireValue::Bytes(v) => {
            write_tag(number, WIRE_LENGTH, &mut out);
            write_varint(v.len() as u64, &mut out);
            out.extend_from_slice(v);
        }
        WireValue::Fixed32(v) => {
            write_tag(number, WIRE_32BIT, &mut out);
            out.extend_from_slice(v);
        }
    }
    out
}

fn write_tag(number: u32, wire: u8, out: &mut Vec<u8>) {
    write_varint(((number as u64) << 3) | wire as u64, out);
}

pub fn write_varint(value: u64, out: &mut Vec<u8>) {
    let mut value = value;
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

pub fn varint(value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    write_varint(value, &mut out);
    out
}

pub fn read_varint(bytes: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut value: u64 = 0;
    let mut shift = 0;
    loop {
        let byte = *bytes
            .get(*pos)
            .ok_or_else(|| "varint ran past the end of the message".to_string())?;
        *pos += 1;
        if shift > 63 {
            return Err("varint is longer than 64 bits".to_string());
        }
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

fn read_fixed<const N: usize>(bytes: &[u8], pos: &mut usize) -> Result<[u8; N], String> {
    let end = *pos + N;
    if end > bytes.len() {
        return Err("fixed-width field ran past the end of the message".to_string());
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*pos..end]);
    *pos = end;
    Ok(out)
}

// ── builders for the handful of messages the account side sends ─────────────
//
// Written as free functions rather than structs: each of these is sent once, its
// field numbers are fixed by the recovered schema, and a builder makes the wire
// shape readable next to the comment that explains it.

pub fn field_bytes(number: u32, value: &[u8]) -> Vec<u8> {
    encode_value(number, &WireValue::Bytes(value.to_vec()))
}

pub fn field_string(number: u32, value: &str) -> Vec<u8> {
    field_bytes(number, value.as_bytes())
}

pub fn field_varint(number: u32, value: u64) -> Vec<u8> {
    encode_value(number, &WireValue::Varint(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixture produced by an independent generator
    /// (`research/myts-login/explore/…`, reproduced in `tests/account_contract.rs`).
    /// It has the field order and defaults a real client bookmark has, including
    /// the `manipulated=3` varint that differs between local row and server blob.
    const ITEM: &str = concat!(
        "122431313131313131312d323232322d343333332d383434342d353535353535353535353535",
        "1a2461616161616161312d626262622d346363632d386464642d656565656565656565656565",
        "2003",
        "2a2461616161616161312d626262622d346363632d386464642d656565656565656565656565",
        "3000",
        "4880e2cfaa06",
        "82012d",
        "0a054c6f626279",
        "120e74732e6578616d706c652e636f6d",
        "18834e",
        "2203616e6e",
        "7001",
        "7a07616263566b6579",
        "b00101",
    );

    fn fixture() -> Vec<u8> {
        let mut bytes = Vec::new();
        for i in 0..ITEM.len() / 2 {
            bytes.push(u8::from_str_radix(&ITEM[i * 2..i * 2 + 2], 16).unwrap());
        }
        bytes
    }

    #[test]
    fn parsing_then_encoding_is_byte_identical() {
        let bytes = fixture();
        let message = Message::parse(&bytes).unwrap();
        assert_eq!(
            message.encode(),
            bytes,
            "a round trip must not rewrite a single byte"
        );
    }

    #[test]
    fn unknown_fields_survive_a_round_trip() {
        // A server-side field this code has no schema for must not be dropped:
        // dropping it would change the plaintext, and the plaintext's `sha512` is
        // what the server checks on the re-uploaded item.
        let mut bytes = fixture();
        bytes.extend_from_slice(&field_string(99, "future field"));
        let message = Message::parse(&bytes).unwrap();
        assert_eq!(message.encode(), bytes);
        assert!(message.get(99).is_some());
    }

    #[test]
    fn editing_one_varint_leaves_the_rest_alone() {
        let bytes = fixture();
        let mut message = Message::parse(&bytes).unwrap();
        assert_eq!(message.varint(4), Some(3));
        message.set_varint(4, 0).unwrap();
        let edited = message.encode();
        assert_eq!(
            edited.len(),
            bytes.len(),
            "same length, so no field resized"
        );
        // Exactly one byte differs; find it and prove it is the 0x03 payload.
        let diffs: Vec<usize> = bytes
            .iter()
            .zip(edited.iter())
            .enumerate()
            .filter(|(_, (a, b))| a != b)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(diffs.len(), 1, "diff positions: {diffs:?}");
        assert_eq!(bytes[diffs[0]], 0x03);
        assert_eq!(edited[diffs[0]], 0x00);
    }

    #[test]
    fn nested_fields_are_readable_and_editable() {
        let bytes = fixture();
        let mut message = Message::parse(&bytes).unwrap();
        let bookmark = message.message(16).unwrap();
        assert_eq!(bookmark.string(1), Some("Lobby"));
        assert_eq!(bookmark.string(2), Some("ts.example.com"));
        assert_eq!(bookmark.varint(3), Some(9987));
        assert_eq!(bookmark.varint(14), Some(1));

        message
            .edit_nested(16, |bm| bm.set_string(1, "Dock!"))
            .unwrap();
        let re = Message::parse(&message.encode()).unwrap();
        assert_eq!(re.message(16).unwrap().string(1), Some("Dock!"));
        // A same-length string edit must not change the total size.
        assert_eq!(message.encode().len(), bytes.len(), "5 B for 5 B");
    }

    #[test]
    fn a_length_prefix_that_grows_is_rewritten_not_patched() {
        // The classic protobuf-editing bug: append to a nested buffer and forget
        // that the outer length varint now has to grow (or that tag+length would
        // be left behind and duplicated).
        let bytes = fixture();
        let mut message = Message::parse(&bytes).unwrap();
        message
            .edit_nested(16, |bm| {
                bm.upsert_string(1, "A much longer lobby name");
                Ok(())
            })
            .unwrap();
        let out = Message::parse(&message.encode()).unwrap();
        assert_eq!(
            out.message(16).unwrap().string(1),
            Some("A much longer lobby name")
        );
        assert!(message.encode().len() > bytes.len());
    }

    #[test]
    fn truncated_and_illegal_messages_are_errors() {
        let bytes = fixture();
        assert!(Message::parse(&bytes[..bytes.len() - 3]).is_err());
        assert!(Message::parse(&[0x08]).is_err(), "varint with no payload");
        assert!(
            Message::parse(&[0x0c]).is_err(),
            "wire type 4 is a group end and has no place here"
        );
        assert!(Message::parse(&[0x00]).is_err(), "field number 0");
    }

    #[test]
    fn set_refuses_to_change_a_field_s_meaning() {
        let bytes = fixture();
        let mut message = Message::parse(&bytes).unwrap();
        let err = message.set_varint(2, 7).unwrap_err();
        assert!(err.contains("not a varint"), "{err}");
        let err = message.set_bytes(4, vec![0]).unwrap_err();
        assert!(err.contains("not length-delimited"), "{err}");
    }

    #[test]
    fn varints_round_trip_at_the_boundaries() {
        for value in [0u64, 1, 127, 128, 16_383, 16_384, u32::MAX as u64, 1 << 62] {
            let encoded = varint(value);
            let mut pos = 0;
            assert_eq!(read_varint(&encoded, &mut pos).unwrap(), value);
            assert_eq!(pos, encoded.len());
        }
    }
}
