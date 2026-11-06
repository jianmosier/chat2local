use crate::{Error, Result, compact, json};
use chat2local_js_value_compat::{Document, Value};

const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut text = String::new();
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);
        text.push(ALPHABET[(a >> 2) as usize] as char);
        text.push(ALPHABET[((a & 3) << 4 | b >> 4) as usize] as char);
        text.push(if chunk.len() > 1 {
            ALPHABET[((b & 15) << 2 | c >> 6) as usize] as char
        } else {
            '='
        });
        text.push(if chunk.len() > 2 {
            ALPHABET[(c & 63) as usize] as char
        } else {
            '='
        });
    }
    text
}
// Windows' original FromBase64String accepts ASCII whitespace, but not Node's
// URL alphabet/ignored junk. POSIX uses Buffer.from(data, 'base64').
pub(crate) fn decode(text: &[u16], windows: bool) -> Result<Vec<u8>> {
    let units: Vec<u16> = if windows {
        text.iter()
            .copied()
            .filter(|c| ![9, 10, 13, 32].contains(c))
            .collect()
    } else {
        text.to_vec()
    };
    if windows && !units.len().is_multiple_of(4) {
        return Err(Error::invalid("Invalid base64 envelope."));
    }
    let mut output = Vec::new();
    let mut bits = 0u32;
    let mut count = 0;
    let mut padding = 0;
    for &unit in &units {
        if unit == 61 {
            padding += 1;
            if !windows {
                break;
            }
            continue;
        }
        let value = match unit {
            65..=90 => Some(unit - 65),
            97..=122 => Some(unit - 97 + 26),
            48..=57 => Some(unit - 48 + 52),
            43 => Some(62),
            47 => Some(63),
            45 if !windows => Some(62),
            95 if !windows => Some(63),
            _ => None,
        };
        let Some(value) = value else {
            if windows {
                return Err(Error::invalid("Invalid base64 envelope."));
            }
            continue;
        };
        if padding != 0 {
            return Err(Error::invalid("Invalid base64 envelope."));
        }
        bits = (bits << 6) | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            output.push((bits >> count) as u8);
        }
    }
    if windows && (padding > 2 || count != padding * 2) {
        return Err(Error::invalid("Invalid base64 envelope."));
    }
    Ok(output)
}
pub(crate) fn seal(doc: &Document) -> Result<Document> {
    let raw = compact(doc)?;
    #[cfg(windows)]
    let (format, bytes) = (
        "windows-dpapi-v1",
        chat2local_agent_platform::current_user_data(raw.as_bytes(), true, usize::MAX)
            .map_err(|_| Error::new("EDPAPI", "Current-user DPAPI operation failed."))?,
    );
    #[cfg(not(windows))]
    let (format, bytes) = ("posix-permissions-only", raw.into_bytes());
    envelope(format, &bytes)
}
pub(crate) fn envelope(format: &str, bytes: &[u8]) -> Result<Document> {
    json(format!("{{\"format\":\"{format}\",\"data\":\"{}\"}}", encode(bytes)).as_bytes())
}
#[cfg(any(test, not(windows)))]
pub(crate) fn posix_payload(format: &[u16], data: &[u16]) -> Result<Vec<u8>> {
    if format != "posix-permissions-only".encode_utf16().collect::<Vec<_>>() {
        return Err(Error::invalid("Unsupported credential vault."));
    }
    decode(data, false)
}
pub(crate) fn unseal(doc: &Document) -> Result<Document> {
    let property = |name: &str| -> Result<Vec<u16>> {
        let id = doc
            .get_property(doc.root(), &name.encode_utf16().collect::<Vec<_>>())?
            .ok_or_else(|| Error::invalid("Unsupported credential vault."))?;
        match doc.value(id)? {
            Value::String(text) => Ok(text.clone()),
            _ => Err(Error::invalid("Unsupported credential vault.")),
        }
    };
    let format = property("format")?;
    #[cfg(windows)]
    let bytes = {
        if format != "windows-dpapi-v1".encode_utf16().collect::<Vec<_>>() {
            return Err(Error::invalid("Unsupported credential vault."));
        }
        let encrypted = decode(&property("data")?, true)?;
        chat2local_agent_platform::current_user_data(&encrypted, false, usize::MAX)
            .map_err(|_| Error::new("EDPAPI", "Current-user DPAPI operation failed."))?
    };
    #[cfg(not(windows))]
    let bytes = posix_payload(&format, &property("data")?)?;
    json(&bytes)
}

// Formatting the already-canonical compact JSON keeps numeric/key/string rules
// in js-value-compat. This scanner never parses or normalizes string contents.
pub(crate) fn pretty(text: &str) -> String {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut quoted = false;
    let mut escaped = false;
    let newline = |out: &mut Vec<u8>, depth: usize| {
        out.push(b'\n');
        for _ in 0..depth {
            out.extend_from_slice(b"  ");
        }
    };
    for (index, byte) in text.bytes().enumerate() {
        if quoted {
            out.push(byte);
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
            continue;
        }
        match byte {
            b'"' => {
                quoted = true;
                out.push(b'"');
            }
            b'[' | b'{' => {
                out.push(byte);
                depth += 1;
                if text.as_bytes().get(index + 1) != Some(&(if byte == b'[' { b']' } else { b'}' }))
                {
                    newline(&mut out, depth);
                }
            }
            b']' | b'}' => {
                depth -= 1;
                if text.as_bytes().get(index.wrapping_sub(1))
                    != Some(&(if byte == b']' { b'[' } else { b'{' }))
                {
                    newline(&mut out, depth);
                }
                out.push(byte);
            }
            b',' => {
                out.push(b',');
                newline(&mut out, depth);
            }
            b':' => out.extend_from_slice(b": "),
            _ => out.push(byte),
        }
    }
    // The scanner works on UTF-8 bytes, not Unicode scalar values.
    String::from_utf8(out).expect("formatting preserves UTF-8")
}
