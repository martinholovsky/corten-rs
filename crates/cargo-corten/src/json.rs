//! A small JSON reader for `cargo metadata` output, so the checker needs no
//! dependency. Bounded nesting; numbers are kept as text.

use std::collections::BTreeMap;
use std::fmt;

/// Deepest nesting accepted.
pub const MAX_DEPTH: usize = 128;

/// A JSON value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Json {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number, as written.
    Number(String),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Json>),
    /// An object.
    Object(BTreeMap<String, Json>),
}

/// Why the text is not JSON this reader accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonError {
    /// Byte offset of the problem.
    pub offset: usize,
    /// What was wrong.
    pub message: &'static str,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid JSON at byte {}: {}", self.offset, self.message)
    }
}

impl std::error::Error for JsonError {}

impl Json {
    /// Parses one JSON document.
    ///
    /// # Errors
    ///
    /// [`JsonError`] for malformed input, nesting deeper than
    /// [`MAX_DEPTH`], or trailing text.
    pub fn parse(text: &str) -> Result<Self, JsonError> {
        let mut p = Parser {
            bytes: text.as_bytes(),
            pos: 0,
        };
        let value = p.value(0)?;
        p.skip_ws();
        if p.pos == p.bytes.len() {
            Ok(value)
        } else {
            Err(p.err("trailing text"))
        }
    }

    /// The member `key` of an object.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(map) => map.get(key),
            _ => None,
        }
    }

    /// The string, if this is one.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// The elements, if this is an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(v) => Some(v),
            _ => None,
        }
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn err(&self, message: &'static str) -> JsonError {
        JsonError {
            offset: self.pos,
            message,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos = self.pos.saturating_add(1);
        Some(b)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos = self.pos.saturating_add(1);
        }
    }

    fn expect_word(&mut self, word: &'static [u8], value: Json) -> Result<Json, JsonError> {
        let end = self.pos.saturating_add(word.len());
        if self.bytes.get(self.pos..end) == Some(word) {
            self.pos = end;
            Ok(value)
        } else {
            Err(self.err("unexpected token"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, JsonError> {
        if depth > MAX_DEPTH {
            return Err(self.err("nesting too deep"));
        }
        self.skip_ws();
        match self.peek() {
            Some(b'n') => self.expect_word(b"null", Json::Null),
            Some(b't') => self.expect_word(b"true", Json::Bool(true)),
            Some(b'f') => self.expect_word(b"false", Json::Bool(false)),
            Some(b'"') => self.string().map(Json::String),
            Some(b'[') => self.array(depth),
            Some(b'{') => self.object(depth),
            Some(b'-' | b'0'..=b'9') => Ok(self.number()),
            _ => Err(self.err("expected a value")),
        }
    }

    fn number(&mut self) -> Json {
        let start = self.pos;
        while matches!(
            self.peek(),
            Some(b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9')
        ) {
            self.pos = self.pos.saturating_add(1);
        }
        let text = self.bytes.get(start..self.pos).unwrap_or(&[]);
        Json::Number(String::from_utf8_lossy(text).into_owned())
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let mut v = 0u32;
        for _ in 0..4 {
            let b = self.bump().ok_or_else(|| self.err("short \\u escape"))?;
            let d = char::from(b)
                .to_digit(16)
                .ok_or_else(|| self.err("bad \\u escape"))?;
            v = v
                .checked_mul(16)
                .and_then(|v| v.checked_add(d))
                .ok_or_else(|| self.err("bad \\u escape"))?;
        }
        Ok(v)
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.bump(); // opening quote
        let mut out = Vec::new();
        loop {
            let b = self.bump().ok_or_else(|| self.err("unterminated string"))?;
            match b {
                b'"' => break,
                b'\\' => {
                    let e = self.bump().ok_or_else(|| self.err("unterminated escape"))?;
                    let c = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let code = if (0xD800..0xDC00).contains(&hi) {
                                if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
                                    return Err(self.err("lone surrogate"));
                                }
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(self.err("bad low surrogate"));
                                }
                                let high = hi.saturating_sub(0xD800);
                                let low = lo.saturating_sub(0xDC00);
                                high.checked_shl(10)
                                    .and_then(|h| h.checked_add(low))
                                    .and_then(|v| v.checked_add(0x1_0000))
                                    .ok_or_else(|| self.err("bad surrogate pair"))?
                            } else {
                                hi
                            };
                            char::from_u32(code).ok_or_else(|| self.err("invalid code point"))?
                        }
                        _ => return Err(self.err("unknown escape")),
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
                0x00..=0x1f => return Err(self.err("control character in string")),
                _ => out.push(b),
            }
        }
        String::from_utf8(out).map_err(|_| self.err("string is not UTF-8"))
    }

    fn array(&mut self, depth: usize) -> Result<Json, JsonError> {
        self.bump();
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.bump();
            return Ok(Json::Array(items));
        }
        loop {
            items.push(self.value(depth.saturating_add(1))?);
            self.skip_ws();
            match self.bump() {
                Some(b',') => {}
                Some(b']') => return Ok(Json::Array(items)),
                _ => return Err(self.err("expected , or ]")),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, JsonError> {
        self.bump();
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.bump();
            return Ok(Json::Object(map));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.err("expected a key"));
            }
            let key = self.string()?;
            self.skip_ws();
            if self.bump() != Some(b':') {
                return Err(self.err("expected :"));
            }
            let value = self.value(depth.saturating_add(1))?;
            map.insert(key, value);
            self.skip_ws();
            match self.bump() {
                Some(b',') => {}
                Some(b'}') => return Ok(Json::Object(map)),
                _ => return Err(self.err("expected , or }")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_metadata_shapes() {
        let j = Json::parse(
            r#"{"packages":[{"name":"a","source":null,"targets":[{"kind":["proc-macro"]}],"v":1.5e3}],"ok":true}"#,
        )
        .unwrap();
        let pkgs = j.get("packages").and_then(Json::as_array).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].get("name").and_then(Json::as_str), Some("a"));
        assert_eq!(pkgs[0].get("source"), Some(&Json::Null));
        assert_eq!(pkgs[0].get("v"), Some(&Json::Number("1.5e3".to_owned())));
    }

    #[test]
    fn decodes_escapes() {
        let j = Json::parse(r#""a\"b\\c\n\u00e9\ud83d\ude00""#).unwrap();
        assert_eq!(j.as_str(), Some("a\"b\\c\né😀"));
    }

    #[test]
    fn rejects_malformed_and_deep() {
        for bad in [
            "",
            "{",
            "[1,]",
            "{\"a\" 1}",
            "\"\\x\"",
            "\"\\ud800\"",
            "nul",
            "1 2",
            "\"a\u{1}\"",
        ] {
            assert!(Json::parse(bad).is_err(), "{bad:?}");
        }
        let deep = "[".repeat(200) + &"]".repeat(200);
        assert!(Json::parse(&deep).is_err());
        let ok = "[".repeat(100) + &"]".repeat(100);
        assert!(Json::parse(&ok).is_ok());
    }
}
