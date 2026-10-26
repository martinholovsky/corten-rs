//! `PathSeg` and `RelPath`: the only names a `DirCap` opens.
//!
//! The grammar is normative and lives in `docs/pathseg.md`; each rule below
//! cites its number there.

use std::fmt;

/// Longest segment, in bytes (rule 1).
pub const MAX_SEGMENT_LEN: usize = 255;

/// Windows device names, matched case-insensitively against the part of a
/// segment before its first dot (rule 6).
const DEVICE_NAMES: &[&str] = &[
    "con", "prn", "aux", "nul", "com0", "com1", "com2", "com3", "com4", "com5", "com6", "com7",
    "com8", "com9", "lpt0", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Why a string is not a `PathSeg`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathSegError {
    /// Empty, or longer than [`MAX_SEGMENT_LEN`] bytes (rule 1).
    Length,
    /// A character outside `A-Z a-z 0-9 . _ -` (rule 2).
    Character,
    /// `.` or a `..` anywhere (rule 3).
    Dots,
    /// Ends with `.` (rule 4).
    TrailingDot,
    /// Starts with `-` (rule 5).
    LeadingDash,
    /// A Windows device name (rule 6).
    DeviceName,
}

impl fmt::Display for PathSegError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Length => "a path segment must be 1 to 255 bytes",
            Self::Character => "a path segment may contain only A-Z a-z 0-9 . _ -",
            Self::Dots => "a path segment may not be `.` or contain `..`",
            Self::TrailingDot => "a path segment may not end with `.`",
            Self::LeadingDash => "a path segment may not start with `-`",
            Self::DeviceName => "a path segment may not be a Windows device name",
        })
    }
}

impl std::error::Error for PathSegError {}

/// One validated name inside a directory. Constructed only by
/// [`PathSeg::parse`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PathSeg(String);

impl PathSeg {
    /// Accepts `text` if every rule in `docs/pathseg.md` section 1 holds.
    ///
    /// # Errors
    ///
    /// Returns the first rule `text` breaks.
    pub fn parse(text: &str) -> Result<Self, PathSegError> {
        if text.is_empty() || text.len() > MAX_SEGMENT_LEN {
            return Err(PathSegError::Length);
        }
        if !text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(PathSegError::Character);
        }
        if text == "." || text.contains("..") {
            return Err(PathSegError::Dots);
        }
        if text.ends_with('.') {
            return Err(PathSegError::TrailingDot);
        }
        if text.starts_with('-') {
            return Err(PathSegError::LeadingDash);
        }
        let base = text.split('.').next().unwrap_or(text);
        if DEVICE_NAMES.iter().any(|d| base.eq_ignore_ascii_case(d)) {
            return Err(PathSegError::DeviceName);
        }
        Ok(Self(text.to_owned()))
    }

    /// The segment's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PathSeg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A non-empty sequence of segments, resolved relative to a `DirCap`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelPath {
    first: PathSeg,
    rest: Vec<PathSeg>,
}

impl RelPath {
    /// A path of one segment.
    #[must_use]
    pub fn new(first: PathSeg) -> Self {
        Self {
            first,
            rest: Vec::new(),
        }
    }

    /// This path with `next` appended.
    #[must_use]
    pub fn join(mut self, next: PathSeg) -> Self {
        self.rest.push(next);
        self
    }

    /// Segments in order.
    pub fn segments(&self) -> impl Iterator<Item = &PathSeg> {
        std::iter::once(&self.first).chain(self.rest.iter())
    }

    /// The last segment.
    #[must_use]
    pub fn last(&self) -> &PathSeg {
        self.rest.last().unwrap_or(&self.first)
    }

    /// The path without its last segment, if it has more than one.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        let (_, init) = self.rest.split_last()?;
        Some(Self {
            first: self.first.clone(),
            rest: init.to_vec(),
        })
    }

    /// Segments joined by `/`. No segment contains a separator, `.` or
    /// `..`, so this names exactly the path the segments describe.
    #[must_use]
    pub fn to_slash_string(&self) -> String {
        self.segments()
            .map(PathSeg::as_str)
            .collect::<Vec<_>>()
            .join("/")
    }
}

impl From<PathSeg> for RelPath {
    fn from(seg: PathSeg) -> Self {
        Self::new(seg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_portable_names() {
        for ok in [
            "a",
            "report.pdf",
            ".config",
            "a_b-c.d",
            "x.tar.gz",
            "CONsole",
            "com10",
        ] {
            assert!(PathSeg::parse(ok).is_ok(), "{ok}");
        }
        assert!(PathSeg::parse(&"a".repeat(255)).is_ok());
    }

    #[test]
    fn rejects_each_rule() {
        let cases: &[(&str, PathSegError)] = &[
            ("", PathSegError::Length),
            ("a/b", PathSegError::Character),
            ("a\\b", PathSegError::Character),
            ("C:x", PathSegError::Character),
            ("a b", PathSegError::Character),
            ("a*", PathSegError::Character),
            ("a~1", PathSegError::Character),
            ("a\0", PathSegError::Character),
            ("é", PathSegError::Character),
            ("/etc", PathSegError::Character),
            (".", PathSegError::Dots),
            ("..", PathSegError::Dots),
            ("...", PathSegError::Dots),
            ("a..b", PathSegError::Dots),
            ("name.", PathSegError::TrailingDot),
            ("-rf", PathSegError::LeadingDash),
            ("con", PathSegError::DeviceName),
            ("NUL.txt", PathSegError::DeviceName),
            ("Com1.log", PathSegError::DeviceName),
            ("lpt9", PathSegError::DeviceName),
        ];
        for (text, err) in cases {
            assert_eq!(PathSeg::parse(text), Err(*err), "{text:?}");
        }
        assert_eq!(PathSeg::parse(&"a".repeat(256)), Err(PathSegError::Length));
    }

    #[test]
    fn relpath_joins_and_splits() {
        let p = RelPath::new(PathSeg::parse("a").unwrap())
            .join(PathSeg::parse("b").unwrap())
            .join(PathSeg::parse("c.txt").unwrap());
        assert_eq!(p.to_slash_string(), "a/b/c.txt");
        assert_eq!(p.last().as_str(), "c.txt");
        assert_eq!(p.parent().unwrap().to_slash_string(), "a/b");
        assert!(
            RelPath::new(PathSeg::parse("a").unwrap())
                .parent()
                .is_none()
        );
    }

    /// Property: whatever bytes are parsed, an accepted segment contains no
    /// separator, NUL or `..`, so joining segments can never escape.
    #[test]
    fn accepted_segments_never_contain_escape_material() {
        let alphabet: &[u8] = b"aZ09._-/\\:\0 *~.";
        // Every string of length 1 to 4 over the alphabet: 15^4 + ... cases.
        let mut stack: Vec<Vec<u8>> = alphabet.iter().map(|b| vec![*b]).collect();
        let mut checked = 0usize;
        while let Some(s) = stack.pop() {
            if let Ok(text) = std::str::from_utf8(&s) {
                checked = checked.saturating_add(1);
                if let Ok(seg) = PathSeg::parse(text) {
                    let t = seg.as_str();
                    assert!(!t.contains(['/', '\\', '\0', ':', ' ']), "{t:?}");
                    assert!(!t.contains(".."), "{t:?}");
                    assert!(t != ".", "{t:?}");
                }
            }
            if s.len() < 4 {
                for b in alphabet {
                    let mut next = s.clone();
                    next.push(*b);
                    stack.push(next);
                }
            }
        }
        assert!(checked > 50_000, "{checked}");
    }
}
