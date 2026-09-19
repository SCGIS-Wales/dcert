//! Zeroizing wrapper for secrets read from the command line, the environment
//! or an interactive prompt.
//!
//! The value is wiped from memory when dropped, never appears in `Debug`
//! output, and dereferences to `str` so call sites that take `&str` need no
//! changes.

use std::fmt;
use std::ops::Deref;
use std::str::FromStr;
use zeroize::Zeroizing;

/// A secret string that is zeroized on drop and redacted in `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// Borrow the secret. Named explicitly so uses are easy to audit.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Deref for Secret {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl FromStr for Secret {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_the_value() {
        let s = Secret::new("hunter2");
        assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
        assert_eq!(s.expose(), "hunter2");
        assert_eq!(&*s, "hunter2");
    }

    #[test]
    fn parses_from_str() {
        let s: Secret = "abc".parse().unwrap();
        assert!(!s.is_empty());
        assert_eq!(s.len(), 3);
    }
}
