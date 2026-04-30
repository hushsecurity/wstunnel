use regex::Regex;

/// Parses an HTTP Authorization header value of the form `Bearer <token>` and
/// returns the token portion. Returns `None` if the header doesn't match the
/// expected shape.
pub(crate) fn extract_bearer(auth_val: &str) -> Option<&str> {
    let re = Regex::new(r"^[Bb]earer\s+([[:graph:]]+)\s*$").unwrap();
    let caps = re.captures(auth_val)?;
    caps.get(1).map(|m| m.as_str())
}
