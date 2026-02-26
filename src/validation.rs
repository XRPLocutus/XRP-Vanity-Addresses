// ============================================================================
//  Pattern Validation
// ============================================================================

use crate::crypto::XRPL_ALPHABET;

/// Validates pattern characters against the XRPL Base58 alphabet.
/// Case-insensitive mode validates against lowercased alphabet.
pub fn validate_vanity_chars(pattern: &str, case_insensitive: bool) -> Result<(), String> {
    let alphabet_str = std::str::from_utf8(XRPL_ALPHABET).unwrap();

    for ch in pattern.chars() {
        let valid = if case_insensitive {
            alphabet_str
                .chars()
                .any(|a| a.to_lowercase().eq(ch.to_lowercase()))
        } else {
            alphabet_str.contains(ch)
        };

        if !valid {
            return Err(format!(
                "Character '{}' is not valid in the XRPL Base58 alphabet.\n\
                 Valid characters: {}",
                ch, alphabet_str
            ));
        }
    }
    Ok(())
}

// ============================================================================
//  Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_chars_valid() {
        assert!(validate_vanity_chars("Bob", false).is_ok());
        assert!(validate_vanity_chars("XRP", false).is_ok());
        assert!(validate_vanity_chars("r3", false).is_ok());
    }

    #[test]
    fn test_validate_chars_invalid() {
        assert!(validate_vanity_chars("O", false).is_err());
        assert!(validate_vanity_chars("0", false).is_err());
        assert!(validate_vanity_chars("I", false).is_err());
        assert!(validate_vanity_chars("l", false).is_err());
    }

    /// Case-insensitive validation must also reject invalid chars.
    #[test]
    fn test_validate_chars_case_insensitive() {
        assert!(validate_vanity_chars("bob", true).is_ok());
        assert!(validate_vanity_chars("O", true).is_ok()); // O matches o in alphabet
        assert!(validate_vanity_chars("0", true).is_err()); // 0 has no match
    }
}
