// ============================================================================
//  Display Helpers & Formatting Utilities
// ============================================================================

const BOX_WIDTH: usize = 84;

pub fn line(label: &str, value: &str) {
    let content = format!("  {}{}", format!("{:<18}", label), value);
    let pad = BOX_WIDTH.saturating_sub(content.len());
    println!("\u{2551}{}{}\u{2551}", content, " ".repeat(pad));
}

pub fn empty() {
    println!("\u{2551}{}\u{2551}", " ".repeat(BOX_WIDTH));
}

pub fn rule() {
    println!("\u{2560}{}\u{2563}", "\u{2550}".repeat(BOX_WIDTH));
}

pub fn top() {
    println!("\u{2554}{}\u{2557}", "\u{2550}".repeat(BOX_WIDTH));
}

pub fn bottom() {
    println!("\u{255A}{}\u{255D}", "\u{2550}".repeat(BOX_WIDTH));
}

pub fn title(text: &str) {
    let pad = BOX_WIDTH.saturating_sub(text.len() + 2);
    println!("\u{2551}  {}{}\u{2551}", text, " ".repeat(pad));
}

// ============================================================================
//  Formatting Utilities
// ============================================================================

pub fn estimate_attempts(pattern_len: usize) -> u64 {
    58u64.saturating_pow(pattern_len as u32)
}

pub fn format_duration(seconds: f64) -> String {
    if seconds < 1.0 {
        format!("{:.0}ms", seconds * 1000.0)
    } else if seconds < 60.0 {
        format!("{:.1}s", seconds)
    } else if seconds < 3600.0 {
        format!("{:.1} min", seconds / 60.0)
    } else if seconds < 86400.0 {
        format!("{:.1} hrs", seconds / 3600.0)
    } else {
        format!("{:.1} days", seconds / 86400.0)
    }
}

pub fn format_large_number(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.2}B", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.2}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        format!("{}", n)
    }
}

// ============================================================================
//  Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_estimate_attempts() {
        assert_eq!(estimate_attempts(1), 58);
        assert_eq!(estimate_attempts(2), 3364);
        assert_eq!(estimate_attempts(3), 195112);
    }

    #[test]
    fn test_format_large_number() {
        assert_eq!(format_large_number(500), "500");
        assert_eq!(format_large_number(1_500), "1.5K");
        assert_eq!(format_large_number(2_500_000), "2.50M");
        assert_eq!(format_large_number(3_000_000_000), "3.00B");
    }
}
