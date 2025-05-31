pub(crate) fn explode(s: &str, delim: char) -> Vec<String> {
    s.split(delim).map(&str::to_string).collect()
}

pub(crate) fn implode(tokens: &[String], delim: char) -> String {
    tokens.join(&delim.to_string())
}

// Decode URL percent-encoding (RFC 3986)
// See https://www.rfc-editor.org/rfc/rfc3986.html#section-2.1
pub(crate) fn url_decode(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let hi = chars.next();
            let lo = chars.next();
            match (hi, lo) {
                (Some(h), Some(l)) if h.is_ascii_hexdigit() && l.is_ascii_hexdigit() => {
                    let hex = format!("{}{}", h, l);
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        result.push(byte as char);
                    } else {
                        eprintln!("Invalid percent-encoded character in URL: \"%{}\"", hex);
                        result.push('%');
                        result.push(h);
                        result.push(l);
                    }
                }
                _ => {
                    eprintln!("Invalid percent-encoded sequence in URL");
                    result.push('%');
                    if let Some(h) = hi {
                        result.push(h);
                    }
                    if let Some(l) = lo {
                        result.push(l);
                    }
                }
            }
        } else {
            result.push(c);
        }
    }

    result
}

// Encode as base64 (RFC 4648)
// See https://www.rfc-editor.org/rfc/rfc4648.html#section-4
pub(crate) fn base64_encode(data: &[u8]) -> String {
    const TAB: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut out = String::with_capacity(4 * data.len().div_ceil(3));
    let mut i = 0;

    while i + 3 <= data.len() {
        let d0 = data[i];
        let d1 = data[i + 1];
        let d2 = data[i + 2];

        out.push(TAB[(d0 >> 2) as usize] as char);
        out.push(TAB[((d0 & 0x03) << 4 | (d1 >> 4)) as usize] as char);
        out.push(TAB[((d1 & 0x0F) << 2 | (d2 >> 6)) as usize] as char);
        out.push(TAB[(d2 & 0x3F) as usize] as char);
        i += 3;
    }

    let rem = data.len() - i;
    if rem == 1 {
        let d0 = data[i];
        out.push(TAB[(d0 >> 2) as usize] as char);
        out.push(TAB[((d0 & 0x03) << 4) as usize] as char);
        out.push('=');
        out.push('=');
    } else if rem == 2 {
        let d0 = data[i];
        let d1 = data[i + 1];
        out.push(TAB[(d0 >> 2) as usize] as char);
        out.push(TAB[((d0 & 0x03) << 4 | (d1 >> 4)) as usize] as char);
        out.push(TAB[((d1 & 0x0F) << 2) as usize] as char);
        out.push('=');
    }

    out
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_explode_implode() {
        let text = "a,b,c";
        let delimiter = ',';

        let parts = explode(text, delimiter);
        assert_eq!(vec!("a", "b", "c"), parts);

        let joined = implode(&parts, delimiter);
        assert_eq!("a,b,c", joined);
    }

    #[test]
    fn test_url_decode_basic() {
        assert_eq!(url_decode("hello%20world"), "hello world");
        assert_eq!(url_decode("test%21value"), "test!value");
    }

    #[test]
    fn test_url_decode_invalid() {
        assert_eq!(url_decode("invalid%zztext"), "invalid%zztext"); // should leave it as-is
        assert_eq!(url_decode("incomplete%2"), "incomplete%2"); // incomplete percent
    }

    #[test]
    fn test_base64_encode_exact() {
        assert_eq!(base64_encode(b"Man"), "TWFu");
        assert_eq!(
            base64_encode(b"any carnal pleasure."),
            "YW55IGNhcm5hbCBwbGVhc3VyZS4="
        );
    }

    #[test]
    fn test_base64_encode_padding() {
        assert_eq!(base64_encode(b"Ma"), "TWE=");
        assert_eq!(base64_encode(b"M"), "TQ==");
    }

    #[test]
    fn test_base64_encode_empty() {
        assert_eq!(base64_encode(b""), "");
    }
}
