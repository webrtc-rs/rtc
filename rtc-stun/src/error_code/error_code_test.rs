use super::*;

#[test]
fn test_display_valid_utf8() {
    let code = ErrorCodeAttribute {
        code: ErrorCode(401),
        reason: b"Unauthorized".to_vec(),
    };
    assert_eq!(format!("{}", code), "401: Unauthorized");
}

#[test]
fn test_display_invalid_utf8_does_not_panic() {
    let code = ErrorCodeAttribute {
        code: ErrorCode(401),
        reason: vec![0xc0, 0xaf],
    };
    let result = format!("{}", code);
    assert_eq!(result, "401: \u{FFFD}\u{FFFD}");
}
