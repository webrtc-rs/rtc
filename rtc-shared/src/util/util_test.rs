use crate::error::{Error, flatten_errs};
use crate::util::math_rand_alpha;

/// pion internal/util TestMathRandAlpha: the string has the requested length and is
/// alphabetical only.
#[test]
fn test_math_rand_alpha() {
    let got = math_rand_alpha(10);
    assert_eq!(got.len(), 10, "math_rand_alpha should return 10 characters");
    assert!(
        got.chars().all(|c| c.is_ascii_alphabetic()),
        "math_rand_alpha should be alpha only: {got}"
    );
}

/// pion internal/util TestMultiError: flattened errors join with newlines, nested flattens
/// collapse, and the message carries every contained error.
#[test]
fn test_multi_error() {
    // pion's input also carries a nil (skipped) and a nested FlattenErrs; Rust has no nil
    // errors, so the equivalent input is err1, err2 and a nested flatten of err3.
    let errs = flatten_errs(vec![
        Error::Other("err1".to_owned()),
        Error::Other("err2".to_owned()),
        flatten_errs(vec![Error::Other("err3".to_owned())]).unwrap_err(),
    ])
    .expect_err("non-empty input must be an error");
    assert_eq!(errs.to_string(), "err1\nerr2\nerr3");
}
