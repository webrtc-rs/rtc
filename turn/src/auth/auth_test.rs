use super::*;

#[test]
fn test_lt_cred() -> Result<()> {
    let username = "1599491771";
    let shared_secret = "foobar";

    let expected_password = "Tpz/nKkyvX/vMSLKvL4sbtBt8Vs=";
    let actual_password = long_term_credentials(username, shared_secret);
    assert_eq!(
        expected_password, actual_password,
        "Expected {expected_password}, got {actual_password}"
    );

    Ok(())
}

#[test]
fn test_generate_auth_key() -> Result<()> {
    let username = "60";
    let password = "HWbnm25GwSj6jiHTEDMTO5D7aBw=";
    let realm = "webrtc.rs";

    let expected_key = vec![
        56, 22, 47, 139, 198, 127, 13, 188, 171, 80, 23, 29, 195, 148, 216, 224,
    ];
    let actual_key = generate_auth_key(username, realm, password);
    assert_eq!(
        expected_key, actual_key,
        "Expected {expected_key:?}, got {actual_key:?}"
    );

    Ok(())
}
