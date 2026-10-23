use super::*;

fn parse_vp9(line: &str) -> Box<dyn Fmtp> {
    parse("video/vp9", 90000, 0, line)
}

#[test]
fn test_vp9_fmtp_match() {
    // pion `TestMatch`, the vp9 cases: a missing profile-id means profile 0.
    let cases = [
        ("equal", "profile-id=2", "profile-id=2", true),
        ("missing profile", "", "", true),
        ("inferred profile", "", "profile-id=0", true),
        ("different profile", "profile-id=0", "profile-id=2", false),
        ("different inferred profile", "", "profile-id=2", false),
    ];
    for (name, a, b, want) in cases {
        let (a, b) = (parse_vp9(a), parse_vp9(b));
        assert_eq!(a.match_fmtp(&*b), want, "{name}");
        assert_eq!(b.match_fmtp(&*a), want, "{name} reversed");
    }
    assert!(!parse_vp9("").match_fmtp(&*parse("video/av1", 90000, 0, "")));
}
