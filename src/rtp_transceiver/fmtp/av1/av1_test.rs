use super::*;

fn parse_av1(line: &str) -> Box<dyn Fmtp> {
    parse("video/av1", 90000, 0, line)
}

#[test]
fn test_av1_fmtp_match() {
    // pion `TestMatch`, the av1 cases: a missing profile means 0 (Main).
    let cases = [
        ("equal", "profile=1", "profile=1", true),
        ("missing profile", "", "", true),
        ("inferred profile", "", "profile=0", true),
        ("different profile", "profile=0", "profile=1", false),
        ("different inferred profile", "", "profile=1", false),
    ];
    for (name, a, b, want) in cases {
        let (a, b) = (parse_av1(a), parse_av1(b));
        assert_eq!(a.match_fmtp(&*b), want, "{name}");
        assert_eq!(b.match_fmtp(&*a), want, "{name} reversed");
    }
    assert!(!parse_av1("").match_fmtp(&*parse("video/vp9", 90000, 0, "")));
}
