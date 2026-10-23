use super::*;

fn parse_h265(line: &str) -> Box<dyn Fmtp> {
    parse("video/h265", 90000, 0, line)
}

fn consistent(a: &dyn Fmtp, b: &dyn Fmtp) -> bool {
    let forward = a.match_fmtp(b);
    assert_eq!(forward, b.match_fmtp(a), "match must be symmetric");
    forward
}

#[test]
fn test_h265_fmtp_match() {
    // pion `TestMatch`, the h265 cases.
    let cases = [
        (
            "downgraded level",
            "level-id=186;profile-id=1;tier-flag=0;tx-mode=SRST",
            "level-id=93;profile-id=1;tier-flag=0;tx-mode=SRST",
            true,
        ),
        (
            "inferred defaults and ignored sprop parameter",
            "",
            "profile-id=1;tier-flag=0;tx-mode=srst;sprop-vps=ignored",
            true,
        ),
        ("different profile", "profile-id=1", "profile-id=2", false),
        ("different tier", "tier-flag=0", "tier-flag=1", false),
        (
            "different transmission mode",
            "tx-mode=SRST",
            "tx-mode=MRST",
            false,
        ),
    ];
    for (name, a, b, want) in cases {
        assert_eq!(consistent(&*parse_h265(a), &*parse_h265(b)), want, "{name}");
    }
    // A different kind never matches.
    assert!(!parse_h265("").match_fmtp(&*parse("video/vp9", 90000, 0, "")));
}
