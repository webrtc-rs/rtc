use super::*;
use crate::lexer::END_LINE;
use crate::util::ATTRIBUTE_KEY;

use std::io::BufReader;
use std::iter::Iterator;

const EXAMPLE_ATTR_EXTMAP1: &str = "extmap:1 http://example.com/082005/ext.htm#ttime";
const EXAMPLE_ATTR_EXTMAP2: &str =
    "extmap:2/sendrecv http://example.com/082005/ext.htm#xmeta short";
const FAILING_ATTR_EXTMAP1: &str =
    "extmap:257/sendrecv http://example.com/082005/ext.htm#xmeta short";
const FAILING_ATTR_EXTMAP2: &str = "extmap:2/blorg http://example.com/082005/ext.htm#xmeta short";

#[test]
fn test_extmap() -> Result<()> {
    let example_attr_extmap1_line = EXAMPLE_ATTR_EXTMAP1;
    let example_attr_extmap2_line = EXAMPLE_ATTR_EXTMAP2;
    let failing_attr_extmap1_line = format!("{ATTRIBUTE_KEY}{FAILING_ATTR_EXTMAP1}{END_LINE}");
    let failing_attr_extmap2_line = format!("{ATTRIBUTE_KEY}{FAILING_ATTR_EXTMAP2}{END_LINE}");
    let passingtests = [
        (EXAMPLE_ATTR_EXTMAP1, example_attr_extmap1_line),
        (EXAMPLE_ATTR_EXTMAP2, example_attr_extmap2_line),
    ];
    let failingtests = vec![
        (FAILING_ATTR_EXTMAP1, failing_attr_extmap1_line),
        (FAILING_ATTR_EXTMAP2, failing_attr_extmap2_line),
    ];

    for (i, u) in passingtests.iter().enumerate() {
        let mut reader = BufReader::new(u.1.as_bytes());
        let actual = ExtMap::unmarshal(&mut reader)?;
        assert_eq!(
            actual.marshal(),
            u.1,
            "{}: {} vs {}",
            i,
            u.1,
            actual.marshal()
        );
    }

    for u in failingtests {
        let mut reader = BufReader::new(u.1.as_bytes());
        let actual = ExtMap::unmarshal(&mut reader);
        assert!(actual.is_err());
    }

    Ok(())
}

// RFC 8285 section 4.3: two-byte-header extension IDs are valid in the range
// 1-255 inclusive. The parser previously capped IDs at 246 (and its error
// message said 1-256), wrongly rejecting valid IDs 247-255.
#[test]
fn test_extmap_id_range_rfc8285() -> Result<()> {
    // 1..=255 are valid; 247 and 255 were wrongly rejected before the fix.
    for value in [1u16, 14, 15, 246, 247, 255] {
        let line =
            format!("{ATTRIBUTE_KEY}extmap:{value} urn:ietf:params:rtp-hdrext:sdes:mid{END_LINE}");
        let mut reader = BufReader::new(line.as_bytes());
        let actual = ExtMap::unmarshal(&mut reader)
            .unwrap_or_else(|e| panic!("extmap id {value} should parse: {e:?}"));
        assert_eq!(actual.value, value);
    }

    // 0 (padding) and anything above 255 must be rejected.
    for value in [0u16, 256, 257, 4096] {
        let line =
            format!("{ATTRIBUTE_KEY}extmap:{value} urn:ietf:params:rtp-hdrext:sdes:mid{END_LINE}");
        let mut reader = BufReader::new(line.as_bytes());
        assert!(
            ExtMap::unmarshal(&mut reader).is_err(),
            "extmap id {value} must be rejected"
        );
    }

    Ok(())
}

#[test]
fn test_transport_cc_extmap() -> Result<()> {
    // a=extmap:<value>["/"<direction>] <URI> <extensionattributes>
    // a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
    let uri = Some(Url::parse(
        "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
    )?);
    let e = ExtMap {
        value: 3,
        uri,
        direction: Direction::Unspecified,
        ext_attr: None,
    };

    let s = e.marshal();
    if s == "3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01" {
        panic!("TestTransportCC failed");
    } else {
        assert_eq!(
            s,
            "extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01"
        )
    }

    Ok(())
}
