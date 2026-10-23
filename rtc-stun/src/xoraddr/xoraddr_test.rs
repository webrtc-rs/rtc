use super::*;
use crate::checks::*;
use base64::prelude::*;

use std::io::BufReader;

#[test]
fn test_xor_safe() -> Result<()> {
    let mut dst = vec![0; 8];
    let a = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let b = vec![8, 7, 7, 6, 6, 3, 4, 1];
    safe_xor_bytes(&mut dst, &a, &b);
    let c = dst.clone();
    safe_xor_bytes(&mut dst, &c, &a);
    for i in 0..dst.len() {
        assert_eq!(b[i], dst[i], "{} != {}", b[i], dst[i]);
    }

    Ok(())
}

#[test]
fn test_xor_safe_bsmaller() -> Result<()> {
    let mut dst = vec![0; 5];
    let a = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let b = vec![8, 7, 7, 6, 6];
    safe_xor_bytes(&mut dst, &a, &b);
    let c = dst.clone();
    safe_xor_bytes(&mut dst, &c, &a);
    for i in 0..dst.len() {
        assert_eq!(b[i], dst[i], "{} != {}", b[i], dst[i]);
    }

    Ok(())
}

#[test]
fn test_xormapped_address_get_from() -> Result<()> {
    let mut m = Message::new();
    let transaction_id = BASE64_STANDARD.decode("jxhBARZwX+rsC6er").unwrap();
    m.transaction_id.0.copy_from_slice(&transaction_id);
    let addr_value = vec![0x00, 0x01, 0x9c, 0xd5, 0xf4, 0x9f, 0x38, 0xae];
    m.add(ATTR_XORMAPPED_ADDRESS, &addr_value);
    let mut addr = XorMappedAddress {
        ip: "0.0.0.0".parse().unwrap(),
        port: 0,
    };
    addr.get_from(&m)?;
    assert_eq!(
        addr.ip.to_string(),
        "213.141.156.236",
        "bad IP {} != 213.141.156.236",
        addr.ip
    );
    assert_eq!(addr.port, 48583, "bad Port {} != 48583", addr.port);

    //"UnexpectedEOF"
    {
        let mut m = Message::new();
        // {0, 1} is correct addr family.
        m.add(ATTR_XORMAPPED_ADDRESS, &[0, 1, 3, 4]);
        let mut addr = XorMappedAddress {
            ip: "0.0.0.0".parse().unwrap(),
            port: 0,
        };
        let result = addr.get_from(&m);
        if let Err(err) = result {
            assert_eq!(
                Error::ErrUnexpectedEof,
                err,
                "len(v) = 4 should render <{}> error, got <{}>",
                Error::ErrUnexpectedEof,
                err
            );
        } else {
            panic!("expected error, got ok");
        }
    }
    //"AttrOverflowErr"
    {
        let mut m = Message::new();
        // {0, 1} is correct addr family.
        m.add(
            ATTR_XORMAPPED_ADDRESS,
            &[0, 1, 3, 4, 5, 6, 7, 8, 9, 1, 1, 1, 1, 1, 2, 3, 4],
        );
        let mut addr = XorMappedAddress {
            ip: "0.0.0.0".parse().unwrap(),
            port: 0,
        };
        let result = addr.get_from(&m);
        if let Err(err) = result {
            assert!(
                is_attr_size_overflow(&err),
                "AddTo should return AttrOverflowErr, got: {err}"
            );
        } else {
            panic!("expected error, got ok");
        }
    }

    Ok(())
}

#[test]
fn test_xormapped_address_get_from_invalid() -> Result<()> {
    let mut m = Message::new();
    let transaction_id = BASE64_STANDARD.decode("jxhBARZwX+rsC6er").unwrap();
    m.transaction_id.0.copy_from_slice(&transaction_id);
    let expected_ip: IpAddr = "213.141.156.236".parse().unwrap();
    let expected_port = 21254u16;
    let mut addr = XorMappedAddress {
        ip: "0.0.0.0".parse().unwrap(),
        port: 0,
    };
    let result = addr.get_from(&m);
    assert!(result.is_err(), "should be error");

    addr.ip = expected_ip;
    addr.port = expected_port;
    addr.add_to(&mut m)?;
    m.write_header();

    let mut m_res = Message::new();
    m.raw[20 + 4 + 1] = 0x21;
    m.decode()?;
    let mut reader = BufReader::new(m.raw.as_slice());
    m_res.read_from(&mut reader)?;
    let result = addr.get_from(&m);
    assert!(result.is_err(), "should be error");

    Ok(())
}

#[test]
fn test_xormapped_address_add_to() -> Result<()> {
    let mut m = Message::new();
    let transaction_id = BASE64_STANDARD.decode("jxhBARZwX+rsC6er").unwrap();
    m.transaction_id.0.copy_from_slice(&transaction_id);
    let expected_ip: IpAddr = "213.141.156.236".parse().unwrap();
    let expected_port = 21254u16;
    let mut addr = XorMappedAddress {
        ip: "213.141.156.236".parse().unwrap(),
        port: expected_port,
    };
    addr.add_to(&mut m)?;
    m.write_header();

    let mut m_res = Message::new();
    m_res.write(&m.raw)?;
    addr.get_from(&m_res)?;
    assert_eq!(
        addr.ip, expected_ip,
        "{} (got) != {} (expected)",
        addr.ip, expected_ip
    );

    assert_eq!(
        addr.port, expected_port,
        "bad Port {} != {}",
        addr.port, expected_port
    );

    Ok(())
}

#[test]
fn test_xormapped_address_add_to_ipv6() -> Result<()> {
    let mut m = Message::new();
    let transaction_id = BASE64_STANDARD.decode("jxhBARZwX+rsC6er").unwrap();
    m.transaction_id.0.copy_from_slice(&transaction_id);
    let expected_ip: IpAddr = "fe80::dc2b:44ff:fe20:6009".parse().unwrap();
    let expected_port = 21254u16;
    let addr = XorMappedAddress {
        ip: "fe80::dc2b:44ff:fe20:6009".parse().unwrap(),
        port: 21254,
    };
    addr.add_to(&mut m)?;
    m.write_header();

    let mut m_res = Message::new();
    let mut reader = BufReader::new(m.raw.as_slice());
    m_res.read_from(&mut reader)?;

    let mut got_addr = XorMappedAddress {
        ip: "0.0.0.0".parse().unwrap(),
        port: 0,
    };
    got_addr.get_from(&m)?;

    assert_eq!(
        got_addr.ip, expected_ip,
        "bad IP {} != {}",
        got_addr.ip, expected_ip
    );
    assert_eq!(
        got_addr.port, expected_port,
        "bad Port {} != {}",
        got_addr.port, expected_port
    );

    Ok(())
}

/*
#[test]
fn TestXORMappedAddress_AddTo_Invalid() -> Result<()> {
    let mut m = Message::new();
    let mut addr = XORMappedAddress{
        ip:   1, 2, 3, 4, 5, 6, 7, 8},
        port: 21254,
    }
    if err := addr.AddTo(m); !errors.Is(err, ErrBadIPLength) {
        t.Errorf("AddTo should return %q, got: %v", ErrBadIPLength, err)
    }
}*/

#[test]
fn test_xormapped_address_string() -> Result<()> {
    let tests = vec![
        (
            // 0
            XorMappedAddress {
                ip: "fe80::dc2b:44ff:fe20:6009".parse().unwrap(),
                port: 124,
            },
            "[fe80::dc2b:44ff:fe20:6009]:124",
        ),
        (
            // 1
            XorMappedAddress {
                ip: "213.141.156.236".parse().unwrap(),
                port: 8147,
            },
            "213.141.156.236:8147",
        ),
    ];

    for (addr, ip) in tests {
        assert_eq!(
            addr.to_string(),
            ip,
            " XORMappesAddres.String() {addr} (got) != {ip} (expected)",
        );
    }

    Ok(())
}

/// pion/transport v5.1.1 utils/xor TestXOR: `xor_bytes` must equal an independent XOR for
/// every length (short-mode sizes), every input/output alignment, without touching the
/// guard byte past the destination. pion fills the inputs from crypto/rand; a fixed
/// deterministic stream exercises the same assertions offline.
#[test]
fn test_xor_matches_pion_xor() {
    // xorshift64*: deterministic stand-in for pion's crypto/rand fills.
    let mut state = 0x2545F4914F6CDD1Du64;
    let mut next_byte = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state >> 32) as u8
    };

    for j in 1..=16usize {
        for align_p in 0..2usize {
            for align_q in 0..2usize {
                for align_d in 0..2usize {
                    let mut buf_p = vec![0u8; j + align_p];
                    let mut buf_q = vec![0u8; j + align_q];
                    let mut buf_d = vec![0u8; j + align_d + 1];
                    for b in buf_p.iter_mut() {
                        *b = next_byte();
                    }
                    for b in buf_q.iter_mut() {
                        *b = next_byte();
                    }
                    buf_d[j + align_d] = 42; // guard byte: must not be overwritten

                    let p = &buf_p[align_p..];
                    let q = &buf_q[align_q..];
                    let d1 = &mut buf_d[align_d..j + align_d];

                    xor_bytes(d1, p, q);

                    let n = p.len().min(q.len());
                    let mut d2 = vec![0u8; n];
                    for i in 0..n {
                        d2[i] = p[i] ^ q[i];
                    }
                    assert_eq!(&d1[..n], &d2[..], "p: {p:?}, q: {q:?}");
                    assert_eq!(buf_d[j + align_d], 42, "guard overwritten");
                }
            }
        }
    }
}
