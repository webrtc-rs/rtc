#[cfg(test)]
mod handshake_cache_test;

use crate::cipher_suite::*;
use crate::handshake::*;

use std::collections::HashMap;

#[derive(Clone, Debug)]
pub(crate) struct HandshakeCacheItem {
    typ: HandshakeType,
    is_client: bool,
    epoch: u16,
    message_sequence: u16,
    data: Vec<u8>,
}

#[derive(Copy, Clone, Debug)]
pub(crate) struct HandshakeCachePullRule {
    pub(crate) typ: HandshakeType,
    pub(crate) epoch: u16,
    pub(crate) is_client: bool,
    pub(crate) optional: bool,
}

#[derive(Clone)]
pub(crate) struct HandshakeCache {
    cache: Vec<HandshakeCacheItem>,
}

impl HandshakeCache {
    pub(crate) fn new() -> Self {
        HandshakeCache { cache: vec![] }
    }

    pub(crate) fn push(
        &mut self,
        data: Vec<u8>,
        epoch: u16,
        message_sequence: u16,
        typ: HandshakeType,
        is_client: bool,
    ) -> bool {
        for i in &self.cache {
            if i.message_sequence == message_sequence && i.is_client == is_client {
                return false;
            }
        }

        self.cache.push(HandshakeCacheItem {
            typ,
            is_client,
            epoch,
            message_sequence,
            data,
        });

        true
    }

    // returns the cached message a rule selects: the latest (highest message_sequence) entry of
    // the rule's type, epoch and sender, or `None` when no entry matches
    fn find(&self, r: &HandshakeCachePullRule) -> Option<&HandshakeCacheItem> {
        let mut item: Option<&HandshakeCacheItem> = None;
        for c in &self.cache {
            if c.typ == r.typ && c.is_client == r.is_client && c.epoch == r.epoch {
                match item {
                    Some(x) if x.message_sequence >= c.message_sequence => {}
                    _ => item = Some(c),
                }
            }
        }
        item
    }

    // returns a list handshakes that match the requested rules
    // rules that can't be satisfied are skipped
    // multiple entries may match a rule, but only the last match is returned (ie ClientHello with cookies)
    pub(crate) fn pull(&self, rules: &[HandshakeCachePullRule]) -> Vec<&HandshakeCacheItem> {
        rules.iter().filter_map(|r| self.find(r)).collect()
    }

    // full_pull_map pulls all handshakes between rules[0] to rules[len(rules)-1] as map.
    pub(crate) fn full_pull_map(
        &self,
        start_seq: isize,
        rules: &[HandshakeCachePullRule],
    ) -> Result<(isize, HashMap<HandshakeType, HandshakeMessage>)> {
        let mut ci = HashMap::new();
        for r in rules {
            let item = self.find(r);
            if !r.optional && item.is_none() {
                // Missing mandatory message.
                return Err(Error::Other("Missing mandatory message".to_owned()));
            }

            if let Some(c) = item {
                ci.insert(r.typ, c);
            }
        }

        let mut out = HashMap::new();
        let mut seq = start_seq;
        for r in rules {
            let t = r.typ;
            if let Some(i) = ci.get(&t) {
                // The cached bytes are already in memory: parse them straight from the slice.
                let raw_handshake = Handshake::unmarshal(&mut i.data.as_slice())?;
                if seq as u16 != raw_handshake.handshake_header.message_sequence {
                    // There is a gap. Some messages are not arrived.
                    return Err(Error::Other(
                        "There is a gap. Some messages are not arrived.".to_owned(),
                    ));
                }
                seq += 1;
                out.insert(t, raw_handshake.handshake_message);
            }
        }

        Ok((seq, out))
    }

    // pull_and_merge calls pull and then merges the results, ignoring any null entries
    pub(crate) fn pull_and_merge(&self, rules: &[HandshakeCachePullRule]) -> Vec<u8> {
        merge(&self.pull(rules), &[])
    }

    // session_hash returns the session hash for Extended Master Secret support
    // https://tools.ietf.org/html/draft-ietf-tls-session-hash-06#section-4
    pub(crate) fn session_hash(
        &self,
        crypto: &dyn crypto::RTCCrypto,
        hf: CipherSuiteHash,
        epoch: u16,
        additional: &[u8],
    ) -> Result<Vec<u8>> {
        // Order defined by https://tools.ietf.org/html/rfc5246#section-7.3
        let handshake_buffer = self.pull(&[
            HandshakeCachePullRule {
                typ: HandshakeType::ClientHello,
                epoch,
                is_client: true,
                optional: false,
            },
            HandshakeCachePullRule {
                typ: HandshakeType::ServerHello,
                epoch,
                is_client: false,
                optional: false,
            },
            HandshakeCachePullRule {
                typ: HandshakeType::Certificate,
                epoch,
                is_client: false,
                optional: false,
            },
            HandshakeCachePullRule {
                typ: HandshakeType::ServerKeyExchange,
                epoch,
                is_client: false,
                optional: false,
            },
            HandshakeCachePullRule {
                typ: HandshakeType::CertificateRequest,
                epoch,
                is_client: false,
                optional: false,
            },
            HandshakeCachePullRule {
                typ: HandshakeType::ServerHelloDone,
                epoch,
                is_client: false,
                optional: false,
            },
            HandshakeCachePullRule {
                typ: HandshakeType::Certificate,
                epoch,
                is_client: true,
                optional: false,
            },
            HandshakeCachePullRule {
                typ: HandshakeType::ClientKeyExchange,
                epoch,
                is_client: true,
                optional: false,
            },
        ]);

        let merged = merge(&handshake_buffer, additional);

        match hf {
            CipherSuiteHash::Sha256 => crypto
                .hash(crypto::HashAlgorithm::Sha256, &merged)
                .map_err(|error| Error::Crypto(error.to_string())),
        }
    }
}

// concatenates the selected messages, then `additional`, into one buffer sized up front
fn merge(items: &[&HandshakeCacheItem], additional: &[u8]) -> Vec<u8> {
    let len = items.iter().map(|i| i.data.len()).sum::<usize>() + additional.len();
    let mut merged = Vec::with_capacity(len);
    for i in items {
        merged.extend_from_slice(&i.data);
    }
    merged.extend_from_slice(additional);
    merged
}
