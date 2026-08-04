use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, KeyIvInit};
use aes::{Aes128, Aes256};
use ccm::Ccm;
use ccm::aead::AeadInPlace;
use ccm::consts::{U8, U12, U16};
use ctr::cipher::StreamCipher as CtrStreamCipher;
use hmac::{Hmac, Mac as RustCryptoMac};
use md5::{Digest, Md5};
use sha1::Sha1;

use crate::{
    AeadAlgorithm, AeadCipher, BlockCipherAlgorithm, CbcAlgorithm, CbcCipher, CryptoError,
    Mac as StreamMac, SecretVec, StreamCipher, StreamCipherAlgorithm,
};

const AES_BLOCK_LEN: usize = 16;
const CCM_NONCE_LEN: usize = 12;

type Aes128Ccm = Ccm<Aes128, U16, U12>;
type Aes128Ccm8 = Ccm<Aes128, U8, U12>;

// SRTP counter mode (RFC 3711 section 4.1.1) is AES-CTR with a big-endian 128-bit counter.
type Aes128Ctr = ctr::Ctr128BE<Aes128>;
type Aes256Ctr = ctr::Ctr128BE<Aes256>;

/// Fills `output` from the thread-local CSPRNG shared by the built-in providers.
///
/// This is a ChaCha-based generator seeded from the operating system and periodically reseeded,
/// not a per-call OS read. `ring::rand::SystemRandom` and `aws_lc_rs::rand::SystemRandom` reach
/// the OS on every call — measured at ~829 ns and ~2196 ns for an 8-byte fill, against ~8 ns
/// here. DTLS generates a GCM explicit nonce and a CBC record IV *per record*, so the difference
/// showed up as a 3-8x regression on DTLS encryption; see `rtc-dtls/benches/README.md`.
///
/// This restores what the pre-provider code did (`rand::rng()`), and matches how BoringSSL and
/// OpenSSL buffer internally. A deployment that requires every byte of entropy to come from a
/// validated module supplies its own [`RTCRandom`](crate::RTCRandom) implementation; that is what
/// the trait is for.
pub(crate) fn fill_random(output: &mut [u8]) -> Result<(), CryptoError> {
    rand::fill(output);
    Ok(())
}

type HmacSha1 = Hmac<Sha1>;

/// HMAC-SHA1 backed by RustCrypto, keyed once.
///
/// `ring` exposes SHA-1 only as `HMAC_SHA1_FOR_LEGACY_USE_ONLY` and does not use the ARMv8 SHA-1
/// instructions, measuring 4469 ns against RustCrypto's 1373 ns over a 1212-byte SRTP packet —
/// 3.3x, and the whole of the SRTP AES-CM/HMAC regression. The built-in providers are already
/// composite (AES-CTR, CCM, CBC and MD5 come from RustCrypto too), so HMAC-SHA1 is composed the
/// same way rather than making the slower backend the default. `aws-lc-rs` has fast SHA-1 and
/// keeps its own.
pub(crate) struct RustCryptoHmacSha1 {
    keyed: HmacSha1,
}

impl RustCryptoHmacSha1 {
    pub(crate) fn new(key: &[u8]) -> Self {
        Self {
            // HMAC accepts any key length: it hashes longer keys and zero-pads shorter ones.
            keyed: <HmacSha1 as RustCryptoMac>::new_from_slice(key)
                .expect("HMAC accepts keys of any length"),
        }
    }
}

impl StreamMac for RustCryptoHmacSha1 {
    fn output_len(&self) -> usize {
        20
    }

    fn sign(&mut self, input: &[&[u8]], output: &mut [u8]) -> Result<(), CryptoError> {
        check_tag_len(20, output.len())?;
        let mut mac = self.keyed.clone();
        for part in input {
            mac.update(part);
        }
        output.copy_from_slice(&mac.finalize().into_bytes());
        Ok(())
    }

    fn verify(&mut self, input: &[&[u8]], expected: &[u8]) -> Result<(), CryptoError> {
        check_tag_len(20, expected.len())?;
        let mut actual = [0u8; 20];
        self.sign(input, &mut actual)?;
        if crate::constant_time_eq(&actual, expected) {
            Ok(())
        } else {
            Err(CryptoError::AuthenticationFailed)
        }
    }
}

pub(crate) fn md5(data: &[u8]) -> Vec<u8> {
    Md5::digest(data).to_vec()
}

pub(crate) fn block_encrypt(
    algorithm: BlockCipherAlgorithm,
    key: &[u8],
    block: &mut [u8],
) -> Result<(), CryptoError> {
    check_len(AES_BLOCK_LEN, block.len(), LengthKind::Output)?;
    match algorithm {
        BlockCipherAlgorithm::Aes128 => {
            check_key_len(16, key.len())?;
            Aes128::new_from_slice(key)
                .map_err(|_| invalid_key(16, key.len()))?
                .encrypt_block(GenericArray::from_mut_slice(block));
        }
        BlockCipherAlgorithm::Aes256 => {
            check_key_len(32, key.len())?;
            Aes256::new_from_slice(key)
                .map_err(|_| invalid_key(32, key.len()))?
                .encrypt_block(GenericArray::from_mut_slice(block));
        }
    }
    Ok(())
}

pub(crate) fn new_stream_cipher(
    algorithm: StreamCipherAlgorithm,
    key: &[u8],
) -> Result<Box<dyn StreamCipher>, CryptoError> {
    let bits = match algorithm {
        StreamCipherAlgorithm::Aes128Ctr => {
            check_key_len(16, key.len())?;
            AesKeyBits::Aes128
        }
        StreamCipherAlgorithm::Aes256Ctr => {
            check_key_len(32, key.len())?;
            AesKeyBits::Aes256
        }
    };
    Ok(Box::new(AesCtr {
        key: SecretVec::new(key.to_vec()),
        bits,
    }))
}

pub(crate) fn new_cbc(
    algorithm: CbcAlgorithm,
    key: &[u8],
) -> Result<Box<dyn CbcCipher>, CryptoError> {
    match algorithm {
        CbcAlgorithm::Aes256Cbc => Ok(Box::new(AesCbc {
            key: ExpandedAesKey::new_256(key)?,
        })),
    }
}

pub(crate) fn new_ccm(
    algorithm: AeadAlgorithm,
    key: &[u8],
) -> Result<Box<dyn AeadCipher>, CryptoError> {
    check_key_len(16, key.len())?;
    let cipher = match algorithm {
        AeadAlgorithm::Aes128Ccm => {
            CommonCcm::Full(Aes128Ccm::new_from_slice(key).map_err(|_| invalid_key(16, key.len()))?)
        }
        AeadAlgorithm::Aes128Ccm8 => CommonCcm::Short(
            Aes128Ccm8::new_from_slice(key).map_err(|_| invalid_key(16, key.len()))?,
        ),
        _ => {
            return Err(CryptoError::UnsupportedAlgorithm(
                crate::CryptoAlgorithm::Aead(algorithm),
            ));
        }
    };
    Ok(Box::new(cipher))
}

// Stores an expanded key inside an already boxed cipher object, avoiding another allocation in
// every constructed state object. Only AES-256 is needed: `CbcAlgorithm` has a single variant,
// and CTR now goes through the `ctr` crate.
#[allow(clippy::large_enum_variant)]
enum ExpandedAesKey {
    Aes256(Aes256),
}

impl ExpandedAesKey {
    fn new_256(key: &[u8]) -> Result<Self, CryptoError> {
        check_key_len(32, key.len())?;
        Ok(Self::Aes256(
            Aes256::new_from_slice(key).map_err(|_| invalid_key(32, key.len()))?,
        ))
    }

    fn encrypt(&self, block: &mut [u8; AES_BLOCK_LEN]) {
        match self {
            Self::Aes256(cipher) => cipher.encrypt_block(GenericArray::from_mut_slice(block)),
        }
    }

    fn decrypt(&self, block: &mut [u8; AES_BLOCK_LEN]) {
        match self {
            Self::Aes256(cipher) => cipher.decrypt_block(GenericArray::from_mut_slice(block)),
        }
    }
}

/// AES counter mode.
///
/// Delegates to the `ctr` crate rather than driving `encrypt_block` once per 16-byte block, which
/// defeats the batching that lets AES-NI / ARMv8 crypto instructions pipeline. Measured ~9-10%
/// faster on a 1200-byte SRTP payload and ~8-10% slower on a two-block RTCP packet, where the
/// per-call setup dominates; RTP traffic dominates in practice. See
/// `rtc-srtp/benches/README.md`.
///
/// The key is retained rather than pre-expanded because `ctr::Ctr128BE` owns its own cipher
/// state and is constructed per call. It is held in a [`SecretVec`] so it is zeroized on drop.
struct AesCtr {
    key: SecretVec,
    bits: AesKeyBits,
}

#[derive(Clone, Copy)]
enum AesKeyBits {
    Aes128,
    Aes256,
}

impl StreamCipher for AesCtr {
    fn apply_keystream(&mut self, iv: &[u8], data: &mut [u8]) -> Result<(), CryptoError> {
        check_nonce_len(AES_BLOCK_LEN, iv.len())?;
        let nonce = GenericArray::from_slice(iv);
        let key = self.key.as_ref();
        match self.bits {
            AesKeyBits::Aes128 => {
                let mut stream = Aes128Ctr::new(GenericArray::from_slice(key), nonce);
                stream.apply_keystream(data);
            }
            AesKeyBits::Aes256 => {
                let mut stream = Aes256Ctr::new(GenericArray::from_slice(key), nonce);
                stream.apply_keystream(data);
            }
        }
        Ok(())
    }
}

struct AesCbc {
    key: ExpandedAesKey,
}

impl CbcCipher for AesCbc {
    fn block_len(&self) -> usize {
        AES_BLOCK_LEN
    }

    fn encrypt_blocks(&mut self, iv: &[u8], blocks: &mut [u8]) -> Result<(), CryptoError> {
        check_nonce_len(AES_BLOCK_LEN, iv.len())?;
        check_blocks(blocks)?;
        let mut previous: [u8; AES_BLOCK_LEN] = iv
            .try_into()
            .map_err(|_| invalid_nonce(AES_BLOCK_LEN, iv.len()))?;

        for chunk in blocks.chunks_exact_mut(AES_BLOCK_LEN) {
            for (byte, prior) in chunk.iter_mut().zip(previous) {
                *byte ^= prior;
            }
            let block: &mut [u8; AES_BLOCK_LEN] = chunk.try_into().expect("exact AES block");
            self.key.encrypt(block);
            previous.copy_from_slice(block);
        }
        Ok(())
    }

    fn decrypt_blocks(&mut self, iv: &[u8], blocks: &mut [u8]) -> Result<(), CryptoError> {
        check_nonce_len(AES_BLOCK_LEN, iv.len())?;
        check_blocks(blocks)?;
        let mut previous: [u8; AES_BLOCK_LEN] = iv
            .try_into()
            .map_err(|_| invalid_nonce(AES_BLOCK_LEN, iv.len()))?;

        for chunk in blocks.chunks_exact_mut(AES_BLOCK_LEN) {
            let ciphertext: [u8; AES_BLOCK_LEN] = chunk.try_into().expect("exact AES block");
            let block: &mut [u8; AES_BLOCK_LEN] = chunk.try_into().expect("exact AES block");
            self.key.decrypt(block);
            for (byte, prior) in block.iter_mut().zip(previous) {
                *byte ^= prior;
            }
            previous = ciphertext;
        }
        Ok(())
    }
}

enum CommonCcm {
    Full(Aes128Ccm),
    Short(Aes128Ccm8),
}

impl AeadCipher for CommonCcm {
    fn tag_len(&self) -> usize {
        match self {
            Self::Full(_) => 16,
            Self::Short(_) => 8,
        }
    }

    fn seal_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        plaintext_and_ciphertext: &mut [u8],
        tag_out: &mut [u8],
    ) -> Result<(), CryptoError> {
        check_nonce_len(CCM_NONCE_LEN, nonce.len())?;
        check_tag_len(self.tag_len(), tag_out.len())?;
        match self {
            Self::Full(cipher) => {
                let tag = cipher
                    .encrypt_in_place_detached(
                        GenericArray::from_slice(nonce),
                        aad,
                        plaintext_and_ciphertext,
                    )
                    .map_err(|_| CryptoError::AuthenticationFailed)?;
                tag_out.copy_from_slice(&tag);
            }
            Self::Short(cipher) => {
                let tag = cipher
                    .encrypt_in_place_detached(
                        GenericArray::from_slice(nonce),
                        aad,
                        plaintext_and_ciphertext,
                    )
                    .map_err(|_| CryptoError::AuthenticationFailed)?;
                tag_out.copy_from_slice(&tag);
            }
        }
        Ok(())
    }

    fn open_in_place(
        &mut self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_plaintext: &mut [u8],
        tag: &[u8],
    ) -> Result<(), CryptoError> {
        check_nonce_len(CCM_NONCE_LEN, nonce.len())?;
        check_tag_len(self.tag_len(), tag.len())?;
        match self {
            Self::Full(cipher) => cipher
                .decrypt_in_place_detached(
                    GenericArray::from_slice(nonce),
                    aad,
                    ciphertext_and_plaintext,
                    GenericArray::from_slice(tag),
                )
                .map_err(|_| CryptoError::AuthenticationFailed),
            Self::Short(cipher) => cipher
                .decrypt_in_place_detached(
                    GenericArray::from_slice(nonce),
                    aad,
                    ciphertext_and_plaintext,
                    GenericArray::from_slice(tag),
                )
                .map_err(|_| CryptoError::AuthenticationFailed),
        }
    }
}

fn check_blocks(blocks: &[u8]) -> Result<(), CryptoError> {
    if blocks.is_empty() || !blocks.len().is_multiple_of(AES_BLOCK_LEN) {
        return Err(CryptoError::OutputTooSmall {
            required: blocks
                .len()
                .next_multiple_of(AES_BLOCK_LEN)
                .max(AES_BLOCK_LEN),
            actual: blocks.len(),
        });
    }
    Ok(())
}

enum LengthKind {
    Output,
}

fn check_len(expected: usize, actual: usize, kind: LengthKind) -> Result<(), CryptoError> {
    if expected == actual {
        return Ok(());
    }
    match kind {
        LengthKind::Output => Err(CryptoError::OutputTooSmall {
            required: expected,
            actual,
        }),
    }
}

pub(crate) fn check_key_len(expected: usize, actual: usize) -> Result<(), CryptoError> {
    if expected == actual {
        Ok(())
    } else {
        Err(invalid_key(expected, actual))
    }
}

pub(crate) fn check_nonce_len(expected: usize, actual: usize) -> Result<(), CryptoError> {
    if expected == actual {
        Ok(())
    } else {
        Err(invalid_nonce(expected, actual))
    }
}

pub(crate) fn check_tag_len(expected: usize, actual: usize) -> Result<(), CryptoError> {
    if expected == actual {
        Ok(())
    } else {
        Err(CryptoError::InvalidTagLength { expected, actual })
    }
}

fn invalid_key(expected: usize, actual: usize) -> CryptoError {
    CryptoError::InvalidKeyLength { expected, actual }
}

fn invalid_nonce(expected: usize, actual: usize) -> CryptoError {
    CryptoError::InvalidNonceLength { expected, actual }
}
