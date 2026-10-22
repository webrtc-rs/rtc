use crate::{
    AeadAlgorithm, AeadCipher, BlockCipherAlgorithm, CbcAlgorithm, CbcCipher, CryptoError,
    StreamCipher, StreamCipherAlgorithm,
};
use aes::cipher::array::{Array, ArraySize};
use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, InnerIvInit, KeyInit};
use aes::{Aes128, Aes256};
use ccm::Ccm;
use ccm::aead::AeadInOut;
use ccm::consts::{U8, U12, U16};
use ctr::cipher::StreamCipher as CtrStreamCipher;
use ctr::{CtrCore, flavors};
use md5::{Digest, Md5};

const AES_BLOCK_LEN: usize = 16;
const CCM_NONCE_LEN: usize = 12;

type Aes128Ccm = Ccm<Aes128, U16, U12>;
type Aes128Ccm8 = Ccm<Aes128, U8, U12>;

// SRTP counter mode (RFC 3711 section 4.1.1) is AES-CTR with a big-endian 128-bit counter.
type Aes128Ctr<'a> = ctr::Ctr128BE<&'a Aes128>;
type Aes256Ctr<'a> = ctr::Ctr128BE<&'a Aes256>;

type Block = Array<u8, U16>;

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
                .encrypt_block(block_mut(block)?);
        }
        BlockCipherAlgorithm::Aes256 => {
            check_key_len(32, key.len())?;
            Aes256::new_from_slice(key)
                .map_err(|_| invalid_key(32, key.len()))?
                .encrypt_block(block_mut(block)?);
        }
    }
    Ok(())
}

pub(crate) fn new_stream_cipher(
    algorithm: StreamCipherAlgorithm,
    key: &[u8],
) -> Result<Box<dyn StreamCipher>, CryptoError> {
    let cipher = match algorithm {
        StreamCipherAlgorithm::Aes128Ctr => {
            check_key_len(16, key.len())?;
            AesCtr::Aes128(Aes128::new_from_slice(key).map_err(|_| invalid_key(16, key.len()))?)
        }
        StreamCipherAlgorithm::Aes256Ctr => {
            check_key_len(32, key.len())?;
            AesCtr::Aes256(Aes256::new_from_slice(key).map_err(|_| invalid_key(32, key.len()))?)
        }
    };
    Ok(Box::new(cipher))
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
            Self::Aes256(cipher) => cipher.encrypt_block(block.into()),
        }
    }

    fn decrypt(&self, block: &mut [u8; AES_BLOCK_LEN]) {
        match self {
            Self::Aes256(cipher) => cipher.decrypt_block(block.into()),
        }
    }
}

/// AES counter mode.
///
/// Delegates to the `ctr` crate rather than driving `encrypt_block` once per 16-byte block, which
/// defeats the batching that lets AES-NI / ARMv8 crypto instructions pipeline.
///
/// The key schedule is expanded once, when the cipher is built, and borrowed for every call.
/// Re-deriving it per packet (`Ctr128BE::new`) cost a full key expansion — ~180 ns for AES-128 on
/// the hardware backends, several times that on the software one — on every SRTP packet, which is
/// a visible share of a 1200-byte packet and most of a two-block RTCP packet. The expanded key is
/// zeroized on drop by the `aes` crate.
///
/// The variants differ in size, but the cipher already lives behind one `Box<dyn StreamCipher>`;
/// boxing the key again would add a pointer chase to every packet to save a few hundred bytes
/// per context.
#[allow(clippy::large_enum_variant)]
enum AesCtr {
    Aes128(Aes128),
    Aes256(Aes256),
}

impl StreamCipher for AesCtr {
    fn apply_keystream(&mut self, iv: &[u8], data: &mut [u8]) -> Result<(), CryptoError> {
        check_nonce_len(AES_BLOCK_LEN, iv.len())?;
        let nonce = block_ref(iv)?;
        match self {
            Self::Aes128(cipher) => {
                let core = CtrCore::<_, flavors::Ctr128BE>::inner_iv_init(&*cipher, nonce);
                Aes128Ctr::from_core(core).apply_keystream(data);
            }
            Self::Aes256(cipher) => {
                let core = CtrCore::<_, flavors::Ctr128BE>::inner_iv_init(&*cipher, nonce);
                Aes256Ctr::from_core(core).apply_keystream(data);
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

        // `check_blocks` has already rejected a length that is not a whole number of blocks, so the
        // remainder this returns is empty and the array chunks are the whole input.
        for block in blocks.as_chunks_mut::<AES_BLOCK_LEN>().0 {
            for (byte, prior) in block.iter_mut().zip(previous) {
                *byte ^= prior;
            }
            self.key.encrypt(block);
            previous = *block;
        }
        Ok(())
    }

    fn decrypt_blocks(&mut self, iv: &[u8], blocks: &mut [u8]) -> Result<(), CryptoError> {
        check_nonce_len(AES_BLOCK_LEN, iv.len())?;
        check_blocks(blocks)?;
        let mut previous: [u8; AES_BLOCK_LEN] = iv
            .try_into()
            .map_err(|_| invalid_nonce(AES_BLOCK_LEN, iv.len()))?;

        for block in blocks.as_chunks_mut::<AES_BLOCK_LEN>().0 {
            // The ciphertext masks the *next* block, so it has to be kept before decryption
            // overwrites it in place.
            let ciphertext = *block;
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
                    .encrypt_inout_detached(
                        array_ref(nonce, invalid_nonce)?,
                        aad,
                        plaintext_and_ciphertext.into(),
                    )
                    .map_err(|_| CryptoError::AuthenticationFailed)?;
                tag_out.copy_from_slice(&tag);
            }
            Self::Short(cipher) => {
                let tag = cipher
                    .encrypt_inout_detached(
                        array_ref(nonce, invalid_nonce)?,
                        aad,
                        plaintext_and_ciphertext.into(),
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
                .decrypt_inout_detached(
                    array_ref(nonce, invalid_nonce)?,
                    aad,
                    ciphertext_and_plaintext.into(),
                    array_ref(tag, tag_error)?,
                )
                .map_err(|_| CryptoError::AuthenticationFailed),
            Self::Short(cipher) => cipher
                .decrypt_inout_detached(
                    array_ref(nonce, invalid_nonce)?,
                    aad,
                    ciphertext_and_plaintext.into(),
                    array_ref(tag, tag_error)?,
                )
                .map_err(|_| CryptoError::AuthenticationFailed),
        }
    }
}

/// Views `bytes` as a fixed-size array, reporting a length mismatch through `err` rather than
/// panicking. Callers have normally length-checked already; this keeps the conversion total.
fn array_ref<N: ArraySize>(
    bytes: &[u8],
    err: fn(usize, usize) -> CryptoError,
) -> Result<&Array<u8, N>, CryptoError> {
    <&Array<u8, N>>::try_from(bytes).map_err(|_| err(N::USIZE, bytes.len()))
}

fn block_ref(bytes: &[u8]) -> Result<&Block, CryptoError> {
    array_ref(bytes, invalid_nonce)
}

fn block_mut(bytes: &mut [u8]) -> Result<&mut Block, CryptoError> {
    let actual = bytes.len();
    <&mut Block>::try_from(bytes).map_err(|_| CryptoError::OutputTooSmall {
        required: AES_BLOCK_LEN,
        actual,
    })
}

fn tag_error(expected: usize, actual: usize) -> CryptoError {
    CryptoError::InvalidTagLength { expected, actual }
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
