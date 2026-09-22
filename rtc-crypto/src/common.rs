use crate::{
    AeadAlgorithm, AeadCipher, BlockCipherAlgorithm, CbcAlgorithm, CbcCipher, CryptoError,
    SecretVec, StreamCipher, StreamCipherAlgorithm,
};
use aes::cipher::{
    Array, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit, KeyIvInit, StreamCipher as _,
};
use aes::{Aes128, Aes256};
use ccm::Ccm;
use ccm::aead::AeadInOut;
use ccm::consts::{U8, U12, U16};
use md5::{Digest, Md5};

const AES_BLOCK_LEN: usize = 16;
const CCM_NONCE_LEN: usize = 12;

/// Blocks decrypted per call into the AES backend by [`AesCbc::decrypt_blocks`]. The ARMv8 and
/// AES-NI backends pipeline 8 blocks at a time and VAES 30 or 64, so a batch of 32 keeps every
/// backend busy while the ciphertext copy that chaining needs stays a 512-byte stack buffer.
///
/// Input shorter than one batch is decrypted a block at a time instead. The block decryptions
/// are independent, so an out-of-order core already overlaps consecutive single-block calls, and
/// below a full batch the buffer setup costs more than batching recovers. Measured with `aes`
/// 0.9.3 on an M1 Max: 128 bytes took 32 ns a block at a time and 41 ns batched; 512 bytes
/// 120 ns and 111 ns; 16 KiB 3.73 µs and 3.40 µs; a 1,200-byte record 274–305 ns and
/// 272–280 ns across runs.
const CBC_DECRYPT_BATCH_BLOCKS: usize = 32;

type Aes128Ccm = Ccm<Aes128, U16, U12>;
type Aes128Ccm8 = Ccm<Aes128, U8, U12>;

// The RustCrypto stack here is `aes` 0.9 / `ctr` 0.10 / `ccm` 0.6. `aes` 0.9 selects its ARMv8
// backend by runtime detection alone, where 0.8 also needed `--cfg aes_armv8` from the final build
// — which applications depending on rtc do not get from this repository's `.cargo/config.toml`,
// so they silently ran software AES (`python3 scripts/bench.py external` checks this). The cost:
// on an M1 Max, 0.9's ARMv8 backend is slower than 0.8's with the cfg — a 1,200-byte AES-128-CTR
// keystream takes ~433 ns rather than ~223 ns, and a CCM seal ~2.0 µs rather than ~1.0 µs — while
// a consumer build without the cfg goes from ~6.0 µs to ~433 ns. The likely cause: 0.8 emits each
// AESE/AESMC pair as one asm block, which the core can fuse, and 0.9 as separate intrinsics.
// Revisit when a later `aes` recovers the difference.

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
                .encrypt_block(as_block(block)?);
        }
        BlockCipherAlgorithm::Aes256 => {
            check_key_len(32, key.len())?;
            Aes256::new_from_slice(key)
                .map_err(|_| invalid_key(32, key.len()))?
                .encrypt_block(as_block(block)?);
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
            Self::Aes256(cipher) => cipher.encrypt_block(block.into()),
        }
    }

    fn decrypt(&self, block: &mut [u8; AES_BLOCK_LEN]) {
        match self {
            Self::Aes256(cipher) => cipher.decrypt_block(block.into()),
        }
    }

    /// Decrypts every whole block of `blocks` in place, handing them to the backend together so
    /// it can process several in parallel.
    fn decrypt_blocks(&self, blocks: &mut [u8]) {
        let (blocks, rest) = Array::slice_as_chunks_mut(blocks);
        debug_assert!(rest.is_empty(), "callers pass whole blocks");
        match self {
            Self::Aes256(cipher) => cipher.decrypt_blocks(blocks),
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
        let key = self.key.as_ref();
        match self.bits {
            AesKeyBits::Aes128 => {
                let mut stream =
                    Aes128Ctr::new_from_slices(key, iv).map_err(|_| invalid_key(16, key.len()))?;
                stream.apply_keystream(data);
            }
            AesKeyBits::Aes256 => {
                let mut stream =
                    Aes256Ctr::new_from_slices(key, iv).map_err(|_| invalid_key(32, key.len()))?;
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

        if blocks.len() < CBC_DECRYPT_BATCH_BLOCKS * AES_BLOCK_LEN {
            for block in blocks.as_chunks_mut::<AES_BLOCK_LEN>().0 {
                // The ciphertext masks the *next* block, so it has to be kept before decryption
                // overwrites it in place.
                let ciphertext = *block;
                self.key.decrypt(block);
                xor_in_place(block, &previous);
                previous = ciphertext;
            }
            return Ok(());
        }

        // Unlike encryption, where each block's input depends on the previous block's output, the
        // block decryptions are independent; only the XOR afterwards chains, and it chains on
        // *ciphertext*. So decrypt a batch at once — letting the backend pipeline it — from a copy
        // of the ciphertext that each plaintext block is then unmasked with.
        let mut ciphertext = [0u8; CBC_DECRYPT_BATCH_BLOCKS * AES_BLOCK_LEN];
        for batch in blocks.chunks_mut(CBC_DECRYPT_BATCH_BLOCKS * AES_BLOCK_LEN) {
            let ciphertext = &mut ciphertext[..batch.len()];
            ciphertext.copy_from_slice(batch);
            self.key.decrypt_blocks(batch);

            // Block i is masked with ciphertext block i - 1; the first with the IV or the last
            // ciphertext block of the previous batch.
            let (first, rest) = batch.split_at_mut(AES_BLOCK_LEN);
            xor_in_place(first, &previous);
            xor_in_place(rest, &ciphertext[..ciphertext.len() - AES_BLOCK_LEN]);
            previous.copy_from_slice(&ciphertext[ciphertext.len() - AES_BLOCK_LEN..]);
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
                    .encrypt_inout_detached(ccm_nonce(nonce)?, aad, plaintext_and_ciphertext.into())
                    .map_err(|_| CryptoError::AuthenticationFailed)?;
                tag_out.copy_from_slice(&tag);
            }
            Self::Short(cipher) => {
                let tag = cipher
                    .encrypt_inout_detached(ccm_nonce(nonce)?, aad, plaintext_and_ciphertext.into())
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
                    ccm_nonce(nonce)?,
                    aad,
                    ciphertext_and_plaintext.into(),
                    ccm_tag(tag)?,
                )
                .map_err(|_| CryptoError::AuthenticationFailed),
            Self::Short(cipher) => cipher
                .decrypt_inout_detached(
                    ccm_nonce(nonce)?,
                    aad,
                    ciphertext_and_plaintext.into(),
                    ccm_tag(tag)?,
                )
                .map_err(|_| CryptoError::AuthenticationFailed),
        }
    }
}

/// `dst ^= src`, over the length of `dst`; `src` is at least as long.
fn xor_in_place(dst: &mut [u8], src: &[u8]) {
    for (byte, mask) in dst.iter_mut().zip(src) {
        *byte ^= mask;
    }
}

/// `block` as the cipher's block type. Callers have checked the length; a mismatch is reported
/// rather than panicking.
fn as_block(block: &mut [u8]) -> Result<&mut Array<u8, U16>, CryptoError> {
    let actual = block.len();
    block.try_into().map_err(|_| CryptoError::OutputTooSmall {
        required: AES_BLOCK_LEN,
        actual,
    })
}

fn ccm_nonce(nonce: &[u8]) -> Result<&Array<u8, U12>, CryptoError> {
    nonce
        .try_into()
        .map_err(|_| invalid_nonce(CCM_NONCE_LEN, nonce.len()))
}

/// The tag as `N` bytes — the tag length of the CCM variant it is passed to, which the caller
/// checked; the conversion's own length check turns a mismatch into an error regardless.
fn ccm_tag<N: aes::cipher::array::ArraySize>(tag: &[u8]) -> Result<&Array<u8, N>, CryptoError> {
    tag.try_into().map_err(|_| CryptoError::InvalidTagLength {
        expected: N::USIZE,
        actual: tag.len(),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Block-at-a-time CBC decryption, as `AesCbc::decrypt_blocks` did before batching.
    fn reference_decrypt(key: &[u8], iv: &[u8], blocks: &mut [u8]) {
        let cipher = Aes256::new_from_slice(key).unwrap();
        let mut previous: [u8; AES_BLOCK_LEN] = iv.try_into().unwrap();
        for block in blocks.as_chunks_mut::<AES_BLOCK_LEN>().0 {
            let ciphertext = *block;
            cipher.decrypt_block(block.into());
            for (byte, prior) in block.iter_mut().zip(previous) {
                *byte ^= prior;
            }
            previous = ciphertext;
        }
    }

    fn pseudo_random_bytes(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    /// Batched decryption matches block-at-a-time decryption, and inverts encryption, for every
    /// length from one block to three batches plus one — so the chaining is checked within a
    /// batch, across one batch boundary, and across two.
    #[test]
    fn cbc_batched_decryption_matches_block_at_a_time() {
        let key = pseudo_random_bytes(1, 32);
        let iv = pseudo_random_bytes(2, AES_BLOCK_LEN);
        let mut cbc = new_cbc(CbcAlgorithm::Aes256Cbc, &key).unwrap();
        for blocks in 1..=3 * CBC_DECRYPT_BATCH_BLOCKS + 1 {
            let plaintext = pseudo_random_bytes(blocks as u64 + 3, blocks * AES_BLOCK_LEN);

            let mut ciphertext = plaintext.clone();
            cbc.encrypt_blocks(&iv, &mut ciphertext).unwrap();

            let mut expected = ciphertext.clone();
            reference_decrypt(&key, &iv, &mut expected);
            assert_eq!(expected, plaintext, "reference, {blocks} blocks");

            let mut actual = ciphertext.clone();
            cbc.decrypt_blocks(&iv, &mut actual).unwrap();
            assert_eq!(actual, plaintext, "{blocks} blocks");
        }
    }

    /// Random ciphertext, not only ciphertext this implementation produced: decryption must agree
    /// with the reference on arbitrary input too.
    #[test]
    fn cbc_batched_decryption_matches_on_arbitrary_ciphertext() {
        let key = pseudo_random_bytes(5, 32);
        let mut cbc = new_cbc(CbcAlgorithm::Aes256Cbc, &key).unwrap();
        for blocks in [1, 2, 31, 32, 33, 64, 65, 88, 100] {
            let iv = pseudo_random_bytes(blocks as u64 + 7, AES_BLOCK_LEN);
            let ciphertext = pseudo_random_bytes(blocks as u64 + 11, blocks * AES_BLOCK_LEN);
            let mut expected = ciphertext.clone();
            reference_decrypt(&key, &iv, &mut expected);
            let mut actual = ciphertext;
            cbc.decrypt_blocks(&iv, &mut actual).unwrap();
            assert_eq!(actual, expected, "{blocks} blocks");
        }
    }
}
