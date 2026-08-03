use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};
use ccm::Ccm;
use ccm::aead::AeadInPlace;
use ccm::consts::{U8, U12, U16};
use md5::{Digest, Md5};

use crate::{
    AeadAlgorithm, AeadCipher, BlockCipherAlgorithm, CbcAlgorithm, CbcCipher, CryptoError,
    StreamCipher, StreamCipherAlgorithm,
};

const AES_BLOCK_LEN: usize = 16;
const CCM_NONCE_LEN: usize = 12;

type Aes128Ccm = Ccm<Aes128, U16, U12>;
type Aes128Ccm8 = Ccm<Aes128, U8, U12>;

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
    let key = match algorithm {
        StreamCipherAlgorithm::Aes128Ctr => ExpandedAesKey::new_128(key)?,
        StreamCipherAlgorithm::Aes256Ctr => ExpandedAesKey::new_256(key)?,
    };
    Ok(Box::new(AesCtr { key }))
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

// Both variants store an expanded key inside an already boxed cipher object. Keeping them inline
// avoids another allocation in every constructed state object.
#[allow(clippy::large_enum_variant)]
enum ExpandedAesKey {
    Aes128(Aes128),
    Aes256(Aes256),
}

impl ExpandedAesKey {
    fn new_128(key: &[u8]) -> Result<Self, CryptoError> {
        check_key_len(16, key.len())?;
        Ok(Self::Aes128(
            Aes128::new_from_slice(key).map_err(|_| invalid_key(16, key.len()))?,
        ))
    }

    fn new_256(key: &[u8]) -> Result<Self, CryptoError> {
        check_key_len(32, key.len())?;
        Ok(Self::Aes256(
            Aes256::new_from_slice(key).map_err(|_| invalid_key(32, key.len()))?,
        ))
    }

    fn encrypt(&self, block: &mut [u8; AES_BLOCK_LEN]) {
        match self {
            Self::Aes128(cipher) => cipher.encrypt_block(GenericArray::from_mut_slice(block)),
            Self::Aes256(cipher) => cipher.encrypt_block(GenericArray::from_mut_slice(block)),
        }
    }

    fn decrypt(&self, block: &mut [u8; AES_BLOCK_LEN]) {
        match self {
            Self::Aes128(cipher) => cipher.decrypt_block(GenericArray::from_mut_slice(block)),
            Self::Aes256(cipher) => cipher.decrypt_block(GenericArray::from_mut_slice(block)),
        }
    }
}

struct AesCtr {
    key: ExpandedAesKey,
}

impl StreamCipher for AesCtr {
    fn apply_keystream(&mut self, iv: &[u8], data: &mut [u8]) -> Result<(), CryptoError> {
        check_nonce_len(AES_BLOCK_LEN, iv.len())?;
        let mut counter: [u8; AES_BLOCK_LEN] = iv
            .try_into()
            .map_err(|_| invalid_nonce(AES_BLOCK_LEN, iv.len()))?;

        for chunk in data.chunks_mut(AES_BLOCK_LEN) {
            let mut stream_block = counter;
            self.key.encrypt(&mut stream_block);
            for (byte, mask) in chunk.iter_mut().zip(stream_block) {
                *byte ^= mask;
            }
            increment_be(&mut counter);
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

fn increment_be(counter: &mut [u8; AES_BLOCK_LEN]) {
    for byte in counter.iter_mut().rev() {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            break;
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
