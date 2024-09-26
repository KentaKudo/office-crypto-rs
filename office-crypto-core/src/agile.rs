use crate::errors::DecryptError::{self, *};
use crate::utils::{b64_decode, validate};

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use sha1::Sha1;
use sha2::{Digest, Sha512};
use std::io::prelude::*;

// unused blocks are meant to verify password/file integrity
const _BLOCK1: [u8; 8] = [0xFE, 0xA7, 0xD2, 0x76, 0x3B, 0x4B, 0x9E, 0x79];
const _BLOCK2: [u8; 8] = [0xD7, 0xAA, 0x0F, 0x6D, 0x30, 0x61, 0x34, 0x4E];
const BLOCK3: [u8; 8] = [0x14, 0x6E, 0x0B, 0xE7, 0xAB, 0xAC, 0xD0, 0xD6];
const _BLOCK4: [u8; 8] = [0x5F, 0xB2, 0xAD, 0x01, 0x0C, 0xB9, 0xE1, 0xF6];
const _BLOCK5: [u8; 8] = [0xA0, 0x67, 0x7F, 0x02, 0xB2, 0x2C, 0x84, 0x33];

const SEGMENT_LENGTH: usize = 4096;

#[derive(Default, Debug)]
pub(crate) struct AgileEncryptionInfo {
    key_data_salt: Vec<u8>,
    key_data_hash_algorithm: String,
    key_data_block_size: u32,
    encrypted_hmac_key: Vec<u8>,
    encrypted_hmac_value: Vec<u8>,
    encrypted_verifier_hash_input: Vec<u8>,
    encrypted_verifier_hash_value: Vec<u8>,
    encrypted_key_value: Vec<u8>,
    spin_count: u32,
    password_salt: Vec<u8>,
    password_hash_algorithm: String,
    password_key_bits: u32,
}

impl AgileEncryptionInfo {
    pub fn new(mut encryption_info: impl Seek + Read) -> Result<Self, DecryptError> {
        encryption_info
            .seek(std::io::SeekFrom::Start(8))
            .map_err(|e| {
                InvalidStructure(format!("AgileEncryption: encryption_info.seek(8): {e}"))
            })?;
        let mut raw_xml = String::new();
        encryption_info.read_to_string(&mut raw_xml).map_err(|e| {
            InvalidStructure(format!(
                "AgileEncryption: encryption_info.read_to_string(): {e}"
            ))
        })?;

        // let raw_xml = String::from_utf8(encryption_info.stream[8..].to_vec())
        //     .map_err(|_| InvalidStructure)?;

        let mut reader = Reader::from_str(&raw_xml);
        reader.trim_text(true);

        let mut aei = Self::default();
        let mut set_key_data = false;
        let mut set_hmac_data = false;
        let mut set_password_node = false;

        loop {
            match reader.read_event().unwrap() {
                Event::Empty(e) => match e.name().as_ref() {
                    b"keyData" if !set_key_data => {
                        for attr in e.attributes() {
                            let attr = attr.map_err(|e| {
                                InvalidStructure(format!(
                                    "AgileEncryption: keyData: attributes(): {e}"
                                ))
                            })?;
                            match attr.key.as_ref() {
                                b"saltValue" => {
                                    aei.key_data_salt = b64_decode(&attr.value)?;
                                }
                                b"hashAlgorithm" => {
                                    aei.key_data_hash_algorithm = String::from_utf8(
                                        attr.value.into_owned(),
                                    )
                                    .map_err(|e| {
                                        InvalidStructure(format!(
                                            "AgileEncryption: keyData.hashAlgorithm: {e}"
                                        ))
                                    })?;
                                }
                                b"blockSize" => {
                                    aei.key_data_block_size =
                                        String::from_utf8(attr.value.into_owned())
                                            .map_err(|e| {
                                                InvalidStructure(format!(
                                                    "AgileEncryption: keyData.blockSize: {e}"
                                                ))
                                            })?
                                            .parse()
                                            .map_err(|e| {
                                                InvalidStructure(format!(
                                            "AgileEncryption: keyData.blockSize: parse(): {e}"
                                        ))
                                            })?;
                                }
                                _ => (),
                            }
                        }
                        set_key_data = true;
                    }
                    b"dataIntegrity" if !set_hmac_data => {
                        for attr in e.attributes() {
                            let attr = attr.map_err(|e| {
                                InvalidStructure(format!(
                                    "AgileEncryption: dataIntegrity: attributes(): {e}"
                                ))
                            })?;
                            match attr.key.as_ref() {
                                b"encryptedHmacKey" => {
                                    aei.encrypted_hmac_key = b64_decode(&attr.value)?;
                                }
                                b"encryptedHmacValue" => {
                                    aei.encrypted_hmac_value = b64_decode(&attr.value)?;
                                }
                                _ => (),
                            }
                        }
                        set_hmac_data = true;
                    }
                    b"p:encryptedKey" if !set_password_node => {
                        for attr in e.attributes() {
                            let attr = attr.map_err(|e| {
                                InvalidStructure(format!(
                                    "AgileEncryption: p:encryptedKey: attributes(): {e}"
                                ))
                            })?;
                            match attr.key.as_ref() {
                                b"encryptedVerifierHashInput" => {
                                    aei.encrypted_verifier_hash_input = b64_decode(&attr.value)?;
                                }
                                b"encryptedVerifierHashValue" => {
                                    aei.encrypted_verifier_hash_value = b64_decode(&attr.value)?;
                                }
                                b"encryptedKeyValue" => {
                                    aei.encrypted_key_value = b64_decode(&attr.value)?;
                                }
                                b"spinCount" => {
                                    aei.spin_count = String::from_utf8(attr.value.into_owned())
                                        .map_err(|e| {
                                            InvalidStructure(format!(
                                                "AgileEncryption: p:encryptedKey.spinCount: {e}"
                                            ))
                                        })?
                                        .parse()
                                        .map_err(|e| {
                                            InvalidStructure(format!(
                                                "AgileEncryption: p:encryptedKey.spinCount: parse(): {e}"
                                            ))
                                        })?;
                                }
                                b"saltValue" => {
                                    aei.password_salt = b64_decode(&attr.value)?;
                                }
                                b"hashAlgorithm" => {
                                    aei.password_hash_algorithm = String::from_utf8(
                                        attr.value.into_owned(),
                                    )
                                    .map_err(|e| {
                                        InvalidStructure(format!(
                                            "AgileEncryption: p:encryptedKey.hashAlgorithm: {e}"
                                        ))
                                    })?;
                                }
                                b"keyBits" => {
                                    aei.password_key_bits =
                                        String::from_utf8(attr.value.into_owned())
                                            .map_err(|e| {
                                                InvalidStructure(format!(
                                                    "AgileEncryption: p:encryptedKey.keyBits: {e}"
                                                ))
                                            })?
                                            .parse()
                                            .map_err(|e| {
                                                InvalidStructure(format!(
                                            "AgileEncryption: p:encryptedKey.keyBits: parse(): {e}"
                                        ))
                                            })?;
                                }
                                _ => (),
                            }
                        }
                        set_password_node = true;
                    }
                    _ => (),
                },
                Event::Eof => break,
                _ => (),
            }
        }

        validate!(
            set_key_data,
            InvalidStructure("AgileEncryption: keyData is missing".to_string())
        )?;
        validate!(
            set_hmac_data,
            InvalidStructure("AgileEncryption: dataIntegrity is missing".to_string())
        )?;
        validate!(
            set_password_node,
            InvalidStructure("AgileEncryption: p:encryptedKey is missing".to_string())
        )?;

        Ok(aei)
    }

    pub fn key_from_password(&self, password: &str) -> Result<Vec<u8>, DecryptError> {
        let digest = self.iterated_hash_from_password(password)?;
        let encryption_key = self.encryption_key(&digest, &BLOCK3)?;
        self.decrypt_encrypted_key(&encryption_key)
    }

    pub fn decrypt(
        &self,
        key: &[u8],
        mut encrypted_stream: impl Seek + Read,
    ) -> Result<Vec<u8>, DecryptError> {
        let mut bytes: [u8; 4] = [0; 4];
        encrypted_stream.read_exact(&mut bytes).map_err(|e| {
            InvalidStructure(format!(
                "AgileEncryption: decrypt: encrypted_steam.read_exact(4): {e}"
            ))
        })?;

        let total_size = u32::from_le_bytes(bytes) as usize;

        let mut block_start: usize = 8; // skip first 8 bytes
        let mut block_index: u32 = 0;
        let mut decrypted: Vec<u8> = vec![0; total_size];
        let key_data_salt: &[u8] = &self.key_data_salt;

        while block_start < (total_size - SEGMENT_LENGTH) {
            let iv = hash(
                &self.key_data_hash_algorithm,
                &[key_data_salt, &block_index.to_le_bytes()].concat(),
            )?;
            let iv = &iv[..16];

            encrypted_stream
                .seek(std::io::SeekFrom::Start(block_start as u64))
                .map_err(|e| {
                    InvalidStructure(format!(
                        "AgileEncryption: decrypt: encrypted_stream(block_start): {e}"
                    ))
                })?;

            let mut in_buf: Vec<u8> = vec![];
            encrypted_stream
                .by_ref()
                .take(SEGMENT_LENGTH as u64)
                .read_to_end(&mut in_buf)
                .map_err(|e| {
                    InvalidStructure(format!(
                        "AgileEncryption: decrypt: encrypted_stream: read segment: {e}"
                    ))
                })?;

            // decrypt from encrypted_stream directly to output Vec
            let plaintext = decrypt_aes_cbc(key, iv, &in_buf)?;
            decrypted[(block_start - 8)..(block_start - 8 + SEGMENT_LENGTH)]
                .copy_from_slice(&plaintext[..SEGMENT_LENGTH]);

            block_index += 1;
            block_start += SEGMENT_LENGTH;
        }

        // parse last block w less than 4096 bytes

        encrypted_stream
            .seek(std::io::SeekFrom::Start(block_start as u64))
            .map_err(|e| {
                InvalidStructure(format!(
                    "AgileEncryption: decrypt: encrypted_stream.seek(block_start): {e}"
                ))
            })?;
        let mut ciphertext: Vec<u8> = vec![];
        encrypted_stream.read_to_end(&mut ciphertext).map_err(|e| {
            InvalidStructure(format!(
                "AgileEncryption: decrypt: encrypted_stream: read remaining: {e}"
            ))
        })?;

        // remaining bytes in encrypted_stream should be a multiple of block size even if we only use some of the decrypted bytes
        validate!(
            ciphertext.len() % 16 == 0,
            InvalidStructure("AgileEncryption: decrypt: remaining block size".to_string())
        )?;

        let iv = hash(
            &self.key_data_hash_algorithm,
            &[key_data_salt, &block_index.to_le_bytes()].concat(),
        )?;
        let iv = &iv[..16];
        let plaintext = decrypt_aes_cbc(key, iv, &ciphertext)?;

        let remaining = total_size - (block_start - 8);
        let irregular_block_len = remaining % 16;
        let mut copy_span = plaintext.len() - 16 + irregular_block_len;
        if irregular_block_len == 0 {
            copy_span += 16;
        }
        decrypted[(block_start - 8)..(block_start + copy_span - 8)]
            .copy_from_slice(&plaintext[..copy_span]);

        Ok(decrypted)
    }

    // this function is ridiculously expensive as it usually runs 10000 SHA512's
    fn iterated_hash_from_password(&self, password: &str) -> Result<Vec<u8>, DecryptError> {
        let pass_utf16: Vec<u16> = password.encode_utf16().collect();
        let pass_utf16: &[u8] = unsafe { pass_utf16.align_to::<u8>().1 };
        let salted: Vec<u8> = [&self.password_salt, pass_utf16].concat();

        let mut h = hash(self.password_hash_algorithm.as_str(), &salted)?;
        for i in 0u32..self.spin_count {
            h = hash(
                self.password_hash_algorithm.as_str(),
                &[i.to_le_bytes().as_ref(), &h].concat(),
            )?;
        }
        Ok(h)
    }

    fn encryption_key(&self, digest: &[u8], block: &[u8]) -> Result<Vec<u8>, DecryptError> {
        let h = hash(
            self.password_hash_algorithm.as_str(),
            &[digest, block].concat(),
        )?;
        Ok(h[..(self.password_key_bits as usize / 8)].to_owned())
    }

    fn decrypt_encrypted_key(&self, key: &[u8]) -> Result<Vec<u8>, DecryptError> {
        decrypt_aes_cbc(key, &self.password_salt, &self.encrypted_key_value)
    }
}

fn decrypt_aes_cbc(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, DecryptError> {
    let mut plaintext = vec![0u8; ciphertext.len()];

    let key_len = key.len() * 8;
    match key_len {
        128 => {
            let cipher = cbc::Decryptor::<aes::Aes128>::new(key.into(), iv.into());
            cipher
                .decrypt_padded_b2b_mut::<NoPadding>(ciphertext, &mut plaintext)
                .map_err(|_| Unknown)?;
        }
        256 => {
            let cipher = cbc::Decryptor::<aes::Aes256>::new(key.into(), iv.into());
            cipher
                .decrypt_padded_b2b_mut::<NoPadding>(ciphertext, &mut plaintext)
                .map_err(|_| Unknown)?;
        }
        _ => return Err(InvalidStructure("unrecognised key length".to_string())),
    }

    Ok(plaintext)
}

fn hash(algorithm: &str, input: &[u8]) -> Result<Vec<u8>, DecryptError> {
    match algorithm {
        "SHA512" => Ok(Sha512::digest(input).as_slice().to_owned()),
        "SHA1" => Ok(Sha1::digest(input).as_slice().to_owned()),
        _ => Err(InvalidStructure("unrecognised hash algorithm".to_string())),
    }
}
