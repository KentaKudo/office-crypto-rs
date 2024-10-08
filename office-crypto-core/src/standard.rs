use crate::errors::DecryptError::{self, *};
use crate::utils::validate;

use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyInit};
use sha1::Sha1;
use sha2::Digest;
use std::io::prelude::*;
use std::io::SeekFrom;

const ITER_COUNT: u32 = 50000;

#[derive(Debug)]
pub(crate) struct StandardEncryptionInfo {
    _flags: u32,
    _size_extra: u32,
    _alg_id: u32,
    _alg_id_hash: u32,
    key_size: u32,
    _provider_type: u32,
    _reserved1: u32,
    _reserved2: u32,
    _csp_name: String,
    _salt_size: u32,
    salt: Vec<u8>,
    _encrypted_verifier: Vec<u8>,
    _verifier_hash_size: u32,
    _encrypted_verifier_hash: Vec<u8>,
}

impl StandardEncryptionInfo {
    pub fn new(mut encryption_info: impl Seek + Read) -> Result<Self, DecryptError> {
        // let header_flags = u32::from_le_bytes(
        //     encryption_info.stream[4..8]
        //         .try_into()
        //         .map_err(|_| InvalidStructure)?,
        // );

        let mut bytes: [u8; 4] = [0; 4];
        encryption_info.seek(SeekFrom::Start(8)).map_err(|e| {
            InvalidStructure(format!(
                "StandardEncryption: encryption_info.seek(versionInfo + headerFlag): {e}"
            ))
        })?;

        encryption_info.read_exact(&mut bytes).map_err(|e| {
            InvalidStructure(format!(
                "StandardEncryption: encryption_info: read headerSize: {e}"
            ))
        })?;

        // TODO: should validate size
        let header_size = u32::from_le_bytes(bytes);

        let mut header_bytes = Vec::new();

        encryption_info.seek(SeekFrom::Start(12)).map_err(|e| {
            InvalidStructure(format!("StandardEncryption: encryption_info.seek(versionInfo + headerFlag + headerSize): {e}"))
        })?;
        encryption_info
            .by_ref()
            .take(header_size as u64)
            .read_to_end(&mut header_bytes)
            .map_err(|e| {
                InvalidStructure(format!(
                    "StandardEncryption: encryption_info: read header: {e}"
                ))
            })?;

        // TODO switch to packed struct maybe
        let flags = u32::from_le_bytes(
            header_bytes[..4]
                .try_into()
                .map_err(|e| InvalidStructure(format!("StandardEncryption: header.flags: {e}")))?,
        );
        let size_extra = u32::from_le_bytes(header_bytes[4..8].try_into().map_err(|e| {
            InvalidStructure(format!("StandardEncryption: header.size_extra: {e}"))
        })?);
        let alg_id =
            u32::from_le_bytes(header_bytes[8..12].try_into().map_err(|e| {
                InvalidStructure(format!("StandardEncryption: header.alg_id: {e}"))
            })?);
        let alg_id_hash = u32::from_le_bytes(header_bytes[12..16].try_into().map_err(|e| {
            InvalidStructure(format!("StandardEncryption: header.alg_id_hash: {e}"))
        })?);
        let key_size =
            u32::from_le_bytes(header_bytes[16..20].try_into().map_err(|e| {
                InvalidStructure(format!("StandardEncryption: header.key_size: {e}"))
            })?);
        let provider_type = u32::from_le_bytes(header_bytes[20..24].try_into().map_err(|e| {
            InvalidStructure(format!("StandardEncryption: header.provider_type: {e}"))
        })?);
        let reserved1 =
            u32::from_le_bytes(header_bytes[24..28].try_into().map_err(|e| {
                InvalidStructure(format!("StandardEncryption: header.reserved1: {e}"))
            })?);
        let reserved2 =
            u32::from_le_bytes(header_bytes[28..32].try_into().map_err(|e| {
                InvalidStructure(format!("StandardEncryption: header.reserved2: {e}"))
            })?);

        let csp_utf16 = header_bytes[32..].to_owned();
        let csp_utf16: &[u16] = unsafe { csp_utf16.align_to::<u16>().1 };
        let csp_name = String::from_utf16(csp_utf16)
            .map_err(|e| InvalidStructure(format!("StandardEncryption: header.csp_name: {e}")))?;

        // check if AES, otherwise RC4
        validate!(alg_id & 0xFF00 == 0x6600, Unimplemented("RC4".to_owned()))?;

        let mut verifier_bytes = Vec::new();

        encryption_info
            .seek(SeekFrom::Start(12 + header_size as u64))
            .map_err(|e| {
                InvalidStructure(format!(
                    "StandardEncryption: encryption_info.seek(header): {e}"
                ))
            })?;
        encryption_info
            .read_to_end(&mut verifier_bytes)
            .map_err(|e| {
                InvalidStructure(format!(
                    "StandardEncryption: encryption_info: read verifier: {e}"
                ))
            })?;

        let salt_size = u32::from_le_bytes(verifier_bytes[..4].try_into().map_err(|e| {
            InvalidStructure(format!("StandardEncryption: verifier.salt_size: {e}"))
        })?);
        let salt = verifier_bytes[4..20].to_owned();
        let encrypted_verifier = verifier_bytes[20..36].to_owned();
        let verifier_hash_size =
            u32::from_le_bytes(verifier_bytes[36..40].try_into().map_err(|e| {
                InvalidStructure(format!(
                    "StandardEncryption: verifier.verifier_hash_size: {e}"
                ))
            })?);
        let encrypted_verifier_hash = verifier_bytes[40..72].to_owned();

        Ok(Self {
            _flags: flags,
            _size_extra: size_extra,
            _alg_id: alg_id,
            _alg_id_hash: alg_id_hash,
            key_size,
            _provider_type: provider_type,
            _reserved1: reserved1,
            _reserved2: reserved2,
            _csp_name: csp_name,
            _salt_size: salt_size,
            salt,
            _encrypted_verifier: encrypted_verifier,
            _verifier_hash_size: verifier_hash_size,
            _encrypted_verifier_hash: encrypted_verifier_hash,
        })
    }

    pub fn key_from_password(&self, password: &str) -> Result<Vec<u8>, DecryptError> {
        let pass_utf16: Vec<u16> = password.encode_utf16().collect();
        let pass_utf16: &[u8] = unsafe { pass_utf16.align_to::<u8>().1 };

        let mut h = Sha1::digest([&self.salt, pass_utf16].concat());
        for i in 0u32..ITER_COUNT {
            h = Sha1::digest([&i.to_le_bytes(), h.as_slice()].concat());
        }

        let block_bytes = [0, 0, 0, 0];
        h = Sha1::digest([h.as_slice(), &block_bytes].concat());
        let cb_required_key_length = self.key_size / 8;
        // let cb_hash = h.len();

        let mut buf1 = [0x36_u8; 64];
        buf1.iter_mut().zip(h.iter()).for_each(|(a, b)| *a ^= *b);
        let x1 = Sha1::digest(buf1);

        let mut buf2 = [0x5c_u8; 64];
        buf2.iter_mut().zip(h.iter()).for_each(|(a, b)| *a ^= *b);
        let x2 = Sha1::digest(buf2);

        Ok([x1, x2].concat()[..(cb_required_key_length as usize)].to_owned())
    }

    pub fn decrypt(
        &self,
        key: &[u8],
        mut encrypted_stream: impl Seek + Read,
    ) -> Result<Vec<u8>, DecryptError> {
        let mut bytes: [u8; 4] = [0; 4];

        encrypted_stream.read_exact(&mut bytes).map_err(|e| {
            InvalidStructure(format!(
                "StandardEncryption: encrypted_stream.read(total_size): {e}"
            ))
        })?;

        let total_size = u32::from_le_bytes(bytes) as usize;

        let block_start = 8;

        encrypted_stream
            .seek(SeekFrom::Start(block_start as u64))
            .map_err(|e| {
                InvalidStructure(format!(
                    "StandardEncryption: encrypted_stream.seek(block_start): {e}"
                ))
            })?;
        let mut encrypted_buf: Vec<u8> = vec![];
        encrypted_stream
            .read_to_end(&mut encrypted_buf)
            .map_err(|e| {
                InvalidStructure(format!(
                    "StandardEncryption: encrypted_stream: read block: {e}"
                ))
            })?;

        // has to be big enough to decrypt into
        let mut decrypted: Vec<u8> = vec![0; encrypted_buf.len()];

        // 16 bit blocks
        validate!(
            (encrypted_buf.len()) % 16 == 0,
            InvalidStructure("StandardEncryption: block size".to_string())
        )?;

        let ecb_cipher = ecb::Decryptor::<aes::Aes128>::new(key.into());
        ecb_cipher
            .decrypt_padded_b2b_mut::<NoPadding>(&encrypted_buf, &mut decrypted)
            .map_err(|e| InvalidStructure(format!("StandardEncryption: decrypt: {e}")))?;

        Ok(decrypted[..total_size].to_vec())
    }
}
