// this file is based on office-crypto 0.1.0 (https://github.com/udbhav1/office-crypto) | MIT License | github.com/jgthms/bulma

use crate::agile::AgileEncryptionInfo;
use crate::errors::DecryptError::{self, *};
use crate::standard::StandardEncryptionInfo;

use std::io::prelude::*;
use std::io::Cursor;

pub fn decrypt_from_bytes(raw: &[u8], password: &str) -> Result<Vec<u8>, DecryptError> {
    let mut olefile = cfb::CompoundFile::open(Cursor::new(raw))
        .map_err(|_| InvalidStructure)
        .map_err(|_| Unknown)?;

    decrypt(&mut olefile, password)
}

pub fn decrypt<F: Read + Seek>(
    olefile: &mut cfb::CompoundFile<F>,
    password: &str,
) -> Result<Vec<u8>, DecryptError> {
    let mut encryption_info_stream = olefile
        .open_stream("EncryptionInfo")
        .map_err(|_| InvalidStructure("olefile.open_stream(\"EncryptionInfo\")".to_string()))?;

    let encrypted_package_stream = olefile
        .open_stream("EncryptedPackage")
        .map_err(|_| InvalidStructure("olefile.open_stream(\"EncryptedPackage\")".to_string()))?;

    let mut magic_bytes: [u8; 4] = [0; 4];
    encryption_info_stream
        .read_exact(&mut magic_bytes)
        .map_err(|_| {
            InvalidStructure("encryption_info_stream.read_exact(magic_bytes)".to_string())
        })?;

    match magic_bytes {
        [4, 0, 4, 0] => {
            let aei = AgileEncryptionInfo::new(encryption_info_stream)?;
            let secret_key = aei.key_from_password(password)?;

            aei.decrypt(&secret_key, encrypted_package_stream)
        }
        [2..=4, 0, 2, 0] => {
            let sei = StandardEncryptionInfo::new(encryption_info_stream)?;
            let secret_key = sei.key_from_password(password)?;

            sei.decrypt(&secret_key, encrypted_package_stream)
        }
        _ => Err(InvalidStructure("magic_bytes".to_string())),
    }
}
