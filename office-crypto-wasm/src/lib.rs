mod utils;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn decrypt(buffer: &[u8], password: &str) -> Result<Vec<u8>, JsError> {
    Ok(office_crypto_rs::decrypt_from_bytes(buffer, password)?)
}
