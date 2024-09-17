use crate::errors::DecryptError::{self, *};

use base64::engine::general_purpose;
use std::io::prelude::*;
use std::io::Cursor;

macro_rules! validate {
    ($assert:expr, $err:expr) => {{
        if ($assert) {
            Ok(())
        } else {
            let error_code: DecryptError = $err;
            Err(error_code)
        }
    }};
}

pub(crate) use validate;

pub(crate) fn b64_decode(bytes: &[u8]) -> Result<Vec<u8>, DecryptError> {
    let mut wrapped_reader = Cursor::new(bytes);
    let mut decoder =
        base64::read::DecoderReader::new(&mut wrapped_reader, &general_purpose::STANDARD);

    let mut result = Vec::new();
    decoder.read_to_end(&mut result).map_err(|_| Unknown)?;
    Ok(result)
}
