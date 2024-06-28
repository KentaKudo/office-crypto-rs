mod crypto;
mod errors;

pub use crypto::decrypt_from_bytes;

#[cfg(test)]
mod test {
    #[test]
    fn test_docx() {
        let docx = include_bytes!("test.docx").to_vec();
        let expected = include_bytes!("test_decrypted.docx").to_vec();

        let bytes = crate::crypto::decrypt_from_bytes(&docx, "test").unwrap();

        assert_eq!(bytes, expected);
    }
}
