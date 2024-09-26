#[test]
fn test_decrypt() {
    let docx = include_bytes!("test.docx").to_vec();
    let expected = include_bytes!("test_decrypted.docx").to_vec();

    let bytes = office_crypto_rs::decrypt_from_bytes(&docx, "test").unwrap();

    assert_eq!(bytes, expected);
}

#[test]
fn test_decrypt_sha1() {
    let docx = include_bytes!("sha1_encrypted.docx").to_vec();
    let expected = include_bytes!("sha1_decrypted.docx").to_vec();

    let bytes = office_crypto_rs::decrypt_from_bytes(&docx, "Test").unwrap();

    assert_eq!(bytes, expected);
}
