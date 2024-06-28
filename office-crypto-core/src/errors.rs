use thiserror::Error;

#[derive(Error, Debug)]
pub enum DecryptError {
    #[error("IO Error")]
    IoError(std::io::Error),
    #[error("Invalid Olefile Header")]
    InvalidHeader,
    #[error("Invalid File Structure")]
    InvalidStructure,
    #[error("Unimplemented: `{0}`")]
    Unimplemented(String),
    #[error("Unknown Error")]
    Unknown,
}
