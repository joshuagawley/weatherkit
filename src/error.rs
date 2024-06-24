use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("JSON error")]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("JWT error")]
    JsonWebTokenError(#[from] jsonwebtoken::errors::Error),
    #[error("System time error")]
    SystemTimeError(#[from] std::time::SystemTimeError),
}

pub type Result<T> = std::result::Result<T, crate::error::Error>;
