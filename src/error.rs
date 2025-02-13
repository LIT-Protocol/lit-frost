use crate::Identifier;
use thiserror::Error as TError;

/// Errors generated from this library
#[derive(Debug, TError)]
pub enum Error {
    /// Verifiable secret sharing scheme errors
    #[error("Vsss error: {0}")]
    Vsss(vsss_rs::Error),
    /// General errors
    #[error("Error: {0}")]
    General(String),
    /// Cheaters found during an aggregate operation
    #[error("Cheaters found: {0:?}")]
    Cheaters(Vec<Identifier>),
}

impl From<vsss_rs::Error> for Error {
    fn from(e: vsss_rs::Error) -> Self {
        Self::Vsss(e)
    }
}

impl<C: frost_core::Ciphersuite> From<frost_core::Error<C>> for Error {
    fn from(e: frost_core::Error<C>) -> Self {
        Error::General(e.to_string())
    }
}

impl From<reddsa::Error> for Error {
    fn from(e: reddsa::Error) -> Self {
        Error::General(e.to_string())
    }
}

impl From<decaf377_rdsa::Error> for Error {
    fn from(e: decaf377_rdsa::Error) -> Self {
        Error::General(e.to_string())
    }
}

/// Results generated by this library
pub type FrostResult<T> = anyhow::Result<T, Error>;
