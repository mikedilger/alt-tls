use std::convert::Infallible;
use std::error::Error as StdError;

/// Errors that can occur in alt-tls
#[derive(Debug)]
pub enum Error {
    Pkcs8(pkcs8::Error),
    RcGen(rcgen::Error),
    Dalek(ed25519_dalek::ed25519::Error),
    X509,
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Pkcs8(e) => Some(e),
            Error::RcGen(e) => Some(e),
            Error::Dalek(e) => Some(e),
            _ => None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Pkcs8(e) => write!(f, "PKCS8: {e}"),
            Error::RcGen(e) => write!(f, "Rcgen: {e}"),
            Error::Dalek(e) => write!(f, "Ed25519 error: {e}"),
            Error::X509 => write!(f, "X509 certificate parsing error"),
        }
    }
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> std::io::Error {
        std::io::Error::other(e)
    }
}

impl From<Infallible> for Error {
    fn from(_: Infallible) -> Self {
        panic!("INFALLIBLE")
    }
}

impl From<pkcs8::Error> for Error {
    fn from(e: pkcs8::Error) -> Error {
        Error::Pkcs8(e)
    }
}

impl From<rcgen::Error> for Error {
    fn from(e: rcgen::Error) -> Error {
        Error::RcGen(e)
    }
}

impl From<ed25519_dalek::ed25519::Error> for Error {
    fn from(e: ed25519_dalek::ed25519::Error) -> Error {
        Error::Dalek(e)
    }
}
