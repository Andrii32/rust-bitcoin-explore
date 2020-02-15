use hex;
use secp256k1;


#[derive(Debug)]
pub enum Error{
    FromHexError(hex::FromHexError),
    InvalidSecretKey,
    UndefinedError(secp256k1::Error)
}

impl From<hex::FromHexError> for Error {
    fn from(err: hex::FromHexError) -> Error {
        Error::FromHexError(err)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(err: secp256k1::Error) -> Error {
        match err {
            secp256k1::Error::InvalidSecretKey => Error::InvalidSecretKey,
            _                                  => Error::UndefinedError(err)
        }
    }
}
