use hex;
use secp256k1;

use crate::errors::{Error};


pub struct SecretKey {
    pub key: secp256k1::SecretKey,
}

impl SecretKey {

    pub fn from_hex(hex: String) -> Result<SecretKey, Error>{
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex, &mut bytes as &mut [u8])?;
        SecretKey::from_slice(&bytes)
    }

    pub fn from_slice(&bytes: &[u8; 32]) -> Result<SecretKey, Error>{
        let key = secp256k1::SecretKey::from_slice(&bytes)?;
        Ok(SecretKey{ key: key })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.key[..].to_vec()
    }

    pub fn to_hex(&self) -> String{
        hex::encode(self.to_bytes())
    }
   
}