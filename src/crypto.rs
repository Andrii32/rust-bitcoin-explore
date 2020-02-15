
use digest::Digest;
use sha2::{Sha256};
use ripemd160::{Ripemd160};

pub fn sha256(key: Vec<u8>) -> Vec<u8>{
    let mut hasher = Sha256::new();     // create a Sha256 object
    hasher.input(key);                  // write input message
    hasher.result().to_vec()            // read hash digest and consume hasher
}

pub fn ripemd160(key: Vec<u8>) -> Vec<u8>{
    let mut hasher = Ripemd160::new();  // create a RIPEMD-160 hasher instance
    hasher.input(key);                  // process input message
    hasher.result().to_vec()            // acquire hash digest in the form of GenericArray, which in this case is equivalent to [u8; 20]
}