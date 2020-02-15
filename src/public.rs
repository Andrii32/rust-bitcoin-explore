use secp256k1::{self, Secp256k1};

use crate::secret::{SecretKey};


pub enum PublicKeyKind{
    Compressed,
    UnCompressed
}

pub struct PublicKey{
    kind: PublicKeyKind,
    key:  secp256k1::PublicKey
}

impl PublicKey{

    pub fn from_secret_key(key: &SecretKey, kind: PublicKeyKind) -> PublicKey{
        PublicKey{
            kind: kind, key: secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &key.key)
        }
    }
        
    pub fn to_bytes(&self) -> Vec<u8> {
        match self.kind{
            PublicKeyKind::Compressed   => self.key.serialize().to_vec(),
            PublicKeyKind::UnCompressed => self.key.serialize_uncompressed().to_vec()
        } 
    }

    pub fn to_hex(&self) -> String{
        hex::encode(self.to_bytes())
    }

}
