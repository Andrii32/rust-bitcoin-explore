use rust_base58::{ToBase58};

mod crypto;
use crypto::{ripemd160, sha256};

mod secret;
use secret::{SecretKey};

mod public;
use public::{PublicKey, PublicKeyKind};

mod errors;
use errors::{Error};


fn main() {
    // Technical background of version 1 Bitcoin addresses  
    // Based on: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    
    println!("Technical background of version 1 Bitcoin addresses\n");

    println!("0 - Having a private ECDSA key");
    let secret_key = SecretKey::from_hex(String::from("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725")).unwrap();
    println!("{:?}", secret_key.to_hex());

    
    println!("1 - Take the corresponding public key generated with it \
             (33 bytes, 1 byte 0x02 (y-coord is even), and 32 bytes corresponding to X coordinate)");
    let pbk_c = PublicKey::from_secret_key(&secret_key, PublicKeyKind::Compressed).to_bytes();
    let pbk_u = PublicKey::from_secret_key(&secret_key, PublicKeyKind::UnCompressed).to_bytes();
    println!("COMPRESSED:   {:?}", hex::encode(&pbk_c));
    println!("UNCOMPRESSED: {:?}", hex::encode(&pbk_u));
          

    println!("2 - Perform SHA-256 hashing on the public key");
    let pbk_c_sha256 = sha256(pbk_c);
    let pbk_u_sha256 = sha256(pbk_u);
    println!("COMPRESSED:   {:?}", hex::encode(&pbk_c_sha256));
    println!("UNCOMPRESSED: {:?}", hex::encode(&pbk_u_sha256));

    println!("3 - Perform RIPEMD-160 hashing on the result of SHA-256");
    let pbk_c_sha256_ripemd160 = ripemd160(pbk_c_sha256);
    let pbk_u_sha256_ripemd160 = ripemd160(pbk_u_sha256);
    println!("COMPRESSED:   {:?}", hex::encode(&pbk_c_sha256_ripemd160));
    println!("UNCOMPRESSED: {:?}", hex::encode(&pbk_u_sha256_ripemd160));

    println!("4 - Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)");
    let mut pbk_c_sha256_ripemd160_mn = pbk_c_sha256_ripemd160.to_vec();
    let mut pbk_u_sha256_ripemd160_mn = pbk_u_sha256_ripemd160.to_vec();
    pbk_c_sha256_ripemd160_mn.insert(0, 0x00);
    pbk_u_sha256_ripemd160_mn.insert(0, 0x00);
    println!("COMPRESSED:   {:?}", hex::encode(&pbk_c_sha256_ripemd160_mn));
    println!("UNCOMPRESSED: {:?}", hex::encode(&pbk_u_sha256_ripemd160_mn));

    println!("\n(note that below steps are the Base58Check encoding, which has multiple library options available implementing it)\n");

    println!("5 - Perform SHA-256 hash on the extended RIPEMD-160 result");
    let pbk_c_sha256_ripemd160_mn_sha256 = sha256(pbk_c_sha256_ripemd160_mn.to_vec());
    let pbk_u_sha256_ripemd160_mn_sha256 = sha256(pbk_u_sha256_ripemd160_mn.to_vec());
    println!("COMPRESSED:   {:?}", hex::encode(&pbk_c_sha256_ripemd160_mn_sha256));
    println!("UNCOMPRESSED: {:?}", hex::encode(&pbk_u_sha256_ripemd160_mn_sha256));

    println!("6 - Perform SHA-256 hash on the result of the previous SHA-256 hash");
    let pbk_c_sha256_ripemd160_mn_sha256_sha256 = sha256(pbk_c_sha256_ripemd160_mn_sha256);
    let pbk_u_sha256_ripemd160_mn_sha256_sha256 = sha256(pbk_u_sha256_ripemd160_mn_sha256);
    println!("COMPRESSED:   {:?}", hex::encode(&pbk_c_sha256_ripemd160_mn_sha256_sha256));
    println!("UNCOMPRESSED: {:?}", hex::encode(&pbk_u_sha256_ripemd160_mn_sha256_sha256));

    println!("7 - Take the first 4 bytes of the second SHA-256 hash. This is the address checksum");
    let pbk_c_sha256_ripemd160_mn_sha256_sha256_checksum = &pbk_c_sha256_ripemd160_mn_sha256_sha256[0..4];
    let pbk_u_sha256_ripemd160_mn_sha256_sha256_checksum = &pbk_u_sha256_ripemd160_mn_sha256_sha256[0..4];
    println!("COMPRESSED:   {:?}", hex::encode(&pbk_c_sha256_ripemd160_mn_sha256_sha256_checksum));
    println!("UNCOMPRESSED: {:?}", hex::encode(&pbk_u_sha256_ripemd160_mn_sha256_sha256_checksum));

    println!("8 - Add the 4 checksum bytes from stage 7 at the end of extended RIPEMD-160 hash from stage 4. This is the 25-byte binary Bitcoin Address.");
    let mut pbk_c_sha256_ripemd160_mn_extended = pbk_c_sha256_ripemd160_mn.to_vec();
    let mut pbk_u_sha256_ripemd160_mn_extended = pbk_u_sha256_ripemd160_mn.to_vec();
    pbk_c_sha256_ripemd160_mn_extended.extend(pbk_c_sha256_ripemd160_mn_sha256_sha256_checksum);
    pbk_u_sha256_ripemd160_mn_extended.extend(pbk_u_sha256_ripemd160_mn_sha256_sha256_checksum);
    println!("COMPRESSED:   {:?}", hex::encode(&pbk_c_sha256_ripemd160_mn_extended));
    println!("UNCOMPRESSED: {:?}", hex::encode(&pbk_u_sha256_ripemd160_mn_extended));

    println!("9 - Convert the result from a byte string into a base58 string using Base58Check encoding. This is the most commonly used Bitcoin Address format");
    let pbk_c_sha256_ripemd160_mn_extended_base58 = pbk_c_sha256_ripemd160_mn_extended.to_base58();
    let pbk_u_sha256_ripemd160_mn_extended_base58 = pbk_u_sha256_ripemd160_mn_extended.to_base58();
    println!("COMPRESSED:   {:?}", pbk_c_sha256_ripemd160_mn_extended_base58);
    println!("UNCOMPRESSED: {:?}", pbk_u_sha256_ripemd160_mn_extended_base58);
}


#[test]
fn test_from_hex_invalid_hex() {
    match SecretKey::from_hex(String::from("WRONG HEX")) {
        Ok(_)    => assert!(false),
        Err(err) => match err {
            Error::FromHexError(_) => assert!(true),
            _                      => assert!(false)
        }
    }
}

#[test]
fn test_from_hex_success() {
    match SecretKey::from_hex(String::from("18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725")) {
        Ok(_)    => assert!(true),
        Err(err) => match err {
            Error::FromHexError(_) => assert!(false),
            _                      => assert!(false)
        }
    }
}

#[test]
fn test_from_hex_invalid_key() {
    match SecretKey::from_hex(String::from("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")) {
        Ok(_)    => assert!(false, "max valid value: 0xFFFF FFFF FFFF FFFF FFFF FFFF FFFF FFFE BAAE DCE6 AF48 A03B BFD2 5E8C D036 4140"),
        Err(err) => match err {
            Error::InvalidSecretKey => assert!(true),
            _                       => assert!(false, "wrong error")
        }
    }
}
