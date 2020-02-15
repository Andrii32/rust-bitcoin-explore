use rust_base58::{ToBase58, FromBase58};

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
    {
        println!("TECHNICAL BACKGROUND OF VERSION 1 BITCOIN ADDRESSES\n");

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

    // Wallet import format
    // Based on: https://en.bitcoin.it/wiki/Wallet_import_format
    println!("\nWALLET IMPORT FORMAT\n");

    // Private key to WIF
    {
        println!("Private key to WIF\n");

        println!("1 - Take a private key");
        let secret_key = SecretKey::from_hex(String::from("0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D")).unwrap();
        println!("{:?}", secret_key.to_hex());

        println!("2 - Add a 0x80 byte in front of it for mainnet addresses or 0xef for testnet addresses. \
                 Also add a 0x01 byte at the end if the private key will correspond to a compressed public key");
        let mut secret_key_prep = secret_key.to_bytes();
        secret_key_prep.insert(0, 0x80);
        println!("{:?}", hex::encode(&secret_key_prep));

        println!("3 - Perform SHA-256 hash on the extended key");
        let secret_key_prep_sha256 = sha256(secret_key_prep.to_vec());
        println!("{:?}", hex::encode(&secret_key_prep_sha256));

        println!("4 - Perform SHA-256 hash on result of SHA-256 hash");
        let secret_key_prep_sha256_sha256 = sha256(secret_key_prep_sha256);
        println!("{:?}", hex::encode(&secret_key_prep_sha256_sha256));

        println!("5 - Take the first 4 bytes of the second SHA-256 hash, this is the checksum");
        let checksum = &secret_key_prep_sha256_sha256[0..4];
        println!("{:?}", hex::encode(&checksum));

        println!("6 - Add the 4 checksum bytes from point 5 at the end of the extended key from point 2");
        let mut secret_key_prep_extended = secret_key_prep.to_vec();
        secret_key_prep_extended.extend(checksum);
        println!("{:?}", hex::encode(&secret_key_prep_extended));

        println!("7 - Convert the result from a byte string into a base58 string using Base58Check encoding. \
                 This is the Wallet Import Format");
        let secret_key_prep_extended_base58 = secret_key_prep_extended.to_base58();
        println!("{:?}", secret_key_prep_extended_base58);
    }

    // WIF to private key
    {
        println!("\nWIF to private key\n");

        println!("1 - Take a Wallet Import Format string");
        let wif = String::from("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ");
        println!("{:?}", &wif);

        println!("2 - Convert it to a byte string using Base58Check encoding");
        let wif_bytes = wif.from_base58().unwrap();
        println!("{:?}", hex::encode(&wif_bytes));

        println!("3 - Drop the last 4 checksum bytes from the byte string");
        let wif_bytes_nochecksum = &wif_bytes[0..wif_bytes.len() - 4].to_vec();
        println!("{:?}", hex::encode(&wif_bytes_nochecksum));

        println!("4 - Drop the first byte (it should be 0x80). \
                 If the private key corresponded to a compressed public key, also drop the last byte (it should be 0x01). \
                 If it corresponded to a compressed public key, the WIF string will have started with K or L instead of 5 \
                 (or c instead of 9 on testnet). This is the private key.");
        
        let mut wif_bytes_nochecksum_nofirst = wif_bytes_nochecksum.to_vec();
        wif_bytes_nochecksum_nofirst.drain(0..1);
        println!("{:?}", hex::encode(&wif_bytes_nochecksum_nofirst));
    }

    // WIF checksum checking
    {
        println!("\nWIF checksum checking\n");
        
        println!("1 - Take a Wallet Import Format string");
        let wif = String::from("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ");
        println!("{:?}", &wif);

        println!("2 - Convert it to a byte string using Base58Check encoding");
        let wif_bytes = wif.from_base58().unwrap();
        println!("{:?}", hex::encode(&wif_bytes));

        println!("3 - Drop the last 4 checksum bytes from the byte string");
        let wif_bytes_nochecksum = &wif_bytes[0..wif_bytes.len() - 4].to_vec();
        println!("{:?}", hex::encode(&wif_bytes_nochecksum));

        println!("4 - Perform SHA-256 hash on the shortened string");
        let wif_bytes_nochecksum_sha256 = sha256(wif_bytes_nochecksum.to_vec());
        println!("{:?}", hex::encode(&wif_bytes_nochecksum_sha256));

        println!("5 - Perform SHA-256 hash on result of SHA-256 hash");
        let wif_bytes_nochecksum_sha256_sha256 = sha256(wif_bytes_nochecksum_sha256.to_vec());
        println!("{:?}", hex::encode(&wif_bytes_nochecksum_sha256_sha256));

        println!("6 - Take the first 4 bytes of the second SHA-256 hash, this is the checksum");
        let checksum = &wif_bytes_nochecksum_sha256_sha256[0..4];
        println!("{:?}", hex::encode(&checksum));

        println!("7 - Make sure it is the same, as the last 4 bytes from point 2");
        let last4 = wif_bytes[(wif_bytes.len() - 4)..wif_bytes.len()].to_vec();
        assert_eq!(checksum.to_vec(), last4.to_vec());
        println!("{:?}", hex::encode(&last4));

        println!("8 - If they are, and the byte string from point 2 starts with 0x80 (0xef for testnet addresses), then there is no error.");
        
    }
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
