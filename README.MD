
#### Pet project goals
 > Try Rust language 

 > Better understand Bitcoin internals

#### Description
main.rs code is mainly based on instructions from [Technical background of version 1 Bitcoin addresses](https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses).

Added example for generating address from uncompressed puplic key.

#### Output
    
    Technical background of version 1 Bitcoin addresses

    0 - Having a private ECDSA key
    "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725"
    1 - Take the corresponding public key generated with it (33 bytes, 1 byte 0x02 (y-coord is even), and 32 bytes corresponding to X coordinate)
    COMPRESSED:   "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
    UNCOMPRESSED: "0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b23522cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6"
    2 - Perform SHA-256 hashing on the public key
    COMPRESSED:   "0b7c28c9b7290c98d7438e70b3d3f7c848fbd7d1dc194ff83f4f7cc9b1378e98"
    UNCOMPRESSED: "600ffe422b4e00731a59557a5cca46cc183944191006324a447bdb2d98d4b408"
    3 - Perform RIPEMD-160 hashing on the result of SHA-256
    COMPRESSED:   "f54a5851e9372b87810a8e60cdd2e7cfd80b6e31"
    UNCOMPRESSED: "010966776006953d5567439e5e39f86a0d273bee"
    4 - Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
    COMPRESSED:   "00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31"
    UNCOMPRESSED: "00010966776006953d5567439e5e39f86a0d273bee"

    (note that below steps are the Base58Check encoding, which has multiple library options available implementing it)

    5 - Perform SHA-256 hash on the extended RIPEMD-160 result
    COMPRESSED:   "ad3c854da227c7e99c4abfad4ea41d71311160df2e415e713318c70d67c6b41c"
    UNCOMPRESSED: "445c7a8007a93d8733188288bb320a8fe2debd2ae1b47f0f50bc10bae845c094"
    6 - Perform SHA-256 hash on the result of the previous SHA-256 hash
    COMPRESSED:   "c7f18fe8fcbed6396741e58ad259b5cb16b7fd7f041904147ba1dcffabf747fd"
    UNCOMPRESSED: "d61967f63c7dd183914a4ae452c9f6ad5d462ce3d277798075b107615c1a8a30"
    7 - Take the first 4 bytes of the second SHA-256 hash. This is the address checksum
    COMPRESSED:   "c7f18fe8"
    UNCOMPRESSED: "d61967f6"
    8 - Add the 4 checksum bytes from stage 7 at the end of extended RIPEMD-160 hash from stage 4. This is the 25-byte binary Bitcoin Address.
    COMPRESSED:   "00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31c7f18fe8"
    UNCOMPRESSED: "00010966776006953d5567439e5e39f86a0d273beed61967f6"
    9 - Convert the result from a byte string into a base58 string using Base58Check encoding. This is the most commonly used Bitcoin Address format
    COMPRESSED:   "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs"
    UNCOMPRESSED: "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
