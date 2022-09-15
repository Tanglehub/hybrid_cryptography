use crate::hybrid_signature::generate_combined_public_key;
use crate::schemes::AlgorithmPurpose;

pub fn hash_combined_public_key(combined_public_key: &[u8]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[
        1 // = purpose number for hashing combined public keys
    ]);
    hasher.update(combined_public_key);
    let result = hasher.finalize();
    return result.as_bytes().to_vec();
}

pub fn generate_address(purpose: AlgorithmPurpose, seed: &[u8]) -> Vec<u8> {
    let combined_public_key = generate_combined_public_key(purpose, seed);
    return hash_combined_public_key(&combined_public_key);
}