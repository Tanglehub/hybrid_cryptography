use crate::schemes::AlgorithmPurpose;

pub fn create_scheme_seed_branch(seed: &[u8], purpose: AlgorithmPurpose, scheme_id: u8, scheme_config_id: u8) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[
        match purpose {
            AlgorithmPurpose::Signature => 0,
            AlgorithmPurpose::KeyEncapsulation => 1
        }, // = purpose number for branching to different algorithms
        scheme_id,
        scheme_config_id,
    ]);
    hasher.update(&seed);
    let result = hasher.finalize();
    return result.as_bytes().to_vec();
}