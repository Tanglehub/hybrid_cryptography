use crate::schemes::key_encapsulation::get_id_to_ref_mapping;
use crate::hybrid_signature::seed_branch::create_scheme_seed_branch;
use crate::hybrid_signature::seed_parser::parse_seed;
use crate::schemes::{AlgorithmPurpose, SizeKind};
use crate::parse_combined_public_key;
use std::convert::TryInto;
use std::mem;
use hex_literal::hex;

// echo -n "I'm Peter and I have nothing up my sleeve, this is a salt for hashing shared secrets." | openssl sha384
const SHARED_SECRET_SALT: &[u8; 48] = &hex!("ca394d16444e060f4006af7a1a44662e29dbcaf7f46953439253fd253e1b9fd6cb0893192f674360c53555615cb36139");

pub fn encapsulate(_seed: &[u8], pk_other_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mapping = get_id_to_ref_mapping();
    let parsed_combined_public_key =
        parse_combined_public_key(AlgorithmPurpose::KeyEncapsulation, &pk_other_bytes).unwrap();
    let mut ciphertexts = Vec::<u8>::new();

    let mut hasher = blake3::Hasher::new();
    hasher.update(SHARED_SECRET_SALT);
    
    for (scheme_id, pk_slice) in parsed_combined_public_key.id_mapping.iter() {
        let scheme_impl = mapping.get(scheme_id).expect(
            format!(
                "Algorithm not with id {} and config {} not found!",
                scheme_id.0, scheme_id.1
            )
            .as_str(),
        );
        
        // Create shared secret and ciphertext
        let (ss, ct) = scheme_impl.encapsulate(&pk_slice);
        hasher.update(&ss);

        // Start by pushing the scheme id and configuration
        ciphertexts.push(scheme_id.0);
        ciphertexts.push(scheme_id.1);

        // Add size data
        let scheme_info = scheme_impl.get_scheme_info();
        if matches!(scheme_info.ct_size_info.kind, SizeKind::VariableSized) {
            // Add byte length if nessecary
            let le_bytes = &ct.len().to_le_bytes();
            let slice_end = scheme_info.ct_size_info.variable_size_bytelen.unwrap() as usize;
            ciphertexts.extend(&le_bytes[..slice_end]);
        }
        ciphertexts.extend(&ct);
    }
    return (hasher.finalize().as_bytes().to_vec(), ciphertexts);
}

pub fn decapsulate(seed: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mapping = get_id_to_ref_mapping();
    let mut idx: usize = 0;

    let mut hasher = blake3::Hasher::new();
    hasher.update(SHARED_SECRET_SALT);
    
    while idx < ciphertext.len() {
        // Get the ID and configuration
        let scheme_id = (ciphertext[idx], ciphertext[idx + 1]);
        let scheme_impl = mapping.get(&scheme_id).expect(
            format!(
                "Algorithm not with id {} and config {} not found!",
                scheme_id.0, scheme_id.1
            )
            .as_str(),
        );
        idx += 2;
        let scheme_info = scheme_impl.get_scheme_info();
        let ciphertext_length = match scheme_info.ct_size_info.kind {
            SizeKind::VariableSized => {
                let ciphertext_len_byte_size =
                scheme_info.ct_size_info.variable_size_bytelen.unwrap() as usize;
                let slice = &ciphertext[idx..idx + ciphertext_len_byte_size];
                idx += ciphertext_len_byte_size;
                let mut vec_bytes = slice.to_vec();
                vec_bytes.resize(mem::size_of::<usize>(), 0u8);
                usize::from_le_bytes(vec_bytes[..].try_into().unwrap())
            }
            SizeKind::FixedSized => {
                scheme_info.ct_size_info.fixed_size.expect("When ct_size_info.kind == SizeKind::FixedSized, ct_size_info.fixed_size must be set!") as usize
            }
        };
        let ciphertext = &ciphertext[idx..idx + ciphertext_length];
        idx += ciphertext_length;

        // Generate keypair
        let parsed_seed = parse_seed(&seed);
        let seed_branch = create_scheme_seed_branch(&parsed_seed.seed, AlgorithmPurpose::KeyEncapsulation, scheme_id.0, scheme_id.1);
        let keypair = scheme_impl.generate_keypair(&seed_branch);
        let ss = scheme_impl.decapsulate(&ciphertext, &keypair.sk);
        hasher.update(&ss);
    }
    return hasher.finalize().as_bytes().to_vec();
}
