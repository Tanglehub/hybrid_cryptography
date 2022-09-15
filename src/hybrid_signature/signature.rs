use crate::hybrid_signature::parse_combined_public_key;
use crate::hybrid_signature::seed_branch::create_scheme_seed_branch;
use crate::hybrid_signature::seed_parser::parse_seed;
use crate::schemes::signature::get_id_to_ref_mapping;
use crate::schemes::{AlgorithmPurpose, SizeKind};
use std::convert::TryInto;
use std::mem;

pub fn sign_message(seed: &[u8], message: &[u8]) -> Vec<u8> {
    let mapping = get_id_to_ref_mapping();
    let parsed_seed = parse_seed(&seed);
    let mut message_signatures = Vec::<u8>::new();
    for scheme_id in parsed_seed.signature_scheme_ids.iter() {
        let scheme_impl = mapping.get(scheme_id).expect(
            format!(
                "Algorithm not with id {} and config {} not found!",
                scheme_id.0, scheme_id.1
            )
            .as_str(),
        );
        let seed_branch = create_scheme_seed_branch(&parsed_seed.seed, AlgorithmPurpose::Signature, scheme_id.0, scheme_id.1);

        // Start by pushing the scheme id and configuration
        message_signatures.push(scheme_id.0);
        message_signatures.push(scheme_id.1);
        // Generate keypair
        let keypair = scheme_impl.generate_keypair(&seed_branch);

        // Sign said message
        let signature = scheme_impl.sign_message(&keypair.sk, message);
        // Add size data
        let scheme_info = scheme_impl.get_scheme_info();
        if matches!(scheme_info.ct_size_info.kind, SizeKind::VariableSized) {
            // Add byte length if nessecary
            let le_bytes = &signature.len().to_le_bytes();
            let slice_end = scheme_info.ct_size_info.variable_size_bytelen.unwrap() as usize;
            message_signatures.extend(&le_bytes[..slice_end]);
        }
        message_signatures.extend(&signature);
    }
    return message_signatures;
}

pub fn verify_message(message: &[u8], combined_public_key: &[u8], signature: &[u8]) -> bool {
    let mapping = get_id_to_ref_mapping();
    let mut idx: usize = 0;
    let parsed_combined_public_key =
        parse_combined_public_key(AlgorithmPurpose::Signature, &combined_public_key);
    while idx < signature.len() {
        // Get the ID and configuration
        let scheme_id = (signature[idx], signature[idx + 1]);
        let scheme_impl = mapping.get(&scheme_id).expect(
            format!(
                "Algorithm with id {} and config {} not found!",
                scheme_id.0, scheme_id.1
            )
            .as_str(),
        );
        idx += 2;
        let scheme_info = scheme_impl.get_scheme_info();
        let signature_length = match scheme_info.ct_size_info.kind {
            SizeKind::VariableSized => {
                let signature_len_byte_size =
                    scheme_info.ct_size_info.variable_size_bytelen.unwrap() as usize;
                let slice = &signature[idx..idx + signature_len_byte_size];
                idx += signature_len_byte_size;
                let mut vec_bytes = slice.to_vec();
                vec_bytes.resize(mem::size_of::<usize>(), 0u8);
                usize::from_le_bytes(vec_bytes[..].try_into().unwrap())
            }
            SizeKind::FixedSized => {
                scheme_info.ct_size_info.fixed_size.expect("When ct_size_info.kind == SizeKind::FixedSized, ct_size_info.fixed_size must be set!") as usize
            }
        };
        let signature = &signature[idx..idx + signature_length];
        let verified = scheme_impl.verify_message(
            &message,
            &signature,
            parsed_combined_public_key
                .id_mapping
                .get(&scheme_id)
                .expect(
                    format!(
                        "Public key not with id {} and config {} not found!",
                        scheme_id.0, scheme_id.1
                    )
                        .as_str(),
                ),
        );
        if !verified {
            return false;
        }
        idx += signature_length;
    }
    return true;
}
