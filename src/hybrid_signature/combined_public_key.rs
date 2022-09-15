use crate::hybrid_signature::seed_branch::create_scheme_seed_branch;
use crate::hybrid_signature::seed_parser::parse_seed;
use crate::schemes::{signature, key_encapsulation};
use crate::schemes::{AlgorithmPurpose, SizeKind, SchemeInfo};

fn add_keyair(public_keys: &mut Vec<u8>, public_key: &[u8], scheme_id: u8, scheme_config_id: u8, scheme_info: SchemeInfo) {
    // Start by pushing the scheme id and configuration
    public_keys.push(scheme_id);
    public_keys.push(scheme_config_id);

    if matches!(scheme_info.pk_size_info.kind, SizeKind::VariableSized) {
        // Add byte length if nessecary
        let le_bytes = &public_key.len().to_le_bytes();
        let slice_end = scheme_info.pk_size_info.variable_size_bytelen.unwrap() as usize;
        public_keys.extend(&le_bytes[..slice_end]);
    }
    public_keys.extend(public_key);
}

pub fn generate_combined_public_key(purpose: AlgorithmPurpose, seed: &[u8]) -> Vec<u8> {
    let parsed_seed = parse_seed(&seed);
    let mut public_keys = Vec::<u8>::new();
    match purpose {
        AlgorithmPurpose::Signature => {
            let mapping = signature::get_id_to_ref_mapping();
            for scheme_id in parsed_seed.signature_scheme_ids.iter() {
                let scheme_impl = mapping.get(scheme_id).expect(
                    format!(
                        "Algorithm not with id {} and config {} not found!",
                        scheme_id.0, scheme_id.1
                    )
                    .as_str(),
                );
                let seed_branch = create_scheme_seed_branch(&parsed_seed.seed, AlgorithmPurpose::Signature, scheme_id.0, scheme_id.1);
                // Generate keypair
                let keypair = scheme_impl.generate_keypair(&seed_branch);
                // Add size data
                let scheme_info = scheme_impl.get_scheme_info();
                add_keyair(&mut public_keys, &keypair.pk, scheme_id.0, scheme_id.1, scheme_info);
            }
        }
        AlgorithmPurpose::KeyEncapsulation => {
            let mapping = key_encapsulation::get_id_to_ref_mapping();
            for scheme_id in parsed_seed.key_encapsulation_scheme_ids.iter() {
                let scheme_impl = mapping.get(scheme_id).expect(
                    format!(
                        "Algorithm not with id {} and config {} not found!",
                        scheme_id.0, scheme_id.1
                    )
                    .as_str(),
                );
                let seed_branch = create_scheme_seed_branch(&parsed_seed.seed, AlgorithmPurpose::KeyEncapsulation, scheme_id.0, scheme_id.1);
                // Generate keypair
                let keypair = scheme_impl.generate_keypair(&seed_branch);
                // Add size data
                let scheme_info = scheme_impl.get_scheme_info();
                add_keyair(&mut public_keys, &keypair.pk, scheme_id.0, scheme_id.1, scheme_info);
            }
        }
    }
    return public_keys;
}
