use std::convert::TryInto;
use std::collections::HashMap;
use std::mem;
use crate::schemes::SizeKind;
use crate::schemes::AlgorithmPurpose;
use crate::scheme_info_mapping::get_id_to_info_mapping;

pub struct ParsedCombinedPublicKey {
    pub id_mapping: HashMap<(u8, u8), Vec<u8>>
}

pub fn parse_combined_public_key(purpose: AlgorithmPurpose, combined_public_key: &[u8]) -> ParsedCombinedPublicKey {
    let mapping = get_id_to_info_mapping(purpose);
    let mut idx: usize = 0;
    let mut id_mapping: HashMap<(u8, u8), Vec<u8>> = HashMap::new();
    while idx < combined_public_key.len() {
        let scheme_id = (combined_public_key[idx], combined_public_key[idx + 1]);
        let scheme_info = mapping.get(&scheme_id).expect(
            format!(
                "Algorithm with id {} and config {} not found!",
                scheme_id.0, scheme_id.1
            )
            .as_str(),
        );
        idx += 2;
        let mut pk_length: usize = 0;
        if matches!(scheme_info.pk_size_info.kind, SizeKind::VariableSized) {
            let pk_len_byte_size = scheme_info
                .pk_size_info
                .variable_size_bytelen
                .unwrap() as usize;
            let slice = &combined_public_key[idx..idx + pk_len_byte_size];
            idx += pk_len_byte_size;
            let mut vec_bytes = slice.to_vec();
            vec_bytes.resize(mem::size_of::<usize>(), 0u8);
            pk_length = usize::from_le_bytes(vec_bytes[..].try_into().unwrap());
        }
        else if matches!(scheme_info.pk_size_info.kind, SizeKind::FixedSized) {
            pk_length = scheme_info.pk_size_info.fixed_size.expect(format!("fixed_size for algorithm with id {} and config {} None while FixedSized is defined!", scheme_id.0, scheme_id.1).as_str()) as usize;
        }

        let pk = &combined_public_key[idx..idx + pk_length];
        id_mapping.insert(scheme_id, pk.to_vec());
        idx += pk_length;
    }
    return ParsedCombinedPublicKey {
        id_mapping: id_mapping
    }
}