use crate::schemes::AlgorithmPurpose;
use crate::schemes::{signature, key_encapsulation, SchemeInfo};
use std::collections::HashMap;

pub fn get_id_to_info_mapping(purpose: AlgorithmPurpose) -> HashMap<(u8, u8), SchemeInfo> {
    let mut map: HashMap<(u8, u8), SchemeInfo> = HashMap::new();
    match purpose {
        AlgorithmPurpose::KeyEncapsulation => {
            let name_mapping = key_encapsulation::get_name_to_ref_mapping();
            for (_k, v) in name_mapping {
                map.insert((v.scheme_id, v.scheme_config_id), v.scheme_impl.get_scheme_info());
            }
        }
        AlgorithmPurpose::Signature => {
            let name_mapping = signature::get_name_to_ref_mapping();
            for (_k, v) in name_mapping {
                map.insert((v.scheme_id, v.scheme_config_id), v.scheme_impl.get_scheme_info());
            }
        }
    }
    return map;
}
