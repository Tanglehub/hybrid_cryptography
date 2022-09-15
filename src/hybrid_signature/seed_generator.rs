use crate::schemes::key_encapsulation;
use crate::schemes::signature;
use std::convert::TryInto;

pub fn generate_random_seed(
    signature_algorithms: &[String],
    key_encapsulation_algorithms: &[String],
) -> Vec<u8> {
    let mut seed = [0u8; 48];
    getrandom::getrandom(&mut seed).expect("Random seed could not be loaded!");
    return wrap_seed(signature_algorithms, key_encapsulation_algorithms, seed);
}

pub fn wrap_seed(
    signature_algorithms: &[String],
    key_encapsulation_algorithms: &[String],
    seed: [u8; 48]
) -> Vec<u8> {
    let signature_mapping = signature::get_name_to_ref_mapping();
    let mut result = Vec::<u8>::new();
    result.push(signature_algorithms.len().try_into().unwrap());
    for algorithm in signature_algorithms {
        let info = signature_mapping
            .get(algorithm)
            .expect(format!("Algorithm {} not found", algorithm).as_str());
        result.push(info.scheme_id);
        result.push(info.scheme_config_id);
    }
    let key_encapsulation_mapping = key_encapsulation::get_name_to_ref_mapping();
    for algorithm in key_encapsulation_algorithms {
        let info = key_encapsulation_mapping
            .get(algorithm)
            .expect(format!("Algorithm {} not found", algorithm).as_str());
        result.push(info.scheme_id);
        result.push(info.scheme_config_id);
    }
    result.extend(seed.iter());
    return result;
}

