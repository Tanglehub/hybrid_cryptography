#[cfg(feature = "saber")]
use crate::schemes::key_encapsulation::Firesaber;
use crate::schemes::key_encapsulation::KeyEncapsulationScheme;
use crate::schemes::key_encapsulation::SchemeInfoReference;
use std::collections::HashMap;

pub fn get_name_to_ref_mapping() -> HashMap<String, SchemeInfoReference> {
    let mut map: HashMap<String, SchemeInfoReference> = HashMap::new();
    #[cfg(feature = "saber")]
    map.insert(
        "firesaber".to_string(),
        SchemeInfoReference {
            scheme_id: 0,
            scheme_config_id: 0,
            scheme_impl: Box::new(Firesaber),
        },
    );
    return map;
}

pub fn get_id_to_ref_mapping() -> HashMap<(u8, u8), Box<dyn KeyEncapsulationScheme>> {
    let mut map: HashMap<(u8, u8), Box<dyn KeyEncapsulationScheme>> = HashMap::new();
    let name_mapping = get_name_to_ref_mapping();
    for (_k, v) in name_mapping {
        map.insert((v.scheme_id, v.scheme_config_id), v.scheme_impl);
    }
    return map;
}
